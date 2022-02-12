#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#define INCLUDE_AUTH_CONST
#define INCLUDE_PEER_CONST
#include <raims/user_db.h>
#include <raims/ev_inbox_transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

UserDB::UserDB( EvPoll &/*p*/,  ConfigTree::User &u,
                ConfigTree::Service &s,  SubDB &sdb,
                StringTab &st,  EventRecord &ev ) noexcept
  : user( u ), svc( s ), sub_db( sdb ), string_tab( st ), events( ev ),
    session_key( 0 ), hello_key( 0 ), cnonce( 0 ), node_ht( 0 ), zombie_ht( 0 ),
    uid_tab( 0 ), peer_ht( 0 ), peer_key_ht( 0 ), peer_keys( 0 ),
    auth_bloom( 0, "auth" ), hb_interval( HB_DEFAULT_INTERVAL ),
    peer_dist( *this )
{
  this->start_mono_time = current_monotonic_time_ns(); 
  this->start_time      = current_realtime_ns();
  this->rand.static_init( this->start_mono_time, this->start_time );
}

bool
UserDB::init( const CryptPass &pwd,  uint32_t my_fd,
              ConfigTree &tree ) noexcept
{
  ConfigTree::User *u;
  uint32_t i;

  /* load the service and check RSA signatures of users configured */
  this->my_svc.load_service( tree, this->svc );
  if ( ! this->my_svc.check_signatures( pwd ) )
    return false;
  if ( this->my_svc.users.is_empty() ) {
    fprintf( stderr, "No users in service %s\n", this->svc.svc.val );
    return false;
  }
  /* put the keys in secure area which can't be swapped or coredumped */
  this->session_key = this->make_secure_obj<HashDigest>();
  this->hello_key   = this->make_secure_obj<HashDigest>();
  this->cnonce      = this->make_secure_obj<CnonceRandom>();
  this->peer_keys   = this->make_secure_obj<PeerKeyCache>();

  /* bridge id is public user hmac + nonce which identifies this peer */
  this->bridge_id.nonce.seed_random();    /* random nonce */
  /* session key is private key used to authenticate messages for bridge_id */
  this->session_key->make_session_rand(); /* random session key */

  this->uid_csum.zero(); /* the xor of all peers authenticated */
  /* index nonce -> bridge_id instance active */
  this->node_ht          = NodeHashTab::resize( NULL );
  /* index nonce -> bridge_id instance which is not reachable */
  this->zombie_ht        = NodeHashTab::resize( NULL );
  /* index hash( uid ) -> uid */
  this->uid_tab          = UidHT::resize( NULL );
  /* index user hmac -> peer data */
  this->peer_ht          = NodeHashTab::resize( NULL );
  /* index hash (src_uid, dest_uid) -> encrypted peer key */
  this->peer_key_ht      = PeerKeyHashTab::resize( NULL );
  this->next_uid         = 0; /* uid assigned to each node */
  this->free_uid_count   = 0; /* after uid freed, this count updated */
  this->uid_auth_count   = 0; /* how many peers are trusted */
  this->uid_hb_count     = 0; /* how many peers are trusted */
  this->send_peer_seqno  = 0; /* sequence num of peer add/del msgs */
  this->link_state_seqno = 0; /* sequence num of link state msgs */
  this->mcast_seqno      = 0; /* sequence num of mcast msgs */
  this->hb_ival_ns       = 0; /* hb interval in nanos */
  this->hb_ival_mask     = 0; /* hb interval mask, pow2 - 1 > hv_ival_ns */
  this->next_ping_mono   = 0; /* when the next random ping timer expires */

  this->new_uid(); /* alloc uid 0 for me prevent loops */
  this->my_src_fd = my_fd;
  this->bridge_tab[ MY_UID ] = NULL;
  /* MY_UID = 0, data for it is *this, peer data are at bridge_tab[ uid ] */
  this->node_ht->upsert_rsz( this->node_ht, this->bridge_id.nonce, MY_UID );
  i = 0;
  for ( u = tree.users.hd; u != NULL; u = u->next )
    if ( u->svc.equals( this->svc.svc ) )
      i++;
  this->peer_db.make( i );
  /* allocated peer data */
  i = 0;
  for ( u = tree.users.hd; u != NULL; u = u->next ) {
    if ( u->svc.equals( this->svc.svc ) )
      this->peer_db[ i++ ] = this->make_peer( u->user, u->svc, u->create,
                                              u->expires );
  }
  UserBuf      my_user( this->user );
  UserHmacData data( my_user );
  /* get the ECDH pub an pri keys, pri for calc ECDH key exchange secret */
  if ( ! data.decrypt( pwd, DO_BOTH ) )
    return false;
  this->bridge_id.hmac = data.user_hmac;
  /* calc my hello key: kdf( my ECDH pub + my RSA svc pub ) */
  data.calc_hello_key( this->my_svc, *this->hello_key );
  bool b = true;
  i = 0;
  /* calculate keys for each peer configured */
  for ( u = tree.users.hd; u != NULL; u = u->next ) {
    if ( u->svc.equals( this->svc.svc ) ) {
      PeerEntry  & peer = *this->peer_db[ i ];
      UserBuf      p_user( *u );
      UserHmacData peer_data( p_user );
      /* get the ECDH pub key for peer */
      if ( ! peer_data.decrypt( pwd, DO_PUB ) )
        return false;
      /* do ECDH to calculate secret for this peer: my pri + peer pub */
      if ( ! data.calc_secret_hmac( peer_data, peer.secret_hmac ) )
        return false;
      /* peer hmac is based on the ECDH pub key plus name and svc */
      peer.hmac = peer_data.user_hmac;
      /* hello key is based on peer ECDH pub + RSA pub of service */
      peer_data.calc_hello_key( this->my_svc, peer.hello_key );
      this->peer_ht->upsert_rsz( this->peer_ht, peer.hmac, i );
      i++;
    }
  }
  this->auth_bloom.add( hello_h );
  this->auth_bloom.add( hb_h ); 
  this->auth_bloom.add( bye_h );
  this->auth_bloom.add( blm_h );
  this->auth_bloom.add( adj_h );
  this->auth_bloom.add_route( S_JOIN_SZ, join_h );
  this->auth_bloom.add_route( S_LEAVE_SZ, leave_h );
  this->auth_bloom.add_route( P_PSUB_SZ, psub_h );
  this->auth_bloom.add_route( P_PSTOP_SZ, pstop_h );
  return b;
}

bool
UserDB::forward_to( UserBridge &n,  const char *sub,
                    size_t sublen,  uint32_t h,  const void *msg,
                    size_t msg_len,  UserRoute &u_rte ) noexcept
{
  if ( &u_rte != n.primary( *this ) ) {
    if ( debug_usr )
      n.printf( "inbox user_route not primary (fd=%u, primary=%u) (%.*s)\n",
                u_rte.mcast_fd, n.primary( *this )->mcast_fd,
                (int) sublen, sub );
    if ( u_rte.rte.is_mcast() && ! u_rte.is_set( UCAST_URL_STATE ) ) {
      n.printf( "inbox has no url\n" );
      uint32_t hops;
      UserBridge *m = this->closest_peer_route( u_rte.rte, n, hops );
      if ( m != NULL ) {
        UserRoute *u_peer = m->user_route_ptr( *this, u_rte.rte.tport_id );
        if ( u_peer->is_valid() &&
             u_peer->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) ) {
          u_rte.mcast_fd = u_peer->mcast_fd;
          u_rte.inbox_fd = u_peer->inbox_fd;
          u_rte.hops     = 1;
          if ( u_peer->is_set( UCAST_URL_STATE ) )
            u_rte.set_ucast( *this, NULL, 0, u_peer );
          else
            u_rte.set_ucast( *this, NULL, 0, u_peer->ucast_src );
          n.printf( "inbox has routing through %s\n", m->peer.user.val );
          this->push_user_route( n, u_rte );
        }
      }
    }
  }
  u_rte.bytes_sent += msg_len;
  u_rte.msgs_sent++;
  if ( u_rte.is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) == 0 ) {
    EvPublish pub( sub, sublen, NULL, 0, msg, msg_len, u_rte.rte.sub_route,
                   this->my_src_fd, h, CABA_TYPE_ID, 'p' );
    /*d_usr( "forwrd %.*s to (%s) inbox %u\n",
            (int) sublen, sub, n.peer.user.val, u_rte.inbox_fd );*/
    return u_rte.rte.sub_route.forward_to( pub, u_rte.inbox_fd );
  }
  if ( u_rte.is_set( UCAST_URL_SRC_STATE ) == 0 ) {
    InboxPublish ipub( sub, sublen, msg, msg_len, u_rte.rte.sub_route,
                       this->my_src_fd, h, CABA_TYPE_ID, u_rte.ucast_url, n.uid,
                       u_rte.url_hash );
    /*d_usr( "forward %.*s to (%s) ucast( %s ) inbox %u\n",
       (int) sublen, sub, n.peer.user.val, u_rte.ucast_url, u_rte.inbox_fd );*/
    return u_rte.rte.sub_route.forward_to( ipub, u_rte.inbox_fd );
  }
  const UserRoute  & u_src = *u_rte.ucast_src;
  const UserBridge & n_src = u_src.n;
  InboxPublish isrc( sub, sublen, msg, msg_len, u_src.rte.sub_route,
                     this->my_src_fd, h, CABA_TYPE_ID, u_src.ucast_url,
                     n_src.uid, u_src.url_hash );
  /*d_usr( "forward %.*s to (%s) ucast( %s ) inbox %u\n",
       (int) sublen, sub, n.peer.user.val, u_src.ucast_url, u_src.inbox_fd );*/
  return u_src.rte.sub_route.forward_to( isrc, u_src.inbox_fd );
}

PeerEntry *
UserDB::make_peer( const StringVal &user,  const StringVal &svc,
                   const StringVal &create,  const StringVal &expires ) noexcept
{
  size_t len = sizeof( PeerEntry );
  PeerEntry * peer = this->make_peer_entry( len );
  peer->user    = user;
  peer->svc     = svc;
  peer->create  = create;
  peer->expires = expires;
  return peer;
}

void
UserDB::release_alloc( void ) noexcept
{
  while ( ! this->buf_list.is_empty() ) {
    UserAllocBuf *p = this->buf_list.pop_hd();
    free_secure_mem( p->buf, UserAllocBuf::BUF_ALLOC_SIZE );
    delete p;
  }
}

void *
UserDB::alloc_slow( size_t size ) noexcept
{
  void * p = ::malloc( sizeof( UserAllocBuf ) );
  UserAllocBuf * b = new ( p ) UserAllocBuf();
  b->buf = (uint8_t *) alloc_secure_mem( UserAllocBuf::BUF_ALLOC_SIZE );
  this->buf_list.push_tl( b );
  return b->alloc( size );
}

void
UserDB::release( void ) noexcept
{
  if ( this->node_ht != NULL ) {
    delete this->node_ht;
    this->node_ht = NULL;
  }
  if ( this->zombie_ht != NULL ) {
    delete this->zombie_ht;
    this->zombie_ht = NULL;
  }
  if ( this->uid_tab != NULL ) {
    delete this->uid_tab;
    this->uid_tab = NULL;
  }
  if ( this->bridge_tab.size != 0 ) {
    this->bridge_tab.clear();
  }
  if ( this->peer_ht != NULL ) {
    delete this->peer_ht;
    this->peer_ht = NULL;
  }
  this->peer_db.clear();
  this->route_list.reset();
  this->hb_queue.reset();
  this->challenge_queue.reset();
  this->subs_queue.reset();
  this->adj_queue.reset();
  this->ping_queue.reset();
  this->pending_queue.reset();
  this->uid_authenticated.reset();
  this->random_walk.reset();
  this->bridge_id.zero();
  this->session_key = NULL;
  this->cnonce      = NULL;
  this->uid_csum.zero();
  this->release_alloc();
}

void
UserDB::check_user_timeout( uint64_t current_mono_time,
                            uint64_t current_time ) noexcept
{
  UserBridge *n;
  char buf[ 256 ];
  bool req_timeout = false;
  while ( this->subs_queue.num_elems > 0 ) {
    n = this->subs_queue.heap[ 0 ];
    if ( current_mono_time < n->subs_timeout() )
      break;
    if ( debug_usr )
      n->printf( "subs request timeout (%s)\n",
             n->primary( *this )->inbox_route_str( buf, sizeof( buf ) ) );
    n->clear( SUBS_REQUEST_STATE );
    this->subs_queue.pop();
  }

  while ( this->adj_queue.num_elems > 0 ) {
    n = this->adj_queue.heap[ 0 ];
    if ( current_mono_time < n->adj_timeout() )
      break;
    /*if ( debug_usr )*/
      n->printf( "adjacency request timeout (%s)\n",
             n->primary( *this )->inbox_route_str( buf, sizeof( buf ) ) );
    n->clear( ADJACENCY_REQUEST_STATE );
    this->adj_queue.pop();
    if ( ! n->test_set( PING_STATE ) ) {
      n->ping_mono_time = current_mono_time;
      this->ping_queue.push( n );
      this->send_ping_request( *n );
    }
    req_timeout = true;
  }

  while ( this->ping_queue.num_elems > 0 ) {
    n = this->ping_queue.heap[ 0 ];
    if ( current_mono_time < n->ping_timeout() )
      break;
    this->ping_queue.pop();
    if ( ++n->ping_fail_count >= 3 ) {
      /*if ( debug_usr )*/
        n->printf( "ping request timeout (%s)\n",
             n->primary( *this )->inbox_route_str( buf, sizeof( buf ) ) );
      if ( n->ping_fail_count > 6 && this->adjacency_unknown.is_empty() ) {
        n->clear( PING_STATE );
        this->remove_authenticated( *n, BYE_PING );
        n = NULL;
      }
      else
        req_timeout = true;
    }
    if ( n != NULL ) {
      n->ping_mono_time = current_mono_time;
      this->ping_queue.push( n );
      this->send_ping_request( *n );
    }
  }

  if ( this->pending_queue.num_elems > 0 )
    this->process_pending_peer( current_mono_time );

  if ( ! this->adjacency_unknown.is_empty() )
    this->process_unknown_adjacency( current_mono_time );

  while ( this->hb_queue.num_elems > 0 ) {
    n = this->hb_queue.heap[ 0 ];
    if ( current_mono_time < n->hb_timeout() )
      break;
    this->events.hb_timeout( n->uid );
    n->printf( "no heartbeat detected in interval %u (%.1fsecs), dropping\n",
               n->hb_interval,
               (double) ( current_mono_time - n->hb_mono_time ) / SEC_TO_NS );
    n->clear( IN_HB_QUEUE_STATE );
    this->hb_queue.pop();
    this->remove_authenticated( *n, BYE_HB_TIMEOUT );
  }

  while ( this->challenge_queue.num_elems > 0 ) {
    n = this->challenge_queue.heap[ 0 ];
    if ( current_mono_time < n->challenge_timeout() )
      break;
    if ( debug_usr )
      n->printf( "clear challenge\n" );
    n->clear( CHALLENGE_STATE );
    this->challenge_queue.pop();
    if ( n->is_set( AUTHENTICATED_STATE ) )
      n->challenge_count = 0;
  }

  UserBridge *m;
  bool run_peer_inc = false;
  this->peer_dist.clear_cache_if_dirty();
  if ( this->peer_dist.inc_run_count == 0 || req_timeout ||
       this->peer_dist.inc_running ) {
    run_peer_inc = true;
  }
  else if ( this->peer_dist.found_inconsistency &&
            this->peer_dist.last_run_mono +
            (uint64_t) this->peer_dist.inc_run_count *
            SEC_TO_NS < current_mono_time ) {
    run_peer_inc = true;
  }
  if ( run_peer_inc ) {
    bool b = this->peer_dist.find_inconsistent2( n, m );
    if ( b ) {
      if ( n != NULL && m != NULL ) {
        if ( ! n->is_set( PING_STATE ) ) {
          d_usr( "find_inconsistent2 from %s(%u) to %s(%u)\n", 
                   n->peer.user.val, n->uid, m->peer.user.val, m->uid );
          this->send_adjacency_request2( *n, *m, DIJKSTRA_SYNC_REQ );
        }
        else if ( n->ping_fail_count >= 3 )
          m = NULL;
      }

      if ( n != NULL && m == NULL ) {
        uint64_t ns,
                 hb_timeout_ns = (uint64_t) n->hb_interval * 2 * SEC_TO_NS;
        ns = n->start_mono_time + hb_timeout_ns; /* if hb and still orphaned */

        if ( this->adjacency_unknown.is_empty() && ns < current_mono_time ) {
          d_usr( "find_inconsistent2 orphaned %s(%u)\n", 
                   n->peer.user.val, n->uid );
          this->remove_authenticated( *n,
            n->ping_fail_count ?  BYE_PING : BYE_ORPHANED );
        }
        else { /* n != NULL && m == NULL */
          for ( size_t j = 0; j < n->adjacency.count; j++ ) {
            AdjacencySpace * p = n->adjacency.ptr[ j ];
            uint32_t uid2;
            if ( p != NULL && p->first( uid2 ) ) {
              do {
                m = this->bridge_tab[ uid2 ];
                if ( m != NULL ) {
                  d_usr( "find_inconsistent3 from %s(%u) to %s(%u)\n", 
                           n->peer.user.val, n->uid, m->peer.user.val, m->uid );
                  this->send_adjacency_request2( *n, *m, DIJKSTRA_SYNC_REQ );
                  goto break_loop;
                }
              } while ( p->next( uid2 ) );
            }
          }
          d_usr( "find_inconsistent2 delay orphaned %s(%u)\n",
                   n->peer.user.val, n->uid );
        break_loop:;
        }
      }
    }
    else {
      if ( ! this->peer_dist.found_inconsistency &&
           this->peer_dist.invalid_mono != 0 ) {
        this->events.converge( this->peer_dist.invalid_reason );
        uint64_t t = ( current_mono_time > this->peer_dist.invalid_mono ) ?
                     ( current_mono_time - this->peer_dist.invalid_mono ) : 0;
        printf( "network converges %.3f secs, %u uids authenticated, %s\n", 
                (double) t / SEC_TO_NS, this->uid_auth_count,
                invalidate_reason_string( this->peer_dist.invalid_reason ) );
      }
      this->find_user_primary_routes();
    }
  }
  else {
    if ( ! this->adjacency_change.is_empty() )
      this->send_adjacency_change();
    if ( this->uid_auth_count > 0 )
      this->interval_ping( current_mono_time, current_time );
    if ( ! this->direct_pending.is_empty() )
      this->process_direct_pending( current_mono_time );
  }
}
const char *
rai::ms::peer_sync_reason_string( PeerSyncReason r ) noexcept {
  return peer_sync_reason_str[ r < MAX_REASON_SYNC ? r : 0 ];
}
const char *
rai::ms::adjacency_change_string( AdjacencyChange c ) noexcept {
  return adjacency_change_str[ c < MAX_ADJ_CHANGE ? c : 0 ];
}
const char *
rai::ms::adjacency_request_string( AdjacencyRequest r ) noexcept {
  return adjacency_request_str[ r < MAX_ADJ_REQ ? r : 0 ];
}
const char *
rai::ms::invalidate_reason_string( InvalidReason r ) noexcept {
  return invalid_reason_str[ r < MAX_INVALIDATE ? r : 0 ];
}

UserBridge *
UserDB::lookup_bridge( MsgFramePublish &pub, const MsgHdrDecoder &dec ) noexcept
{
  Nonce        bridge;
  UserBridge * n;
  size_t       n_pos;
  uint32_t     uid;
  if ( ! dec.get_bridge( bridge ) )
    return NULL;

  if ( this->node_ht->find( bridge, n_pos, uid ) ) {
    n = this->bridge_tab[ uid ];
    if ( n != NULL ) {
      n->user_route = n->user_route_ptr( *this, pub.rte.tport_id );
      if ( ! n->user_route->is_valid() )
        this->add_user_route( *n, pub.rte, pub.src_route, dec, NULL );
      pub.status = FRAME_STATUS_NO_AUTH;
    }
    else if ( uid == MY_UID )
      pub.status = FRAME_STATUS_MY_MSG;
    else
      pub.status = FRAME_STATUS_NO_USER;
    return n;
  }
  return NULL;
}
/* find user from the session : user.Nonce field */
UserBridge *
UserDB::lookup_user( MsgFramePublish &pub,  const MsgHdrDecoder &dec ) noexcept
{
  Nonce        bridge;
  UserBridge * n;
  size_t       n_pos;
  uint32_t     uid;
  /* find node in peer_tab[ node.hash() ] = node_entry -> node */
  if ( ! dec.get_bridge( bridge ) )
    return NULL;
  /* find by nonce */
  if ( this->node_ht->find( bridge, n_pos, uid ) ) {
    n = this->bridge_tab[ uid ];
    if ( n != NULL ) {
      n->user_route = n->user_route_ptr( *this, pub.rte.tport_id );
      if ( ! n->user_route->is_valid() )
        this->add_user_route( *n, pub.rte, pub.src_route, dec, NULL );
      pub.status = FRAME_STATUS_NO_AUTH;
    }
    else if ( uid == MY_UID )
      pub.status = FRAME_STATUS_MY_MSG;
    else
      pub.status = FRAME_STATUS_NO_USER;
    return n;
  }
  /* check if peer was declared dead */
  if ( this->zombie_ht->find( bridge, n_pos, uid ) ) {
    n = this->bridge_tab[ uid ];
    if ( n != NULL ) {
      switch ( dec.type ) {
        case U_SESSION_BYE: /* these don't effect zombie status */
        case U_PEER_DEL:
        case U_ADJACENCY:
        case U_SUB_LEAVE:
        case U_PSUB_STOP:
          if ( debug_usr )
            n->printf( "no zombie %.*s\n",
                        (int) pub.subject_len, pub.subject );
          break;
        default:
          this->add_user_route( *n, pub.rte, pub.src_route, dec, NULL );
          n->printf( "reanimate zombie %.*s\n",
                     (int) pub.subject_len, pub.subject );
          break;
      }
    }
    pub.status = FRAME_STATUS_NO_AUTH;
    return n;
  }
  UserNonce user_bridge_id;
  size_t    p_pos;
  uint32_t  pid;
  /* if no user_bridge_id, no user hmac to lookup peer */
  if ( ! dec.get_hmac( FID_USER_HMAC, user_bridge_id.hmac ) ) {
    pub.status = FRAME_STATUS_NO_USER;
    return NULL;
  }
  /* if no peer, no auth keys */
  if ( ! this->peer_ht->find( user_bridge_id.hmac, p_pos, pid ) ) {
    pub.status = FRAME_STATUS_NO_USER;
    return NULL;
  }
  user_bridge_id.nonce = bridge;
  pub.status = FRAME_STATUS_NO_AUTH;
  /* new user */
  return this->add_user( pub.rte, NULL, pub.src_route, user_bridge_id,
                         *this->peer_db[ pid ], dec );
}

void
UserRoute::set_ucast( UserDB &user_db,  const void *p,  size_t len,
                      const UserRoute *src ) noexcept
{
  if ( len == 0 && this->ucast_url_len == 0 && this->ucast_src == src )
    return;

  if ( len == 0 ) {
    /*if ( debug_usr )*/
      this->n.printf( "clear_ucast( t=%s )\n", this->rte.name );
    this->ucast_url_len = 0;
    this->url_hash      = 0;
    this->ucast_src     = src;
    if ( this->ucast_url != NULL ) {
      ::free( this->ucast_url );
      this->ucast_url = NULL;
    }
    this->clear( UCAST_URL_STATE );
    if ( src == NULL )
      this->clear( UCAST_URL_SRC_STATE );
    else
      this->set( UCAST_URL_SRC_STATE );
  }
  else {
    if ( len == this->ucast_url_len &&
         ::memcmp( this->ucast_url, p, len ) == 0 &&
         ! this->is_set( UCAST_URL_SRC_STATE ) )
      return;

    /*if ( debug_usr )*/
      this->n.printf( "set_ucast( %.*s, t=%s, src=%s )\n",
                      (int) len, (char *) p,
                      this->rte.name,
                      src ? src->n.peer.user.val : "null" );
    this->ucast_url = (char *) ::realloc( this->ucast_url, len + 1 );
    ::memcpy( this->ucast_url, p, len );
    this->ucast_url[ len ] = '\0';
    this->ucast_url_len = len;
    this->url_hash      = kv_crc_c( this->ucast_url, len, 0 );
    this->ucast_src     = NULL;
    this->set( UCAST_URL_STATE );
    this->clear( UCAST_URL_SRC_STATE );
  }
  user_db.peer_dist.invalidate( ADD_UCAST_URL_INV );
}

void
UserRoute::set_mesh( UserDB &user_db,  const void *p,  size_t len ) noexcept
{
  if ( debug_usr )
    this->n.printf( "set_mesh( %.*s, tport=%s )\n", (int) len, (char *) p,
                    this->rte.name );
  if ( len == 0 && this->mesh_url_len == 0 )
    return;

  if ( len == 0 ) {
    this->mesh_url_len = 0;
    this->url_hash     = 0;
    if ( this->mesh_url != NULL ) {
      ::free( this->mesh_url );
      this->mesh_url = NULL;
    }
    this->clear( MESH_URL_STATE );
  }
  else {
    if ( len == this->mesh_url_len && ::memcmp( this->mesh_url, p, len ) == 0 )
      return;

    this->mesh_url = (char *) ::realloc( this->mesh_url, len + 1 );
    ::memcpy( this->mesh_url, p, len );
    this->mesh_url[ len ] = '\0';
    this->mesh_url_len    = len;
    this->url_hash        = kv_crc_c( this->mesh_url, len, 0 );

    this->set( MESH_URL_STATE );
  }
  user_db.peer_dist.invalidate( ADD_MESH_URL_INV );
}

char *
UserRoute::inbox_route_str( char *buf,  size_t buflen ) noexcept
{
  EvPoll     & poll   = this->rte.poll;
  const char * uaddr  = NULL,
             * pre    = NULL,
             * s      = NULL;
  size_t       i, len = 0;
  uint32_t     uid    = 0;

  i = ::snprintf( buf, buflen, "%s.%u ", this->rte.transport.tport.val,
                  this->rte.tport_id );

  switch ( this->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE |
                         MESH_URL_STATE ) ) {
    default: { /* normal tcp */
      uint32_t ucast_fd = this->inbox_fd;
      if ( ucast_fd == NO_RTE ) {
        s   = "no_rte";
        len = 6;
      }
      else if ( ucast_fd < poll.maxfd && poll.sock[ ucast_fd ] != NULL ) {
        uint32_t uid2;
        s   = poll.sock[ ucast_fd ]->peer_address.buf;
        len = get_strlen64( s );
        pre = this->rte.transport.type.val;
        if ( this->rte.uid_connected.first( uid2 ) ) {
          if ( uid2 != this->n.uid ) { /* if routing through another uid */
            UserBridge * n = this->rte.user_db.bridge_tab[ uid2 ];
            if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) { /* ptp */
              uaddr = n->peer.user.val;
              uid   = uid2;
            }
          }
        }
      }
      break;
    }
    case UCAST_URL_STATE:
      s   = this->ucast_url;
      len = this->ucast_url_len;
      break;
    case UCAST_URL_SRC_STATE: {
      const UserRoute & u_src = *this->ucast_src;
      uaddr = u_src.n.peer.user.val;
      uid   = u_src.n.uid;
      s     = u_src.ucast_url;
      len   = u_src.ucast_url_len;
      break;
    }
    case MESH_URL_STATE:
      s   = this->mesh_url;
      len = this->mesh_url_len;
      break;
  }
  if ( uaddr != NULL )
    i += ::snprintf( &buf[ i ], buflen - i, "%s.%u@", uaddr, uid );
  if ( pre != NULL )
    i += ::snprintf( &buf[ i ], buflen - i, "%s://", pre );
  ::snprintf( &buf[ i ], buflen - i, "%.*s", (int) len, s );
  return buf;
}

/* initialize a route index for rte */
void
UserDB::add_user_route( UserBridge &n,  TransportRoute &rte,  uint32_t fd,
                      const MsgHdrDecoder &dec,  const UserRoute *src ) noexcept
{
  UserRoute * u_ptr;
  uint32_t    inbox_fd = fd, /* same as mcast unless transport has ucast ptp */
              hops     = 0;
  bool        has_hops = false;
  if ( dec.test( FID_HOPS ) ) {
    cvt_number<uint32_t>( dec.mref[ FID_HOPS ], hops );
    has_hops = true;
  }
  else { /* this may fail if ADJ message recvd before hb/auth,
            but can be fixed later when a hb is recvd (in heartbeat.cpp:160) */
    if ( ( dec.type < U_SESSION_HELLO || dec.type > U_SESSION_BYE ) &&
         dec.type != U_INBOX_AUTH )
      hops = 1;
  }
#if 0
  else if ( ! rte.is_mcast() ) {
    if ( this->route_list[ fd ].sys_route_refs > 0 ) {
      if ( dec.type < U_SESSION_HELLO || dec.type > U_SESSION_BYE )
        hops = 1;
    }
  }
#endif
  this->events.add_user_route( n.uid, rte.tport_id, src ? src->n.uid : 0, hops);
  d_usr( "add_user_route( %s, %s, %s, fd=%u, hops=%u, has=%s )\n",
         dec.get_type_string(), n.peer.user.val, rte.name, fd, hops,
         has_hops?"true":"false");

  u_ptr = n.user_route_ptr( *this, rte.tport_id );
  if ( fd == rte.inbox_fd || fd == rte.mcast_fd ) {
    fd       = rte.mcast_fd;
    inbox_fd = rte.inbox_fd;
  }
  u_ptr->mcast_fd = fd;
  u_ptr->inbox_fd = inbox_fd;
  u_ptr->hops     = hops;
  n.user_route    = u_ptr;
  this->set_mesh_url( *u_ptr, dec );
#if 0
  if ( dec.test( FID_MESH_URL ) ) {
    size_t       url_len = dec.mref[ FID_MESH_URL ].fsize;
    const char * url     = (const char *) dec.mref[ FID_MESH_URL ].fptr;
    u_ptr->set_mesh( url, url_len );
  }
#endif
  /* if directly attached to a transport route, hops == 0 */
  if ( hops == 0 ) {
    if ( dec.test( FID_UCAST_URL ) ) {
      size_t       url_len = dec.mref[ FID_UCAST_URL ].fsize;
      const char * url     = (const char *) dec.mref[ FID_UCAST_URL ].fptr;
      u_ptr->set_ucast( *this, url, url_len, NULL );
    }
  }
  /* if routing through a hop that has an inbox */
  else if ( src != NULL ) {
    if ( inbox_fd == src->inbox_fd &&
         src->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) != 0 ) {
      if ( src->is_set( UCAST_URL_STATE ) )
        u_ptr->set_ucast( *this, NULL, 0, src );
      else
        u_ptr->set_ucast( *this, NULL, 0, src->ucast_src );
    }
  }
  if ( n.is_set( AUTHENTICATED_STATE ) ) {
    this->push_user_route( n, *u_ptr );
    if ( u_ptr->hops == 0 )
      this->add_inbox_route( n, NULL );
  }
}

void
UserDB::find_user_primary_routes( void ) noexcept
{
  uint32_t count = this->transport_tab.count;
  if ( count == 1 && ! this->transport_tab.ptr[ 0 ]->is_mcast() &&
                     ! this->transport_tab.ptr[ 0 ]->is_mesh() )
    return;

  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      continue;
#if 0
    uint32_t min_dist  = this->peer_dist.max_uid,
             my_dist   = min_dist,
             min_route = count,
             /*min_count = 0,*/
             my_route  = n.primary_route;
    bool     is_mcast  = false;
    for ( uint32_t i = 0; i < count; i++ ) {
      TransportRoute *rte = this->transport_tab.ptr[ i ];
      uint32_t d = this->peer_dist.calc_transport_cache( uid, i, *rte );
      if ( d <= min_dist ) {
        if ( d < min_dist ) {
          min_dist  = d;
          min_route = i;
          /*min_count = 1;*/
          is_mcast  = rte->is_mcast();
        }
        /*else {
          min_count++;
        }*/
#if 0
        else if ( d == 1 ) {
          UserRoute *u_ptr = n.user_route_ptr( *this, i );
          if ( u_ptr->is_set( MESH_URL_STATE ) ) {
            min_dist  = d;
            min_route = i;
            is_mcast  = false;
          }
        }
#endif
      }
      if ( i == my_route )
        my_dist = d;
    }
#endif
    uint32_t min_route;
    if ( ! this->peer_dist.get_primary_tport( uid, min_route ) ) {
      n.printf( "no route, primary tport %u\n", n.primary_route );
      continue;
    }

    UserRoute * u_ptr    = n.user_route_ptr( *this, min_route );
    uint32_t    min_dist = peer_dist.calc_transport_cache( uid, min_route,
                                                           u_ptr->rte );
    if ( n.primary_route != min_route ) {
      UserRoute * primary = n.primary( *this );
      uint32_t    my_dist = peer_dist.calc_transport_cache( uid,
                                                            n.primary_route,
                                                            primary->rte );
      n.printf( "old primary route is tport %s.%u(d=%u),"
                " using shorter route %s.%u(d=%u)\n",
          primary->rte.transport.tport.val,
          primary->rte.tport_id, my_dist,
          u_ptr->rte.transport.tport.val,
          u_ptr->rte.tport_id, min_dist );

      if ( ! u_ptr->is_valid() && min_dist > 0 ) {
        uint32_t hops;
        UserBridge *m = this->closest_peer_route( u_ptr->rte, n, hops );
        if ( m == NULL ) {
          n.printf( "no closest peer route, old primary tport %u\n",
                     n.primary_route );
          continue;
        }
        UserRoute *u_peer = m->user_route_ptr( *this, min_route );
        if ( ! u_peer->is_valid() ) {
          n.printf( "no peer route yet, using old primary tport %u\n",
                     n.primary_route );
          continue;
        }
        u_ptr->mcast_fd = u_peer->mcast_fd;
        u_ptr->inbox_fd = u_peer->inbox_fd;
        u_ptr->hops     = 1;
        n.user_route    = u_ptr;
        if ( u_peer->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) ) {
          if ( u_peer->is_set( UCAST_URL_STATE ) )
            u_ptr->set_ucast( *this, NULL, 0, u_peer );
          else
            u_ptr->set_ucast( *this, NULL, 0, u_peer->ucast_src );
        }
        this->push_user_route( n, *u_ptr );
      }
      this->add_inbox_route( n, u_ptr );
    }
    else if ( u_ptr->rte.is_mcast() && min_dist > 0 ) {
      uint32_t hops;
      UserBridge *m = this->closest_peer_route( u_ptr->rte, n, hops );
      if ( m != NULL ) {
        UserRoute *u_peer = m->user_route_ptr( *this, min_route );
        if ( u_peer->mcast_fd == u_ptr->mcast_fd &&
             u_peer->inbox_fd == u_ptr->inbox_fd ) {

          if ( u_peer->is_set( UCAST_URL_SRC_STATE ) ) {
            if ( ! u_ptr->is_set( UCAST_URL_SRC_STATE ) ||
                 u_ptr->ucast_src != u_peer->ucast_src ) {
              const UserRoute * ucast_src = u_peer->ucast_src;
              n.printf( "set ucast thourgh %s\n", ucast_src->n.peer.user.val );
              u_ptr->set_ucast( *this, NULL, 0, ucast_src );
            }
          }
          else if ( u_peer->is_set( UCAST_URL_STATE ) ) {
            if ( ! u_ptr->is_set( UCAST_URL_SRC_STATE ) ||
                 u_ptr->ucast_src != u_peer ) {
              n.printf( "set ucast thourgh %s\n", u_peer->n.peer.user.val );
              u_ptr->set_ucast( *this, NULL, 0, u_peer );
            }
          }
        }
      }
    }
    if ( min_dist > 0 && u_ptr->is_set( MESH_URL_STATE ) ) {
      if ( this->start_time > n.start_time ) {
        this->direct_pending.update( u_ptr );
      }
    }
  }
}

void
DirectList::update( UserRoute *u ) noexcept
{
  this->update( u->rte, u->mesh_url, u->mesh_url_len, u->url_hash,
                u->n.bridge_id.nonce );
}

void
DirectList::update( TransportRoute &rte,  const char *url,  uint32_t len,
                    uint32_t h,  const Nonce &b_nonce ) noexcept
{
  MeshRoute *m;
  for ( m = this->hd; m != NULL; m = m->next ) {
    if ( m->mesh_url_len == len && ::memcmp( m->mesh_url, url, len ) == 0 )
      return;
  }
  void * p = ::malloc( sizeof( MeshRoute ) + len + 1 );
  char * s = &((char *) p)[ sizeof( MeshRoute ) ];
  ::memcpy( s, url, len );
  s[ len ] = '\0';
  if ( h == 0 )
    h = kv_crc_c( s, len, 0 );
  m = new ( p ) MeshRoute( rte, s, len, h, b_nonce );
  this->push_tl( m );
}

void
UserDB::process_direct_pending( uint64_t curr_mono ) noexcept
{
  MeshRoute * next;
  size_t      n_pos;
  uint32_t    uid;

  this->direct_pending.last_process_mono = curr_mono;
  for ( MeshRoute *m = this->direct_pending.hd; m != NULL; m = next ) {
    next = m->next;
    if ( this->node_ht->find( m->b_nonce, n_pos, uid ) ) {
      UserBridge * n = this->bridge_tab[ uid ];
      if ( n != NULL ) {
        if ( this->start_time > n->start_time )
          m->rte.add_mesh_connect( m->mesh_url, m->url_hash );
        this->direct_pending.pop( m );
        delete m;
      }
    }
  }
}

UserBridge *
UserDB::closest_peer_route( TransportRoute &rte,  UserBridge &n,
                            uint32_t &dist ) noexcept
{
  uint32_t uid;
  if ( rte.uid_connected.is_member( n.uid ) ) {
    dist = 0;
    return &n;
  }
  uint32_t d, max_uid = this->peer_dist.max_uid,
           min_uid    = max_uid,
           min_dist   = max_uid;
  for ( bool ok = rte.uid_connected.first( uid ); ok;
        ok = rte.uid_connected.next( uid ) ) {
    UserBridge *src = this->bridge_tab.ptr[ uid ];
    d = this->peer_dist.calc_distance_from( *src, n.uid );
    if ( d < min_dist ) {
      min_dist = d;
      min_uid  = uid;
    }
  }
  if ( min_dist == max_uid )
    return NULL;
  dist = min_dist;
  return this->bridge_tab.ptr[ min_uid ];
}

/* initialize a new user from a peer definition, configured or sent by another
 * node, with a route; if a from another node, src contains the inbox url
 * that inbox ptp needs to route through */
UserBridge *
UserDB::add_user( TransportRoute &rte,  const UserRoute *src,  uint32_t fd,
                  const UserNonce &user_bridge_id,  const PeerEntry &peer,
                  const MsgHdrDecoder &dec ) noexcept
{
  UserBridge * n;
  size_t       size, rtsz;
  uint32_t     uid,
               seed;
  uid  = this->new_uid();
  rtsz = sizeof( UserRoute ) * UserBridge::USER_ROUTE_BASE;
  size = sizeof( UserBridge ) + rtsz;
  seed = (uint32_t) this->rand.next();
  n    = this->make_user_bridge( size, peer, seed );
  n->bridge_id = user_bridge_id;
  n->uid       = uid;
  ::memset( (void *) &n[ 1 ], 0, rtsz );
  n->u_buf[ 0 ] = (UserRoute *) (void *) &n[ 1 ];
  this->add_user_route( *n, rte, fd, dec, src );
  this->bridge_tab[ uid ] = n;
  this->node_ht->upsert_rsz( this->node_ht, user_bridge_id.nonce, uid );

  return n;
}

UserRoute *
UserBridge::init_user_route( UserDB &me,  uint32_t i,  uint32_t j,
                             uint32_t id ) noexcept
{
  if ( id >= MAX_ROUTE_PTR )
    return NULL;
  if ( this->u_buf[ i ] == NULL ) {
    size_t size = sizeof( UserRoute ) * ( USER_ROUTE_BASE << i );
    void * m = ::malloc( size );
    ::memset( m, 0, size );
    this->u_buf[ i ] = (UserRoute *) (void *) m;
  }
  if ( id >= this->max_route )
    this->max_route = id + 1;
  return new ( (void *) &this->u_buf[ i ][ j ] )
             UserRoute( *this, *me.transport_tab.ptr[ id ] );
}

uint32_t
UserDB::new_uid( void ) noexcept
{
  size_t   id_pos;
  uint32_t uid, id_h;
  do {
    uid  = this->next_uid++; /* make sure hash( id ) is unique */
    id_h = kv_hash_uint( uid );
  } while ( this->uid_tab->find( id_h, id_pos ) );
  this->uid_tab->set_rsz( this->uid_tab, id_h, id_pos, uid );
  this->bridge_tab.make( this->next_uid, true );
  return uid;
}

void
UserDB::retire_source( uint32_t fd ) noexcept
{
  for (;;) {
    UserBridge *n = this->close_source_route( fd );
    if ( n == NULL )
      break;
    this->remove_authenticated( *n, BYE_SOURCE );
  }
  if ( ! this->adjacency_change.is_empty() )
    this->send_adjacency_change();
}

const char *
rai::ms::auth_stage_string( AuthStage stage ) noexcept
{
  if ( stage < MAX_AUTH )
    return auth_stage[ stage ];
  return auth_stage[ 0 ];
}

const char *
rai::ms::bye_reason_string( ByeReason bye ) noexcept
{
  if ( bye < MAX_BYE )
    return bye_reason[ bye ];
  return bye_reason[ 0 ];
}

void
UserDB::add_authenticated( UserBridge &n,
                           const MsgHdrDecoder &dec,
                           AuthStage stage,
                           UserBridge *src ) noexcept
{
  const char * from = auth_stage_string( stage );
  bool send_add = false;
  n.printn( "add authentication from %s via %s @ %s, state %s\n", from,
    ( src == &n ? "challenge" : src->peer.user.val ), src->user_route->rte.name,
    ( n.is_set( ZOMBIE_STATE ) != 0 ? "reanimated" : "new" ) );
  /*printf( "ha1: " ); n.ha1.print(); printf( "\n" );*/
  if ( n.test_clear( ZOMBIE_STATE ) ) {
    size_t pos;
    if ( this->zombie_ht->find( n.bridge_id.nonce, pos ) )
      this->zombie_ht->remove( pos );
    this->node_ht->upsert_rsz( this->node_ht, n.bridge_id.nonce, n.uid );
  }
  if ( ! n.test_set( AUTHENTICATED_STATE ) ) {
    this->events.auth_add( n.uid, src ? src->uid : 0, stage );
    if ( dec.test( FID_UPTIME ) ) {
      uint64_t uptime   = 0,
               cur_time = current_monotonic_time_ns();

      cvt_number<uint64_t>( dec.mref[ FID_UPTIME ], uptime );
      n.start_mono_time = cur_time - uptime;

      if ( dec.test( FID_INTERVAL ) ) {
        uint32_t ival = 0;
        cvt_number<uint32_t>( dec.mref[ FID_INTERVAL ], ival );
        n.hb_interval = ival;
        n.hb_mono_time = cur_time;
        if ( ival != 0 ) {
          uint64_t delta = uptime % ( (uint64_t) ival * SEC_TO_NS );
          n.hb_mono_time -= delta;
        }
      }
    }
    if ( dec.test( FID_START ) ) {
      uint64_t start = 0;
      cvt_number<uint64_t>( dec.mref[ FID_START ], start );
      if ( n.start_time == 0 )
        n.start_time = start;
      else if ( n.start_time != start ) {
        n.printf( "start time is not correct %lu != %lu\n",
                  n.start_time, start );
      }
    }
    if ( n.sub_seqno == 0 ) {
      McastBuf mcb;
      uint32_t seed = n.user_route->rte.sub_route.prefix_seed( mcb.len() ),
               hash = kv_crc_c( mcb.buf, mcb.len(), seed );
      n.bloom.add_route( mcb.len(), hash );
    }
    if ( this->pending_queue.num_elems > 0 )
      this->remove_pending_peer( &n.bridge_id.nonce, 0 );
    this->uid_authenticated.add( n.uid );
    this->set_ucast_url( *n.user_route, dec );
    this->set_mesh_url( *n.user_route, dec );
    this->push_source_route( n );
    this->add_inbox_route( n, NULL );
    this->uid_auth_count++;
    d_usr( "+++ uid_auth_count=%u +%s\n", this->uid_auth_count,
            n.peer.user.val );
#if 0
    n.user_route->rte.connected_auth.add( n.user_route->mcast_fd );
    if ( ! n.is_set( IN_HB_QUEUE_STATE ) ) {
      if ( n.user_route->hops == 0 ) {
        n.set( IN_HB_QUEUE_STATE );
        n.hb_mono_time = current_monotonic_time_ns();
        this->hb_queue.push( &n );
        this->events.hb_queue( n.uid );
      }
    }
#endif
    if ( stage >= AUTH_FROM_ADJ_RESULT && src != NULL )
      send_add = true;
  }
  if ( ! this->adjacency_unknown.is_empty() )
    this->add_unknown_adjacency( n );
  if ( ! this->adjacency_change.is_empty() ) {
    if ( stage != AUTH_FROM_HELLO ) /* stage 1, need stage 2 */
      this->send_adjacency_change();
  }
  if ( send_add )
    this->forward_peer_add( n, src->user_route->rte );
}

void
UserDB::remove_authenticated( UserBridge &n,  ByeReason bye ) noexcept
{
  size_t n_pos;
  bool   send_del = false;

  /*if ( debug_usr )*/
    n.printn( "remove auth %s %s\n", bye_reason_string( bye ),
               n.is_set( ZOMBIE_STATE ) ? "zombie" : "" );
  if ( n.test_clear( AUTHENTICATED_STATE ) ) {
    this->events.auth_remove( n.uid, bye );
    this->uid_authenticated.remove( n.uid );
    this->pop_source_route( n );
    if ( bye != BYE_HB_TIMEOUT )
      this->remove_adjacency( n );
    this->uid_auth_count--;
    this->sub_db.sub_update_mono_time = current_monotonic_time_ns();
    d_usr( "--- uid_auth_count=%u -%s\n", this->uid_auth_count,
            n.peer.user.val );
    /**this->uid_csum = *this->uid_csum ^ n.bridge_id.nonce;
    printf( "--- uid_auth_count %u uid_csum ", this->uid_auth_count );
    this->uid_csum->print(); printf( "\n" );*/

    send_del = true;
  }
  if ( n.test_clear( HAS_HB_STATE ) )
    this->uid_hb_count--;
  if ( n.test_clear( IN_HB_QUEUE_STATE ) )
    this->hb_queue.remove( &n );
  this->remove_inbox_route( n );

  if ( n.test_clear( CHALLENGE_STATE ) ) {
    n.challenge_count = 0;
    this->challenge_queue.remove( &n );
  }
  if ( n.test_clear( SUBS_REQUEST_STATE ) )
    this->subs_queue.remove( &n );
  if ( n.test_clear( ADJACENCY_REQUEST_STATE ) )
    this->adj_queue.remove( &n );
  if ( n.test_clear( PING_STATE ) )
    this->ping_queue.remove( &n );

  n.bloom.unlink( true );
  n.bloom.zero();
  n.sub_seqno = 0;
  n.link_state_seqno = 0;
  n.uid_csum.zero();

  if ( this->node_ht->find( n.bridge_id.nonce, n_pos ) )
    this->node_ht->remove( n_pos );

  if ( ! n.is_set( ZOMBIE_STATE ) )
    this->zombie_ht->upsert_rsz( this->zombie_ht, n.bridge_id.nonce, n.uid );
  n.state = ZOMBIE_STATE;

  for ( size_t i = 0; i < n.max_route; i++ )
    n.user_route_ptr( *this, i )->reset();

  if ( ! this->adjacency_change.is_empty() )
    this->send_adjacency_change();
  if ( send_del )
    this->send_peer_del( n );
}

void
UserDB::set_ucast_url( UserRoute &u_rte,  const MsgHdrDecoder &dec ) noexcept
{
  /* check if url based point to point */
  if ( u_rte.hops == 0 && dec.test( FID_UCAST_URL ) ) {
    u_rte.set_ucast( *this, dec.mref[ FID_UCAST_URL ].fptr,
                     dec.mref[ FID_UCAST_URL ].fsize, NULL );
  }
}

void
UserDB::set_mesh_url( UserRoute &u_rte,  const MsgHdrDecoder &dec ) noexcept
{
  /* check if url based point to point */
  if ( dec.test( FID_MESH_URL ) ) {
    uint32_t     url_len = dec.mref[ FID_MESH_URL ].fsize;
    const char * url     = (const char *) dec.mref[ FID_MESH_URL ].fptr;
    if ( debug_usr )
      u_rte.n.printf( "(%s) set_mesh_url(%s) %.*s\n",
        publish_type_to_string( dec.type ),
        u_rte.rte.transport.tport.val, url_len, url );
    u_rte.set_mesh( *this, url, url_len );
  }
}

void
UserDB::add_transport( TransportRoute &rte ) noexcept
{
  uint32_t    count = this->transport_tab.count;
  TransportRoute *t = this->transport_tab.ptr[ 0 ];
  this->peer_dist.invalidate( ADD_TRANSPORT_INV );

  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      continue;

    if ( count == 2 && ! n.bloom.has_link( t->router_rt->r ) ) {
      t->router_rt->add_bloom_ref( &n.bloom );
      d_usr( "add_bloom_ref( %s, %s )\n", n.peer.user.val,
              t->transport.tport.val );
    }
    rte.router_rt->add_bloom_ref( &n.bloom );
    d_usr( "add_bloom_ref( %s, %s )\n", n.peer.user.val,
           rte.transport.tport.val );
  }
}

void
UserDB::add_inbox_route( UserBridge &n,  UserRoute *primary ) noexcept
{
  /* add point to point route */
  InboxBuf    ibx( n.bridge_id );
  UserRoute * inbox = n.primary( *this );
  uint32_t    count = this->transport_tab.count;

  if ( primary == NULL ) {
    for ( uint32_t i = 0; i < count; i++ ) {
      UserRoute * u_ptr = n.user_route_ptr( *this, i );
      if ( u_ptr->is_valid() ) {
        if ( primary == NULL ||
             this->peer_dist.calc_transport_cache( n.uid, i, u_ptr->rte ) <
             this->peer_dist.calc_transport_cache( n.uid, i, primary->rte ) ) {
          primary = u_ptr;
        }
      }
    }
  }
  if ( inbox->is_set( INBOX_ROUTE_STATE ) ) {
    if ( primary != inbox ) {
      if ( debug_usr )
        n.printf( "del inbox route %.*s -> %u\n",
                  (int) ibx.len(), ibx.buf, inbox->inbox_fd );
      n.bloom.unlink( false );
      inbox->rte.sub_route.del_pattern_route_str( ibx.buf, ibx.len(),
                                                  inbox->inbox_fd );
      inbox->rte.primary_count--;
      inbox->clear( INBOX_ROUTE_STATE );
    }
  }
  if ( primary == NULL ) {
    n.printe( "add inbox no valid route\n" );
    return;
  }
  if ( n.primary_route != primary->rte.tport_id ) {
    n.primary_route = primary->rte.tport_id;
    n.hb_seqno = 0;
    if ( n.is_set( IN_HB_QUEUE_STATE ) ) {
      n.hb_mono_time = current_monotonic_time_ns();
      this->hb_queue.remove( &n );
      this->hb_queue.push( &n );
    }
  }
  if ( ! primary->test_set( INBOX_ROUTE_STATE ) ) {
    if ( debug_usr )
      n.printf( "add inbox_route %.*s -> %u (%s) (bcast %u)\n",
              (int) ibx.len(), ibx.buf, primary->inbox_fd,
              primary->ucast_url_len == 0 ? "ptp" : primary->ucast_url,
              primary->mcast_fd );
    primary->rte.sub_route.create_bloom_route( primary->mcast_fd, &n.bloom );
    primary->rte.sub_route.add_pattern_route_str( ibx.buf, ibx.len(),
                                                  primary->inbox_fd );
    primary->rte.primary_count++;
  }
  else {
    if ( debug_usr )
      n.printf( "inbox exists %.*s -> %u (%s) (bcast %u)\n",
              (int) ibx.len(), ibx.buf, primary->inbox_fd,
              primary->ucast_url_len == 0 ? "ptp" : primary->ucast_url,
              primary->mcast_fd );
  }
  if ( ! n.test_set( INBOX_ROUTE_STATE ) ) {
    uint32_t seed = primary->rte.sub_route.prefix_seed( ibx.len() ),
             hash = kv_crc_c( ibx.buf, ibx.len(), seed );
    n.bloom.add_route( ibx.len(), hash );
  }
  if ( count > 1 ) {
    for ( size_t i = 0; i < count; i++ ) {
      TransportRoute *t = this->transport_tab.ptr[ i ];
      if ( ! n.bloom.has_link( t->router_rt->r ) ) {
        t->router_rt->add_bloom_ref( &n.bloom );
        d_usr( "add_bloom_ref( %s, %s )\n", n.peer.user.val,
               t->transport.tport.val );
      }
    }
  }
}

void
UserDB::remove_inbox_route( UserBridge &n ) noexcept
{
  InboxBuf ibx( n.bridge_id );
  UserRoute * u_ptr = n.primary( *this );

  if ( u_ptr->test_clear( INBOX_ROUTE_STATE ) ) {
    if ( debug_usr )
      n.printf( "remove_inbox_route %.*s -> %u (%s) (bcast %u)\n",
              (int) ibx.len(), ibx.buf, u_ptr->inbox_fd,
              u_ptr->ucast_url_len == 0 ? "ptp" : u_ptr->ucast_url,
              u_ptr->mcast_fd );
    u_ptr->rte.sub_route.del_pattern_route_str( ibx.buf, ibx.len(),
                                                u_ptr->inbox_fd );
    u_ptr->rte.primary_count--;
  }
  if ( n.test_clear( INBOX_ROUTE_STATE ) ) {
    uint32_t seed = u_ptr->rte.sub_route.prefix_seed( ibx.len() ),
             hash = kv_crc_c( ibx.buf, ibx.len(), seed );
    n.bloom.del_route( ibx.len(), hash );
  }
}

char *
UserNonce::to_string( char *buf ) noexcept
{
  size_t sz = this->hmac.to_base64( buf );
  buf[ sz++ ] = ':';
  sz += this->nonce.to_base64( &buf[ sz ] );
  return buf;
}

int
UserBridge::printn( const char *fmt, ... ) const noexcept
{
  va_list ap;
  int n, m;
  char buf[ NONCE_B64_LEN + 1 ];
  this->bridge_id.nonce.to_base64_str( buf );
  n = fprintf( stdout, "%s.%u [%s] ", this->peer.user.val, this->uid, buf );
  va_start( ap, fmt );
  m = vfprintf( stdout, fmt, ap );
  va_end( ap );
  return ( n >= 0 && m >= 0 ) ? n + m : -1;
}

int
UserBridge::printf( const char *fmt, ... ) const noexcept
{
  va_list ap;
  int n, m;
  /*char buf[ 64 ];
  int sz = this->bridge_id.nonce.to_base64( buf );*/
  n = fprintf( stdout, "%s.%u ", this->peer.user.val, this->uid );
  va_start( ap, fmt );
  m = vfprintf( stdout, fmt, ap );
  va_end( ap );
  return ( n >= 0 && m >= 0 ) ? n + m : -1;
}

int
UserBridge::printe( const char *fmt, ... ) const noexcept
{
  va_list ap;
  int n, m;
  char buf[ NONCE_B64_LEN + 1 ];
  this->bridge_id.nonce.to_base64_str( buf );
  n = fprintf( stderr, "%s.%u [%s] ", this->peer.user.val, this->uid, buf );
  va_start( ap, fmt );
  m = vfprintf( stderr, fmt, ap );
  va_end( ap );
  return ( n >= 0 && m >= 0 ) ? n + m : -1;
}

void
PeerEntry::print( void ) noexcept
{
  printf( "user: \"%s\"\n", this->user.val );
  printf( "svc: \"%s\"\n", this->svc.val );
  printf( "create: \"%s\"\n", this->create.val );
  printf( "expires: \"%s\"\n", this->expires.val );
}

static inline char *
cat( char *s,  const char *state,  bool comma )
{
  if ( comma ) *s++ = ',';
  while ( *state ) *s++ = *state++;
  return s;
}

char *
rai::ms::user_state_string( uint32_t state,  char *buf ) noexcept
{
  char *s = buf;
  if ( ( state & CHALLENGE_STATE ) != 0 )
    s = cat( s, "challenge", s > buf );
  if ( ( state & AUTHENTICATED_STATE ) != 0 )
    s = cat( s, "authenticated", s > buf );
  if ( ( state & INBOX_ROUTE_STATE ) != 0 )
    s = cat( s, "inbox_route", s > buf );
  if ( ( state & IN_ROUTE_LIST_STATE ) != 0 )
    s = cat( s, "in_route_list", s > buf );
  if ( ( state & SENT_ZADD_STATE ) != 0 )
    s = cat( s, "sent_zadd", s > buf );
  if ( ( state & IN_HB_QUEUE_STATE ) != 0 )
    s = cat( s, "in_hb_queue", s > buf );
  if ( ( state & SUBS_REQUEST_STATE ) != 0 )
    s = cat( s, "subs_request", s > buf );
  if ( ( state & ADJACENCY_REQUEST_STATE ) != 0 )
    s = cat( s, "adj_request", s > buf );
  if ( ( state & PING_STATE ) != 0 )
    s = cat( s, "ping", s > buf );
  if ( ( state & ZOMBIE_STATE ) != 0 )
    s = cat( s, "zombie", s > buf );
  if ( ( state & DEAD_STATE ) != 0 )
    s = cat( s, "dead", s > buf );
  if ( ( state & UCAST_URL_STATE ) != 0 )
    s = cat( s, "ucast", s > buf );
  if ( ( state & UCAST_URL_SRC_STATE ) != 0 )
    s = cat( s, "ucast_src", s > buf );
  if ( ( state & MESH_URL_STATE ) != 0 )
    s = cat( s, "mesh", s > buf );
  if ( ( state & HAS_HB_STATE ) != 0 )
    s = cat( s, "hb", s > buf );
  if ( ( state & IS_INIT_STATE ) != 0 )
    s = cat( s, "init", s > buf );
  *s = '\0';
  return buf;
}

char *
rai::ms::user_state_abrev( uint32_t state,  char *buf ) noexcept
{
  char *s = buf;
  if ( ( state & CHALLENGE_STATE ) != 0 )
    s = cat( s, "chall", s > buf );
  if ( ( state & AUTHENTICATED_STATE ) != 0 )
    s = cat( s, "auth", s > buf );
  if ( ( state & INBOX_ROUTE_STATE ) != 0 )
    s = cat( s, "inbox", s > buf );
  if ( ( state & IN_ROUTE_LIST_STATE ) != 0 )
    s = cat( s, "rtlst", s > buf );
  if ( ( state & SENT_ZADD_STATE ) != 0 )
    s = cat( s, "zadd", s > buf );
  if ( ( state & IN_HB_QUEUE_STATE ) != 0 )
    s = cat( s, "hbq", s > buf );
  if ( ( state & SUBS_REQUEST_STATE ) != 0 )
    s = cat( s, "subs", s > buf );
  if ( ( state & ADJACENCY_REQUEST_STATE ) != 0 )
    s = cat( s, "adj", s > buf );
  if ( ( state & PING_STATE ) != 0 )
    s = cat( s, "ping", s > buf );
  if ( ( state & ZOMBIE_STATE ) != 0 )
    s = cat( s, "zomb", s > buf );
  if ( ( state & DEAD_STATE ) != 0 )
    s = cat( s, "dead", s > buf );
  if ( ( state & UCAST_URL_STATE ) != 0 )
    s = cat( s, "ucast", s > buf );
  if ( ( state & UCAST_URL_SRC_STATE ) != 0 )
    s = cat( s, "usrc", s > buf );
  if ( ( state & MESH_URL_STATE ) != 0 )
    s = cat( s, "mesh", s > buf );
  if ( ( state & HAS_HB_STATE ) != 0 )
    s = cat( s, "hb", s > buf );
  if ( ( state & IS_INIT_STATE ) != 0 )
    s = cat( s, "in", s > buf );
  *s = '\0';
  return buf;
}

