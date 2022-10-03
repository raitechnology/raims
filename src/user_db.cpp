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

UserDB::UserDB( EvPoll &p,  ConfigTree::User &u,
                ConfigTree::Service &s,  SubDB &sdb,
                StringTab &st,  EventRecord &ev ) noexcept
  : ipc_transport( 0 ), poll( p ), user( u ), svc( s ), sub_db( sdb ),
    string_tab( st ), events( ev ), svc_dsa( 0 ), user_dsa( 0 ),
    session_key( 0 ), hello_key( 0 ), cnonce( 0 ), hb_keypair( 0 ),
    node_ht( 0 ), zombie_ht( 0 ), peer_ht( 0 ), peer_key_ht( 0 ),
    peer_keys( 0 ), peer_bloom( 0, "(peer)", p.g_bloom_db ),
    hb_interval( HB_DEFAULT_INTERVAL ), reliability( DEFAULT_RELIABILITY ),
    next_uid( 0 ), free_uid_count( 0 ), my_src_fd( -1 ), uid_auth_count( 0 ),
    uid_hb_count( 0 ), send_peer_seqno( 0 ), link_state_seqno( 0 ),
    mcast_seqno( 0 ), hb_ival_ns( 0 ), hb_ival_mask( 0 ), next_ping_mono( 0 ),
    peer_dist( *this )
{
  this->start_time = current_realtime_ns();
  /* fill in lower nanos if resolution is low */
  for ( uint64_t i = 1000000000; i > 0; i /= 1000 ) {
    if ( ( this->start_time % i ) == 0 ) {
      uint64_t r;
      rand::fill_urandom_bytes( &r, sizeof( r ) );
      this->start_time += r % i;
      while ( current_realtime_ns() < this->start_time )
        kv_sync_pause();
      break;
    }
  }
  this->start_mono_time = current_monotonic_time_ns(); 
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
#if 0
  if ( this->my_svc.users.is_empty() ) {
    fprintf( stderr, "No users in service %s\n", this->svc.svc.val );
    return false;
  }
#endif
  /* put the keys in secure area which can't be swapped or coredumped */
  this->svc_dsa      = this->make_secure_obj<DSA>();
  this->user_dsa     = this->make_secure_obj<DSA>();
  this->session_key  = this->make_secure_obj<HashDigest>();
  this->hello_key    = this->make_secure_obj<HashDigest>();
  this->cnonce       = this->make_secure_obj<CnonceRandom>();
  this->hb_keypair   = this->make_secure_obj<EC25519>();
  this->peer_keys    = this->make_secure_obj<PeerKeyCache>();
  this->hb_keypair->gen_key();
  if ( ! this->my_svc.get_dsa( pwd, *this->svc_dsa, DO_BOTH ) ) {
    printf( "service %s public key loaded\n", this->my_svc.service );
    this->svc_dsa->sk.zero();
  }
  else {
    printf( "service %s key pair loaded\n", this->my_svc.service );
  }

  /* bridge id is public user hmac + nonce which identifies this peer */
  this->bridge_id.nonce.seed_random();    /* random nonce */
  /* session key is private key used to authenticate messages for bridge_id */
  this->session_key->make_session_rand(); /* random session key */

  /* the xor of all peers authenticated */
  this->uid_csum         = this->bridge_id.nonce;
  /* index nonce -> bridge_id instance active */
  this->node_ht          = NodeHashTab::resize( NULL );
  /* index nonce -> bridge_id instance which is not reachable */
  this->zombie_ht        = NodeHashTab::resize( NULL );
  /* index user hmac -> peer data */
  this->peer_ht          = NodeHashTab::resize( NULL );
  /* index hash (src_uid, dest_uid) -> encrypted peer key */
  this->peer_key_ht      = PeerKeyHashTab::resize( NULL );
  this->next_uid         = 0; /* uid assigned to each node */
  this->free_uid_count   = 0; /* after uid freed, this count updated */
  this->uid_auth_count   = 0; /* how many peers are trusted */
  this->uid_hb_count     = 0; /* how many peers are trusted */
  this->uid_ping_count   = 0; /* ping counter */
  this->next_ping_uid    = 0; /* next pinged uid */
  this->send_peer_seqno  = 0; /* sequence num of peer add/del msgs */
  this->link_state_seqno = 0; /* sequence num of link state msgs */
  this->mcast_seqno      = 0; /* sequence num of mcast msgs */
  this->hb_ival_ns       = 0; /* hb interval in nanos */
  this->hb_ival_mask     = 0; /* hb interval mask, pow2 - 1 > hv_ival_ns */
  this->next_ping_mono   = 0; /* when the next random ping timer expires */
  this->name_send_seqno  = 0;
  this->name_send_time   = 0;
  this->last_auth_mono   = this->start_mono_time;
  this->converge_time    = this->start_time;
  this->net_converge_time= this->start_time;
  this->converge_mono    = this->start_mono_time;

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
  UserHmacData data( my_user, *this->user_dsa );
  /* get the DSA pub an pri keys */
  if ( ! data.decrypt( pwd, DO_BOTH ) ) {
    fprintf( stderr, "user %s key pair failed to load\n", my_user.user );
    return false;
  }
  if ( this->user.user_id < tree.user_cnt ) {
    printf( "user %s key pair loaded\n", my_user.user );
  }
  else {
    if ( this->svc_dsa->sk.is_zero() ) {
      fprintf( stderr, "service %s key pair needed for transient user\n",
               this->my_svc.service );
      return false;
    }
    printf( "transient user %s created\n", my_user.user );
  }
  this->bridge_id.hmac = data.user_hmac;
  /* calc my hello key: kdf( my DSA pub + my RSA svc pub ) */
  this->calc_hello_key( this->start_time, data.user_hmac, *this->hello_key );
  bool b = true;
  i = 0;
  /* calculate keys for each peer configured */
  for ( u = tree.users.hd; u != NULL; u = u->next ) {
    if ( u->svc.equals( this->svc.svc ) ) {
      PeerEntry  & peer = *this->peer_db[ i ];
      UserBuf      p_user( *u );
      UserHmacData peer_data( p_user, peer.dsa );
      /* get the DSA pub key for peer */
      if ( ! peer_data.decrypt( pwd, DO_PUB ) )
        return false;
      /* peer hmac is based on the DSA pub key plus name and svc */
      peer.hmac = peer_data.user_hmac;
      this->peer_ht->upsert_rsz( this->peer_ht, peer.hmac, i );
      i++;
    }
  }
  this->peer_bloom.add( hello_h );
  this->peer_bloom.add( hb_h ); 
  this->peer_bloom.add( bye_h );
  this->peer_bloom.add( blm_h );
  this->peer_bloom.add( adj_h );
  this->peer_bloom.add_route( S_JOIN_SZ, join_h );
  this->peer_bloom.add_route( S_LEAVE_SZ, leave_h );
  this->peer_bloom.add_route( P_PSUB_SZ, psub_h );
  this->peer_bloom.add_route( P_PSTOP_SZ, pstop_h );
  return b;
}

void
UserDB::calc_hello_key( uint64_t start_time,  const HmacDigest &user_hmac,
                        HashDigest &ha ) noexcept
{
  PolyHmacDigest svc_hmac;
  ha.kdf_bytes( this->my_svc.pub_key, this->my_svc.pub_key_len,
                &start_time, sizeof( start_time ) );
  svc_hmac.calc_2( ha, this->my_svc.service, this->my_svc.service_len,
                       this->my_svc.create, this->my_svc.create_len );
  ha.kdf_bytes( svc_hmac.dig, HMAC_SIZE, user_hmac.dig, HMAC_SIZE );
}

void
UserDB::calc_secret_hmac( UserBridge &n,  PolyHmacDigest &secret_hmac ) noexcept
{
  HashDigest ha;
  EC25519 ec;
  ec.pri = this->hb_keypair->pri;
  ec.pub = n.hb_pubkey;
  ec.shared_secret();

  if ( n.peer_hello < *this->hello_key ) {
    ha.kdf_bytes( this->hello_key->dig, HASH_DIGEST_SIZE );
    secret_hmac.calc_2( ha, n.peer_hello.dig, HASH_DIGEST_SIZE,
                            ec.secret.key, EC25519_KEY_LEN );
  }
  else {
    ha.kdf_bytes( n.peer_hello.dig, HASH_DIGEST_SIZE );
    secret_hmac.calc_2( ha, this->hello_key->dig, HASH_DIGEST_SIZE,
                            ec.secret.key, EC25519_KEY_LEN );
  }
#if 0
  char buf[ EC25519_KEY_B64_LEN + 1 ];
  buf[ EC25519_KEY_B64_LEN ] = '\0';
  kv::bin_to_base64( ec.pri.key, EC25519_KEY_LEN, buf, false );
  printf( "pri: %s\n", buf );
  kv::bin_to_base64( ec.pub.key, EC25519_KEY_LEN, buf, false );
  printf( "pub: %s\n", buf );
  kv::bin_to_base64( ec.secret.key, EC25519_KEY_LEN, buf, false );
  printf( "secret: %s\n", buf );
#endif
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
      uint32_t tmp_cost;
      UserBridge *m = this->closest_peer_route( u_rte.rte, n, tmp_cost );
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
                       this->my_src_fd, h, CABA_TYPE_ID, u_rte.ucast_url.val,
                       n.uid, u_rte.url_hash );
    /*d_usr( "forward %.*s to (%s) ucast( %s ) inbox %u\n",
       (int) sublen, sub, n.peer.user.val, u_rte.ucast_url, u_rte.inbox_fd );*/
    return u_rte.rte.sub_route.forward_to( ipub, u_rte.inbox_fd );
  }
  const UserRoute  & u_src = *u_rte.ucast_src;
  const UserBridge & n_src = u_src.n;
  InboxPublish isrc( sub, sublen, msg, msg_len, u_src.rte.sub_route,
                     this->my_src_fd, h, CABA_TYPE_ID, u_src.ucast_url.val,
                     n_src.uid, u_src.url_hash );
  /*d_usr( "forward %.*s to (%s) ucast( %s ) inbox %u\n",
       (int) sublen, sub, n.peer.user.val, u_src.ucast_url, u_src.inbox_fd );*/
  return u_src.rte.sub_route.forward_to( isrc, u_src.inbox_fd );
}

bool
UserDB::forward_pub( const MsgFramePublish &pub,  const UserBridge &,
                     const MsgHdrDecoder &dec ) noexcept
{
  bool b = true;
  if ( dec.is_mcast_type() ) {
    size_t count = this->transport_tab.count;
    if ( count > 1 || pub.rte.connect_count > 1 ) {
      kv::EvPublish tmp( pub );
      for ( size_t i = 0; i < count; i++ ) {
        TransportRoute * rte = this->transport_tab.ptr[ i ];
        tmp.pub_type = 'p';
        if ( rte->connect_count > 0 ) {
          if ( rte != &pub.rte )
            b &= rte->forward_to_connected_auth( tmp );
          else if ( rte->connect_count > 1 )
            b &= rte->forward_to_connected_auth_not_fd( tmp, pub.src_route );
        }
      }
    }
  }
  return b;
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

PeerEntry *
UserDB::find_peer( const char *u,  uint32_t ulen,
                   const char *c,  uint32_t clen,
                   const char *e,  uint32_t elen,
                   const HmacDigest &hmac ) noexcept
{
  PeerEntry * peer;
  size_t      p_pos;
  uint32_t    pid;

  if ( ! this->peer_ht->find( hmac, p_pos, pid ) ) {
    if ( ulen == 0 || clen == 0 )
      return NULL;
    pid = (uint32_t) this->peer_db.count;
    StringVal user_sv, svc_sv, create_sv, expires_sv;
    this->string_tab.ref_string( u, ulen, user_sv );
    this->string_tab.ref_string( c, clen, create_sv );
    this->string_tab.ref_string( e, elen, expires_sv );
    peer = this->make_peer( user_sv, this->svc.svc, create_sv, expires_sv );
    this->peer_db[ pid ] = peer;
    peer->hmac = (PolyHmacDigest &) hmac;
    this->peer_ht->upsert_rsz( this->peer_ht, peer->hmac, pid );
  }
  else {
    peer = this->peer_db[ pid ];
  }
  return peer;
}

PeerEntry *
UserDB::find_peer( const MsgHdrDecoder &dec,
                   const HmacDigest &hmac ) noexcept
{
  const char * user        = NULL,
             * create      = NULL,
             * expires     = NULL;
  uint32_t     user_len    = 0,
               create_len  = 0,
               expires_len = 0;

  if ( dec.test( FID_USER ) ) {
    user     = (const char *) dec.mref[ FID_USER ].fptr;
    user_len = (uint32_t) dec.mref[ FID_USER ].fsize;
  }
  if ( dec.test( FID_CREATE ) ) {
    create      = (const char *) dec.mref[ FID_CREATE ].fptr;
    create_len  = (uint32_t) dec.mref[ FID_CREATE ].fsize;
  }
  if ( dec.test( FID_EXPIRES ) ) {
    expires     = (const char *) dec.mref[ FID_EXPIRES ].fptr;
    expires_len = (uint32_t)     dec.mref[ FID_EXPIRES ].fsize;
  }
  return this->find_peer( user, user_len, create, create_len,
                          expires, expires_len, hmac );
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
  this->uid_rtt.reset();
  this->bridge_id.zero();
  this->session_key = NULL;
  this->cnonce      = NULL;
  this->hb_keypair  = NULL;
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
    bool b = this->peer_dist.find_inconsistent( n, m );
    if ( b ) {
      if ( n != NULL && m != NULL ) {
        if ( ! n->is_set( PING_STATE ) ) {
          d_usr( "find_inconsistent from %s(%u) to %s(%u)\n", 
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
          d_usr( "find_inconsistent orphaned %s(%u)\n", 
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
                  d_usr( "find_inconsistent from %s(%u) to %s(%u)\n", 
                           n->peer.user.val, n->uid, m->peer.user.val, m->uid );
                  this->send_adjacency_request2( *n, *m, DIJKSTRA_SYNC_REQ );
                  goto break_loop;
                }
              } while ( p->next( uid2 ) );
            }
          }
          d_usr( "find_inconsistent delay orphaned %s(%u)\n",
                   n->peer.user.val, n->uid );
        break_loop:;
        }
      }
    }
    else {
      if ( ! this->peer_dist.found_inconsistency &&
           this->peer_dist.invalid_mono != 0 ) {
        this->events.converge( this->peer_dist.invalid_reason );
        this->converge_time = current_time;
        if ( current_time > this->net_converge_time )
          this->net_converge_time = current_time;
        this->converge_mono = current_mono_time;
        uint64_t t = ( current_mono_time > this->peer_dist.invalid_mono ) ?
                     ( current_mono_time - this->peer_dist.invalid_mono ) : 0;
        printf( "network converges %.3f secs, %u uids authenticated, %s\n", 
                (double) t / SEC_TO_NS, this->uid_auth_count,
                invalidate_reason_string( this->peer_dist.invalid_reason ) );
      }
      this->find_adjacent_routes();
    }
  }
  else {
    if ( ! this->adjacency_change.is_empty() )
      this->send_adjacency_change();
    if ( this->uid_auth_count > 0 )
      this->interval_ping( current_mono_time, current_time );
    if ( ! this->mesh_pending.is_empty() )
      this->process_mesh_pending( current_mono_time );
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

#if 0
static MsgFrameStatus lookup_NO_AUTH( void ) { return FRAME_STATUS_NO_AUTH; }
static MsgFrameStatus lookup_MY_MSG( void ) { return FRAME_STATUS_MY_MSG; }
static MsgFrameStatus lookup_NO_USER( void ) { return FRAME_STATUS_NO_USER; }
#else
#define lookup_NO_AUTH() FRAME_STATUS_NO_AUTH
#define lookup_MY_MSG()  FRAME_STATUS_MY_MSG
#define lookup_NO_USER() FRAME_STATUS_NO_USER
#endif

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
      pub.status = lookup_NO_AUTH();
    }
    else if ( uid == MY_UID )
      pub.status = lookup_MY_MSG();
    else
      pub.status = lookup_NO_USER();
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
      pub.status = lookup_NO_AUTH();
    }
    else if ( uid == MY_UID )
      pub.status = lookup_MY_MSG();
    else
      pub.status = lookup_NO_USER();
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
          if ( debug_usr )
            n->printf( "reanimate zombie %.*s\n",
                       (int) pub.subject_len, pub.subject );
          break;
      }
    }
    pub.status = lookup_NO_AUTH();
    return n;
  }
  UserNonce user_bridge_id;
  uint64_t  start;
  /* if no user_bridge_id, no user hmac to lookup peer */
  if ( ! dec.get_hmac( FID_USER_HMAC, user_bridge_id.hmac ) ||
       ! dec.get_ival<uint64_t>( FID_START, start ) ) {
    pub.status = lookup_NO_USER();
    return NULL;
  }
  PeerEntry * peer = this->find_peer( dec, user_bridge_id.hmac );
  if ( peer == NULL ) {
    pub.status = lookup_NO_USER();
    return NULL;
  }
  HashDigest  hello;
  user_bridge_id.nonce = bridge;
  this->calc_hello_key( start, user_bridge_id.hmac, hello );
  pub.status = lookup_NO_AUTH();
  /* new user */
  return this->add_user( pub.rte, NULL, pub.src_route, user_bridge_id,
                         *peer, start, dec, hello );
}

void
UserRoute::set_ucast( UserDB &user_db,  const void *p,  size_t len,
                      const UserRoute *src ) noexcept
{
  if ( len == 0 && this->ucast_url.len == 0 && this->ucast_src == src )
    return;

  if ( len == 0 ) {
    /*if ( debug_usr )*/
      this->n.printf( "clear_ucast( t=%s )\n", this->rte.name );
    this->ucast_url.zero();
    this->url_hash  = 0;
    this->ucast_src = src;
    this->clear( UCAST_URL_STATE );
    if ( src == NULL )
      this->clear( UCAST_URL_SRC_STATE );
    else
      this->set( UCAST_URL_SRC_STATE );
  }
  else {
    if ( this->ucast_url.equals( (const char *) p, len ) &&
         ! this->is_set( UCAST_URL_SRC_STATE ) )
      return;

    /*if ( debug_usr )*/
      this->n.printf( "set_ucast( %.*s, t=%s, src=%s )\n",
                      (int) len, (char *) p,
                      this->rte.name,
                      src ? src->n.peer.user.val : "null" );
    user_db.string_tab.ref_string( (const char *) p, len, this->ucast_url );
    this->url_hash  = kv_crc_c( this->ucast_url.val, len, 0 );
    this->ucast_src = NULL;
    this->set( UCAST_URL_STATE );
    this->clear( UCAST_URL_SRC_STATE );
  }
  user_db.peer_dist.invalidate( ADD_UCAST_URL_INV );
}

void
UserRoute::set_mesh( UserDB &user_db,  const void *p,  size_t len ) noexcept
{
  if ( len == 0 && this->mesh_url.len == 0 )
    return;
  if ( ! this->rte.is_mesh() )
    return;

  if ( len == 0 ) {
    /*if ( debug_usr )*/
      this->n.printf( "clear_mesh( t=%s )\n", this->rte.name );
    this->mesh_url.zero();
    this->url_hash = 0;
    this->clear( MESH_URL_STATE );
  }
  else {
    if ( this->mesh_url.equals( (const char *) p, len ) )
      return;

    user_db.string_tab.ref_string( (const char *) p, len, this->mesh_url );
    this->url_hash = kv_crc_c( this->mesh_url.val, len, 0 );

    /*if ( debug_usr )*/
      this->n.printf( "set_mesh( %.*s, tport=%s, hash=%x )\n",
                      (int) len, (char *) p, this->rte.name, this->url_hash );
   this->rte.mesh_conn_hash = this->url_hash;

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
      s   = this->ucast_url.val;
      len = this->ucast_url.len;
      break;
    case UCAST_URL_SRC_STATE: {
      const UserRoute & u_src = *this->ucast_src;
      uaddr = u_src.n.peer.user.val;
      uid   = u_src.n.uid;
      s     = u_src.ucast_url.val;
      len   = u_src.ucast_url.len;
      break;
    }
    case MESH_URL_STATE:
      s   = this->mesh_url.val;
      len = this->mesh_url.len;
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
/* use adjacency tab to find the best routes for each pear */
void
UserDB::find_adjacent_routes( void ) noexcept
{
#if 0
  if ( this->transport_tab.count == 1 &&
       ! this->transport_tab.ptr[ 0 ]->is_mcast() &&
       ! this->transport_tab.ptr[ 0 ]->is_mesh() )
    return;
  char src_buf[ 32 ];
  uint32_t uid;
  for ( uid = 1; uid < this->next_uid; uid++ ) {
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      continue;
    printf( "tport %s = primary %u, secondary %u, cost %u\n",
            this->peer_dist.uid_name( uid, src_buf, sizeof( src_buf ) ),
            this->peer_dist.primary[ uid ], this->peer_dist.secondary[ uid ],
            this->peer_dist.primary_cost[ uid ] );
  }
#endif
  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      continue;

    UserRoute * u_ptr;
    uint32_t hops, min_cost;

    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ ) {
      UidSrcPath   & path    = n.src_path[ i ];
      ForwardCache & forward = this->forward_path[ i ];
      if ( ! this->peer_dist.get_path( forward, uid, i, path ) ) {
        if ( debug_usr )
          n.printf( "no route, path %u\n", i );
      }
      else {
        u_ptr = n.user_route_ptr( *this, path.tport );
        hops  = u_ptr->rte.uid_connected.is_member( n.uid ) ? 0 : 1;
        /* route through another peer */
        if ( ! u_ptr->is_valid() && hops > 0 ) {
          UserBridge *m = this->bridge_tab.ptr[ path.src_uid ];
          if ( m == NULL ) {
            n.printf( "no closest peer route, old primary tport %u\n",
                       n.primary_route );
            continue;
          }
          UserRoute *u_peer = m->user_route_ptr( *this, path.tport );
          if ( ! u_peer->is_valid() ) {
            n.printf( "no peer route yet, using old primary tport %u\n",
                       n.primary_route );
            continue;
          }
          u_ptr->mcast_fd = u_peer->mcast_fd;
          u_ptr->inbox_fd = u_peer->inbox_fd;
          u_ptr->hops     = 1;
          if ( u_peer->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) ) {
            if ( u_peer->is_set( UCAST_URL_STATE ) )
              u_ptr->set_ucast( *this, NULL, 0, u_peer );
            else
              u_ptr->set_ucast( *this, NULL, 0, u_peer->ucast_src );
          }
          this->push_user_route( n, *u_ptr );
        }
        /* primary go to other */
        if ( i > 0 && u_ptr->is_valid() ) {
          if ( debug_usr )
            n.printf( "new route, path %u tport=%u (%s)\n", i, path.tport,
                      u_ptr->rte.name );
          if ( n.bloom_rt[ i ] != NULL ) {
            n.bloom_rt[ i ]->del_bloom_ref( &n.bloom );
            n.bloom_rt[ i ]->remove_if_empty();
            n.bloom_rt[ i ] = NULL;
          }
          n.bloom_rt[ i ] = u_ptr->rte.sub_route.create_bloom_route(
                                               u_ptr->mcast_fd, &n.bloom, i );
        }
      }
    }
    UidSrcPath & path = n.src_path[ 0 ];
    if ( path.cost == 0 ) {
      n.printf( "no route, primary tport %u\n", n.primary_route );
      continue;
    }
    u_ptr    = n.user_route_ptr( *this, path.tport );
    hops     = u_ptr->rte.uid_connected.is_member( n.uid ) ? 0 : 1,
    min_cost = peer_dist.calc_transport_cache( uid, path.tport, 0 );

    if ( n.primary_route != path.tport ) {
      UserRoute * primary = n.primary( *this );
      uint32_t    my_cost = peer_dist.calc_transport_cache( uid,
                                                           n.primary_route, 0 );
      if ( my_cost >= min_cost ) {
        n.printf( "old primary route is tport %s(d=%u),"
                  " using route %s(d=%u)\n",
            primary->rte.name, my_cost, u_ptr->rte.name, min_cost );
        this->add_inbox_route( n, u_ptr );
      }
    }
    else if ( u_ptr->rte.is_mcast() && hops > 0 ) {
      UserBridge *m = this->bridge_tab.ptr[ path.src_uid ];
      /*UserBridge *m = this->closest_peer_route( u_ptr->rte, n, tmp_cost );*/
      if ( m != NULL ) {
        UserRoute *u_peer = m->user_route_ptr( *this, path.tport );
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
#if 0
    if ( hops > 0 && u_ptr->is_set( MESH_URL_STATE ) ) {
      if ( this->start_time > n.start_time ) {
        this->mesh_pending.update( u_ptr );
      }
    }
#endif
  }
}
#if 0
void
MeshDirectList::update( UserRoute *u ) noexcept
{
  this->update( u->rte, u->mesh_url, u->mesh_url_len, u->url_hash,
                u->n.bridge_id.nonce );
}
#endif
void
MeshDirectList::update( TransportRoute &rte,  const char *url,  uint32_t len,
                    uint32_t h,  const Nonce &b_nonce,  bool is_mesh ) noexcept
{
  MeshRoute *m;
  if ( rte.mesh_id == NULL && is_mesh ) {
    fprintf( stderr, "%s not in a mesh: %.*s\n", rte.name, len, url );
    return;
  }
  else if ( rte.mesh_id != NULL && ! is_mesh ) {
    fprintf( stderr, "%s is in a mesh: %.*s\n", rte.name, len, url );
    return;
  }
  if ( h == 0 )
    h = kv_crc_c( url, len, 0 );
  for ( m = this->hd; m != NULL; m = m->next ) {
    if ( m->url_hash == h )
      return;
  }
  void * p = ::malloc( sizeof( MeshRoute ) + len + 1 );
  char * s = &((char *) p)[ sizeof( MeshRoute ) ];
  ::memcpy( s, url, len );
  s[ len ] = '\0';
  if ( is_mesh )
    m = new ( p ) MeshRoute( *rte.mesh_id, s, len, h, b_nonce, true );
  else
    m = new ( p ) MeshRoute( rte, s, len, h, b_nonce, false );
  this->push_tl( m );
}

void
UserDB::process_mesh_pending( uint64_t curr_mono ) noexcept
{
  MeshRoute * next;
  size_t      n_pos;
  uint32_t    uid;

  this->mesh_pending.last_process_mono = curr_mono;
  for ( MeshRoute *m = this->mesh_pending.hd; m != NULL; m = next ) {
    next = m->next;
    if ( m->conn_mono_time == 0 ) {
      if ( this->node_ht->find( m->b_nonce, n_pos, uid ) ) {
        UserBridge * n = this->bridge_tab[ uid ];
        if ( n != NULL ) {
          m->conn_mono_time = curr_mono;
          if ( m->is_mesh ) {
            if ( this->start_time > n->start_time ) {
              if ( m->rte.add_mesh_connect( m->mesh_url, m->url_hash ) ) {
                n->printf( "add_mesh ok %s\n", m->mesh_url );
              }
            }
          }
          else {
            if ( m->rte.add_tcp_connect( m->mesh_url, m->url_hash ) ) {
              n->printf( "add_tcp ok %s\n", m->mesh_url );
            }
          }
        }
      }
    }
    if ( m->start_mono_time == 0 )
      m->start_mono_time = curr_mono;
    else if ( m->start_mono_time + SEC_TO_NS < curr_mono ) {
      this->mesh_pending.pop( m );
      delete m;
    }
  }
}

UserBridge *
UserDB::closest_peer_route( TransportRoute &rte,  UserBridge &n,
                            uint32_t &cost ) noexcept
{
  uint32_t uid, d,
           min_uid  = 0,
           min_cost = COST_MAXIMUM;
  for ( bool ok = rte.uid_connected.first( uid ); ok;
        ok = rte.uid_connected.next( uid ) ) {
    if ( uid != n.uid ) {
      d = this->peer_dist.calc_cost( uid, n.uid, 0 );
      if ( d < min_cost ) {
        min_cost = d;
        min_uid  = uid;
      }
    }
  }
  if ( min_cost == COST_MAXIMUM )
    return NULL;
  cost = min_cost;
  return this->bridge_tab.ptr[ min_uid ];
}

/* initialize a new user from a peer definition, configured or sent by another
 * node, with a route; if a from another node, src contains the inbox url
 * that inbox ptp needs to route through */
UserBridge *
UserDB::add_user( TransportRoute &rte,  const UserRoute *src,  uint32_t fd,
                  const UserNonce &user_bridge_id,  PeerEntry &peer,
                  uint64_t start,  const MsgHdrDecoder &dec,
                  HashDigest &hello ) noexcept
{
  UserBridge * n;
  size_t       size, rtsz;
  uint32_t     uid,
               seed;
  uid  = this->new_uid();
  rtsz = sizeof( UserRoute ) * UserBridge::USER_ROUTE_BASE;
  size = sizeof( UserBridge ) + rtsz;
  seed = (uint32_t) this->rand.next();
  n    = this->make_user_bridge( size, peer, this->poll.g_bloom_db, seed );
  n->bridge_id  = user_bridge_id;
  n->uid        = uid;
  n->start_time = start;
  n->peer_hello = hello;
  hello.zero();
  ::memset( (void *) &n[ 1 ], 0, rtsz );
  n->u_buf[ 0 ] = (UserRoute *) (void *) &n[ 1 ];
  this->add_user_route( *n, rte, fd, dec, src );
  this->bridge_tab[ uid ] = n;
  this->node_ht->upsert_rsz( this->node_ht, user_bridge_id.nonce, uid );

  return n;
}

UserBridge *
UserDB::add_user2( const UserNonce &user_bridge_id,  PeerEntry &peer,
                   uint64_t start,  HashDigest &hello ) noexcept
{
  UserBridge * n;
  size_t       size, rtsz;
  uint32_t     uid,
               seed;
  uid  = this->new_uid();
  rtsz = sizeof( UserRoute ) * UserBridge::USER_ROUTE_BASE;
  size = sizeof( UserBridge ) + rtsz;
  seed = (uint32_t) this->rand.next();
  n    = this->make_user_bridge( size, peer, this->poll.g_bloom_db, seed );
  n->bridge_id  = user_bridge_id;
  n->uid        = uid;
  n->start_time = start;
  n->peer_hello = hello;
  hello.zero();
  ::memset( (void *) &n[ 1 ], 0, rtsz );
  n->u_buf[ 0 ] = (UserRoute *) (void *) &n[ 1 ];
  this->bridge_tab[ uid ] = n;
  this->node_ht->upsert_rsz( this->node_ht, user_bridge_id.nonce, uid );

  return n;
}

UserRoute *
UserBridge::init_user_route( UserDB &me,  uint32_t i,  uint32_t j,
                             uint32_t id ) noexcept
{
  if ( this->u_buf[ i ] == NULL ) {
    size_t size = sizeof( UserRoute ) * ( USER_ROUTE_BASE << i );
    void * m = ::malloc( size );
    ::memset( m, 0, size );
    this->u_buf[ i ] = (UserRoute *) (void *) m;
  }
  return new ( (void *) &this->u_buf[ i ][ j ] )
             UserRoute( *this, *me.transport_tab.ptr[ id ] );
}

uint32_t
UserDB::new_uid( void ) noexcept
{
  uint32_t uid = this->next_uid++; /* make sure hash( id ) is unique */
  this->bridge_tab.make( this->next_uid, true );
  return uid;
}

void
UserDB::retire_source( TransportRoute &,  uint32_t fd ) noexcept
{
  for (;;) {
    UserBridge *n = this->close_source_route( fd );
    if ( n == NULL )
      break;
    this->remove_authenticated( *n, BYE_SOURCE );
  }
  if ( ! this->adjacency_change.is_empty() )
    this->send_adjacency_change();

  if ( fd < this->route_list.count ) {
    UserRouteList & list = this->route_list[ fd ];
    if ( list.sys_route_refs == 0 ) {
      BloomRoute *b = this->peer_bloom.get_bloom_by_fd( fd, 0 );
      if ( b != NULL ) {
        b->del_bloom_ref( &this->peer_bloom );
        b->remove_if_empty();
      }
    }
  }
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
  uint64_t     cur_time = current_monotonic_time_ns();
  const char * from     = auth_stage_string( stage );
  bool         send_add = false;

  this->last_auth_mono = cur_time;
  n.auth_count++;
  if ( cur_time - n.auth_mono_time > SEC_TO_NS ) {
    n.printn( "add authentication from %s via %s @ %s, state %s, count=%u\n",
      from, ( src == &n ? "challenge" : src->peer.user.val ),
      src->user_route->rte.name,
      ( n.is_set( ZOMBIE_STATE ) != 0 ? "reanimated" : "new" ),
      n.auth_count );
    n.auth_mono_time = cur_time;
  }

  /*printf( "ha1: " ); n.ha1.print(); printf( "\n" );*/
  if ( n.test_clear( ZOMBIE_STATE ) ) {
    size_t pos;
    if ( this->zombie_ht->find( n.bridge_id.nonce, pos ) )
      this->zombie_ht->remove( pos );
    this->node_ht->upsert_rsz( this->node_ht, n.bridge_id.nonce, n.uid );
  }
  if ( ! n.test_set( AUTHENTICATED_STATE ) ) {
    this->events.auth_add( n.uid, src ? src->uid : 0, stage );
    /*printf( "--- uid_csum " ); this->uid_csum.print(); printf( "\n" );*/
    this->uid_csum ^= n.bridge_id.nonce;
    /*printf( "--- uid_auth_count %u uid_csum ", this->uid_auth_count );
    this->uid_csum.print(); printf( "\n" );*/

    if ( dec.test( FID_UPTIME ) ) {
      uint64_t uptime = 0;
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
      uint32_t seed = this->poll.sub_route.prefix_seed( mcb.len() ),
               hash = kv_crc_c( mcb.buf, mcb.len(), seed );
      n.bloom.add_route( (uint16_t) mcb.len(), hash );
    }
    if ( this->pending_queue.num_elems > 0 )
      this->remove_pending_peer( &n.bridge_id.nonce, 0 );
    this->uid_authenticated.add( n.uid );
    this->uid_rtt.add( n.uid );
    if ( n.user_route != NULL ) {
      this->set_ucast_url( *n.user_route, dec );
      this->set_mesh_url( *n.user_route, dec );
    }
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
    this->send_peer_add( n, &src->user_route->rte );
}

void
UserDB::remove_authenticated( UserBridge &n,  ByeReason bye ) noexcept
{
  size_t n_pos;
  bool   send_del = false;

  this->last_auth_mono = current_monotonic_time_ns();
  /*if ( debug_usr )*/
    n.printn( "remove auth %s %s\n", bye_reason_string( bye ),
               n.is_set( ZOMBIE_STATE ) ? "zombie" : "" );
  if ( n.test_clear( AUTHENTICATED_STATE ) ) {
    this->events.auth_remove( n.uid, bye );
    this->uid_authenticated.remove( n.uid );
    this->uid_rtt.remove( n.uid );
    this->pop_source_route( n );
    if ( bye != BYE_HB_TIMEOUT )
      this->remove_adjacency( n );
    this->uid_auth_count--;
    this->sub_db.sub_update_mono_time = this->last_auth_mono;
    d_usr( "--- uid_auth_count=%u -%s\n", this->uid_auth_count,
            n.peer.user.val );
    this->uid_csum ^= n.bridge_id.nonce;
    /*printf( "--- uid_auth_count %u uid_csum ", this->uid_auth_count );
    this->uid_csum.print(); printf( "\n" );*/

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

  if ( this->ipc_transport != NULL &&
       n.bloom.has_link( this->ipc_transport->fd ) )
    this->ipc_transport->sub_route.do_notify_bloom_deref( n.bloom );
  n.bloom.unlink( false );
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ ) {
    if ( n.bloom_rt[ i ] != NULL ) {
      n.bloom_rt[ i ]->remove_if_empty();
      n.bloom_rt[ i ] = NULL;
    }
    n.forward_path[ i ].reset();
    n.src_path[ i ].zero();
  }
  n.bloom.zero();
  n.adjacency.reset();
  n.sub_seqno = 0;
  n.link_state_seqno = 0;
  n.uid_csum.zero();

  if ( this->node_ht->find( n.bridge_id.nonce, n_pos ) )
    this->node_ht->remove( n_pos );

  if ( ! n.is_set( ZOMBIE_STATE ) )
    this->zombie_ht->upsert_rsz( this->zombie_ht, n.bridge_id.nonce, n.uid );
  n.state = ZOMBIE_STATE;
  n.user_route_reset();
  n.user_route = NULL;
  n.primary_route = 0;

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
    uint32_t     url_len = (uint32_t) dec.mref[ FID_MESH_URL ].fsize;
    const char * url     = (const char *) dec.mref[ FID_MESH_URL ].fptr;
    if ( debug_usr )
      u_rte.n.printf( "(%s) set_mesh_url(%s) %.*s\n",
        publish_type_to_string( dec.type ),
        u_rte.rte.transport.tport.val, url_len, url );
    u_rte.set_mesh( *this, url, url_len );
  }
}

void
UserDB::add_bloom_routes( UserBridge &n,  TransportRoute &rte ) noexcept
{
  BloomRoute *rt = rte.router_rt[ 0 ];
  if ( ! n.bloom.has_link( rt->r ) ) {
    rt->add_bloom_ref( &n.bloom );
    if ( rte.is_set( TPORT_IS_IPC ) )
      rte.sub_route.do_notify_bloom_ref( n.bloom );
    for ( uint8_t i = 1; i < COST_PATH_COUNT; i++ )
      rte.router_rt[ i ]->add_bloom_ref( &n.bloom );
    d_usr( "add_bloom_ref( %s, %s )\n", n.peer.user.val,
           rte.transport.tport.val );
  }
}

void
UserDB::add_transport( TransportRoute &rte ) noexcept
{
  this->peer_dist.invalidate( ADD_TRANSPORT_INV );

  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      continue;
    this->add_bloom_routes( n, rte );
  }
}

void
UserDB::add_inbox_route( UserBridge &n,  UserRoute *primary ) noexcept
{
  /* add point to point route */
  InboxBuf    ibx( n.bridge_id );
  UserRoute * inbox = n.primary( *this );
  uint32_t    count = (uint32_t) this->transport_tab.count;

  if ( primary == NULL ) {
    uint32_t primary_route = n.primary_route;
    for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
      UserRoute * u_ptr = n.user_route_ptr( *this, tport_id );
      if ( u_ptr->is_valid() ) {
        if ( primary == NULL ||
             this->peer_dist.calc_transport_cache( n.uid, tport_id, 0 ) <
             this->peer_dist.calc_transport_cache( n.uid, primary_route, 0 ) ) {
          primary_route = tport_id;
          primary = u_ptr;
        }
      }
    }
  }
  if ( inbox->is_set( INBOX_ROUTE_STATE ) ) {
    /* reassign primary, deref inbox */
    if ( primary != inbox ) {
      if ( debug_usr )
        n.printf( "del inbox route %.*s -> %u\n",
                  (int) ibx.len(), ibx.buf, inbox->inbox_fd );
      if ( this->ipc_transport != NULL &&
           n.bloom.has_link( this->ipc_transport->fd ) )
        this->ipc_transport->sub_route.do_notify_bloom_deref( n.bloom );
      n.bloom_rt[ 0 ]->del_bloom_ref( &n.bloom );
      n.bloom_rt[ 0 ]->remove_if_empty();
      n.bloom_rt[ 0 ] = NULL;
      inbox->rte.sub_route.del_pattern_route_str( ibx.buf, (uint16_t) ibx.len(),
                                                  inbox->inbox_fd );
      inbox->rte.primary_count--;
      inbox->clear( INBOX_ROUTE_STATE );
    }
  }
  if ( primary == NULL ) {
    n.printe( "add inbox no valid route\n" );
    return;
  }
  /* reset hb timeout */
  if ( n.primary_route != primary->rte.tport_id ) {
    n.primary_route = primary->rte.tport_id;
    n.hb_seqno = 0;
    if ( n.is_set( IN_HB_QUEUE_STATE ) ) {
      n.hb_mono_time = current_monotonic_time_ns();
      this->hb_queue.remove( &n );
      this->hb_queue.push( &n );
    }
  }
  /* add bloom for sending messages to peer */
  if ( ! primary->test_set( INBOX_ROUTE_STATE ) ) {
    if ( debug_usr )
      n.printf( "add inbox_route %.*s -> %u (%s) (bcast %u)\n",
              (int) ibx.len(), ibx.buf, primary->inbox_fd,
              primary->ucast_url.len == 0 ? "ptp" : primary->ucast_url.val,
              primary->mcast_fd );
    n.bloom_rt[ 0 ] = primary->rte.sub_route.create_bloom_route(
                                               primary->mcast_fd, &n.bloom, 0 );
    primary->rte.sub_route.do_notify_bloom_ref( n.bloom );
    primary->rte.sub_route.add_pattern_route_str( ibx.buf, (uint16_t) ibx.len(),
                                                  primary->inbox_fd );
    primary->rte.primary_count++;
  }
  /* already routing */
  else {
    if ( debug_usr )
      n.printf( "inbox exists %.*s -> %u (%s) (bcast %u)\n",
              (int) ibx.len(), ibx.buf, primary->inbox_fd,
              primary->ucast_url.len == 0 ? "ptp" : primary->ucast_url.val,
              primary->mcast_fd );
  }
  /* add inbox to bloom */
  if ( ! n.test_set( INBOX_ROUTE_STATE ) ) {
    uint32_t seed = primary->rte.sub_route.prefix_seed( ibx.len() ),
             hash = kv_crc_c( ibx.buf, ibx.len(), seed );
    n.bloom.add_route( (uint16_t) ibx.len(), hash );
  }
  for ( uint32_t i = 0; i < count; i++ ) {
    TransportRoute & rte = *this->transport_tab.ptr[ i ];
    this->add_bloom_routes( n, rte );
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
              u_ptr->ucast_url.len == 0 ? "ptp" : u_ptr->ucast_url.val,
              u_ptr->mcast_fd );
    u_ptr->rte.sub_route.del_pattern_route_str( ibx.buf, (uint16_t) ibx.len(),
                                                u_ptr->inbox_fd );
    u_ptr->rte.primary_count--;
  }
  if ( n.test_clear( INBOX_ROUTE_STATE ) ) {
    uint32_t seed = u_ptr->rte.sub_route.prefix_seed( ibx.len() ),
             hash = kv_crc_c( ibx.buf, ibx.len(), seed );
    n.bloom.del_route( (uint16_t) ibx.len(), hash );
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

const char *
UserDB::uid_names( const BitSpace &uids,  char *buf,
                   size_t buflen ) noexcept
{
  UIntBitSet bits( uids.ptr );
  return this->uid_names( bits, uids.bit_size(), buf, buflen );
}

const char *
UserDB::uid_names( const UIntBitSet &uids,  uint32_t max_uid,
                   char *buf,  size_t buflen ) noexcept
{
  uint32_t uid;
  size_t   off = 0;
  buf[ 0 ] = '\0';
  for ( bool ok = uids.first( uid, max_uid ); ok;
        ok = uids.next( uid, max_uid ) ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    const UserBridge &n = *this->bridge_tab.ptr[ uid ];
    off += ::snprintf( &buf[ off ], buflen - off, "%s.%u ",
                       n.peer.user.val, uid );
  }
  if ( off > 0 )
    buf[ off - 1 ] = '\0';
  return buf;
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

