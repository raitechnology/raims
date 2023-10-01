#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#define INCLUDE_AUTH_CONST
#define INCLUDE_PEER_CONST
#include <raims/user_db.h>
#include <raims/ev_inbox_transport.h>
#include <raimd/json_msg.h>
#include <raikv/os_file.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

UserDB::UserDB( EvPoll &p,  ConfigTree::User &u,  ConfigTree::Service &s,
                const PeerId &src,  SubDB &sdb,  StringTab &st, EventRecord &ev,
                BitSpace &rs ) noexcept
  : ipc_transport( 0 ), poll( p ), user( u ), svc( s ), sub_db( sdb ),
    string_tab( st ), events( ev ), router_set( rs ),
    svc_dsa( 0 ), user_dsa( 0 ), session_key( 0 ), hello_key( 0 ),
    cnonce( 0 ), hb_keypair( 0 ),
    node_ht( 0 ), zombie_ht( 0 ), host_ht( 0 ), peer_ht( 0 ), peer_key_ht( 0 ),
    peer_keys( 0 ), peer_bloom( 0, "(peer)", p.g_bloom_db ), my_src( src ), 

    hb_interval( HB_DEFAULT_INTERVAL ),
    reliability( DEFAULT_RELIABILITY ),
    next_uid( 0 ), free_uid_count( 0 ), uid_auth_count( 0 ),
    uid_hb_count( 0 ), bloom_fail_cnt( 0 ),

    send_peer_seqno( 0 ), link_state_seqno( 0 ),
    link_state_sum( 0 ), mcast_send_seqno( 0 ), hb_ival_ns( 0 ),
    hb_ival_mask( 0 ), next_ping_mono( 0 ), peer_dist( *this )
{
  uint64_t i;
  this->start_time = current_realtime_ns();
  this->start_mono_time = current_monotonic_time_ns(); 
  /* fill in lower nanos if resolution is low */
  for ( i = 1000000000; i > 0; i /= 1000 ) {
    if ( ( this->start_time % i ) == 0 ) {
      uint64_t r;
      rand::fill_urandom_bytes( &r, sizeof( r ) );
      this->start_time += r % i;
      while ( current_realtime_ns() < this->start_time )
        kv_sync_pause();
      break;
    }
  }
  this->rand.static_init( this->start_mono_time, this->start_time );
  this->host_id = make_host_id( u );
  this->bridge_id.nonce.seed_random();    /* random nonce */
  ::memset( this->msg_send_counter, 0, sizeof( this->msg_send_counter ) );
}

bool
UserDB::init( const CryptPass &pwd,  ConfigTree &tree ) noexcept
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
  /* index nonce_int -> uid */
  this->host_ht          = UIntHashTab::resize( NULL );
  this->next_uid         = 0; /* uid assigned to each node */
  this->free_uid_count   = 0; /* after uid freed, this count updated */
  this->uid_auth_count   = 0; /* how many peers are trusted */
  this->uid_hb_count     = 0; /* how many peers are trusted */
  this->uid_ping_count   = 0; /* ping counter */
  this->next_ping_uid    = 0; /* next pinged uid */
  this->bloom_fail_cnt   = 0;
  this->send_peer_seqno  = 0; /* sequence num of peer add/del msgs */
  this->link_state_seqno = 0; /* sequence num of link state msgs */
  this->link_state_sum   = 0; /* sum of link state seqnos */
  this->mcast_send_seqno = 0; /* sequence num of mcast msgs */
  this->hb_ival_ns       = 0; /* hb interval in nanos */
  this->hb_ival_mask     = 0; /* hb interval mask, pow2 - 1 > hv_ival_ns */
  this->next_ping_mono   = 0; /* when the next random ping timer expires */
  this->name_send_seqno  = 0;
  this->name_send_time   = 0;
  this->last_idle_check_ns = 0;
  this->route_check_mono = 0;
  this->bloom_check_mono = 0;
  this->last_auth_mono   = this->start_mono_time;
  this->converge_time    = this->start_time;
  this->net_converge_time= this->start_time;
  this->converge_mono    = this->start_mono_time;

  this->new_uid(); /* alloc uid 0 for me prevent loops */
  this->bridge_tab[ MY_UID ] = NULL;
  /* MY_UID = 0, data for it is *this, peer data are at bridge_tab[ uid ] */
  this->node_ht->upsert_rsz( this->node_ht, this->bridge_id.nonce, MY_UID );
  this->host_ht->upsert_rsz( this->host_ht, this->host_id, MY_UID );
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
}

void
UserDB::find_inbox_peer( UserBridge &n,  UserRoute &u_rte ) noexcept
{
  n.printf( "inbox has no url\n" );
  uint32_t tmp_cost;
  UserBridge *m = this->closest_peer_route( u_rte.rte, n, tmp_cost );
  if ( m != NULL ) {
    UserRoute *u_peer = m->user_route_ptr( *this, u_rte.rte.tport_id );
    if ( u_peer->is_valid() &&
         u_peer->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) ) {
      u_rte.mcast = u_peer->mcast;
      u_rte.inbox = u_peer->inbox;
      u_rte.connected( 1 );
      if ( u_peer->is_set( UCAST_URL_STATE ) )
        this->set_ucast_url( u_rte, u_peer, "fwd" );
      else
        this->set_ucast_url( u_rte, u_peer->ucast_src, "fwd2" );
      n.printf( "inbox has routing through %s\n", m->peer.user.val );
      this->push_user_route( n, u_rte );
    }
  }
}

bool
UserDB::forward_to( InboxPub &p ) noexcept
{
  UserBridge & n     = p.n;
  UserRoute  & u_rte = *p.u_ptr;
  bool b;

  if ( u_rte.rte.is_mcast() ) {
    if ( u_rte.is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) == 0 )
      this->find_inbox_peer( n, u_rte );
  }
  if ( debug_usr ) {
    n.printf( "forward_to %.*s to %s (fd=%u)\n",
              (int) p.sublen, p.sub, u_rte.rte.name, u_rte.inbox.fd );
    /*kv_pub_debug = 1;*/
  }
  u_rte.bytes_sent += p.msglen + p.frag_size;
  u_rte.msgs_sent++;
  if ( u_rte.is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) == 0 ) {
    if ( p.frag_size == 0 ) {
      EvPublish pub( p.sub, p.sublen, NULL, 0, p.msg, p.msglen,
                     u_rte.rte.sub_route, *p.src_route, p.subj_hash,
                     CABA_TYPE_ID );
      b = u_rte.rte.sub_route.forward_to( pub, u_rte.inbox.fd, p.data );
    }
    else {
      MsgFragPublish fvp( p.sub, p.sublen, p.msg, p.msglen,
                          u_rte.rte.sub_route, *p.src_route, p.subj_hash,
                          CABA_TYPE_ID, p.frag, p.frag_size );
      b = u_rte.rte.sub_route.forward_to( fvp, u_rte.inbox.fd, p.data );
    }
  }
  else if ( u_rte.is_set( UCAST_URL_SRC_STATE ) == 0 ) {
    InboxPublish ipub( p.sub, p.sublen, p.msg, p.msglen, u_rte.rte.sub_route,
                       *p.src_route, p.subj_hash, CABA_TYPE_ID,
                       u_rte.ucast_url.val, n.uid, u_rte.url_hash,
                       p.frag, p.frag_size );
    b = u_rte.rte.sub_route.forward_to( ipub, u_rte.inbox.fd, p.data );
  }
  else {
    const UserRoute  & u_src = *u_rte.ucast_src;
    const UserBridge & n_src = u_src.n;
    InboxPublish isrc( p.sub, p.sublen, p.msg, p.msglen, u_src.rte.sub_route,
                       *p.src_route, p.subj_hash, CABA_TYPE_ID,
                       u_src.ucast_url.val, n_src.uid, u_src.url_hash,
                       p.frag, p.frag_size );
    b = u_src.rte.sub_route.forward_to( isrc, u_src.inbox.fd, p.data );
  }
  /*if ( debug_usr ) {
    kv_pub_debug = 0;
  }*/
  return b;
}

bool
UserDB::bcast_send( EvPublish &pub ) noexcept
{
  /* bcast to all connected */
  bool b = true;
  size_t count = this->transport_tab.count;
  if ( count > 1 ) {
    kv::BitSpace unique;
    for ( size_t i = 0; i < count; i++ ) {
      TransportRoute * rte = this->transport_tab.ptr[ i ];
      if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
        if ( ! unique.superset( rte->uid_connected ) ) {
          b &= rte->forward_to_connected_auth( pub );
          unique.add( rte->uid_connected );
        }
      }
    }
  }
  return b;
}

bool
UserDB::mcast_send( EvPublish &pub,  uint8_t path_select ) noexcept
{
  /* mcast using forwarding rules */
  ForwardCache   & forward = this->forward_path[ path_select ];
  TransportRoute * rte;
  uint32_t         tport_id;
  bool             b = true;

  this->peer_dist.update_path( forward, path_select );
  if ( forward.first( tport_id ) ) {
    do {
      rte = this->transport_tab.ptr[ tport_id ];
      b  &= rte->sub_route.forward_except( pub, this->router_set );
    } while ( forward.next( tport_id ) );
  }
  return b;
}

bool
UserDB::bcast_pub( const MsgFramePublish &pub,  const UserBridge &n,
                   const MsgHdrDecoder &dec ) noexcept
{
  /* bcast to all connected */
  bool b = true;
  if ( dec.is_mcast_type() ) {
    size_t count = this->transport_tab.count;
    if ( count > 1 || pub.rte.connect_count > 1 ) {
      EvPublish tmp( pub );
      BitSpace unique;
      unique.add( n.uid );
      for ( size_t i = 0; i < count; i++ ) {
        TransportRoute * rte = this->transport_tab.ptr[ i ];
        tmp.publish_type = PUB_TYPE_NORMAL;
        if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
          if ( ! unique.superset( rte->uid_connected ) ) {
            if ( rte != &pub.rte )
              b &= rte->forward_to_connected_auth( tmp );
            else if ( rte->connect_count > 1 )
              b &= rte->forward_to_connected_auth_not_fd( tmp,
                                                          pub.src_route.fd );
            unique.add( rte->uid_connected );
          }
        }
      }
    }
  }
  return b;
}

bool
UserDB::mcast_pub( const MsgFramePublish &pub,  UserBridge &n,
                   const MsgHdrDecoder &dec ) noexcept
{
  /* mcast using forwarding rules */
  bool b = true;
  if ( dec.is_mcast_type() ) {
    uint8_t path_select = pub.shard;
    ForwardCache   & forward = n.forward_path[ path_select ];
    TransportRoute * rte;
    uint32_t         tport_id;

    this->peer_dist.update_source_path( forward, n.uid, path_select );
    if ( forward.first( tport_id ) ) {
      do {
        EvPublish tmp( pub );
        tmp.publish_type = PUB_TYPE_NORMAL;
        rte = this->transport_tab.ptr[ tport_id ];
        b  &= rte->sub_route.forward_except( tmp, this->router_set );
      } while ( forward.next( tport_id ) );
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
  if ( this->host_ht != NULL ) {
    delete this->host_ht;
    this->host_ht = NULL;
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
  this->mesh_queue.reset();
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
    if ( n->unknown_adj_refs != 0 )
      n->printf( "adjacency request timeout (%s) unknown adj refs %u\n",
             n->primary( *this )->inbox_route_str( buf, sizeof( buf ) ),
             n->unknown_adj_refs );
    n->clear( ADJACENCY_REQUEST_STATE );
    this->adj_queue.pop();
    if ( n->is_set( AUTHENTICATED_STATE ) ) {
      if ( ! n->test_set( PING_STATE ) ) {
        n->ping_mono_time = current_mono_time;
        this->ping_queue.push( n );
        this->send_ping_request( *n );
      }
    }
    req_timeout = true;
  }

  while ( this->mesh_queue.num_elems > 0 ) {
    n = this->mesh_queue.heap[ 0 ];
    if ( current_mono_time < n->mesh_timeout() )
      break;
    this->mesh_queue.pop();
    n->printf( "mesh request timeout\n" );
    n->clear( MESH_REQUEST_STATE );
  }

  while ( this->ping_queue.num_elems > 0 ) {
    n = this->ping_queue.heap[ 0 ];
    if ( current_mono_time < n->ping_timeout() )
      break;
    this->ping_queue.pop();
    if ( ! n->is_set( AUTHENTICATED_STATE ) ) {
      n->printf( "ping request zombie\n" );
      n->clear( PING_STATE );
      n = NULL;
    }
    else if ( ++n->ping_fail_count >= 3 ) {
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
    n->hb_miss++;
    n->printe( "no heartbeat detected in interval %u (%.1fsecs), dropping\n",
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

  if ( this->converge_network( current_mono_time, current_time,
                               req_timeout ) ) {
    if ( ! this->adjacency_change.is_empty() )
      this->send_adjacency_change();
    if ( this->uid_auth_count > 0 )
      this->interval_ping( current_mono_time, current_time );
    if ( ! this->mesh_pending.is_empty() )
      this->process_mesh_pending( current_mono_time );
  }
}

bool
UserDB::converge_network( uint64_t current_mono_time,  uint64_t current_time,
                          bool req_timeout ) noexcept
{
  UserBridge *n, *m;
  bool run_peer_inc = false;
  this->peer_dist.clear_cache_if_dirty();
  if ( this->peer_dist.inc_run_count == 0 || req_timeout ||
       this->peer_dist.inc_running ) {
    /*printf( "test1 inc_run_count %u req_timeout %u inc_running %u "
            "update %lu reas %u\n",
            this->peer_dist.inc_run_count, req_timeout,
            this->peer_dist.inc_running, this->peer_dist.update_seqno,
            this->peer_dist.invalid_reason );*/
    run_peer_inc = true;
  }
  else if ( this->peer_dist.found_inconsistency &&
            this->peer_dist.last_run_mono +
            (uint64_t) this->peer_dist.inc_run_count *
            SEC_TO_NS < current_mono_time ) {
    /*printf( "test2 inc_run_count %u\n", this->peer_dist.inc_run_count );*/
    run_peer_inc = true;
  }
  if ( ! run_peer_inc ) {
    if ( this->route_check_mono < this->converge_mono &&
         current_mono_time > this->converge_mono + SEC_TO_NS ) {
      this->route_check_mono = this->converge_mono;
      this->bloom_check_mono = this->converge_mono + SEC_TO_NS;
      this->find_adjacent_routes();
      this->check_blooms();
    }
    else if ( this->bloom_check_mono > this->converge_mono &&
              current_mono_time > this->bloom_check_mono ) {
      bool ok = this->check_blooms();
      if ( ! ok ) {
        fprintf( stderr, "bloom check failed 2\n" );
        this->bloom_fail_cnt++;
        this->find_adjacent_routes();
      }
      else {
        if ( this->bloom_fail_cnt != 0 ) {
          printf( "bloom check ok\n" );
          this->bloom_fail_cnt = 0;
        }
      }
      uint64_t delta = ( this->bloom_check_mono - this->converge_mono );
      if ( ok && delta / SEC_TO_NS > 20 ) /* stop after ok for 20 secs */
        this->bloom_check_mono = 0;
      else
        this->bloom_check_mono += delta; /* pow2 backoff */
    }
    return true;
  }
  int state = this->peer_dist.find_inconsistent2( n, m );
  if ( state != AdjDistance::CONSISTENT ) {
    if ( state == AdjDistance::LINK_MISSING ) {
      if ( n != NULL && m != NULL ) {
        bool n_less = ( n->adj_req_throttle.mono_time <=
                        m->adj_req_throttle.mono_time );
        if ( ! n_less ) {
          UserBridge * x = n;
          n = m; m = x;
        }
      }
      else if ( n == NULL ) {
        n = m;
        m = NULL;
      }
      if ( ! n->is_set( PING_STATE ) &&
           ! n->throttle_adjacency( 0, current_mono_time ) ) {
        /*printf( "---- find_inconsistent from %s(%u) to %s(%u) "
           "inc_run_count %u, req_timeout %s inc_running %s found_inc %s\n",
                 n->peer.user.val, n->uid, m->peer.user.val, m->uid,
                 this->peer_dist.inc_run_count, req_timeout?"t":"f",
                 this->peer_dist.inc_running?"t":"f",
                 this->peer_dist.found_inconsistency?"t":"f" );*/
        this->send_adjacency_request( *n, DIJKSTRA_SYNC_REQ );
      }
      else if ( n->ping_fail_count >= 3 ) {
        m = NULL;
        state = AdjDistance::UID_ORPHANED;
      }
    }
    if ( state == AdjDistance::UID_ORPHANED ) {
      uint64_t ns, ns2, hb_timeout_ns;
      hb_timeout_ns = sec_to_ns( n->hb_interval * 2 ) + SEC_TO_NS;
      ns  = n->start_mono_time + hb_timeout_ns; /* if hb and still orphaned */
      ns2 = this->start_mono_time + hb_timeout_ns;

      if ( this->adjacency_unknown.is_empty() &&
           ns < current_mono_time && ns2 < current_mono_time ) {
        d_usr( "find_inconsistent orphaned %s(%u)\n",
                 n->peer.user.val, n->uid );
        this->remove_authenticated( *n,
          n->ping_fail_count ? BYE_PING : BYE_ORPHANED );
      }
      else { /* n != NULL && m == NULL */
        if ( ! n->throttle_adjacency( 0, current_mono_time ) )
          this->send_adjacency_request( *n, DIJKSTRA_SYNC_REQ );
      }
    }
  }
  else {
    if ( ! this->peer_dist.found_inconsistency &&
         this->peer_dist.invalid_mono != 0 ) {
      uint32_t src_uid = this->peer_dist.invalid_src_uid;
      this->events.converge( this->peer_dist.invalid_reason, src_uid );
      this->converge_time = current_time;
      if ( current_time > this->net_converge_time )
        this->net_converge_time = current_time;
      this->converge_mono = current_mono_time;
      uint32_t p = this->peer_dist.get_path_count();
      uint64_t x = current_monotonic_time_ns();
      uint64_t t = ( x > this->peer_dist.invalid_mono ) ?
                   ( x - this->peer_dist.invalid_mono ) : 0;
      const char * src_user = this->user.user.val;
      if ( src_uid != 0 )
        src_user = this->bridge_tab.ptr[ src_uid ]->peer.user.val;
      printf(
        "network converges %.3f secs, %u path%s, %u uids authenticated, "
        "%s from %s.%u\n",
              (double) t / SEC_TO_NS, p, p>1?"s":"", this->uid_auth_count,
              invalidate_reason_string( this->peer_dist.invalid_reason ),
              src_user, src_uid );
    }
    this->find_adjacent_routes();
  }
  return false;
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
const char *
rai::ms::adjacency_result_string( char *buf,  AdjacencyRequest r,
                                  uint32_t which ) noexcept {
  const char *s = adjacency_request_str[ r < MAX_ADJ_REQ ? r : 0 ];
  size_t len = ::strlen( s );
  ::memcpy( buf, s, len );
  if ( which == 0 )
    ::strcpy( &buf[ len ], ",null" );
  else {
    if ( ( which & 1 ) != 0 ) { /* SYNC_LINK */
      ::strcpy( &buf[ len ], ",link" );
      len += 5;
    }
    if ( ( which & 2 ) != 0 ) { /* SYNC_SUB */
      ::strcpy( &buf[ len ], ",sub" );
      len += 4;
    }
    if ( ( which & 4 ) != 0 ) { /* SYNC_NULL */
      ::strcpy( &buf[ len ], ",force" );
    }
  }
  return buf;
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
      UserRoute *u_ptr = n->user_route_ptr( *this, pub.rte.tport_id );
      n->user_route = u_ptr;
      if ( ! u_ptr->is_valid() ||
           ( ! u_ptr->mcast.equals( pub.src_route ) &&
             ! u_ptr->inbox.equals( pub.src_route ) ) )
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
      UserRoute *u_ptr = n->user_route_ptr( *this, pub.rte.tport_id );
      n->user_route = u_ptr;
      if ( ! u_ptr->is_valid() ||
           ( ! u_ptr->mcast.equals( pub.src_route ) &&
             ! u_ptr->inbox.equals( pub.src_route ) ) )
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

bool
UserRoute::set_ucast( UserDB &user_db,  const void *p,  size_t len,
                      const UserRoute *src ) noexcept
{
  if ( len == 0 && this->ucast_url.len == 0 && this->ucast_src == src )
    return false;

  if ( len == 0 ) {
    if ( debug_usr )
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
      return false;
    if ( debug_usr )
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
  /*user_db.peer_dist.invalidate( ADD_UCAST_URL_INV );*/
  return true;
}

bool
UserRoute::set_mesh( UserDB &user_db,  const void *p,  size_t len ) noexcept
{
  if ( len == 0 && this->mesh_url.len == 0 )
    return false;
  if ( ! this->rte.is_mesh() )
    return false;

  if ( len == 0 ) {
    if ( debug_usr )
      this->n.printf( "clear_mesh( t=%s )\n", this->rte.name );
    this->mesh_url.zero();
    this->url_hash = 0;
    this->rte.mesh_url_hash = 0;
    this->rte.mesh_url.zero();
    this->clear( MESH_URL_STATE );
  }
  else {
    if ( this->mesh_url.equals( (const char *) p, len ) )
      return false;
    user_db.string_tab.ref_string( (const char *) p, len, this->mesh_url );
    this->url_hash = kv_crc_c( this->mesh_url.val, len, 0 );

    if ( debug_usr )
      this->n.printf( "set_mesh( %.*s, tport=%s, hash=%x )\n",
                      (int) len, (char *) p, this->rte.name, this->url_hash );
    this->rte.mesh_url_hash = this->url_hash;
    this->rte.mesh_url      = this->mesh_url;

    this->set( MESH_URL_STATE );
  }
  /*user_db.peer_dist.invalidate( ADD_MESH_URL_INV );*/
  return true;
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
      PeerId ucast = this->inbox;
      if ( ucast.fd == NO_RTE ) {
        s   = "no_rte";
        len = 6;
      }
      else if ( (uint32_t) ucast.fd <= poll.maxfd &&
                poll.sock[ ucast.fd ] != NULL ) {
        uint32_t uid2;
        s   = poll.sock[ ucast.fd ]->peer_address.buf;
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
  if ( uaddr != NULL && i < buflen )
    i += ::snprintf( &buf[ i ], buflen - i, "%s.%u@", uaddr, uid );
  if ( pre != NULL && i < buflen )
    i += ::snprintf( &buf[ i ], buflen - i, "%s://", pre );
  if ( i < buflen )
    ::snprintf( &buf[ i ], buflen - i, "%.*s", (int) len, s );
  return buf;
}
/* initialize a route index for rte */
void
UserDB::add_user_route( UserBridge &n,  TransportRoute &rte,  const PeerId &pid,
                      const MsgHdrDecoder &dec,  const UserRoute *src ) noexcept
{
  UserRoute * u_ptr;
  PeerId      inbox = pid,
              mcast = pid;
  uint32_t    hops  = 0;

  if ( ( dec.type < U_SESSION_HELLO || dec.type > U_SESSION_BYE ) &&
         dec.type != U_INBOX_AUTH )
    hops = 1;

  this->events.add_user_route( n.uid, rte.tport_id, src ? src->n.uid : 0, hops);
  d_usr( "add_user_route( %s, %s, %s, fd=%u, hops=%u )\n",
         dec.get_type_string(), n.peer.user.val, rte.name, mcast.fd, hops );

  u_ptr = n.user_route_ptr( *this, rte.tport_id );
  if ( mcast.equals( rte.inbox ) || mcast.equals( rte.mcast ) ) {
    mcast = rte.mcast;
    inbox = rte.inbox;
  }
  if ( u_ptr->is_valid() && u_ptr->is_set( IN_ROUTE_LIST_STATE ) ) {
    if ( ! u_ptr->mcast.equals( mcast ) ) {
      printf( "** add_user_route remap route_list old_fd %u "
             "( %s, %s, %s, fd=%u, hops=%u )\n",
             u_ptr->mcast.fd, dec.get_type_string(), n.peer.user.val,
             rte.name, mcast.fd, hops );
    }
    this->pop_user_route( n, *u_ptr );
  }
  u_ptr->mcast = mcast;
  u_ptr->inbox = inbox;
  u_ptr->connected( hops );
  n.user_route = u_ptr;
  this->set_mesh_url( *u_ptr, dec, "add" );

  /* if directly attached to a transport route, hops == 0 */
  if ( hops == 0 ) {
    if ( dec.test( FID_UCAST_URL ) )
      this->set_ucast_url( *u_ptr, dec, "add" );
  }
  /* if routing through a hop that has an inbox */
  else if ( src != NULL ) {
    if ( inbox.equals( src->inbox ) &&
         src->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) != 0 ) {
      if ( src->is_set( UCAST_URL_STATE ) )
        this->set_ucast_url( *u_ptr, src, "add2" );
      else
        this->set_ucast_url( *u_ptr, src->ucast_src, "add3" );
    }
  }
  if ( n.is_set( AUTHENTICATED_STATE ) ) {
    this->push_user_route( n, *u_ptr );
    if ( u_ptr->hops() == 0 )
      this->add_inbox_route( n, NULL );
  }
}
/* use adjacency tab to find the best routes for each pear */
void
UserDB::find_adjacent_routes( void ) noexcept
{
  uint32_t path_cnt = this->peer_dist.get_path_count();
  for ( uint32_t path_select = 0; path_select < path_cnt; path_select++ ) {
    ForwardCache & forward = this->forward_path[ path_select ];
    this->peer_dist.update_path( forward, path_select );
  }

  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      continue;

    UserRoute * u_ptr, * primary;
    uint32_t hops, min_cost, my_cost;

    for ( uint32_t path_select = 0; path_select < path_cnt; path_select++ ) {
      ForwardCache & forward = this->forward_path[ path_select ];
      UidSrcPath   & path    = forward.path[ uid ];

      if ( path.cost == 0 || path.tport >= this->transport_tab.count ) {
        if ( debug_usr )
          n.printf( "no route, path %u\n", path_select );
        if ( path.tport >= this->transport_tab.count )
          n.printe( "no route tport %u\n", path.tport );
        continue;
      }

      u_ptr = n.user_route_ptr( *this, path.tport );
      hops  = u_ptr->rte.uid_connected.is_member( n.uid ) ? 0 : 1;
      /* route through another peer */
      if ( ! u_ptr->is_set( IN_ROUTE_LIST_STATE ) && hops > 0 ) {
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
        u_ptr->mcast = u_peer->mcast;
        u_ptr->inbox = u_peer->inbox;
        u_ptr->connected( 1 );
        if ( u_peer->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE ) ) {
          if ( u_peer->is_set( UCAST_URL_STATE ) )
            this->set_ucast_url( *u_ptr, u_peer, "find" );
          else
            this->set_ucast_url( *u_ptr, u_peer->ucast_src, "find2" );
        }
        this->push_user_route( n, *u_ptr );
      }
      /* primary go to other */
      if ( path_select > 0 && u_ptr->is_valid() ) {
        if ( debug_usr )
          n.printf( "new route, path %u tport=%u (%s)\n", path_select,
                    path.tport, u_ptr->rte.name );
        if ( n.bloom_rt[ path_select ] != NULL ) {
          n.bloom_rt[ path_select ]->del_bloom_ref( &n.bloom );
          n.bloom_rt[ path_select ]->remove_if_empty();
          n.bloom_rt[ path_select ] = NULL;
        }
        n.bloom_rt[ path_select ] = u_ptr->rte.sub_route.create_bloom_route(
                                     u_ptr->mcast.fd, &n.bloom, path_select );
      }
    }
    /* if path count was larger before */
    for ( uint32_t x = path_cnt; x < n.bloom_rt.count; x++ ) {
      if ( n.bloom_rt.ptr[ x ] != NULL ) {
        n.bloom_rt.ptr[ x ]->del_bloom_ref( &n.bloom );
        n.bloom_rt.ptr[ x ]->remove_if_empty();
        n.bloom_rt.ptr[ x ] = NULL;
      }
    }
    /* update primary route */
    ForwardCache & forward = this->forward_path[ 0 ];
    UidSrcPath   & path    = forward.path[ uid ];
    if ( path.cost == 0 ) {
      if ( debug_usr )
        n.printf( "no primary route yet\n" );
      continue;
    }
    u_ptr    = n.user_route_ptr( *this, path.tport );
    hops     = u_ptr->rte.uid_connected.is_member( n.uid ) ? 0 : 1,
    min_cost = path.cost;

    if ( n.primary_route == path.tport )
      primary = u_ptr;
    else
      primary = n.primary( *this );

    if ( u_ptr->is_valid() && primary != u_ptr ) {
      if ( ! primary->is_valid() )
        my_cost = COST_MAXIMUM;
      else
        my_cost = peer_dist.calc_transport_cache( uid, n.primary_route, 0 );
      if ( my_cost >= min_cost ) {
        if ( debug_usr )
          n.printf( "old primary route is tport %s(d=%u),"
                    " using route %s(d=%u)\n",
              primary->rte.name, my_cost, u_ptr->rte.name, min_cost );
        this->add_inbox_route( n, u_ptr );
        primary = u_ptr;
      }
    }
    else if ( u_ptr->rte.is_mcast() && hops > 0 ) {
      UserBridge *m = this->bridge_tab.ptr[ path.src_uid ];
      /*UserBridge *m = this->closest_peer_route( u_ptr->rte, n, tmp_cost );*/
      if ( m != NULL ) {
        UserRoute *u_peer = m->user_route_ptr( *this, path.tport );
        if ( u_peer->mcast.equals( u_ptr->mcast ) &&
             u_peer->inbox.equals( u_ptr->inbox ) ) {

          if ( u_peer->is_set( UCAST_URL_SRC_STATE ) ) {
            if ( ! u_ptr->is_set( UCAST_URL_SRC_STATE ) ||
                 u_ptr->ucast_src != u_peer->ucast_src ) {
              const UserRoute * ucast_src = u_peer->ucast_src;
              this->set_ucast_url( *u_ptr, ucast_src, "find3" );
            }
          }
          else if ( u_peer->is_set( UCAST_URL_STATE ) ) {
            if ( ! u_ptr->is_set( UCAST_URL_SRC_STATE ) ||
                 u_ptr->ucast_src != u_peer ) {
              n.printf( "set ucast thourgh %s\n", u_peer->n.peer.user.val );
              this->set_ucast_url( *u_ptr, u_peer, "find4" );
            }
          }
        }
      }
    }
    if ( n.bloom_rt[ 0 ] != NULL &&
         (uint32_t) primary->mcast.fd != n.bloom_rt[ 0 ]->r ) {
      if ( debug_usr )
        n.printf( "updating primary route, new mcast_fd %u\n",
                  primary->mcast.fd );
      this->add_inbox_route( n, primary );
    }
  }
}

bool
UserDB::check_blooms( void ) noexcept
{
  bool failed = false;

  uint32_t path_cnt = this->peer_dist.get_path_count();
  for ( uint32_t path_select = 0; path_select < path_cnt; path_select++ ) {
    ForwardCache & forward = this->forward_path[ path_select ];
    this->peer_dist.update_path( forward, path_select );
  }

  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    uint32_t no_path = 0, invalid = 0, null_bloom = 0, fd_not_set = 0;
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      continue;

    for ( uint32_t path_select = 0; path_select < path_cnt; path_select++ ) {
      ForwardCache & forward = this->forward_path[ path_select ];
      UidSrcPath   & path    = forward.path[ uid ];
      if ( path.cost == 0 ) {
        no_path |= 1 << path_select;
      }
      else {
        UserRoute * u_ptr = n.user_route_ptr( *this, path.tport );
        if ( u_ptr == NULL || ! u_ptr->is_valid() )
          invalid |= 1 << path_select;
        else if ( n.bloom_rt[ path_select ] == NULL )
          null_bloom |= 1 << path_select;
        else if ( n.bloom_rt[ path_select ]->r != (uint32_t) u_ptr->mcast.fd )
          fd_not_set |= 1 << path_select;
      }
    }

    if ( ( no_path | invalid | null_bloom | fd_not_set ) != 0 ) {
      n.printe( "check_rt no_path=%x invalid=%x null_bloom=%x fd_not_set=%x\n",
                no_path, invalid, null_bloom, fd_not_set );
      failed = true;
    }
  }
  return ! failed;
}

void
MeshDirectList::update( TransportRoute &rte,  const StringVal &tport,
                        const StringVal &url,  uint32_t h,
                        const Nonce &b_nonce,  bool is_mesh ) noexcept
{
  MeshRoute *m;
  if ( rte.mesh_id == NULL && is_mesh ) {
    fprintf( stderr, "%s not in a mesh: %.*s\n", rte.name, url.len, url.val );
    return;
  }
  else if ( rte.mesh_id != NULL && ! is_mesh ) {
    fprintf( stderr, "%s is in a mesh: %.*s\n", rte.name, url.len, url.val );
    return;
  }
  if ( h == 0 )
    h = kv_crc_c( url.val, url.len, 0 );
  for ( m = this->hd; m != NULL; m = m->next ) {
    if ( m->url_hash == h && m->mesh_url.equals( url ) )
      return;
  }
  void * p = ::malloc( sizeof( MeshRoute ) );
  StringVal url_ref( url );
  StringVal tport_ref( tport );
  rte.user_db.string_tab.add_string( url_ref );
  rte.user_db.string_tab.add_string( tport_ref );
  if ( is_mesh )
    m = new ( p )
      MeshRoute( *rte.mesh_id, tport_ref, url_ref, h, b_nonce, true );
  else
    m = new ( p ) MeshRoute( rte, tport_ref, url_ref, h, b_nonce, false );
  this->push_tl( m );
}

void
UserDB::process_mesh_pending( uint64_t curr_mono ) noexcept
{
  MeshRoute  * next;
  UserBridge * n;
  size_t       n_pos;
  uint32_t     uid;

  this->mesh_pending.last_process_mono = curr_mono;
  for ( MeshRoute *m = this->mesh_pending.hd; m != NULL; m = next ) {
    next = m->next;
    if ( m->conn_mono_time == 0 ) {
      if ( this->node_ht->find( m->b_nonce, n_pos, uid ) ||
           this->zombie_ht->find( m->b_nonce, n_pos, uid ) ) {
        n = this->bridge_tab[ uid ];
        if ( n != NULL ) {
          m->conn_mono_time = curr_mono;
          if ( ! m->rte.transport.tport.equals( m->tport_name ) ) {
            n->printe( "transport not equal to %s\n", m->tport_name.val );
          }
          else if ( m->is_mesh ) {
            if ( this->start_time > n->start_time ) {
              if ( m->rte.add_mesh_connect( m->mesh_url.val, m->url_hash ) ) {
                if ( debug_usr )
                  n->printf( "add_mesh ok %s\n", m->mesh_url.val );
              }
            }
          }
          else if ( ! m->rte.is_mcast() ) {
            if ( m->rte.add_tcp_connect( m->mesh_url.val, m->url_hash ) ) {
              if ( debug_usr )
                n->printf( "add_tcp ok %s\n", m->mesh_url.val );
            }
          }
          else {
            UserRoute * u_ptr = n->user_route_ptr( *this, m->rte.tport_id );
            if ( u_ptr->url_hash != m->url_hash ||
                 ! u_ptr->is_set( UCAST_URL_STATE ) )
              this->set_ucast_url( *u_ptr, m->mesh_url.val, m->mesh_url.len,
                                   "pend" );
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

void
UserDB::update_host_id( UserBridge &n,  const MsgHdrDecoder &dec ) noexcept
{
  uint32_t host_id;

  if ( ! dec.get_ival<uint32_t>( FID_HOST_ID, host_id ) )
    return;
  this->update_host_id( &n, host_id );
}

void
UserDB::update_host_id( UserBridge *n,  uint32_t host_id ) noexcept
{
  uint32_t old_host_id = ( n == NULL ? this->host_id : n->host_id ),
           upd_uid     = ( n == NULL ? MY_UID : n->uid ),
           coll_uid;
  size_t   pos;

  if ( host_id == old_host_id )
    return;

  if ( this->host_ht->find( host_id, pos, coll_uid ) ) {
    bool is_auth = ( coll_uid == 0 ? true :
          ( this->bridge_tab.ptr[ coll_uid ] != NULL &&
            this->bridge_tab.ptr[ coll_uid ]->is_set( AUTHENTICATED_STATE ) ) );
    if ( is_auth ) {
      const char * coll_user = ( coll_uid == 0 ? this->user.user.val :
                                this->bridge_tab.ptr[ coll_uid ]->peer.user.val );
      const char * upd_user  = ( upd_uid == 0 ? this->user.user.val :
                                this->bridge_tab.ptr[ upd_uid ]->peer.user.val );
      fprintf( stderr, "collision: %s.%u host_id %08x exists (%s.%u)\n",
          upd_user, upd_uid, (uint32_t) htonl( host_id ), coll_user, coll_uid );
    }
  }
  if ( this->host_ht->find( old_host_id, pos ) )
    this->host_ht->remove( pos );
  this->host_ht->upsert_rsz( this->host_ht, host_id, upd_uid );
  if ( n != NULL )
    n->host_id = host_id;
  else
    this->host_id = host_id;
}

/* initialize a new user from a peer definition, configured or sent by another
 * node, with a route; if a from another node, src contains the inbox url
 * that inbox ptp needs to route through */
UserBridge *
UserDB::add_user( TransportRoute &rte,  const UserRoute *src, const PeerId &pid,
                  const UserNonce &user_bridge_id,  PeerEntry &peer,
                  uint64_t start,  const MsgHdrDecoder &dec,
                  HashDigest &hello ) noexcept
{
  UserBridge * n;
  size_t       size, rtsz;
  uint32_t     uid, seed, host_id;

  if ( ! dec.get_ival<uint32_t>( FID_HOST_ID, host_id ) )
    host_id = make_host_id( peer );
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
  this->add_user_route( *n, rte, pid, dec, src );
  this->bridge_tab[ uid ] = n;
  this->node_ht->upsert_rsz( this->node_ht, user_bridge_id.nonce, uid );
  this->update_host_id( n, host_id );
  /*if ( this->ipc_transport != NULL && this->ipc_transport->rv_svc != NULL )
    this->ipc_transport->rv_svc->update_host_inbox_patterns( uid );*/

  return n;
}

UserBridge *
UserDB::add_user2( const UserNonce &user_bridge_id,  PeerEntry &peer,
                   uint64_t start,  HashDigest &hello,
                   uint32_t host_id ) noexcept
{
  UserBridge * n;
  size_t       size, rtsz;
  uint32_t     uid, seed;

  if ( host_id == 0 )
    host_id = make_host_id( peer );
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
  this->update_host_id( n, host_id );
  /*if ( this->ipc_transport != NULL && this->ipc_transport->rv_svc != NULL )
    this->ipc_transport->rv_svc->update_host_inbox_patterns( uid );*/

  return n;
}

UserRoute *
UserBridge::init_user_route( UserDB &me,  uint32_t i,  uint32_t j,
                             uint32_t id ) noexcept
{
  void * m;
  if ( this->u_buf[ i ] == NULL ) {
    size_t size = sizeof( UserRoute ) * ( USER_ROUTE_BASE << i );
    m = ::malloc( size );
    ::memset( m, 0, size );
    this->u_buf[ i ] = (UserRoute *) (void *) m;
  }
  m = (void *) &this->u_buf[ i ][ j ];
  if ( id < me.transport_tab.count )
    return new ( m ) UserRoute( *this, *me.transport_tab.ptr[ id ] );
  this->printe( "bad init_user_route tport_id %u\n", id );
  ::memset( m, 0, sizeof( UserRoute ) );
  return (UserRoute *) m;
}

uint32_t
UserDB::new_uid( void ) noexcept
{
  uint32_t uid = this->next_uid++; /* make sure hash( id ) is unique */
  this->bridge_tab.make( this->next_uid, true );
  return uid;
}

void
UserDB::retire_source( TransportRoute &rte,  uint32_t fd ) noexcept
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
        d_usr( "retire peer bloom fd %u\n", fd );
        b->del_bloom_ref( &this->peer_bloom );
        b->remove_if_empty();
      }
      else {
        d_usr( "retire fd %u peer_bloom not found\n", fd );
      }
    }
    else {
      d_usr( "retire fd %u sys_route_refs %u\n", fd, list.sys_route_refs );
    }
  }
  if ( debug_usr )
    rte.printf( "retire_source( %u )\n", fd );
  /*this->check_bloom_route( rte, 0 );*/
}

const char *
rai::ms::auth_stage_string( AuthStage stage ) noexcept
{
  if ( stage < MAX_AUTH )
    return auth_stage[ stage ];
  return auth_stage[ 0 ];
}
#if 0
const char *
rai::ms::bye_reason_string( ByeReason bye ) noexcept
{
  if ( bye < MAX_BYE )
    return bye_reason[ bye ];
  return bye_reason[ 0 ];
}
#endif
void
UserDB::add_authenticated( UserBridge &n,
                           const MsgHdrDecoder &dec,
                           AuthStage stage,
                           UserBridge *src ) noexcept
{
  uint64_t     cur_mono = current_monotonic_time_ns();
  const char * from     = auth_stage_string( stage );
  bool         send_add = false;

  this->last_auth_mono = cur_mono;
  if ( n.is_set( ZOMBIE_STATE ) ) {
    if ( n.last_auth_type == BYE_BYE ) {
      n.printf( "refusing to auth bye bye\n" );
      return;
    }
    if ( stage >= AUTH_FROM_ADJ_RESULT && n.auth_mono_time > 0 ) {
      uint32_t countdown = 0;
      /* removed auth within the last 15 seconds */
      if ( n.remove_auth_mono + sec_to_ns( 15 ) > cur_mono )
        countdown = ( n.auth_count > 8 ? 8 : n.auth_count );
      /* last added auth within grace period */
      if ( n.auth_mono_time + sec_to_ns( countdown * 2 ) > cur_mono ) {
        n.printf( "refusing to auth %s after %s within %u secs\n",
                  from, auth_stage_string( n.last_auth_type ), countdown * 2 );
        return;
      }
    }
  }
  if ( stage <= AUTH_TRUST ) /* from key exchange */
    n.auth_count = 0;
  n.last_auth_type = stage;
  n.auth_count++;
  if ( cur_mono - n.auth_mono_time >= sec_to_ns( 1 ) ) {
    n.printn( "add authentication from %s via %s @ %s, state %s, count=%u\n",
      from, ( src == &n ? "challenge" : src->peer.user.val ),
      src->user_route->rte.name,
      ( n.is_set( ZOMBIE_STATE ) != 0 ? "reanimated" : "new" ),
      n.auth_count );
    n.auth_mono_time = cur_mono;
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
      n.start_mono_time = cur_mono - uptime;

      if ( dec.test( FID_INTERVAL ) ) {
        uint32_t ival = 0;
        cvt_number<uint32_t>( dec.mref[ FID_INTERVAL ], ival );
        n.hb_interval = ival;
        n.hb_mono_time = cur_mono;
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
        n.printf( "start time is not correct %" PRIu64 " != %" PRIu64 "\n",
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
      this->set_ucast_url( *n.user_route, dec, "auth" );
      this->set_mesh_url( *n.user_route, dec, "auth" );
    }
    this->push_source_route( n );
    UserRoute * primary = NULL;
    if ( stage == AUTH_FROM_HANDSHAKE )
      primary = n.user_route;
    this->add_inbox_route( n, primary );
    if ( primary != NULL )
      this->set_connected_user_route( n, *primary );
    n.bloom_uid =
      this->sub_db.uid_route.create_bloom_route( n.uid, &n.bloom, 0 );
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
    this->add_unknown_adjacency( &n, NULL );
  if ( ! this->adjacency_change.is_empty() ) {
    if ( stage != AUTH_FROM_HELLO ) /* stage 1, need stage 2 */
      this->send_adjacency_change();
  }
  if ( send_add )
    this->send_peer_add( n, &src->user_route->rte );
}

void
UserDB::remove_authenticated( UserBridge &n,  AuthStage bye ) noexcept
{
  size_t n_pos;
  bool   send_del = false;

  this->last_auth_mono = current_monotonic_time_ns();
  n.last_auth_type = bye;
  /*if ( debug_usr )*/
    n.printn( "remove auth %s %s\n", auth_stage_string( bye ),
               n.is_set( ZOMBIE_STATE ) ? "zombie" : "" );
  if ( n.test_clear( AUTHENTICATED_STATE ) ) {
    n.remove_auth_time = this->poll.now_ns;
    n.remove_auth_mono = this->last_auth_mono;
    this->events.auth_remove( n.uid, bye );
    this->uid_authenticated.remove( n.uid );
    this->uid_rtt.remove( n.uid );
    this->pop_source_route( n );
    if ( bye != BYE_HB_TIMEOUT && bye != BYE_PING )
      this->remove_adjacency( n );
    this->uid_auth_count--;
    this->sub_db.sub_update_mono_time = this->last_auth_mono;
    d_usr( "--- uid_auth_count=%u -%s\n", this->uid_auth_count,
            n.peer.user.val );
    this->uid_csum ^= n.bridge_id.nonce;
    /*printf( "--- uid_auth_count %u uid_csum ", this->uid_auth_count );
    this->uid_csum.print(); printf( "\n" );*/
    if ( bye != BYE_CONSOLE )
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
  if ( n.test_clear( MESH_REQUEST_STATE ) )
    this->mesh_queue.remove( &n );
  if ( n.test_clear( PING_STATE ) )
    this->ping_queue.remove( &n );
  n.ping_fail_count = 0;
  n.hb_seqno = 0;

  if ( this->ipc_transport != NULL &&
       n.bloom.has_link( this->ipc_transport->fd ) )
    this->ipc_transport->sub_route.do_notify_bloom_deref( n.bloom );
  n.bloom.unlink( false );
  uint32_t path_select = 0;
  for ( ; path_select < n.bloom_rt.count; path_select++ ) {
    if ( n.bloom_rt.ptr[ path_select ] != NULL ) {
      n.bloom_rt.ptr[ path_select ]->remove_if_empty();
      n.bloom_rt.ptr[ path_select ] = NULL;
    }
  }
  if ( n.bloom_uid != NULL ) {
    n.bloom_uid->remove_if_empty();
    n.bloom_uid = NULL;
  }
  n.bloom.zero();
  n.adjacency.reset();
  this->sub_db.update_sub_seqno( n.sub_seqno, 0 );
  this->update_link_state_seqno( n.link_state_seqno, 0 );
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

bool
UserDB::check_uid_csum( const UserBridge &n,  const Nonce &peer_csum ) noexcept
{
  if ( this->uid_csum == peer_csum )
    return true;

  Nonce check_csum = this->bridge_id.nonce;
  uint32_t count = 0;

  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    UserBridge *n2 = this->bridge_tab[ uid ];
    if ( n2 == NULL || ! n2->is_set( AUTHENTICATED_STATE ) )
      continue;
    check_csum ^= n2->bridge_id.nonce;
    count++;
  }
  char buf[ NONCE_B64_LEN + 1 ], buf2[ NONCE_B64_LEN + 1 ];
  n.printf( "uid_csum not equal my=[%s] hb[%s] uid_count=%u/%u check=%s\n",
            this->uid_csum.to_base64_str( buf ),
            peer_csum.to_base64_str( buf2 ), count, this->next_uid,
            ( check_csum == this->uid_csum ) ? "ok" : "incorrect" );

  if ( check_csum != this->uid_csum )
    this->uid_csum = check_csum;
  return this->uid_csum == peer_csum;
}

void
UserDB::set_ucast_url( UserRoute &u_rte,  const MsgHdrDecoder &dec,
                       const char *src ) noexcept
{
  /* check if url based point to point */
  if ( u_rte.hops() == 0 && dec.test( FID_UCAST_URL ) ) {
    uint32_t     url_len = (uint32_t) dec.mref[ FID_UCAST_URL ].fsize;
    const char * url     = (const char *) dec.mref[ FID_UCAST_URL ].fptr;
    if ( u_rte.set_ucast( *this, url, url_len, NULL ) ) {
      if ( debug_usr )
        u_rte.n.printf( "(%s) set_ucast_url(%s) %.*s (%s)\n",
          publish_type_to_string( dec.type ),
          u_rte.rte.name, url_len, url, src );
    }
  }
}

void
UserDB::set_ucast_url( UserRoute &u_rte,  const UserRoute *ucast_src,
                       const char *src ) noexcept
{
  if ( u_rte.set_ucast( *this, NULL, 0, ucast_src ) ) {
    if ( debug_usr )
      u_rte.n.printf( "set ucast thourgh %s (%s)\n", ucast_src != NULL ?
                      ucast_src->n.peer.user.val : "(null)", src );
  }
}

void
UserDB::set_ucast_url( UserRoute &u_rte,  const char *url,  size_t url_len,
                       const char *src ) noexcept
{
  if ( u_rte.set_ucast( *this, url, url_len, NULL ) ) {
    if ( debug_usr )
      u_rte.n.printf( "set_ucast_url(%s) %.*s (%s)\n",
        u_rte.rte.name, (int) url_len, url, src );
  }
}

void
UserDB::set_mesh_url( UserRoute &u_rte,  const MsgHdrDecoder &dec,
                      const char *src ) noexcept
{
  /* check if url based point to point */
  if ( dec.test( FID_MESH_URL ) ) {
    uint32_t     url_len = (uint32_t) dec.mref[ FID_MESH_URL ].fsize;
    const char * url     = (const char *) dec.mref[ FID_MESH_URL ].fptr;
    if ( u_rte.set_mesh( *this, url, url_len ) ) {
      if ( debug_usr )
        u_rte.n.printf( "(%s) set_mesh_url(%s) %.*s (%s)\n",
          publish_type_to_string( dec.type ),
          u_rte.rte.name, url_len, url, src );
    }
  }
}

void
UserDB::add_bloom_routes( UserBridge &n,  TransportRoute &rte ) noexcept
{
  BloomRoute *rt = rte.router_rt;
  if ( ! n.bloom.has_link( rt->r ) ) {
    rt->add_bloom_ref( &n.bloom );
    if ( rte.is_set( TPORT_IS_IPC ) )
      rte.sub_route.do_notify_bloom_ref( n.bloom );
  }
}

void
UserDB::add_transport( TransportRoute &rte ) noexcept
{
  this->peer_dist.invalidate( ADD_TRANSPORT_INV, 0 );

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
    if ( primary != inbox ||
         n.bloom_rt[ 0 ]->r != (uint32_t) primary->mcast.fd ) {
      if ( debug_usr || debug_ibx )
        n.printf( "del inbox route %.*s -> %u (%s)\n",
                  (int) ibx.len(), ibx.buf, inbox->inbox.fd, inbox->rte.name );
      /*if ( this->ipc_transport != NULL &&
           n.bloom.has_link( this->ipc_transport->fd ) )
        this->ipc_transport->sub_route.do_notify_bloom_deref( n.bloom );*/
      n.bloom_rt[ 0 ]->del_bloom_ref( &n.bloom );
      n.bloom_rt[ 0 ]->remove_if_empty();
      n.bloom_rt[ 0 ] = NULL;
      inbox->rte.sub_route.del_pattern_route_str( ibx.buf, (uint16_t) ibx.len(),
                                                  inbox->inbox.fd );
      inbox->clear( INBOX_ROUTE_STATE );
    }
  }
  if ( primary == NULL ) {
    n.printf( "add inbox no valid routes yet\n" );
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
    if ( debug_usr || debug_ibx )
      n.printf( "add inbox_route %.*s -> %u (%s) (bcast %u) (%s)\n",
              (int) ibx.len(), ibx.buf, primary->inbox.fd,
              primary->ucast_url.len == 0 ? "ptp" : primary->ucast_url.val,
              primary->mcast.fd, primary->rte.name );
    if ( ! primary->is_set( IN_ROUTE_LIST_STATE ) )
      this->push_user_route( n, *primary );
    if ( n.bloom_rt[ 0 ] != NULL ) {
      n.bloom_rt[ 0 ]->del_bloom_ref( &n.bloom );
      n.bloom_rt[ 0 ]->remove_if_empty();
      n.bloom_rt[ 0 ] = NULL;
    }
    n.bloom_rt[ 0 ] = primary->rte.sub_route.create_bloom_route(
                                               primary->mcast.fd, &n.bloom, 0 );
    /*this->check_bloom_route2();*/
    primary->rte.sub_route.do_notify_bloom_ref( n.bloom );
    primary->rte.sub_route.add_pattern_route_str( ibx.buf, (uint16_t) ibx.len(),
                                                  primary->inbox.fd );
  }
  /* already routing */
  else {
    if ( debug_usr )
      n.printf( "inbox exists %.*s -> %u (%s) (bcast %u) (%s)\n",
              (int) ibx.len(), ibx.buf, primary->inbox.fd,
              primary->ucast_url.len == 0 ? "ptp" : primary->ucast_url.val,
              primary->mcast.fd, primary->rte.name );
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
      n.printf( "remove_inbox_route %.*s -> %u (%s) (bcast %u) (%s)\n",
              (int) ibx.len(), ibx.buf, u_ptr->inbox.fd,
              u_ptr->ucast_url.len == 0 ? "ptp" : u_ptr->ucast_url.val,
              u_ptr->mcast.fd, u_ptr->rte.name );
    u_ptr->rte.sub_route.del_pattern_route_str( ibx.buf, (uint16_t) ibx.len(),
                                                u_ptr->inbox.fd );
  }
  if ( n.test_clear( INBOX_ROUTE_STATE ) ) {
    uint32_t seed = u_ptr->rte.sub_route.prefix_seed( ibx.len() ),
             hash = kv_crc_c( ibx.buf, ibx.len(), seed );
    n.bloom.del_route( (uint16_t) ibx.len(), hash );
  }
}

bool
UserDB::write_hostid_cache( void ) noexcept
{
  ConfigJson   cache;
  JsonObject * ar = NULL;
  uint32_t     hid, uid;
  size_t       pos;

  if ( this->host_ht == NULL ) {
    JsonValue * id = cache.make_hostid( this->host_id );
    cache.push_field( ar, this->user.user, id );
  }
  else {
    for ( bool b = this->host_ht->first( pos ); b;
          b = this->host_ht->next( pos ) ) {
      this->host_ht->get( pos, hid, uid );
      JsonValue * id = cache.make_hostid( hid );
      if ( uid == 0 )
        cache.push_field( ar, this->user.user, id );
      else {
        UserBridge * n = this->bridge_tab.ptr[ uid ];
        if ( n != NULL )
          cache.push_field( ar, n->peer.user, id );
      }
    }
  }
  const char * d;
  if ( (d = ::getenv( "TMP" )) == NULL &&
       (d = ::getenv( "TEMP" )) == NULL ) {
    d = "/tmp";
  }
  size_t l = ::strlen( d );
  CatMalloc npath( l + 7 + this->user.user.len + 9 + 1 ),
            opath( l + 7 + this->user.user.len + 5 + 1 );
  npath.x( d, l ).x( "/raims_", 7 )
       .x( this->user.user.val, this->user.user.len )
       .x( ".yaml.new", 9 ).end();
  opath.x( d, l ).x( "/raims_", 7 )
       .x( this->user.user.val, this->user.user.len )
       .x( ".yaml", 5 ).end();
  ConfigFilePrinter out;
  if ( out.open_file( npath.start ) == 0 ) {
    ar->print_yaml( &out );
    out.close();
#if defined( _MSC_VER ) || defined( __MINGW32__ )
    os_unlink( opath.start );
#endif
    if ( os_rename( npath.start, opath.start ) == 0 ) {
      printf( "saved host_id %08x (%s)\n",
               (uint32_t) ntohl( this->host_id ), opath.start );
      return true;
    }
    perror( opath.start );
    return false;
  }
  perror( npath.start );
  return false;
}

bool
UserDB::read_hostid_cache( void ) noexcept
{
  const char * d;
  if ( (d = ::getenv( "TMP" )) == NULL &&
       (d = ::getenv( "TEMP" )) == NULL ) {
    d = "/tmp";
  }
  size_t l = ::strlen( d );
  CatMalloc opath( l + 7 + this->user.user.len + 5 + 1 );
  opath.x( d, l ).x( "/raims_", 7 )
       .x( this->user.user.val, this->user.user.len )
       .x( ".yaml", 5 ).end();

  MDMsgMem   mem;
  JsonMsgCtx ctx;
  MapFile    map( opath.start );
  os_stat    st;
  int        status;

  status = os_fstat( opath.start, &st );
  if ( status < 0 || st.st_size == 0 )
    return false;
  /* recursion check */
  if ( ! map.open() ) {
    perror( opath.start );
    return false;
  }
  status = ctx.parse( (char *) map.map, 0, map.map_size, NULL, mem, true );
  if ( status != 0 ) {
    fprintf( stderr, "JSON parse error in \"%s\", status %d/%s\n", opath.start,
             status, Err::err( status )->descr );
    if ( ctx.input != NULL ) {
      fprintf( stderr, "line %u col %u\n", (uint32_t) ctx.input->line_count,
               (uint32_t) ( ctx.input->offset - ctx.input->line_start + 1 ) );
    }
    return false;
  }
  MDFieldIter * iter;
  if ( (status = ctx.msg->get_field_iter( iter )) == 0 ) {
    if ( (status = iter->first()) == 0 ) {
      do {
        MDName nm;
        MDReference mref;
        if ( iter->get_name( nm ) != 0 )
          break;
        if ( nm.fnamelen != this->user.user.len + 1 ||
           ::memcmp( nm.fname, this->user.user.val, this->user.user.len ) != 0 )
          continue;
        if ( iter->get_reference( mref ) != 0 )
          break;
        const uint8_t * ptr = mref.fptr,
                      * end = &ptr[ mref.fsize ];
        char sbuf[ 32 ];
        size_t slen = sizeof( sbuf );
        if ( mref.ftype != MD_STRING ) {
          if ( to_string( mref, sbuf, slen ) == 0 ) {
            ptr = (uint8_t *) sbuf;
            end = &((uint8_t *) sbuf)[ slen ];
          }
        }
        #define hex( c ) ( c >= '0' && c <= '9' ) ? ( c - '0' ): \
                         ( c >= 'A' && c <= 'F' ) ? ( c - 'A' + 10 ) : \
                         ( c >= 'a' && c <= 'f' ) ? ( c - 'a' + 10 ) : 16
        uint32_t h = 0, a, b;
        while ( ptr < end && *ptr <= ' ' )
          ptr++;
        for ( int i = 3; ; ) {
          if ( &ptr[ i*2+1 ] >= end )
            break;
          h = ( h << 4 ) | (a = hex( ptr[ i*2 ] ));
          h = ( h << 4 ) | (b = hex( ptr[ i*2+1 ] ));
          if ( ( a | b ) == 16 )
            break;
          if ( --i == -1 ) {
            this->host_id = h;
            printf( "loaded host_id %08x (%s)\n",
                     (uint32_t) ntohl( h ), opath.start );
            return true;
          }
        }
        #undef hex
      } while ( (status = iter->next()) == 0 );
    }
  }
  return false;
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
    if ( off >= buflen )
      break;
  }
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
    s = cat( s, "rl", s > buf );
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

