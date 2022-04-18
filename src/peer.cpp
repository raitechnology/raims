#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raims/user_db.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

static inline bool
get_bridge_nonce( Nonce &b_nonce,  const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.test( FID_SESSION ) ) {
    b_nonce.copy_from(
      &((uint8_t *) dec.mref[ FID_SESSION ].fptr)[ HMAC_SIZE ] );
    return true;
  }
  if ( dec.test( FID_SYNC_BRIDGE ) ) {
    b_nonce.copy_from( dec.mref[ FID_SYNC_BRIDGE ].fptr );
    return true;
  }
  return false;
}

void
UserDB::make_peer_sync_msg( UserBridge &dest,  UserBridge &n,
                            const char *sub,  size_t sublen,  uint32_t h,
                            MsgCat &m,  uint32_t hops,  bool in_mesh/*,
                            TransportRoute &rte*/ ) noexcept
{
  size_t user_len      = n.peer.user.len,
         svc_len       = n.peer.svc.len,
         create_len    = n.peer.create.len,
         expires_len   = n.peer.expires.len,
         ucast_url_len = n.user_route->ucast_url_len,
         mesh_url_len  = n.user_route->mesh_url_len/*,
         mesh_db_len   = ( in_mesh ? this->mesh_db_size( rte ) : 0 )*/;
  BloomCodec code;
  n.bloom.encode( code );

  HashDigest tmp_ha1, encrypted_ha1;
  Nonce      cnonce = this->cnonce->calc();
  this->get_peer_key( MY_UID, n.uid, tmp_ha1 );
  encrypted_ha1.encrypt_key_nonce( tmp_ha1, cnonce, n.peer_key );

  MsgEst e( sublen );
  e.seqno     ()
   .time      ()
   .session   ()
   .sess_key  ()
   .cnonce    ()
   .hops      ()
   .uptime    ()
   .start     ()
   .interval  ()
   .user      ( user_len       )
   .service   ( svc_len        )
   .create    ( create_len     )
   .expires   ( expires_len    )
   .sub_seqno ()
   .link_state()
   .bloom     ( code.code_sz * 4 )
   .ucast_url ( ucast_url_len )
   .mesh_url  ( mesh_url_len )
   .adjacency ( this->adjacency_size( &n ) );
   /*.mesh_db   ( mesh_db_len );*/

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .seqno     ( ++dest.send_inbox_seqno )
   .time      ( n.hb_time  )
   .session   ( n.bridge_id.hmac, n.bridge_id.nonce )
   .sess_key  ( encrypted_ha1 )
   .cnonce    ( cnonce        )
   .hops      ( hops          )
   .uptime    ( n.uptime()    )
   .start     ( n.start_time  )
   .interval  ( n.hb_interval )
   .user      ( n.peer.user.val   , user_len       )
   .service   ( n.peer.svc.val    , svc_len        )
   .create    ( n.peer.create.val , create_len     )
   .expires   ( n.peer.expires.val, expires_len    )
   .sub_seqno ( n.sub_seqno   )
   .link_state( n.link_state_seqno )
   .bloom     ( code.ptr       , code.code_sz * 4 );
  if ( ucast_url_len != 0 && hops == 0 )
    m.ucast_url( n.user_route->ucast_url, ucast_url_len );
  if ( mesh_url_len != 0 && in_mesh )
    m.mesh_url( n.user_route->mesh_url, mesh_url_len );
  this->adjacency_submsg( &n, m );
  /*if ( mesh_db_len != 0 && in_mesh )
    this->mesh_db_submsg( rte, m );*/
  m.close( e.sz, h, CABA_INBOX );
  m.sign( sub, sublen, *this->session_key );
}

bool
UserDB::recv_sync_request( const MsgFramePublish &pub,  UserBridge &n,
                           const MsgHdrDecoder &dec ) noexcept
{
  Nonce        b_nonce;
  UserBridge * user_n;
  size_t       n_pos;
  uint32_t     uid = 0;
  
  if ( ! get_bridge_nonce( b_nonce, dec ) )
    return true;
  d_peer( "sync request %.*s\n", (int) pub.subject_len, pub.subject );
  /* XXX zombie state ? */
  if ( this->node_ht->find( b_nonce, n_pos, uid ) ) {
    user_n = this->bridge_tab[ uid ];
    if ( user_n != NULL ) {
      MsgCat   m;
      InboxBuf ibx( n.bridge_id, _SYNC_RPY );
      uint32_t hops    = 1;
      bool     in_mesh = pub.rte.uid_in_mesh->is_member( uid );
      if ( pub.rte.uid_connected.is_member( n.uid ) ) { /* if both connected */
        if ( pub.rte.uid_connected.is_member( uid ) )
          hops = 0;
      }
      if ( hops == 1 )
        in_mesh = false;
      this->events.recv_sync_req( n.uid, pub.rte.tport_id, uid, hops );
      uint32_t h = ibx.hash();
      this->make_peer_sync_msg( n, *user_n, ibx.buf, ibx.len(), h, m,
                                hops, in_mesh );
      if ( debug_peer )
        printf(
            "forward b_nonce: %.*s to %s.%u for %s.%u hops=%u, in_mesh=%u\n",
            (int) ibx.len(), ibx.buf, n.peer.user.val, n.uid,
            user_n->peer.user.val, uid, hops, in_mesh?1:0 );
      return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
    }
  }
  StringVal user_sv;
  if ( dec.test( FID_USER ) ) {
    const char * user     = (const char *) dec.mref[ FID_USER ].fptr;
    uint32_t     user_len = (uint32_t) dec.mref[ FID_USER ].fsize;
    this->string_tab.ref_string( user, user_len, user_sv );
  }
  this->events.recv_sync_fail( n.uid, pub.rte.tport_id, user_sv.id );
  char buf[ NONCE_B64_LEN + 1 ];
  n.printf( "sync_request(user=%.*s), b_nonce not found: [%s]\n",
            user_sv.len, user_sv.val, b_nonce.to_base64_str( buf ) );
  return true;
}

void
UserDB::get_peer_key2( uint32_t src_uid,  const Nonce &dest_nonce,
                       HashDigest &hash ) noexcept
{
  HashDigest * src_ha1;
  Nonce      * src_nonce;

  if ( src_uid == MY_UID ) {
    src_ha1   = this->session_key;
    src_nonce = &this->bridge_id.nonce;
  }
  else {
    src_ha1   = &this->bridge_tab[ src_uid ]->peer_key;
    src_nonce = &this->bridge_tab[ src_uid ]->bridge_id.nonce;
  }
  hash.kdf_peer_nonce( *src_ha1, *src_nonce, dest_nonce );
}

void
UserDB::get_peer_key( uint32_t src_uid,  uint32_t dest_uid,
                      HashDigest &hash ) noexcept
{
  PeerKeyHash h( src_uid, dest_uid );
  size_t      pos;
  uint32_t    off;
  if ( this->peer_key_ht->find( h, pos, off ) ) {
    hash.copy_from( &this->peer_keys->cache[ off ] );
  }
  else {
    this->get_peer_key2( src_uid, this->bridge_tab[ dest_uid ]->bridge_id.nonce,
                         hash );
    off = this->peer_keys->new_key();
    if ( off == 0 ) {
      this->peer_key_ht->clear_all();
      this->peer_key_ht->upsert_rsz( this->peer_key_ht, h, off );
    }
    else {
      this->peer_key_ht->set_rsz( this->peer_key_ht, h, pos, off );
    }
    hash.copy_to( &this->peer_keys->cache[ off ] );
  }
}
/* decode msg which contains an encrypted peer key */
bool
UserDB::decode_peer_msg( UserBridge &from_n,  const MsgHdrDecoder &dec,
                         UserNonce &sync_bridge_id,  HashDigest &ha1,
                         UserBridge *&user_n,  UserBuf *user,
                         /*uint8_t *pub_der,  size_t &pub_sz,*/
                         uint64_t &start ) noexcept
{
  HashDigest     sess_key,
                 tmp_ha1;
  Nonce          cnonce;
  PolyHmacDigest hmac;
  uint64_t       time = 0,
                 seqno = 0;
  size_t         n_pos;
  uint32_t       uid;

  if ( ! dec.test_6( FID_SESSION, FID_SEQNO, FID_TIME, FID_SESS_KEY,
                     FID_CNONCE, FID_START ) )
    return false;

  sync_bridge_id.copy_from( dec.mref[ FID_SESSION ].fptr );
  if ( user_n == NULL ) {
    if ( this->node_ht->find( sync_bridge_id.nonce, n_pos, uid ) ||
         this->zombie_ht->find( sync_bridge_id.nonce, n_pos, uid ) ) {
      user_n = this->bridge_tab[ uid ];
      if ( user_n == NULL ) {
        if ( uid == MY_UID ) {
          fprintf( stderr, "My uid in peer add\n" );
          return false;
        }
        fprintf( stderr, "Peer is null\n" );
      }
    }
  }
  sess_key.copy_from( dec.mref[ FID_SESS_KEY ].fptr );
  cnonce.copy_from( dec.mref[ FID_CNONCE ].fptr );
  cvt_number<uint64_t>( dec.mref[ FID_TIME ], time );
  cvt_number<uint64_t>( dec.mref[ FID_SEQNO ], seqno );
  cvt_number<uint64_t>( dec.mref[ FID_START ], start );

  this->get_peer_key2( from_n.uid, sync_bridge_id.nonce, tmp_ha1 );
  ha1.decrypt_key_nonce( tmp_ha1, cnonce, sess_key );
  /*printf( "ha1 decrypt: " ); ha1.print(); printf( "\n" );*/
  if ( user_n != NULL && user_n->is_set( AUTHENTICATED_STATE | ZOMBIE_STATE ) ) {
    if ( user_n->peer_key != ha1 ) {
      fprintf( stderr, "peer_key doesn't match\n" );
      return false;
    }
  }
  if ( ! dec.test_4( FID_USER, FID_SERVICE, FID_CREATE, FID_EXPIRES/*,
                     FID_PUB_KEY*/ ) ) {
    fprintf( stderr, "fid missing\n" );
    return false;
  }
  copy_max( user->user, user->user_len, MAX_USER_LEN,
           dec.mref[ FID_USER ].fptr, dec.mref[ FID_USER ].fsize );
  copy_max( user->service, user->service_len, MAX_SERVICE_LEN,
           dec.mref[ FID_SERVICE ].fptr, dec.mref[ FID_SERVICE ].fsize );
  copy_max( user->create, user->create_len, MAX_TIME_LEN,
           dec.mref[ FID_CREATE ].fptr, dec.mref[ FID_CREATE ].fsize );
  copy_max( user->expires, user->expires_len, MAX_TIME_LEN,
           dec.mref[ FID_EXPIRES ].fptr, dec.mref[ FID_EXPIRES ].fsize );
  return true;
}
/* recv a peer key */
UserBridge *
UserDB::make_peer_session( const MsgFramePublish &pub,  UserBridge &from_n,
                           const MsgHdrDecoder &dec,
                           UserBridge *user_n ) noexcept
{
  UserNonce  sync_bridge_id;
  HashDigest peer_key;
  UserBuf    user;
  uint64_t   start = 0;
  
  if ( this->decode_peer_msg( from_n, dec, sync_bridge_id, peer_key, user_n,
                              &user, start ) ) {
    /* if peer not in db, add one */
    if ( user_n == NULL ) {
      PeerEntry * peer;
      size_t      p_pos;
      uint32_t    pid;
      if ( ! this->peer_ht->find( sync_bridge_id.hmac, p_pos, pid ) ) {
        /* new peer */
        pid  = (uint32_t) this->peer_db.count;
        StringVal user_sv, svc_sv, create_sv, expires_sv;
        this->string_tab.ref_string( user.user, user.user_len, user_sv );
        this->string_tab.ref_string( user.service, user.service_len, svc_sv );
        this->string_tab.ref_string( user.create, user.create_len, create_sv );
        this->string_tab.ref_string( user.expires, user.expires_len,
                                     expires_sv );
        peer = this->make_peer( user_sv, svc_sv, create_sv, expires_sv );
        this->peer_db[ pid ] = peer;
        peer->hmac = sync_bridge_id.hmac;

        this->peer_ht->upsert_rsz( this->peer_ht, peer->hmac, pid );
      }
      else {
        peer = this->peer_db[ pid ];
      }
      TransportRoute & rte = from_n.user_route->rte;
      user_n = this->add_user( rte, from_n.user_route, pub.src_route,
                               sync_bridge_id, *peer, dec );
    }
    user_n->peer_key = peer_key;
    user_n->start_time = start;
  }
  peer_key.zero();
  return user_n;
}

struct PeerDBRec : public MsgFldSet {
  Nonce        nonce;
  const char * ucast_url,
             * mesh_url,
             * user;
  uint32_t     ucast_url_len,
               mesh_url_len,
               user_len,
               hops;
  uint64_t     sub_seqno,
               link_state;
  PeerDBRec  * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  PeerDBRec() : ucast_url( 0 ), mesh_url( 0 ), user( 0 ),
                ucast_url_len( 0 ), mesh_url_len( 0 ), user_len( 0 ),
                hops( 0 ), sub_seqno( 0 ), link_state( 0 ), next( 0 ) {
    this->nonce.zero();
  }
  void set_field( uint32_t fid,  MDReference &mref ) {
    switch ( fid ) {
      case FID_BRIDGE:
        this->nonce.copy_from( mref.fptr );
        break;
      case FID_USER:
        this->user     = (const char *) mref.fptr;
        this->user_len = (uint32_t) mref.fsize;
        break;
      case FID_HOPS:
        cvt_number<uint32_t>( mref, this->hops );
        break;
      case FID_SUB_SEQNO:
        cvt_number<uint64_t>( mref, this->sub_seqno );
        break;
      case FID_LINK_STATE:
        cvt_number<uint64_t>( mref, this->link_state );
        break;
      case FID_UCAST_URL:
        this->ucast_url     = (const char *) mref.fptr;
        this->ucast_url_len = (uint32_t) mref.fsize;
        break;
      case FID_MESH_URL:
        this->mesh_url     = (const char *) mref.fptr;
        this->mesh_url_len = (uint32_t) mref.fsize;
        break;
      default:
        break;
    }
  }
  void print( void ) const {
    char buf[ NONCE_B64_LEN + 1 ];
    printf( "  nonce[%s] user[%.*s] hops[%u] sub[%" PRIu64 "] link[%" PRIu64 "] ucast[%.*s] mesh[%.*s]\n",
            this->nonce.to_base64_str( buf ),
            this->user_len, this->user,
            this->hops, this->sub_seqno, this->link_state,
            this->ucast_url_len, this->ucast_url,
            this->mesh_url_len, this->mesh_url );
  }
  static void print_rec_list( const PeerDBRec *rec_list,
                              UserBridge &n ) noexcept {
    n.printf( "peer_db (%s):\n", n.user_route->rte.transport.tport.val );
    for ( const PeerDBRec *r = rec_list; r != NULL; r = r->next ) {
      r->print();
    }
  }
};

bool
UserDB::recv_peer_db( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec,  AuthStage stage ) noexcept
{
  PeerDBRec * rec_list = dec.decode_rec_list<PeerDBRec>( FID_PEER_DB );

  this->events.recv_peer_db( n.uid, pub.rte.tport_id, stage );
  if ( debug_peer )
    PeerDBRec::print_rec_list( rec_list, n );

  while ( rec_list != NULL ) {
    PeerDBRec  & rec = *rec_list;
    UserBridge * user_n = NULL;
    size_t       n_pos;
    uint32_t     uid;
    bool         updated_mesh = false;
    rec_list = rec.next;
    if ( this->node_ht->find( rec.nonce, n_pos, uid ) ||
         this->zombie_ht->find( rec.nonce, n_pos, uid ) ) {
      if ( uid == MY_UID )
        continue;
      user_n = this->bridge_tab[ uid ];
    }
    if ( user_n == NULL || ! user_n->is_set( AUTHENTICATED_STATE ) ) {
      StringVal user_sv;
      this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
      this->start_pending_peer( rec.nonce, n, false, user_sv, PEER_DB_SYNC );
    }
    else {
      if ( user_n->link_state_seqno < rec.link_state ||
           user_n->sub_seqno < rec.sub_seqno ) {
        this->send_adjacency_request2( n, *user_n, PEERDB_SYNC_REQ );
      }
      if ( rec.mesh_url_len != 0 ) {
        UserRoute * u_ptr   = user_n->user_route_ptr( *this, pub.rte.tport_id );
        if ( u_ptr->is_valid() ) {
          if ( debug_peer )
            user_n->printf( "peer_add mesh_url: %.*s\n", (int) rec.mesh_url_len,
                            rec.mesh_url );
          u_ptr->set_mesh( *this, rec.mesh_url, rec.mesh_url_len );
          updated_mesh = true;
        }
      }
    }
    if ( ! updated_mesh && rec.mesh_url_len != 0 ) {
      this->direct_pending.update( pub.rte, rec.mesh_url, rec.mesh_url_len,
                                   0, rec.nonce );
    }
  }
  return true;
}

bool
UserDB::make_peer_db_msg( UserBridge &n,  const char *sub,  size_t sublen,
                          uint32_t h,  MsgCat &m ) noexcept
{
  UserRoute  * u_ptr = n.user_route,
             * u_ptr2;
  UserBridge * n2;
  uint32_t     uid,
               tport_id = u_ptr->rte.tport_id,
               count = 0;
  MsgEst pdb;
  if ( this->uid_authenticated.first( uid ) ) {
    do {
      if ( uid != n.uid ) {
        if ( (n2 = this->bridge_tab[ uid ]) != NULL ) {
          u_ptr2 = n2->user_route_ptr( *this, tport_id );
          pdb.bridge2   ()
             .user      ( n2->peer.user.len )
             .hops      ()
             .sub_seqno ()
             .link_state();
          if ( u_ptr2->is_valid() )
            pdb.ucast_url( u_ptr2->ucast_url_len )
               .mesh_url ( u_ptr2->mesh_url_len  );
          count++;
        }
      }
    } while ( this->uid_authenticated.next( uid ) );
  }
  if ( count == 0 )
    return false;

  MsgEst e( sublen );
  e.seqno()
   .peer_db( pdb.sz );

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .seqno( ++n.send_inbox_seqno   );

  SubMsgBuf submsg( m );
  submsg.open_submsg();

  if ( this->uid_authenticated.first( uid ) ) {
    do {
      if ( uid != n.uid ) {
        if ( (n2 = this->bridge_tab[ uid ]) != NULL ) {
          bool     in_mesh = u_ptr->rte.uid_in_mesh->is_member( uid );
          uint32_t hops    = u_ptr->rte.uid_connected.is_member( uid ) ? 0:1;

          submsg.bridge2   ( n2->bridge_id.nonce )
                .user      ( n2->peer.user.val, n2->peer.user.len )
                .hops      ( hops                 )
                .sub_seqno ( n2->sub_seqno        )
                .link_state( n2->link_state_seqno );

          u_ptr2 = n2->user_route_ptr( *this, tport_id );
          if ( u_ptr2->is_valid() ) {
            if ( u_ptr2->ucast_url_len != 0 && hops == 0 )
              submsg.ucast_url( u_ptr2->ucast_url, u_ptr2->ucast_url_len );
            if ( u_ptr2->mesh_url_len != 0 && in_mesh )
              submsg.mesh_url( u_ptr2->mesh_url, u_ptr2->mesh_url_len );
          }
        }
      }
    } while ( this->uid_authenticated.next( uid ) );
  }

  submsg.close( m, FID_PEER_DB );
  m.close( e.sz, h, CABA_INBOX );
  m.sign( sub, sublen, *this->session_key );
  return true;
}

void
UserDB::send_peer_db( UserBridge &n ) noexcept
{
  MsgCat   m;
  InboxBuf ibx( n.bridge_id, _ADD_RTE );

  uint32_t h = ibx.hash();
  if ( this->make_peer_db_msg( n, ibx.buf, ibx.len(), h, m ) )
    this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}

bool
UserDB::recv_peer_add( const MsgFramePublish &pub,  UserBridge &n,
                       MsgHdrDecoder &dec,  AuthStage stage ) noexcept
{
  Nonce        b_nonce;
  size_t       n_pos;
  UserBridge * user_n = NULL;
  StringVal    user_sv;
  uint32_t     uid;

  if ( ! n.is_set( AUTHENTICATED_STATE ) )
    return true;
  if ( dec.test( FID_PEER_DB ) )
    return this->recv_peer_db( pub, n, dec, stage );
  if ( ! get_bridge_nonce( b_nonce, dec ) )
    return true;

  if ( this->node_ht->find( b_nonce, n_pos, uid ) ||
       this->zombie_ht->find( b_nonce, n_pos, uid ) ) {
    if ( uid == MY_UID )
      return true;
    user_n = this->bridge_tab[ uid ];
  }
  if ( dec.test( FID_SESS_KEY ) &&
       ( user_n == NULL || ! user_n->is_set( AUTHENTICATED_STATE ) ) )
    user_n = this->make_peer_session( pub, n, dec, user_n );
  if ( dec.test( FID_USER ) ) {
    const char * user     = (const char *) dec.mref[ FID_USER ].fptr;
    uint32_t     user_len = (uint32_t) dec.mref[ FID_USER ].fsize;
    this->string_tab.ref_string( user, user_len, user_sv );
  }
  this->events.recv_peer_add( n.uid, pub.rte.tport_id,
                           ( user_n == NULL ? UserRoute::NO_RTE : user_n->uid ),
                              stage, user_sv.id );

  if ( user_n == NULL || ! user_n->is_set( AUTHENTICATED_STATE ) ) {
    if ( user_n != NULL && user_n->is_set( ZOMBIE_STATE ) ) {
      if ( debug_peer )
        n.printf( "%.*s reanimate zombie user %s from %s\n",
                  (int) pub.subject_len, pub.subject,
                  user_n->peer.user.val, n.peer.user.val );
      this->add_user_route( *user_n, pub.rte, pub.src_route, dec,
                            n.user_route_ptr( *this, pub.rte.tport_id ) );
      this->add_authenticated( *user_n, dec, stage, &n );
    }
    else if ( user_n != NULL && dec.test( FID_SESS_KEY ) ) {
      if ( debug_peer )
        n.printf( "%.*s add_auth user %s from %s\n", (int) pub.subject_len,
                  pub.subject, user_n==NULL ? "unknown" : user_n->peer.user.val,
                  n.peer.user.val );
      this->add_authenticated( *user_n, dec, stage, &n );
    }
    if ( user_n == NULL || ! user_n->is_set( AUTHENTICATED_STATE ) ) {
      if ( debug_peer )
        n.printf( "%.*s start_pending user %s from %s\n",
            (int) pub.subject_len, pub.subject,
            user_n==NULL ? "unknown" : user_n->peer.user.val, n.peer.user.val );
      return this->start_pending_peer( b_nonce, n, false, user_sv,
                                       PEER_ADD_SYNC );
    }
  }

  if ( dec.test_2( FID_ADJACENCY, FID_LINK_STATE ) ||
       dec.test_2( FID_BLOOM, FID_SUB_SEQNO ) )
    this->recv_adjacency_result( pub, *user_n, dec );

  if ( dec.test( FID_MESH_URL ) ) {
    size_t       url_len = dec.mref[ FID_MESH_URL ].fsize;
    const char * url     = (const char *) dec.mref[ FID_MESH_URL ].fptr;
    UserRoute  * u_ptr   = user_n->user_route_ptr( *this, pub.rte.tport_id );
    if ( u_ptr->is_valid() ) {
      if ( debug_peer )
        user_n->printf( "peer_add mesh_url: %.*s\n", (int) url_len, url );
      this->set_mesh_url( *u_ptr, dec );
    }
    else {
      if ( debug_peer )
        user_n->printf( "peer_add not valid route mesh_url %.*s from %s @ %s\n",
          (int) url_len, url, n.peer.user.val, pub.rte.name );
      this->add_user_route( *user_n, pub.rte, pub.src_route, dec, NULL );
    }
  }
  /*if ( dec.test( FID_MESH_DB ) ) {
    this->recv_mesh_db( pub, n, dec );
  }*/
  return true;
}

bool
UserDB::recv_add_route( const MsgFramePublish &pub,  UserBridge &n,
                        MsgHdrDecoder &dec ) noexcept
{
  d_peer( "recv route %.*s\n", (int) pub.subject_len, pub.subject );
  return this->recv_peer_add( pub, n, dec, AUTH_FROM_ADD_ROUTE );
}


bool
UserDB::recv_sync_result( const MsgFramePublish &pub,  UserBridge &n,
                          MsgHdrDecoder &dec ) noexcept
{
  d_peer( "sync result %.*s\n", (int) pub.subject_len, pub.subject );
  return this->recv_peer_add( pub, n, dec, AUTH_FROM_SYNC_RESULT );
}

void
UserDB::make_peer_add_msg( UserBridge &n,  const char *sub,  size_t sublen,
                           uint32_t h,  MsgCat &m,  uint32_t hops,
                           bool in_mesh ) noexcept
{
  size_t ucast_url_len = n.user_route->ucast_url_len,
         mesh_url_len  = n.user_route->mesh_url_len,
         user_len      = n.peer.user.len;

  MsgEst e( sublen );
  e.seqno      ()
   .time       ()
   .sync_bridge()
   .user       ( user_len )
   .hops       ()
   .sub_seqno  ()
   .link_state ()
   .ucast_url  ( ucast_url_len )
   .mesh_url   ( mesh_url_len );

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .seqno      ( ++this->send_peer_seqno )
   .time       ( n.hb_time  )
   .sync_bridge( n.bridge_id.nonce )
   .user       ( n.peer.user.val, user_len )  /* for information */
   .hops       ( hops               )
   .sub_seqno  ( n.sub_seqno        )
   .link_state ( n.link_state_seqno );

  if ( ucast_url_len != 0 && hops == 0 )
    m.ucast_url( n.user_route->ucast_url, ucast_url_len );
  if ( mesh_url_len != 0 && in_mesh )
    m.mesh_url( n.user_route->mesh_url, mesh_url_len );

  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( sub, sublen, *this->session_key );
}

void
UserDB::send_peer_add( UserBridge &n ) noexcept
{
  size_t count = this->transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * rte = this->transport_tab.ptr[ i ];
    d_peer( "send Z_ADD for %s via %s, connect %u\n",
            n.peer.user.val, rte->transport.tport.val, rte->connect_count );
    if ( rte->connect_count > 0 ) {
      MsgCat m;
      uint32_t hops = 0;
      bool     in_mesh = rte->uid_in_mesh->is_member( n.uid );
      if ( ! rte->uid_connected.is_member( n.uid ) ) {
        hops = 1;
        in_mesh = false;
      }
      this->events.send_add_route( n.uid, (uint32_t) i, hops );
      this->make_peer_add_msg( n, Z_ADD, Z_ADD_SZ, add_h, m, hops, in_mesh );
      EvPublish pub( Z_ADD, Z_ADD_SZ, NULL, 0, m.msg, m.len(),
                     rte->sub_route, this->my_src_fd, add_h,
                     CABA_TYPE_ID, 'p' );
      rte->forward_to_connected_auth( pub );
    }
  }
}

void
UserDB::forward_peer_add( UserBridge &n,
                          const TransportRoute &except_rte ) noexcept
{
  size_t count = this->transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * rte = this->transport_tab.ptr[ i ];
    if ( rte != &except_rte ) {
      d_peer( "send Z_ADD for %s via %s, connect %u\n",
              n.peer.user.val, rte->transport.tport.val, rte->connect_count );
      if ( rte->connect_count > 0 ) {
        MsgCat m;
        uint32_t hops = 0;
        bool     in_mesh = rte->uid_in_mesh->is_member( n.uid );
        if ( ! rte->uid_connected.is_member( n.uid ) ) {
          hops = 1;
          in_mesh = false;
        }
        this->events.send_add_route( n.uid, (uint32_t) i, hops );
        this->make_peer_add_msg( n, Z_ADD, Z_ADD_SZ, add_h, m, hops, in_mesh );
        EvPublish pub( Z_ADD, Z_ADD_SZ, NULL, 0, m.msg, m.len(),
                       rte->sub_route, this->my_src_fd, add_h,
                       CABA_TYPE_ID, 'p' );
        rte->forward_to_connected_auth( pub );
      }
    }
  }
}

/* construct msg that encrypts a peers key for distribution */
void
UserDB::make_peer_del_msg( UserBridge &n,  const char *sub,  size_t sublen,
                           uint32_t h,  MsgCat &m ) noexcept
{
  size_t user_len = n.peer.user.len;

  MsgEst e( sublen );
  e.seqno      ()
   .time       ()
   .sync_bridge()
   .user       ( user_len ); /* for information */

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .seqno      ( ++this->send_peer_seqno )
   .time       ( n.hb_time )
   .sync_bridge( n.bridge_id.nonce )
   .user       ( n.peer.user.val, user_len ); /* for information */

  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( sub, sublen, *this->session_key );
}

void
UserDB::send_peer_del( UserBridge &n ) noexcept
{
  size_t count = this->transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 ) {
      MsgCat m;
      if ( debug_peer )
        printf( "send Z_DEL(%" PRIu64 ") for %s via %s, connect=%u\n",
                this->send_peer_seqno, n.peer.user.val,
                rte->transport.tport.val, rte->connect_count );
      this->events.send_peer_delete( n.uid, (uint32_t) i );
      this->make_peer_del_msg( n, Z_DEL, Z_DEL_SZ, del_h, m );
      EvPublish pub( Z_DEL, Z_DEL_SZ, NULL, 0, m.msg, m.len(),
                     rte->sub_route, this->my_src_fd, del_h,
                     CABA_TYPE_ID, 'p' );
      rte->forward_to_connected_auth( pub );
    }
  }
}

bool
UserDB::recv_peer_del( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec ) noexcept
{
  Nonce        b_nonce;
  size_t       n_pos;
  UserBridge * user_n = NULL;
  uint32_t     uid    = 0;
  
  if ( ! get_bridge_nonce( b_nonce, dec ) )
    return true;
  if ( this->node_ht->find( b_nonce, n_pos, uid ) ) {
    user_n = this->bridge_tab[ uid ];
    if ( user_n != NULL ) {
      if ( debug_peer )
        printf( "recv Z_DEL(%" PRIu64 ") for %s from %s via %s\n",
                dec.seqno, user_n->peer.user.val, n.peer.user.val,
                pub.rte.transport.tport.val );
      uint32_t refs = this->peer_dist.inbound_refs( user_n->uid );
      if ( refs == 0 ) {
        if ( debug_peer )
          printf( "drop %s\n", user_n->peer.user.val );
        this->remove_authenticated( *user_n, BYE_DROPPED );
      }
      else if ( debug_peer ) {
        printf( "still has refs %s: %u\n", user_n->peer.user.val, refs );
      }
    }
  }
  if ( debug_peer && user_n == NULL )
    printf( "recv Z_DEL(%" PRIu64 ") from %s via %s, already gone\n",
                dec.seqno, n.peer.user.val, pub.rte.transport.tport.val );
  return true;
}

struct MeshDBRec : public MsgFldSet {
  Nonce        nonce;
  const char * mesh_url,
             * user;
  uint32_t     mesh_url_len,
               user_len;
  MeshDBRec  * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  MeshDBRec() : mesh_url( 0 ), user( 0 ), mesh_url_len( 0 ), user_len( 0 ),
                next( 0 ) {
    this->nonce.zero();
  }
  void set_field( uint32_t fid,  MDReference &mref ) {
    switch ( fid ) {
      case FID_BRIDGE:
        this->nonce.copy_from( mref.fptr );
        break;
      case FID_USER:
        this->user     = (const char *) mref.fptr;
        this->user_len = (uint32_t) mref.fsize;
        break;
      case FID_MESH_URL:
        this->mesh_url     = (const char *) mref.fptr;
        this->mesh_url_len = (uint32_t) mref.fsize;
        break;
      default:
        break;
    }
  }
  void print( void ) const {
    char buf[ NONCE_B64_LEN + 1 ];
    printf( "  nonce[%s] user[%.*s] mesh[%.*s]\n",
            this->nonce.to_base64_str( buf ),
            this->user_len, this->user,
            this->mesh_url_len, this->mesh_url );
  }
  static void print_rec_list( const MeshDBRec *rec_list,
                              UserBridge &n ) noexcept {
    n.printf( "mesh_db (%s):\n", n.user_route->rte.transport.tport.val );
    for ( const MeshDBRec *r = rec_list; r != NULL; r = r->next ) {
      r->print();
    }
  }
};

bool
UserDB::recv_mesh_db( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept
{
  MeshDBRec * rec_list = dec.decode_rec_list<MeshDBRec>( FID_MESH_DB );

  /*this->events.recv_peer_db( n.uid, pub.rte.tport_id, stage );*/
  if ( debug_peer )
    MeshDBRec::print_rec_list( rec_list, n );

  while ( rec_list != NULL ) {
    MeshDBRec  & rec = *rec_list;
    UserBridge * user_n = NULL;
    size_t       n_pos;
    uint32_t     uid;
    bool         updated_mesh = false;
    rec_list = rec.next;
    if ( this->node_ht->find( rec.nonce, n_pos, uid ) ||
         this->zombie_ht->find( rec.nonce, n_pos, uid ) ) {
      if ( uid == MY_UID )
        continue;
      user_n = this->bridge_tab[ uid ];
    }
    if ( user_n == NULL || ! user_n->is_set( AUTHENTICATED_STATE ) ) {
      StringVal user_sv;
      this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
      this->start_pending_peer( rec.nonce, n, false, user_sv, PEER_DB_SYNC );
    }
    else {
      if ( rec.mesh_url_len != 0 ) {
        UserRoute * u_ptr   = user_n->user_route_ptr( *this, pub.rte.tport_id );
        if ( u_ptr->is_valid() ) {
          u_ptr->set_mesh( *this, rec.mesh_url, rec.mesh_url_len );
          this->direct_pending.update( u_ptr );
          updated_mesh = true;
        }
      }
    }
    if ( ! updated_mesh && rec.mesh_url_len != 0 ) {
      this->direct_pending.update( pub.rte, rec.mesh_url, rec.mesh_url_len,
                                   0, rec.nonce );
    }
  }
  return true;
}

size_t
UserDB::mesh_db_size( TransportRoute &rte,  uint32_t except_uid,
                      const MsgHdrDecoder &dec ) noexcept
{
  TransportRoute * rte2;
  uint8_t        * filter = NULL;
  size_t           filter_size = 0, i = 0;
  uint32_t         uid, count = 0;

  if ( dec.test( FID_MESH_FILTER ) ) {
    filter      = dec.mref[ FID_MESH_FILTER ].fptr;
    filter_size = dec.mref[ FID_MESH_FILTER ].fsize / 4;
  }
  MsgEst e;
  for ( size_t tid = 0; tid < this->transport_tab.count; tid++ ) {
    rte2 = this->transport_tab.ptr[ tid ];
    if ( rte2->mesh_id == rte.mesh_id ) {
      for ( bool ok = rte2->uid_connected.first( uid ); ok;
            ok = rte2->uid_connected.next( uid ) ) {
        if ( uid == except_uid )
          continue;
        UserBridge * n     = this->bridge_tab.ptr[ uid ];
        UserRoute  * u_ptr = n->user_route_ptr( *this, rte2->tport_id );
        for ( i = 0; i < filter_size; i++ ) {
          uint32_t h;
          ::memcpy( &h, &filter[ i * 4 ], 4 );
          if ( h == u_ptr->url_hash )
            break;
        }
        if ( i == filter_size ) {
          if ( u_ptr->is_set( MESH_URL_STATE ) ) {
            e.user    ( n->peer.user.len )
             .bridge2 ()
             .mesh_url( u_ptr->mesh_url_len );
            count++;
          }
        }
      }
    }
  }
  if ( count == 0 )
    return 0;
  return e.sz;
}

void
UserDB::mesh_db_submsg( TransportRoute &rte,  uint32_t except_uid,
                        const MsgHdrDecoder &dec,  MsgCat &m ) noexcept
{
  TransportRoute * rte2;
  uint8_t        * filter = NULL;
  size_t           filter_size = 0, i = 0;
  uint32_t         uid;

  if ( dec.test( FID_MESH_FILTER ) ) {
    filter      = dec.mref[ FID_MESH_FILTER ].fptr;
    filter_size = dec.mref[ FID_MESH_FILTER ].fsize / 4;
  }
  SubMsgBuf s( m );
  s.open_submsg();

  for ( size_t tid = 0; tid < this->transport_tab.count; tid++ ) {
    rte2 = this->transport_tab.ptr[ tid ];
    if ( rte2->mesh_id == rte.mesh_id ) {
      for ( bool ok = rte2->uid_connected.first( uid ); ok;
            ok = rte2->uid_connected.next( uid ) ) {
        if ( uid == except_uid )
          continue;
        UserBridge * n     = this->bridge_tab.ptr[ uid ];
        UserRoute  * u_ptr = n->user_route_ptr( *this, rte2->tport_id );
        for ( i = 0; i < filter_size; i++ ) {
          uint32_t h;
          ::memcpy( &h, &filter[ i * 4 ], 4 );
          if ( h == u_ptr->url_hash )
            break;
        }
        if ( i == filter_size ) {
          if ( u_ptr->is_set( MESH_URL_STATE ) ) {
            s.user    ( n->peer.user.val, n->peer.user.len )
             .bridge2 ( n->bridge_id.nonce )
             .mesh_url( u_ptr->mesh_url, u_ptr->mesh_url_len );
          }
        }
      }
    }
  }
  s.close( m, FID_MESH_DB );
}

bool
UserDB::recv_mesh_request( const MsgFramePublish &pub,  UserBridge &n,
                           const MsgHdrDecoder &dec ) noexcept
{
  char     ret_buf[ 16 ];
  InboxBuf ibx( n.bridge_id, dec.get_return( ret_buf, _MESH_RPY ) );
  bool     in_mesh     = pub.rte.uid_in_mesh->is_member( n.uid );
  size_t   mesh_db_len = 0;
  
  if ( in_mesh )
    mesh_db_len = this->mesh_db_size( pub.rte, n.uid, dec );

  if ( mesh_db_len == 0 ) {
    n.printf( "mesh_request hash zero entries\n" );
    return true;
  }
  if ( debug_peer )
    n.printf( "mesh_request\n" );
  MsgEst e( ibx.len() );
  e.seqno  ()
   .mesh_db( mesh_db_len );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno( ++n.send_inbox_seqno );
  this->mesh_db_submsg( pub.rte, n.uid, dec, m );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}

bool
UserDB::recv_mesh_result( const MsgFramePublish &pub,  UserBridge &n,
                          MsgHdrDecoder &dec ) noexcept
{
  if ( debug_peer )
    n.printf( "mesh_result\n" );
  if ( dec.test( FID_MESH_DB ) )
    return this->recv_mesh_db( pub, n, dec );
  return true;
}

bool
UserDB::send_mesh_request( UserBridge &n,  MsgHdrDecoder &dec ) noexcept
{
  InboxBuf    ibx( n.bridge_id, _MESH_REQ );
  BitSpace  & uid_in_mesh = *n.user_route->rte.uid_in_mesh;
  UserRoute * u_ptr;
  uint32_t    uid,
              t = n.user_route->rte.tport_id,
              url_count = 0,
            * filter;
  bool        ok;

  for ( ok = uid_in_mesh.first( uid ); ok; ok = uid_in_mesh.next( uid ) ) {
    u_ptr = this->bridge_tab.ptr[ uid ]->user_route_ptr( *this, t );
    if ( u_ptr->url_hash != 0 )
      url_count++;
  }
  if ( url_count > 0 ) {
    filter = (uint32_t *) dec.mem.make( url_count * 4 );
    url_count = 0;
    for ( ok = uid_in_mesh.first( uid ); ok; ok = uid_in_mesh.next( uid ) ) {
      u_ptr = this->bridge_tab.ptr[ uid ]->user_route_ptr( *this, t );
      if ( u_ptr->url_hash != 0 )
        filter[ url_count++ ] = u_ptr->url_hash;
    }
  }
  MsgEst e( ibx.len() );
  e.seqno      ()
   .mesh_filter( url_count * 4 );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno( ++n.send_inbox_seqno  );
  if ( url_count > 0 )
    m.mesh_filter( filter, url_count * 4 );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}

void
UserDB::process_unknown_adjacency( uint64_t current_mono_time ) noexcept
{
  this->peer_dist.clear_cache_if_dirty();
  for ( AdjPending *p = this->adjacency_unknown.hd; p != NULL; p = p->next ) {
    if ( p->request_time_mono == 0 ||
         p->request_time_mono +
           UserPendingRoute::pending_timeout_total < current_mono_time ) {
      UserPendingRoute * pr = NULL;
      UserBridge       * n,
                       * m;
      uint32_t           uid,
                         dist;
      if ( p->reason != UNAUTH_ADJ_SYNC ) {
        n = this->bridge_tab.ptr[ p->uid ];
        if ( n->is_set( AUTHENTICATED_STATE ) ) {
          m = this->closest_peer_route( p->rte, *n, dist );
          if ( m != NULL )
            pr = this->start_pending_adj( *p, *m );
          else
            pr = this->start_pending_adj( *p, *n );
        }
      }
      for ( bool ok = p->rte.uid_connected.first( uid ); ok;
            ok = p->rte.uid_connected.next( uid ) ) {
        UserBridge * n = this->bridge_tab.ptr[ uid ];
        if ( n->bridge_id.nonce != p->nonce ) {
          if ( pr == NULL )
            pr = this->start_pending_adj( *p, *n );
          else {
            const PendingUid puid( n->uid, p->rte.tport_id );
            if ( ! pr->is_member( puid ) )
              if ( ! pr->push( puid ) )
                break;
          }
        }
      }
      if ( debug_peer ) {
        char buf[ NONCE_B64_LEN + 1 ];
        if ( pr == NULL ) {
          printf( "no route found, nonce [%s] user %.*s reason %s\n",
                  p->nonce.to_base64_str( buf ),
                  p->user_sv.len, p->user_sv.val,
                  peer_sync_reason_string( p->reason ) );
        }
        else {
          uint32_t uid = pr->hd.uid,
                   tid = pr->hd.tport_id;
          UserBridge     * n   = this->bridge_tab.ptr[ uid ];
          TransportRoute * rte = this->transport_tab.ptr[ tid ];
          printf( "route to %s.%u over %s nonce [%s] user %.*s reason %s\n",
                  n->peer.user.val, uid, rte->transport.tport.val,
                  p->nonce.to_base64_str( buf ),
                  p->user_sv.len, p->user_sv.val,
                  peer_sync_reason_string( p->reason ) );
        }
      }
      p->request_time_mono = current_mono_time;
      p->request_count++;
    }
  }
}

UserPendingRoute *
UserDB::find_pending_peer( const Nonce &b_nonce,
                           const PendingUid &puid ) noexcept
{
  UserPendingRoute *p;
  for ( size_t i = 0; i < this->pending_queue.num_elems; i++ ) {
    p = this->pending_queue.heap[ i ];
    if ( p->bridge_nonce == b_nonce ) {
      if ( ! p->is_member( puid ) )
        p->push( puid );
      return p;
    }
  }
  return NULL;
}

bool
UserDB::start_pending_peer( const Nonce &b_nonce,  UserBridge &n,
                            bool delay,  const StringVal &user_sv,
                            PeerSyncReason reason ) noexcept
{
  const PendingUid puid( n.uid, n.user_route->rte.tport_id );
  if ( this->find_pending_peer( b_nonce, puid ) != NULL )
    return true;

  UserPendingRoute *p = new ( ::malloc( sizeof( UserPendingRoute ) ) )
                        UserPendingRoute( b_nonce, puid, user_sv, reason );
  uint64_t current_mono_time = current_monotonic_time_ns();
  bool b = true;
  if ( delay ) {
    p->pending_add_mono  = current_mono_time;
    p->request_time_mono = current_mono_time +
                           this->rand.next() % PEER_RAND_DELAY_NS;
    if ( debug_peer )
      n.printf( "start pending delay %.3fms\n",
          ( p->request_time_mono - current_mono_time ) / ( 1000.0 * 1000.0 ) );
  }
  else {
    b = this->request_pending_peer( *p, current_mono_time );
    p->request_time_mono = current_mono_time;
    p->request_count++;
  }
  this->pending_queue.push( p );
  return b;
}

UserPendingRoute *
UserDB::start_pending_adj( AdjPending &adj,  UserBridge &n ) noexcept
{
  const PendingUid puid( n.uid, adj.rte.tport_id );
  UserPendingRoute *p;
  p = this->find_pending_peer( adj.nonce, puid );
  if ( p != NULL )
    return p;

  p = new ( ::malloc( sizeof( UserPendingRoute ) ) )
      UserPendingRoute( adj.nonce, puid, adj.user_sv, adj.reason );
  uint64_t current_mono_time = current_monotonic_time_ns();
  p->pending_add_mono  = current_mono_time;
  p->request_time_mono = current_mono_time +
                         this->rand.next() % PEER_RAND_DELAY_NS;
  if ( adj.pending_time_mono == 0 )
    adj.pending_time_mono = current_mono_time;
  adj.request_time_mono = p->request_time_mono;
  p->pending_seqno = adj.pending_seqno;
  if ( debug_peer )
    n.printf( "start adj pending delay %.3fms\n",
          ( p->request_time_mono - current_mono_time ) / ( 1000.0 * 1000.0 ) );
  this->pending_queue.push( p );
  return p;
}

void
UserDB::process_pending_peer( uint64_t current_mono_time ) noexcept
{
  while ( this->pending_queue.num_elems > 0 ) {
    UserPendingRoute *p = this->pending_queue.heap[ 0 ];

    if ( current_mono_time < p->pending_timeout() )
      break;
    this->pending_queue.pop();

    if ( p->request_count > UserPendingRoute::MAX_REQUESTS ) {
      char buf[ NONCE_B64_LEN + 1 ];
      UserBridge * n = this->bridge_tab[ p->ptr->uid ];
      printf( "timeout pending peer [%s] (%.*s) -> %s (%s)\n",
              p->bridge_nonce.to_base64_str( buf ), p->user_sv.len,
              p->user_sv.val, n->peer.user.val,
              peer_sync_reason_string( p->reason ) );
      delete p;
    }
    else {
      if ( (p->ptr = p->ptr->next) == NULL )
        p->ptr = &p->hd;
      this->request_pending_peer( *p, current_mono_time );
      p->request_time_mono = current_mono_time;
      p->request_count++;
      this->pending_queue.push( p );
    }
  }
}

bool
UserDB::request_pending_peer( UserPendingRoute &p,
                              uint64_t current_mono_time ) noexcept
{
  UserBridge * n = this->bridge_tab[ p.ptr->uid ];

  if ( p.pending_add_mono == 0 )
    p.pending_add_mono = current_mono_time;
  if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
    return true;
  UserRoute * u_ptr = n->user_route_ptr( *this, p.ptr->tport_id );
  if ( u_ptr == NULL || ! u_ptr->is_valid() )
    return true;
  n->user_route = u_ptr;

  this->events.send_sync_req( n->uid, p.ptr->tport_id, p.user_sv.id,
                              p.reason );
  InboxBuf ibx( n->bridge_id, _SYNC_REQ );

  MsgEst e( ibx.len() );
  e.seqno      ()
   .sync_bridge()
   .user       ( p.user_sv.len );

  MsgCat m;
  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno      ( ++n->send_inbox_seqno )
   .sync_bridge( p.bridge_nonce );
  if ( p.user_sv.len > 0 )
    m.user( p.user_sv.val, p.user_sv.len );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  if ( debug_peer ) {
    char buf[ NONCE_B64_LEN + 1 ];
    printf( "sync peer [%s] %.*s -> %s (%s)\n",
            p.bridge_nonce.to_base64_str( buf ), p.user_sv.len,
            p.user_sv.val, n->peer.user.val,
            peer_sync_reason_string( p.reason ) );
  }
  return this->forward_to_inbox( *n, ibx, h, m.msg, m.len(), false );
}

void
UserDB::remove_pending_peer( const Nonce *b_nonce,  uint64_t pseqno ) noexcept
{
  UserPendingRoute *p;
  char buf[ NONCE_B64_LEN + 1 ];
  d_peer( "remove_pending_peer [%s] seqno %" PRIu64 "\n",
          b_nonce == NULL ? "" : b_nonce->to_base64_str( buf ), pseqno );
  for ( size_t i = 0; i < this->pending_queue.num_elems; i++ ) {
    p = this->pending_queue.heap[ i ];
    if ( ( b_nonce != NULL && p->bridge_nonce == *b_nonce ) ||
         ( pseqno != 0 && p->pending_seqno == pseqno ) ) {
      this->pending_queue.remove( p );
      delete p;
      return;
    }
  }
}

