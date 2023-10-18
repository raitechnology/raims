#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raims/session.h>

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
                            MsgCat &m,  uint32_t hops ) noexcept
{
  size_t user_len    = n.peer.user.len,
         svc_len     = n.peer.svc.len,
         create_len  = n.peer.create.len,
         expires_len = n.peer.expires.len;
  BloomCodec code;
  n.bloom.encode( code );

  HashDigest tmp_ha1, encrypted_ha1;
  Nonce      cnonce = this->cnonce->calc();
  this->get_peer_key( MY_UID, n.uid, tmp_ha1 );
  encrypted_ha1.encrypt_key_nonce( tmp_ha1, cnonce, n.peer_key );

  MsgEst e( sublen );
  e.seqno      ()
   .time       ()
   .session    ()
   .sess_key   ()
   .cnonce     ()
   .hops       ()
   .uptime     ()
   .start      ()
   .interval   ()
   .user       ( user_len       )
   .service    ( svc_len        )
   .create     ( create_len     )
   .expires    ( expires_len    )
   .sub_seqno  ()
   .link_state ()
   .hb_skew    ()
   .host_id    ()
   .bloom      ( code.code_sz * 4 )
   .adjacency  ( this->adjacency_size( &n ) );

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .seqno      ( dest.inbox.next_send( U_INBOX_SYNC_RPY ) )
   .time       ( n.hb_time  )
   .session    ( n.bridge_id.hmac, n.bridge_id.nonce )
   .sess_key   ( encrypted_ha1 )
   .cnonce     ( cnonce        )
   .hops       ( hops          )
   .uptime     ( n.uptime()    )
   .start      ( n.start_time  )
   .interval   ( n.hb_interval )
   .user       ( n.peer.user.val   , user_len       )
   .service    ( n.peer.svc.val    , svc_len        )
   .create     ( n.peer.create.val , create_len     )
   .expires    ( n.peer.expires.val, expires_len    )
   .sub_seqno  ( n.sub_seqno   )
   .link_state ( n.link_state_seqno )
   .hb_skew    ( n.hb_skew )
   .host_id    ( n.host_id )
   .bloom      ( code.ptr       , code.code_sz * 4 );

  this->adjacency_submsg( &n, m );
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
    if ( user_n != NULL && user_n->is_set( AUTHENTICATED_STATE ) ) {
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
      this->make_peer_sync_msg( n, *user_n, ibx.buf, ibx.len(), h, m, hops );
      if ( debug_peer )
        printf(
            "forward peer: %.*s to %s.%u for %s.%u hops=%u, in_mesh=%u\n",
            (int) ibx.len(), ibx.buf, n.peer.user.val, n.uid,
            user_n->peer.user.val, uid, hops, in_mesh?1:0 );
      return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
    }
  }
  StringVal user_sv;
  if ( dec.test( FID_USER ) ) {
    const char * user     = (const char *) dec.mref[ FID_USER ].fptr;
    uint32_t     user_len = (uint32_t) dec.mref[ FID_USER ].fsize;
    this->string_tab.ref_string( user, user_len, user_sv );
  }
  this->events.recv_sync_fail( n.uid, pub.rte.tport_id, user_sv.id );
  if ( debug_peer ) {
    char buf[ NONCE_B64_LEN + 1 ];
    n.printf( "sync_request(user=%.*s), peer not found: [%s]\n",
              user_sv.len, user_sv.val, b_nonce.to_base64_str( buf ) );
  }
  /* check if peer is gone */
  if ( this->zombie_ht->find( b_nonce, n_pos, uid ) ) {
    user_n = this->bridge_tab[ uid ];
    if ( user_n != NULL ) {
      MsgCat   m;
      InboxBuf ibx( n.bridge_id, _SYNC_RPY );

      MsgEst e( ibx.len() );
      e.seqno      ()
       .time       ()
       .session    ()
       .user       ( user_n->peer.user.len )
       .auth_stage ();

      m.reserve( e.sz );
      m.open( this->bridge_id.nonce, ibx.len() )
       .seqno      ( n.inbox.next_send( U_INBOX_SYNC_RPY ) )
       .time       ( user_n->hb_time  )
       .session    ( user_n->bridge_id.hmac, user_n->bridge_id.nonce )
       .user       ( user_n->peer.user.val, user_n->peer.user.len )
       .auth_stage ( user_n->last_auth_type );

      uint32_t h = ibx.hash();
      m.close( e.sz, h, CABA_INBOX );
      m.sign( ibx.buf, ibx.len(), *this->session_key );

      return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
    }
  }
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
                         uint64_t &start ) noexcept
{
  HashDigest sess_key,
             tmp_ha1;
  Nonce      cnonce;
  uint64_t   time    = 0,
             seqno   = 0;
  size_t     n_pos;
  uint32_t   uid;

  if ( ! dec.test_6( FID_SESSION, FID_SEQNO, FID_TIME, FID_SESS_KEY,
                     FID_CNONCE, FID_START ) )
    return false;

  sync_bridge_id.copy_from( dec.mref[ FID_SESSION ].fptr );
  if ( user_n == NULL ) {
    if ( this->node_ht->find( sync_bridge_id.nonce, n_pos, uid ) ||
         this->zombie_ht->find( sync_bridge_id.nonce, n_pos, uid ) ) {
      user_n = this->bridge_tab[ uid ];
      if ( user_n != NULL && user_n->last_auth_type == BYE_BYE ) {
        user_n = NULL;
        return false;
      }
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
  if ( ! dec.test_4( FID_USER, FID_SERVICE, FID_CREATE, FID_EXPIRES ) ) {
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
      PeerEntry * peer = this->find_peer( user.user, user.user_len,
                                          user.create, user.create_len,
                                          user.expires, user.expires_len,
                                          sync_bridge_id.hmac );
      TransportRoute & rte = from_n.user_route->rte;
      HashDigest hello;
      this->calc_hello_key( start, sync_bridge_id.hmac, hello );
      user_n = this->add_user( rte, from_n.user_route, pub.src_route,
                               sync_bridge_id, *peer, start, dec, hello );
    }
    user_n->peer_key = peer_key;
    user_n->start_time = start;

    if ( dec.test( FID_HB_SKEW ) ) {
      int64_t hb_skew = 0;
      cvt_number<int64_t>( dec.mref[ FID_HB_SKEW ], hb_skew );
      if ( user_n->hb_skew == 0 ||
           user_n->hb_skew != min_abs( user_n->hb_skew, hb_skew ) ) {
        user_n->hb_skew     = hb_skew;
        user_n->hb_skew_ref = from_n.uid;
        user_n->skew_upd++;
      }
    }
    if ( dec.test( FID_HOST_ID ) ) {
      uint32_t host_id = 0;
      cvt_number<uint32_t>( dec.mref[ FID_HOST_ID ], host_id );
      if ( host_id != 0 && host_id != user_n->host_id )
        this->update_host_id( user_n, host_id );
    }
  }
  peer_key.zero();
  return user_n;
}

void
PeerDBRec::print( void ) const noexcept
{
  char buf[ NONCE_B64_LEN + 1 ];
  printf( "  nonce[%s] user[%.*s] hops[%u] sub[%" PRIu64 "] link[%" PRIu64 "]\n",
          this->nonce.to_base64_str( buf ),
          this->user_len, this->user,
          this->hops, this->sub_seqno, this->link_state );
}

void
PeerDBRec::print_rec_list( const PeerDBRec *rec_list, UserBridge &n ) noexcept
{
  n.printf( "peer_db (%s):\n", n.user_route->rte.transport.tport.val );
  for ( const PeerDBRec *r = rec_list; r != NULL; r = r->next ) {
    r->print();
  }
}

bool
UserDB::recv_peer_db( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec,  AuthStage stage ) noexcept
{
  PeerDBRec * rec_list = dec.decode_rec_list<PeerDBRec>( FID_PEER_DB );
  bool need_adjacency = false;

  this->events.recv_peer_db( n.uid, pub.rte.tport_id, stage );
  if ( debug_peer )
    PeerDBRec::print_rec_list( rec_list, n );

  while ( rec_list != NULL ) {
    PeerDBRec  & rec = *rec_list;
    UserBridge * user_n = NULL;
    size_t       n_pos;
    uint32_t     uid;
    rec_list = rec.next;
    if ( this->node_ht->find( rec.nonce, n_pos, uid ) ||
         this->zombie_ht->find( rec.nonce, n_pos, uid ) ) {
      if ( uid == MY_UID )
        continue;
      user_n = this->bridge_tab[ uid ];
      if ( user_n != NULL && user_n->last_auth_type == BYE_BYE )
        continue;
    }
    if ( user_n == NULL || ! user_n->is_set( AUTHENTICATED_STATE ) ) {
      StringVal user_sv;
      this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
      this->start_pending_peer( rec.nonce, n, false, user_sv, PEER_DB_SYNC );
    }
    else if ( user_n->link_state_seqno < rec.link_state ||
              user_n->sub_seqno < rec.sub_seqno ) {
      need_adjacency = true;
    }
    if ( user_n != NULL && rec.hb_skew != 0 ) {
      if ( user_n->hb_skew == 0 ||
           user_n->hb_skew != min_abs( user_n->hb_skew, rec.hb_skew ) ) {
        user_n->hb_skew     = rec.hb_skew;
        user_n->hb_skew_ref = n.uid;
        user_n->skew_upd++;
      }
    }
    if ( user_n != NULL && rec.host_id != 0 &&
         user_n->host_id != rec.host_id ) {
      this->update_host_id( user_n, rec.host_id );
    }
  }
  if ( need_adjacency )
    this->send_adjacency_request( n, PEERDB_SYNC_REQ );
  return true;
}

size_t
UserDB::peer_db_size( UserBridge &n,  bool is_adj_req ) noexcept
{
  MsgEst       pdb;
  UserBridge * n2;
  uint32_t     uid;

  if ( this->uid_authenticated.first( uid ) ) {
    do {
      if ( uid != n.uid ) {
        if ( (n2 = this->bridge_tab[ uid ]) != NULL ) {
          pdb.bridge2    ()
             .user       ( n2->peer.user.len )
             .sub_seqno  ()
             .link_state ();
          if ( ! is_adj_req ) {
            pdb.hops     ()
               .hb_skew  ()
               .host_id  ();
          }
        }
      }
    } while ( this->uid_authenticated.next( uid ) );
  }
  return pdb.sz;
}

void
UserDB::peer_db_submsg( UserBridge &n,  MsgCat &m,  bool is_adj_req ) noexcept
{
  UserRoute  * u_ptr = n.user_route;
  UserBridge * n2;
  uint32_t     uid;

  SubMsgBuf submsg( m );
  submsg.open_submsg();

  if ( this->uid_authenticated.first( uid ) ) {
    do {
      if ( uid != n.uid ) {
        if ( (n2 = this->bridge_tab[ uid ]) != NULL ) {
          submsg.bridge2    ( n2->bridge_id.nonce )
                .user       ( n2->peer.user.val, n2->peer.user.len )
                .sub_seqno  ( n2->sub_seqno        )
                .link_state ( n2->link_state_seqno );
          if ( ! is_adj_req ) {
            uint32_t hops = u_ptr->rte.uid_connected.is_member( uid ) ? 0:1;
            submsg.hops     ( hops                 )
                  .hb_skew  ( n2->hb_skew          ) 
                  .host_id  ( n2->host_id          );
          }
        }
      }
    } while ( this->uid_authenticated.next( uid ) );
  }
  submsg.close( m, FID_PEER_DB );
}

bool
UserDB::make_peer_db_msg( UserBridge &n,  const char *sub,  size_t sublen,
                          uint32_t h,  MsgCat &m ) noexcept
{
  size_t peer_db_len = this->peer_db_size( n );
  if ( peer_db_len == 0 )
    return false;

  MsgEst e( sublen );
  e.seqno()
   .peer_db( peer_db_len );

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .seqno( n.inbox.next_send( U_INBOX_ADD_RTE ) );

  this->peer_db_submsg( n, m );
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
    this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
}

bool
UserDB::recv_peer_add( const MsgFramePublish &pub,  UserBridge &n,
                       MsgHdrDecoder &dec,  AuthStage stage ) noexcept
{
  Nonce        b_nonce;
  size_t       n_pos;
  UserBridge * user_n = NULL;
  StringVal    user_sv;
  uint32_t     uid, stage_num;

  if ( ! n.is_set( AUTHENTICATED_STATE ) )
    return true;
  if ( dec.test( FID_PEER_DB ) )
    return this->recv_peer_db( pub, n, dec, stage );
  if ( ! get_bridge_nonce( b_nonce, dec ) )
    return true;
  if ( dec.test( FID_USER ) ) {
    const char * user     = (const char *) dec.mref[ FID_USER ].fptr;
    uint32_t     user_len = (uint32_t) dec.mref[ FID_USER ].fsize;
    this->string_tab.ref_string( user, user_len, user_sv );
  }

  if ( this->node_ht->find( b_nonce, n_pos, uid ) ||
       this->zombie_ht->find( b_nonce, n_pos, uid ) ) {
    if ( uid == MY_UID )
      return true;
    user_n = this->bridge_tab[ uid ];
    if ( user_n != NULL && user_n->last_auth_type == BYE_BYE )
      return true;
    if ( dec.get_ival<uint32_t>( FID_AUTH_STAGE, stage_num ) ) {
      if ( is_bye_stage( stage_num ) ) {
        this->remove_authenticated( *user_n, (AuthStage) stage_num );
        this->events.recv_peer_add( n.uid, pub.rte.tport_id,
                                    user_n->uid, stage_num, user_sv.id );
        return true;
      }
    }
  }
  if ( dec.get_ival<uint32_t>( FID_AUTH_STAGE, stage_num ) ) {
    if ( is_bye_stage( stage_num ) ) {
      d_peer( "bye peer I never knew\n" ); /* likely a previous instance */
      this->add_unknown_adjacency( NULL, &b_nonce );
      return true;
    }
  }

  if ( dec.test( FID_SESS_KEY ) &&
       ( user_n == NULL || ! user_n->is_set( AUTHENTICATED_STATE ) ) )
    user_n = this->make_peer_session( pub, n, dec, user_n );
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
      if ( user_n == NULL || user_n->last_auth_type != BYE_BYE )
        return this->start_pending_peer( b_nonce, n, false, user_sv,
                                         PEER_ADD_SYNC );
      return true;
    }
  }

  if ( dec.test_2( FID_ADJACENCY, FID_LINK_STATE ) ||
       dec.test_2( FID_BLOOM, FID_SUB_SEQNO ) )
    this->recv_adjacency_result( pub, *user_n, dec );
#if 0
  /* XXX must make sure arrived over the correct mesh link */
  if ( dec.test( FID_MESH_URL ) ) {
    size_t       url_len = dec.mref[ FID_MESH_URL ].fsize;
    const char * url     = (const char *) dec.mref[ FID_MESH_URL ].fptr;
    this->mesh_pending.update( pub.rte, url, url_len, 0,
                               user_n->bridge_id.nonce );
  }
#endif
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
UserDB::send_peer_add( UserBridge &n,
                       const TransportRoute *except_rte ) noexcept
{
  size_t count = this->transport_tab.count;
  kv::BitSpace unique;
  unique.add( n.uid );
  this->msg_send_counter[ U_PEER_ADD ]++;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * rte = this->transport_tab.ptr[ i ];
    if ( rte != except_rte ) {
      if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
        if ( ! unique.superset( rte->uid_connected ) ) {
          d_peer( "send Z_ADD for %s via %s, connect %u\n",
               n.peer.user.val, rte->transport.tport.val, rte->connect_count );
          uint32_t hops = 0;
          if ( ! rte->uid_connected.is_member( n.uid ) )
            hops = 1;
          this->events.send_add_route( n.uid, (uint32_t) i, hops );

          size_t user_len = n.peer.user.len;

          MsgEst e( Z_ADD_SZ );
          e.seqno      ()
           .time       ()
           .sync_bridge()
           .user       ( user_len )
           .hops       ()
           .sub_seqno  ()
           .link_state ();

          MsgCat m;
          m.reserve( e.sz );
          m.open( this->bridge_id.nonce, Z_ADD_SZ )
           .seqno      ( ++this->send_peer_seqno )
           .time       ( n.hb_time  )
           .sync_bridge( n.bridge_id.nonce )
           .user       ( n.peer.user.val, user_len )  /* for information */
           .hops       ( hops               )
           .sub_seqno  ( n.sub_seqno        )
           .link_state ( n.link_state_seqno );

          m.close( e.sz, add_h, CABA_RTR_ALERT );
          m.sign( Z_ADD, Z_ADD_SZ, *this->session_key );

          EvPublish pub( Z_ADD, Z_ADD_SZ, NULL, 0, m.msg, m.len(),
                         rte->sub_route, this->my_src, add_h, CABA_TYPE_ID );
          rte->forward_to_connected_auth( pub );
          unique.add( rte->uid_connected );
        }
      }
    }
  }
}

void
UserDB::send_peer_del( UserBridge &n ) noexcept
{
  size_t count = this->transport_tab.count;
  kv::BitSpace unique;
  unique.add( n.uid );
  this->msg_send_counter[ U_PEER_DEL ]++;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
      if ( ! unique.superset( rte->uid_connected ) ) {
        if ( debug_peer )
          printf( "send Z_DEL(%" PRIu64 ") for %s via %s, connect=%u\n",
                  this->send_peer_seqno, n.peer.user.val,
                  rte->transport.tport.val, rte->connect_count );
        this->events.send_peer_delete( n.uid, (uint32_t) i );

        MsgEst e( Z_DEL_SZ );
        e.seqno      ()
         .time       ()
         .sync_bridge()
         .user       ( n.peer.user.len ) /* for information */
         .auth_stage ();

        MsgCat m;
        m.reserve( e.sz );
        m.open( this->bridge_id.nonce, Z_DEL_SZ )
         .seqno      ( ++this->send_peer_seqno )
         .time       ( n.hb_time )
         .sync_bridge( n.bridge_id.nonce )
         .user       ( n.peer.user.val, n.peer.user.len )
         .auth_stage ( n.last_auth_type );

        m.close( e.sz, del_h, CABA_RTR_ALERT );
        m.sign( Z_DEL, Z_DEL_SZ, *this->session_key );

        EvPublish pub( Z_DEL, Z_DEL_SZ, NULL, 0, m.msg, m.len(),
                       rte->sub_route, this->my_src, del_h, CABA_TYPE_ID );
        rte->forward_to_connected_auth( pub );
        unique.add( rte->uid_connected );
      }
    }
  }
}

bool
UserDB::recv_peer_del( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec ) noexcept
{
  Nonce        b_nonce;
  size_t       n_pos;
  uint16_t     bye    = BYE_DROPPED;
  UserBridge * user_n = NULL;
  uint32_t     uid    = 0;
  
  if ( ! get_bridge_nonce( b_nonce, dec ) )
    return true;
  if ( dec.test( FID_AUTH_STAGE ) )
    cvt_number<uint16_t>( dec.mref[ FID_AUTH_STAGE ], bye );
  if ( this->node_ht->find( b_nonce, n_pos, uid ) ) {
    user_n = this->bridge_tab[ uid ];
    if ( user_n != NULL ) {
      if ( debug_peer )
        printf( "recv Z_DEL(%" PRIu64 ") for %s from %s via %s\n",
                dec.seqno, user_n->peer.user.val, n.peer.user.val,
                pub.rte.transport.tport.val );
      uint32_t refs = this->peer_dist.inbound_refs( user_n->uid );
      if ( refs == 0 || bye == BYE_BYE ) {
        if ( debug_peer )
          printf( "drop %s\n", user_n->peer.user.val );
        this->remove_authenticated( *user_n, (AuthStage) bye );
      }
      else if ( debug_peer ) {
        printf( "still has refs %s: %u\n", user_n->peer.user.val, refs );
      }
    }
  }
  else if ( bye == BYE_BYE ) {
    if ( this->zombie_ht->find( b_nonce, n_pos, uid ) ) {
      user_n = this->bridge_tab[ uid ];
      if ( user_n != NULL ) {
        user_n->last_auth_type = BYE_BYE;
        user_n = NULL;
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
  StringVal    mesh_url,
               user;
  MeshDBRec  * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  MeshDBRec() : next( 0 ) {
    this->nonce.zero();
  }
  void set_field( uint32_t fid,  MDReference &mref ) {
    switch ( fid ) {
      case FID_BRIDGE:
        this->nonce.copy_from( mref.fptr );
        break;
      case FID_USER:
        this->user.val = (const char *) mref.fptr;
        this->user.len = (uint32_t) mref.fsize;
        break;
      case FID_MESH_URL:
        this->mesh_url.val = (const char *) mref.fptr;
        this->mesh_url.len = (uint32_t) mref.fsize;
        break;
      default:
        break;
    }
  }
  void print( void ) const {
    char buf[ NONCE_B64_LEN + 1 ];
    printf( "  nonce[%s] user[%.*s] mesh[%.*s]\n",
            this->nonce.to_base64_str( buf ),
            this->user.len, this->user.val,
            this->mesh_url.len, this->mesh_url.val );
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
  TransportRoute * rte = &pub.rte;
  MeshDBRec * rec_list = dec.decode_rec_list<MeshDBRec>( FID_MESH_DB );

  /*this->events.recv_peer_db( n.uid, pub.rte.tport_id, stage );*/
  if ( debug_peer )
    MeshDBRec::print_rec_list( rec_list, n );

  if ( ! dec.test_2( FID_MESH_URL, FID_TPORT ) ) {
    n.printf( "ignoring mesh db without mesh url and tport\n" );
    return true;
  }
  StringVal mesh_url( (const char *) dec.mref[ FID_MESH_URL ].fptr,
                      dec.mref[ FID_MESH_URL ].fsize );
  StringVal tport   ( (const char *) dec.mref[ FID_TPORT ].fptr,
                      dec.mref[ FID_TPORT ].fsize );
  if ( ! rte->mesh_url.equals( mesh_url ) ||
       ! rte->transport.tport.equals( tport ) ) {
    rte = rte->mgr.find_mesh( mesh_url );
    if ( rte == NULL || ! rte->transport.tport.equals( tport ) ) {
      n.printf( "recv mesh db %.*s no mesh url found (%.*s)\n",
                tport.len, tport.val, mesh_url.len, mesh_url.val );
      return true;
    }
  }
  if ( debug_peer ) {
    ArrayOutput bout;
    bout.s( "tport( " )
        .b( tport.val, tport.len )
        .s( ", url " )
        .b( mesh_url.val, mesh_url.len )
        .s( ") [" );
    for ( MeshDBRec *rec = rec_list; rec != NULL; rec = rec->next ) {
      bout.b( rec->mesh_url.val, rec->mesh_url.len )
          .s( "," );
    }
    bout.s( "]" );
    n.printf( "mesh_db(%s): %.*s\n", rte->name, (int) bout.count, bout.ptr );
  }
  while ( rec_list != NULL ) {
    MeshDBRec  & rec = *rec_list;
    rec_list = rec.next;
    if ( rec.mesh_url.len != 0 ) {
      this->mesh_pending.update( *rte, tport, rec.mesh_url, 0, rec.nonce );
    }
  }
  return true;
}

struct UcastDBRec : public MsgFldSet {
  Nonce        nonce;
  StringVal    ucast_url,
               user;
  UcastDBRec * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  UcastDBRec() : next( 0 ) {
    this->nonce.zero();
  }
  void set_field( uint32_t fid,  MDReference &mref ) {
    switch ( fid ) {
      case FID_BRIDGE:
        this->nonce.copy_from( mref.fptr );
        break;
      case FID_USER:
        this->user.val = (const char *) mref.fptr;
        this->user.len = (uint32_t) mref.fsize;
        break;
      case FID_UCAST_URL:
        this->ucast_url.val = (const char *) mref.fptr;
        this->ucast_url.len = (uint32_t) mref.fsize;
        break;
      default:
        break;
    }
  }
  void print( void ) const {
    char buf[ NONCE_B64_LEN + 1 ];
    printf( "  nonce[%s] user[%.*s] ucast[%.*s]\n",
            this->nonce.to_base64_str( buf ),
            this->user.len, this->user.val,
            this->ucast_url.len, this->ucast_url.val );
  }
  static void print_rec_list( const UcastDBRec *rec_list,
                              UserBridge &n ) noexcept {
    n.printf( "ucast_db (%s):\n", n.user_route->rte.transport.tport.val );
    for ( const UcastDBRec *r = rec_list; r != NULL; r = r->next ) {
      r->print();
    }
  }
};

bool
UserDB::recv_ucast_db( const MsgFramePublish &pub,  UserBridge &n,
                       MsgHdrDecoder &dec ) noexcept
{
  TransportRoute * rte = &pub.rte;
  UcastDBRec     * rec_list = dec.decode_rec_list<UcastDBRec>( FID_UCAST_DB );

  /*this->events.recv_peer_db( n.uid, pub.rte.tport_id, stage );*/
  if ( debug_peer )
    UcastDBRec::print_rec_list( rec_list, n );

  if ( ! dec.test_2( FID_UCAST_URL, FID_TPORT ) ) {
    n.printf( "ignoring ucast db without ucast url and tport\n" );
    return true;
  }
  StringVal ucast_url( (const char *) dec.mref[ FID_UCAST_URL ].fptr,
                       dec.mref[ FID_UCAST_URL ].fsize );
  StringVal tport   ( (const char *) dec.mref[ FID_TPORT ].fptr,
                      dec.mref[ FID_TPORT ].fsize );
  if ( ! rte->ucast_url.equals( ucast_url ) ||
       ! rte->transport.tport.equals( tport ) ) {
    rte = rte->mgr.find_ucast( ucast_url );
    if ( rte == NULL ) {
      n.printf( "no ucast url found (%.*s)\n", ucast_url.len, ucast_url.val );
      return true;
    }
  }
  while ( rec_list != NULL ) {
    UcastDBRec & rec = *rec_list;
    size_t   n_pos;
    uint32_t uid;
    rec_list = rec.next;
    if ( rec.ucast_url.len != 0 ) {
      if ( this->node_ht->find( rec.nonce, n_pos, uid ) ) {
        UserBridge * n = this->bridge_tab[ uid ];
        if ( n != NULL ) {
          UserRoute * u_ptr = n->user_route_ptr( *this, rte->tport_id );
          this->set_ucast_url( *u_ptr, rec.ucast_url.val, rec.ucast_url.len,
                               "recv" );
        }
      }
      else {
        this->mesh_pending.update( *rte, tport, rec.ucast_url, 0, rec.nonce,
                                   false );
      }
    }
  }
  return true;
}

size_t
UserDB::ucast_db_size( TransportRoute &rte,  UrlDBFilter &filter ) noexcept
{
  MsgEst e;
  if ( ! filter.filter_hash( rte.ucast_url_hash ) ) {
    e.user      ( this->user.user.len )
     .bridge2   ()
     .ucast_url ( rte.ucast_url.len );
  }
  uint32_t uid;
  for ( bool ok = rte.uid_connected.first( uid ); ok;
        ok = rte.uid_connected.next( uid ) ) {
    UserBridge * n     = this->bridge_tab.ptr[ uid ];
    UserRoute  * u_ptr = n->user_route_ptr( *this, rte.tport_id );

    if ( u_ptr != NULL && u_ptr->is_valid() &&
         u_ptr->is_set( UCAST_URL_STATE ) ) {
      bool is_matched = filter.filter_hash( u_ptr->url_hash );
      if ( uid == filter.except_uid )
        continue;

      if ( ! is_matched ) {
        e.user     ( n->peer.user.len )
         .bridge2  ()
         .ucast_url( u_ptr->ucast_url.len );
        filter.return_count++;
      }
    }
  }
  if ( ! this->filter_db_size( filter ) )
    return 0;
  return e.sz;
}

void
UserDB::ucast_db_submsg( TransportRoute &rte,  UrlDBFilter &filter,
                         MsgCat &m ) noexcept
{
  SubMsgBuf s( m );
  s.open_submsg();

  if ( ! filter.filter_hash( rte.ucast_url_hash ) ) {
    s.user      ( this->user.user.val, this->user.user.len )
     .bridge2   ( this->bridge_id.nonce )
     .ucast_url ( rte.ucast_url.val, rte.ucast_url.len );
  }
  uint32_t uid;
  for ( bool ok = rte.uid_connected.first( uid ); ok;
        ok = rte.uid_connected.next( uid ) ) {
    if ( uid == filter.except_uid )
      continue;

    UserBridge * n     = this->bridge_tab.ptr[ uid ];
    UserRoute  * u_ptr = n->user_route_ptr( *this, rte.tport_id );

    if ( u_ptr != NULL && u_ptr->is_valid() &&
         u_ptr->is_set( UCAST_URL_STATE ) ) {
      if ( ! filter.filter_hash( u_ptr->url_hash ) ) {
        s.user     ( n->peer.user.val, n->peer.user.len )
         .bridge2  ( n->bridge_id.nonce )
         .ucast_url( u_ptr->ucast_url.val, u_ptr->ucast_url.len );
      }
    }
  }
  s.close( m, FID_UCAST_DB );
}

void
UrlDBFilter::setup_filter( MsgHdrDecoder &dec ) noexcept
{
  void * ptr = NULL;
  this->url_count = 0;

  if ( this->is_mesh_filter && dec.test( FID_MESH_FILTER ) ) {
    ptr             = dec.mref[ FID_MESH_FILTER ].fptr;
    this->url_count = dec.mref[ FID_MESH_FILTER ].fsize / 4;

    if ( dec.type == U_INBOX_MESH_RPY )
      this->invert_match = true;
  }
  else if ( ! this->is_mesh_filter && dec.test( FID_UCAST_FILTER ) ) {
    ptr             = dec.mref[ FID_UCAST_FILTER ].fptr;
    this->url_count = dec.mref[ FID_UCAST_FILTER ].fsize / 4;

    if ( dec.type == U_INBOX_UCAST_RPY )
      this->invert_match = true;
  }

  if ( ptr != NULL && this->url_count > 0 ) {
    this->match_count = 0;

    this->hash = (uint32_t *) dec.mem.make( this->url_count * 4 );
    ::memcpy( this->hash, ptr, this->url_count * 4 );

    this->matched = (bool *) dec.mem.make( this->url_count * sizeof( bool ) );
    ::memset( this->matched, 0, this->url_count * sizeof( bool ) );
  }
}

bool
UserDB::filter_db_size( UrlDBFilter &filter ) noexcept
{
  if ( ! filter.invert_match && filter.match_count < filter.url_count ) {
    if ( filter.match_count == 0 ) {
      filter.request_count = filter.url_count;
    }
    else {
      uint32_t i = 0, j = filter.url_count - 1;
      while ( i < j ) {
        if ( ! filter.matched[ i ] ) {
          i++;
        }
        else {
          bool     m = filter.matched[ i ];
          uint32_t h = filter.hash[ i ];
          filter.matched[ i ] = filter.matched[ j ];
          filter.hash[ i ]    = filter.hash[ j ];
          filter.matched[ j ] = m;
          filter.hash[ j ]    = h;
          --j;
        }
      }
      filter.request_count = i;
    }
  }
  if ( filter.return_count == 0 && filter.request_count == 0 )
    return false;
  return true;
}

size_t
UserDB::mesh_db_size( TransportRoute &rte,  UrlDBFilter &filter,
                      Nonce &csum ) noexcept
{
  TransportRoute * rte2;
  uint32_t         tport_id, uid,
                   tport_count = this->transport_tab.count;
  BitSpace         uid_vec;

  MsgEst e;
  csum = this->bridge_id.nonce;
  for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
    rte2 = this->transport_tab.ptr[ tport_id ];
    if ( rte2->mesh_id == rte.mesh_id &&
         rte2->uid_connected.cost[ 0 ] != COST_BAD ) {
      for ( bool ok = rte2->uid_connected.first( uid ); ok;
            ok = rte2->uid_connected.next( uid ) ) {
        UserBridge * n     = this->bridge_tab.ptr[ uid ];
        UserRoute  * u_ptr = n->user_route_ptr( *this, rte2->tport_id );

        if ( u_ptr != NULL && u_ptr->is_valid() &&
             u_ptr->is_set( MESH_URL_STATE ) ) {
          if ( ! uid_vec.test_set( uid ) ) {
            csum ^= n->bridge_id.nonce;
          }
          bool is_matched = filter.filter_hash( u_ptr->url_hash );
          if ( uid == filter.except_uid )
            continue;

          if ( ! is_matched ) {
            e.user    ( n->peer.user.len )
             .bridge2 ()
             .mesh_url( u_ptr->mesh_url.len );
            filter.return_count++;
          }
        }
      }
    }
  }
  if ( ! this->filter_db_size( filter ) )
    return 0;
  return e.sz;
}

void
UserDB::mesh_db_submsg( TransportRoute &rte,  UrlDBFilter &filter,
                        MsgCat &m ) noexcept
{
  TransportRoute * rte2;
  uint32_t         tport_id, uid,
                   tport_count = this->transport_tab.count;
  SubMsgBuf s( m );
  s.open_submsg();

  for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
    rte2 = this->transport_tab.ptr[ tport_id ];
    if ( rte2->mesh_id == rte.mesh_id &&
         rte2->uid_connected.cost[ 0 ] != COST_BAD ) {
      for ( bool ok = rte2->uid_connected.first( uid ); ok;
            ok = rte2->uid_connected.next( uid ) ) {
        UserBridge * n     = this->bridge_tab.ptr[ uid ];
        UserRoute  * u_ptr = n->user_route_ptr( *this, rte2->tport_id );

        if ( u_ptr != NULL && u_ptr->is_valid() &&
             u_ptr->is_set( MESH_URL_STATE ) ) {

          bool is_matched = filter.filter_hash( u_ptr->url_hash );
          if ( uid == filter.except_uid )
            continue;

          if ( ! is_matched ) {
            s.user    ( n->peer.user.val, n->peer.user.len )
             .bridge2 ( n->bridge_id.nonce )
             .mesh_url( u_ptr->mesh_url.val, u_ptr->mesh_url.len );
          }
        }
      }
    }
  }
  s.close( m, FID_MESH_DB );
}

bool
UserDB::recv_mesh_request( const MsgFramePublish &pub,  UserBridge &n,
                           MsgHdrDecoder &dec ) noexcept
{
  char             ret_buf[ 16 ];
  InboxBuf         ibx( n.bridge_id, dec.get_return( ret_buf, _MESH_RPY ) );
  TransportRoute * rte = &pub.rte;
  UserRoute      * u_ptr = NULL;
  Nonce            mesh_csum;
  size_t           mesh_db_len = 0;
  UrlDBFilter      filter( n.uid, true, &dec );
  uint32_t         req_tport_id = 0;
  MeshStatus       status = MESH_OK;
  
  if ( ! dec.test_3( FID_MESH_URL, FID_TPORT, FID_TPORTID ) )
    return true;

  mesh_csum.zero();
  cvt_number<uint32_t>( dec.mref[ FID_TPORTID ], req_tport_id );

  StringVal mesh_url( (const char *) dec.mref[ FID_MESH_URL ].fptr,
                      dec.mref[ FID_MESH_URL ].fsize );
  StringVal tport   ( (const char *) dec.mref[ FID_TPORT ].fptr,
                      dec.mref[ FID_TPORT ].fsize );
  if ( ! rte->mesh_url.equals( mesh_url ) ||
       ! rte->transport.tport.equals( tport ) ) {
    rte = rte->mgr.find_mesh( mesh_url );
    if ( rte == NULL || ! rte->transport.tport.equals( tport ) ) {
      n.printf( "recv mesh req %.*s no mesh url found (%.*s)\n",
                tport.len, tport.val, mesh_url.len, mesh_url.val );
      status = MESH_NOT_FOUND;
    }
  }
  if ( status == MESH_OK ) {
    if ( debug_peer )
      n.printf( "recv_mesh_request( %.*s.%u, %.*s, %.*s )\n",
                tport.len, tport.val, req_tport_id, mesh_url.len, mesh_url.val,
                rte->mesh_url.len, rte->mesh_url.val );
    if ( rte->uid_in_mesh->is_member( n.uid ) ) {
      mesh_db_len = this->mesh_db_size( *rte, filter, mesh_csum );
      if ( debug_peer )
        n.printf(
          "%s filter match_count %u url_count %u return_count %u db_len %u\n",
                   dec.get_type_string(), filter.match_count, filter.url_count,
                   filter.return_count, (uint32_t) mesh_db_len );

      Nonce csum2 = mesh_csum;
      csum2 ^= this->bridge_id.nonce;
      if ( csum2 != *rte->mesh_csum ) {
        char buf[ NONCE_B64_LEN + 1 ], buf2[ NONCE_B64_LEN + 1 ];
        rte->printf( "update csum %s, rte csum %s\n",
                csum2.to_base64_str( buf ),
                rte->mesh_csum->to_base64_str( buf2 ) );
        *rte->mesh_csum = csum2;
      }
    }
    if ( filter.return_count == 0 /*&& filter.request_count == 0*/ ) {
      if ( debug_peer ) {
        char buf[ NONCE_B64_LEN + 1 ];
        n.printf( "mesh_request has zero entries (%s) csum %s\n", rte->name,
                  mesh_csum.to_base64_str( buf ) );
      }
      status = MESH_NO_ENTRIES;
    }
  }
  MsgEst e( ibx.len() );
  e.seqno    ();
  if ( u_ptr != NULL ) {
    e.mesh_url( u_ptr->mesh_url.len )
     .tport   ( u_ptr->rte.transport.tport.len );
  }
  else {
    e.mesh_url( mesh_url.len )
     .tport   ( tport.len );
  }
  if ( status != MESH_NOT_FOUND )
    e.mesh_csum();
  e.mesh_info()
   .tportid();
  if ( filter.return_count > 0 )
    e.mesh_db( mesh_db_len );
  if ( filter.request_count > 0 )
    e.mesh_filter( filter.request_count * 4 );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno    ( n.inbox.next_send( U_INBOX_MESH_RPY ) );
  if ( u_ptr != NULL ) {
    m.mesh_url ( u_ptr->mesh_url.val, u_ptr->mesh_url.len )
     .tport    ( u_ptr->rte.transport.tport.val,
                 u_ptr->rte.transport.tport.len );
  }
  else {
    m.mesh_url( mesh_url.val, mesh_url.len )
     .tport   ( tport.val, tport.len );
  }
  if ( status != MESH_NOT_FOUND )
    m.mesh_csum( mesh_csum );
  m.mesh_info( status )
   .tportid( req_tport_id );
  if ( status == MESH_OK ) {
    if ( filter.request_count > 0 )
      m.mesh_filter( filter.hash, filter.request_count * 4 );
    if ( filter.return_count > 0 )
      this->mesh_db_submsg( *rte, filter, m );
  }
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
}

bool
UserDB::recv_mesh_result( const MsgFramePublish &pub,  UserBridge &n,
                          MsgHdrDecoder &dec ) noexcept
{
  if ( n.test_clear( MESH_REQUEST_STATE ) )
    this->mesh_queue.remove( &n );

  /*if ( dec.test( FID_MESH_FILTER ) )
    this->recv_mesh_request( pub, n, dec );*/

  if ( dec.test( FID_MESH_INFO ) ) {
    uint32_t status = MESH_OK;
    UserRoute * u_ptr = NULL;
    cvt_number<uint32_t>( dec.mref[ FID_MESH_INFO ], status );
    if ( dec.test( FID_MESH_CSUM ) ) {
      uint32_t tport_id = 0;
      cvt_number<uint32_t>( dec.mref[ FID_TPORTID ], tport_id );
      StringVal mesh_url( (const char *) dec.mref[ FID_MESH_URL ].fptr,
                          dec.mref[ FID_MESH_URL ].fsize );
      StringVal tport   ( (const char *) dec.mref[ FID_TPORT ].fptr,
                          dec.mref[ FID_TPORT ].fsize );
      TransportRoute * rte = NULL;
      if ( tport_id < this->transport_tab.count )
        rte = this->transport_tab.ptr[ tport_id ];

      if ( rte != NULL && rte->transport.tport.equals( tport ) ) {
        u_ptr = n.user_route_ptr( *this, tport_id );

        if ( rte->mesh_cache == NULL )
          rte->mesh_cache = new ( ::malloc( sizeof( MeshCsumCache ) ) )
            MeshCsumCache();
        rte->mesh_cache->uid = n.uid;
        rte->mesh_cache->csum.copy_from( dec.mref[ FID_MESH_CSUM ].fptr );
        char buf[ NONCE_B64_LEN + 1 ];
        n.printf( "tport %.*s cache mesh csum %s\n", tport.len, tport.val,
          rte->mesh_cache->csum.to_base64_str( buf ) );
      }
      if ( u_ptr == NULL )
        n.printf( "mesh status %u mismatch tport=%.*s id=%u n=%s\n", status,
                  tport.len, tport.val, tport_id, rte ? rte->name : "null" );
    }
    else if ( status != MESH_OK ) {
      n.printf( "mesh status %u\n", status );
    }
  }

  if ( dec.test( FID_MESH_DB ) )
    return this->recv_mesh_db( pub, n, dec );
  return true;
}

bool
UserDB::send_mesh_request( UserBridge &n,  MsgHdrDecoder &dec,
                           const Nonce &peer_csum ) noexcept
{
  InboxBuf         ibx( n.bridge_id, _MESH_REQ );
  TransportRoute & rte = n.user_route->rte;
  BitRefCount    & uid_in_mesh = *rte.uid_in_mesh;
  UserRoute      * u_ptr;
  UserBridge     * mesh_n;
  uint32_t         uid,
                   url_count = 0,
                   tport_count = this->transport_tab.count,
                   tport_id,
                 * filter = NULL;
  Nonce            csum = this->bridge_id.nonce;
  bool             ok;

  if ( ! n.user_route->is_set( MESH_URL_STATE ) )
    return true;
  for ( ok = uid_in_mesh.first( uid ); ok; ok = uid_in_mesh.next( uid ) ) {
    mesh_n = this->bridge_tab.ptr[ uid ];
    csum ^= mesh_n->bridge_id.nonce;
    for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
      if ( tport_id == rte.tport_id )
        continue;
      u_ptr = mesh_n->user_route_ptr( *this, tport_id );
      if ( u_ptr == NULL || ! u_ptr->is_valid() )
        continue;
      if ( u_ptr->is_set( MESH_URL_STATE ) &&
           u_ptr->rte.mesh_id == rte.mesh_id )
        url_count++;
    }
  }
  if ( csum == peer_csum ) {
    Nonce my_csum = *rte.mesh_csum;
    my_csum ^= this->bridge_id.nonce;
    if ( my_csum != csum ) {
      char buf[ NONCE_B64_LEN + 1 ], buf2[ NONCE_B64_LEN + 1 ];
      n.printf( "my mesh csum wrong %s, updating to %s\n",
                my_csum.to_base64_str( buf ),
                csum.to_base64_str( buf2 ) );
      csum ^= this->bridge_id.nonce;
      *rte.mesh_csum = csum;
    }
    /*return true;*/
  }
  if ( n.throttle_mesh( 1 ) )
    return true;
  this->mesh_queue.push( &n );
  if ( debug_peer ) {
    ArrayOutput bout;
    for ( ok = uid_in_mesh.first( uid ); ok; ok = uid_in_mesh.next( uid ) ) {
      mesh_n = this->bridge_tab.ptr[ uid ];
      bout.s( mesh_n->peer.user.val )
          .s( "." )
          .i( uid )
          .s( "," );
    }
    n.printf( "mesh_request(%s) tport_id=%u cur_uids[%.*s]\n",
              rte.name, rte.tport_id, (int) bout.count, bout.ptr );
  }
  if ( url_count > 0 ) {
    filter = (uint32_t *) dec.mem.make( url_count * 4 );
    url_count = 0;
    for ( ok = uid_in_mesh.first( uid ); ok; ok = uid_in_mesh.next( uid ) ) {
      mesh_n = this->bridge_tab.ptr[ uid ];
      for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
        if ( tport_id == rte.tport_id )
          continue;
        u_ptr = mesh_n->user_route_ptr( *this, tport_id );
        if ( u_ptr == NULL || ! u_ptr->is_valid() )
          continue;
        if ( u_ptr->is_set( MESH_URL_STATE ) &&
             u_ptr->rte.mesh_id == rte.mesh_id ) {
          filter[ url_count++ ] = u_ptr->url_hash;
          url_count++;
        }
      }
    }
  }
  u_ptr = n.user_route;
  MsgEst e( ibx.len() );
  e.seqno      ()
   .mesh_url   ( u_ptr->mesh_url.len )
   .tport      ( rte.transport.tport.len )
   .tportid    ()
   .mesh_filter( url_count * 4 );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno   ( n.inbox.next_send( U_INBOX_MESH_REQ ) )
   .mesh_url( u_ptr->mesh_url.val, u_ptr->mesh_url.len )
   .tport   ( rte.transport.tport.val, rte.transport.tport.len )
   .tportid ( rte.tport_id );
  if ( url_count > 0 )
    m.mesh_filter( filter, url_count * 4 );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
}

void
UserDB::process_unknown_adjacency( uint64_t current_mono_time ) noexcept
{
  this->peer_dist.clear_cache_if_dirty();
  AdjPending * next = NULL;
  for ( AdjPending *p = this->adjacency_unknown.hd; p != NULL; p = next ) {
    next = p->next;

    if ( p->request_time_mono != 0 &&
         p->request_time_mono +
           UserPendingRoute::pending_timeout_total >= current_mono_time )
      continue;

    if ( p->request_count > 5 || p->rec_count == 0 ) {
      next = p->next;
      this->adjacency_unknown.pop( p );
      this->remove_pending_peer( NULL, p->pending_seqno );
      delete p;
      continue;
    }

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
      if ( n->bridge_id.nonce != p->rec_list->nonce ) {
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

    p->request_time_mono = current_mono_time;
    p->request_count++;
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
  p = this->find_pending_peer( adj.rec_list->nonce, puid );
  if ( p != NULL )
    return p;

  p = new ( ::malloc( sizeof( UserPendingRoute ) ) )
    UserPendingRoute( adj.rec_list->nonce, puid, adj.rec_list->user,
                      adj.reason );
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

    bool     remove_pending = false,
             is_timeout     = false;
    size_t   n_pos;
    uint32_t uid;

    if ( this->zombie_ht->find( p->bridge_nonce, n_pos, uid ) ) {
      UserBridge *n = this->bridge_tab[ uid ];
      if ( n != NULL && n->last_auth_type == BYE_BYE )
        remove_pending = true;
    }
    if ( ! remove_pending &&
         p->request_count > UserPendingRoute::MAX_REQUESTS ) {
      remove_pending = true;
      is_timeout = true;
    }

    if ( remove_pending ) {
      char buf[ NONCE_B64_LEN + 1 ];
      UserBridge * n = this->bridge_tab[ p->ptr->uid ];
      printf( "%s pending peer [%s] (%.*s) -> %s (%s)\n",
              ( is_timeout ? "timeout" : "bye_bye" ),
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
   .seqno      ( n->inbox.next_send( U_INBOX_SYNC_REQ ) )
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
  return this->forward_to_inbox( *n, ibx, h, m.msg, m.len() );
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

