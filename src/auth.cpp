#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raims/session.h>
#include <raims/ev_inbox_transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

void
StageAuth::copy_from_peer( const MsgHdrDecoder &dec ) noexcept
{
  this->zero();
  dec.get_ival<uint64_t>( FID_TIME, this->time );
  dec.get_ival<uint64_t>( FID_SEQNO, this->seqno );
  dec.get_nonce( FID_CNONCE, this->cnonce );
}

bool
StageAuth::copy_from_auth( const MsgHdrDecoder &dec,
                           const StageAuth &auth ) noexcept
{
  this->zero();
  if ( dec.get_ival<uint64_t>( FID_AUTH_TIME, this->time ) &&
       dec.get_ival<uint64_t>( FID_AUTH_SEQNO, this->seqno ) ) {
    if ( auth.time == this->time && auth.seqno == this->seqno ) {
      this->cnonce = auth.cnonce;
      return true;
    }
  }
  return false;
}

void
StageAuth::construct( uint64_t time, uint64_t seqno,
                      const Nonce &nonce ) noexcept
{
  this->time   = time;
  this->seqno  = seqno;
  this->cnonce = nonce;
}

bool
StageAuth::copy_from_hb( const MsgHdrDecoder &dec,
                         const TransportRoute &rte ) noexcept
{
  this->zero();
  if ( dec.get_ival<uint64_t>( FID_AUTH_TIME, this->time ) &&
       dec.get_ival<uint64_t>( FID_AUTH_SEQNO, this->seqno ) ) {
    if ( rte.hb_time == this->time && rte.hb_seqno == this->seqno ) {
      this->cnonce = rte.hb_cnonce;
      return true;
    }
    else {
      for ( int i = 0; i < 3 && rte.auth[ i ].time != 0; i++ ) {
        if ( rte.auth[ i ].time == this->time &&
             rte.auth[ i ].seqno == this->seqno ) {
          this->cnonce = rte.auth[ i ].cnonce;
          return true;
        }
      }
    }
  }
  return false;
}

bool
UserDB::compare_version( UserBridge &n, MsgHdrDecoder &dec ) noexcept
{
  static const char * ver_str;
  static size_t       ver_len;

  if ( ver_len == 0 ) {
    ver_str = ms_get_version();
    ver_len = ::strlen( ver_str );
  }
  if ( ! dec.test( FID_VERSION ) ) {
    n.printf( "version not present\n" );
    return false;
  }
  else {
    size_t fsize = dec.mref[ FID_VERSION ].fsize;
    void * fptr  = dec.mref[ FID_VERSION ].fptr;
    if ( fsize != ver_len || ::memcmp( fptr, ver_str, ver_len ) != 0 ) {
      n.printe( "version diff: %.*s != %.*s\n", (int) fsize,
                (char *) fptr, (int) ver_len, ver_str );
      return false;
    }
  }
  n.printf( "version matches %.*s\n", (int) ver_len, ver_str );
  return true;
}
/* direct _I.Nonce.auth message */
bool
UserDB::on_inbox_auth( const MsgFramePublish &pub,  UserBridge &n,
                       MsgHdrDecoder &dec ) noexcept
{
  /* client hb / hello -> server
   * server challenge  -> client auth [stage 1]  client trusts server
   * client challenge  -> server auth [stage 2]  server trusts client
   * server trust      -> client      [stage 3]  server notifies trust */
  StageAuth tmp_auth;
  AuthStage stage = AUTH_NONE;
  uint32_t  stage_num = stage;
  AdjCost   cost( COST_DEFAULT );
  uint32_t  rem_tport_id = 0;

  if ( ! dec.get_ival<uint32_t>( FID_AUTH_STAGE, stage_num ) )
    return true;

  stage = (AuthStage) stage_num;
  if ( stage == 1 )
    this->compare_version( n, dec );
  if ( stage != AUTH_TRUST ) {
    if ( ! dec.test_4( FID_CNONCE, FID_AUTH_TIME, FID_AUTH_SEQNO, FID_PUBKEY ) )
      return true;
  }

  switch ( stage ) {
    /* replying to a hb send after client connects, usually _X.HELLO */
    case AUTH_FROM_HELLO:
      if ( ! n.auth[ 0 ].copy_from_hb( dec, n.user_route->rte ) ) {
        n.printf( "no hb found, stage 1\n" );
        return true;
      }
      break;
    /* replying to a challenge sent as a result of my challenge */
    case AUTH_FROM_HANDSHAKE:
      if ( ! tmp_auth.copy_from_auth( dec, n.auth[ 1 ] ) ) {
        n.printf( "no auth found, stage 2, challenge_count %u\n",
                  n.challenge_count );
        if ( dec.test( FID_START ) ) {
          uint64_t start = 0;
          cvt_number<uint64_t>( dec.mref[ FID_START ], start );
          if ( start > this->start_time && n.challenge_count < 5 ) {
            n.printf( "retry stage 1\n" );
            n.auth[ 0 ].construct( n.hb_time, n.hb_seqno, n.hb_cnonce );
            n.auth[ 1 ].construct( current_realtime_ns(),
                                   n.inbox.next_send( U_INBOX_AUTH ),
                                   this->cnonce->calc() );
            n.challenge_count++;
            this->send_challenge( n, AUTH_FROM_HELLO );
          }
        }
        return true;
      }
      n.auth[ 0 ] = tmp_auth;
      break;
    /* must be authenticated for stage 3, for trust msg */
    default: {
      if ( stage != AUTH_TRUST || ! n.is_set( AUTHENTICATED_STATE ) ) {
        char buf[ MAX_NONCE_STATE_STRING ];
        n.printe( "bad stage %u, state=%s\n", stage,
                  n.state_to_string( buf ) );
        return true;
      }
      break;
    }
  }

  if ( stage != AUTH_TRUST ) {
    if ( ! this->recv_challenge( pub, n, dec, stage ) ) {
      n.printf( "auth failed stage %u\n", stage );
      /*if ( n.test( AUTHENTICATED_STATE ) ) {
        this->remove_authenticated( n, true );
      }*/
      return true;
    }

    if ( debug_auth )
      n.printf( "auth success stage %u\n", stage );
    if ( ! n.is_set( AUTHENTICATED_STATE ) )
      this->add_authenticated( n, dec, stage, &n );

    n.auth[ 0 ].copy_from_peer( dec );
    n.auth[ 1 ].construct( current_realtime_ns(),
                           n.inbox.next_send( U_INBOX_AUTH ),
                           this->cnonce->calc() );
    /* stage 1, send a challenge back */
    if ( stage == AUTH_FROM_HELLO ) {
      this->send_challenge( n, AUTH_FROM_HANDSHAKE );
      if ( ! n.test_set( CHALLENGE_STATE ) ) {
        n.challenge_count++;
        this->challenge_queue.push( &n );
      }
    }
    else { /* AUTH_FROM_HANDSHAKE, stage 2, completed auth */
      this->send_trusted( pub, n, dec );
    }
  }
  else {
    this->recv_trusted( pub, n, dec );
  }
  if ( n.is_set( AUTHENTICATED_STATE ) ) {
    StringVal tport;
    if ( dec.test( FID_TPORT ) ) {
      tport.val = (const char *) dec.mref[ FID_TPORT ].fptr;
      tport.len = dec.mref[ FID_TPORT ].fsize;
    }
    if ( dec.get_ival<uint32_t>( FID_TPORTID, rem_tport_id ) ) {
      AdjCost cost;
      if ( cost.parse( (char *) dec.mref[ FID_ADJ_COST ].fptr,
                       dec.mref[ FID_ADJ_COST ].fsize ) == AdjCost::COST_OK )
        n.user_route->rte.update_cost( n, tport, &cost, rem_tport_id, "i1" );
      else
        n.user_route->rte.update_cost( n, tport, NULL, rem_tport_id, "i2" );
    }
    if ( ! n.test_set( SENT_ZADD_STATE ) ) {
      this->send_peer_add( n );    /* broadcast _Z.ADD with new peer */
      n.user_route->set( SENT_ZADD_STATE );
      this->send_peer_db( n ); /* populate peer with _I.<nonce>.add_rte */
      if ( ! this->adjacency_change.is_empty() )
        this->send_adjacency_change(); /* broadcast _Z.ADJ with adjacency */
    }
    if ( dec.test( FID_LINK_STATE ) ) {
      uint64_t link_state,
               sub_seqno;
      dec.get_ival<uint64_t>( FID_LINK_STATE, link_state );
      dec.get_ival<uint64_t>( FID_SUB_SEQNO, sub_seqno );
      if ( n.link_state_seqno < link_state || n.sub_seqno < sub_seqno ) {
        if ( debug_auth )
          n.printf( "auth link_state %" PRIu64 " != link_state %" PRIu64 " || "
                    "auth sub_seqno %" PRIu64 " != sub_seqno %" PRIu64 "\n", n.link_state_seqno,
                    link_state, n.sub_seqno, sub_seqno );
        this->send_adjacency_request( n, AUTH_SYNC_REQ );
      }
    }
    if ( ! n.is_set( IN_HB_QUEUE_STATE ) ) {
      if ( debug_auth )
        n.printf( "add to hb_queue\n" );
      this->events.hb_queue( n.uid, 0 );
      n.set( IN_HB_QUEUE_STATE );
      this->hb_queue.push( &n );
    }
  }
  return true;
}
/* compute the challenge and send the auth_key to peer */
bool
UserDB::send_challenge( UserBridge &n,  AuthStage stage ) noexcept
{
  InboxBuf   ibx( n.bridge_id, _AUTH );
  HashDigest challenge_ha1,
             encrypted_ha1;
  TransportRoute & rte = n.user_route->rte;
  PolyHmacDigest secret_hmac;
  StringVal mesh_url;
  if ( rte.mesh_id != NULL )
    mesh_url = rte.mesh_id->mesh_url;
  
  this->events.send_challenge( n.uid, rte.tport_id, stage );
  if ( debug_auth )
    n.printf( "send stage %u verify(%" PRIu64 ",%" PRIu64 ",0x%08" PRIx64 ")\n", stage,
              n.auth[ 0 ].seqno, n.auth[ 0 ].time,
              n.auth[ 0 ].cnonce.nonce[ 0 ] );
  const char * ver_str = ms_get_version();
  size_t       ver_len = ::strlen( ver_str );
  char         cost_buf[ 64 ];
  size_t       cost_len = rte.uid_connected.cost.str_size( cost_buf,
                                                          sizeof( cost_buf ) );

  MsgEst e( ibx.len() );
  e.user_hmac  ()
   .seqno      ()
   .version    ( ver_len )
   .time       ()
   .uptime     ()
   .interval   ()
   .sub_seqno  ()
   .link_state ()
   .auth_seqno ()
   .auth_time  ()
   .auth_key   ()
   .cnonce     ()
   .pubkey     ()
   .auth_stage ()
   .user       ( this->user.user.len )
   .create     ( this->user.create.len )
   .expires    ( this->user.expires.len )
   .start      ()
   .ucast_url  ( rte.ucast_url.len )
   .mesh_url   ( mesh_url.len )
   .adj_cost   ( cost_len )
   .tportid    ()
   .tport      ( rte.transport.tport.len )
   .host_id    ()
   .pk_sig     ();

  MsgCat m;
  m.reserve( e.sz );
  this->calc_secret_hmac( n, secret_hmac );
  challenge_ha1.kdf_challenge_secret( secret_hmac, n.bridge_id.nonce,
                                      this->bridge_id.nonce,
                                      n.auth[ 0 ].cnonce, n.auth[ 1 ].cnonce,
                                      n.auth[ 0 ].seqno, n.auth[ 0 ].time,
                                      stage );
  encrypted_ha1.encrypt_hash( challenge_ha1, *this->session_key );

  n.challenge_mono_time = current_monotonic_time_ns();
  uint64_t uptime = n.challenge_mono_time - this->start_mono_time;
  m.open( this->bridge_id.nonce, ibx.len() )
   .user_hmac  ( this->bridge_id.hmac   )
   .seqno      ( n.auth[ 1 ].seqno      )
   .time       ( n.auth[ 1 ].time       )
   .uptime     ( uptime                 )
   .interval   ( this->hb_interval      )
   .sub_seqno  ( this->sub_db.sub_seqno )
   .link_state ( this->link_state_seqno )
   .auth_seqno ( n.auth[ 0 ].seqno      )
   .auth_time  ( n.auth[ 0 ].time       )
   .auth_key   ( encrypted_ha1          )
   .cnonce     ( n.auth[ 1 ].cnonce     )
   .pubkey     ( this->hb_keypair->pub  )
   .auth_stage ( stage                  )
   .user       ( this->user.user.val, this->user.user.len )
   .create     ( this->user.create.val, this->user.create.len )
   .expires    ( this->user.expires.val, this->user.expires.len )
   .start      ( this->start_time       )
   .version    ( ver_str, ver_len       );

  if ( rte.ucast_url.len != 0 )
    m.ucast_url( rte.ucast_url.val, rte.ucast_url.len );
  if ( mesh_url.len != 0 )
    m.mesh_url( mesh_url.val, mesh_url.len );
  if ( rte.uid_connected.is_advertised )
    m.adj_cost( cost_buf, cost_len );
  m.tportid( rte.tport_id )
   .tport( rte.transport.tport.val, rte.transport.tport.len )
   .host_id( this->host_id );
  m.pk_sig();
  uint32_t h = ibx.hash();
  DSA * dsa = ( ! this->svc_dsa->sk.is_zero() ? this->svc_dsa : this->user_dsa );
  m.close( e.sz, h, CABA_INBOX );
  m.sign_dsa( ibx.buf, ibx.len(), *this->session_key, *this->hello_key, *dsa );
  m.sign( ibx.buf, ibx.len(), *this->session_key );
  secret_hmac.zero();
  encrypted_ha1.zero();
  challenge_ha1.zero();
  return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
}
/* compute the challenge and match the auth_key field */
bool
UserDB::recv_challenge( const MsgFramePublish &pub,  UserBridge &n,
                        const MsgHdrDecoder &dec,
                        AuthStage stage ) noexcept
{
  HashDigest challenge_ha1,
             encrypted_ha1,
             save_key;
  Nonce      recv_cnonce;
  PolyHmacDigest secret_hmac;

  this->events.recv_challenge( n.uid, pub.rte.tport_id, stage );
  recv_cnonce.copy_from( dec.mref[ FID_CNONCE ].fptr );
  n.hb_pubkey.copy_from( dec.mref[ FID_PUBKEY ].fptr );

  if ( debug_auth )
    n.printf( "recv stage %u verify(%" PRIu64 ",%" PRIu64 ",0x%08" PRIx64 ")\n", stage,
              n.auth[ 0 ].seqno, n.auth[ 0 ].time,
              n.auth[ 0 ].cnonce.nonce[ 0 ] );
  this->calc_secret_hmac( n, secret_hmac );
  challenge_ha1.kdf_challenge_secret( secret_hmac,
                                      this->bridge_id.nonce,
                                      n.bridge_id.nonce,
                                      n.auth[ 0 ].cnonce, recv_cnonce,
                                      n.auth[ 0 ].seqno, n.auth[ 0 ].time,
                                      stage );
  encrypted_ha1.copy_from( dec.mref[ FID_AUTH_KEY ].fptr );
  save_key = n.peer_key;
  n.peer_key.decrypt_hash( challenge_ha1, encrypted_ha1 );
  secret_hmac.zero();
  encrypted_ha1.zero();
  challenge_ha1.zero();
#if 0
  MsgBufVerify m( pub.msg, pub.msg_len, dec.mref[ FID_DIGEST ].fptr,
                  dec.mref[ FID_DIGEST ].fsize );
  return m.verify( n.peer_key, pub.hmac );
#endif
  if ( ! dec.msg->verify_sig( n.peer_hello, *this->svc_dsa ) ) {
    if ( ! dec.msg->verify_sig( n.peer_hello, n.peer.dsa ) ) {
      n.printe( "auth msg failed to verify with service %s public key\n",
                this->my_svc.service );
      return false;
    }
    else {
      n.printf( "auth msg verified with user public key\n" );
    }
  }
  else {
    n.printf( "auth msg verified with service %s public key\n",
              this->my_svc.service );
  }
  /* requires material from both peers, could fail even if sign ok if
   * my auth[] history is old, restart key exchange in that case */
  if ( ! dec.msg->verify( n.peer_key ) ) {
    n.peer_key = save_key;
    return false;
  }
  return true;
}
/* notify peer that it is trusted */
bool
UserDB::send_trusted( const MsgFramePublish &/*pub*/,  UserBridge &n,
                      MsgHdrDecoder & ) noexcept
{
  InboxBuf ibx( n.bridge_id, _AUTH );
  UserRoute      * u_ptr    = n.user_route;
  TransportRoute & rte      = u_ptr->rte;
  bool        in_mesh       = rte.uid_in_mesh->is_member( n.uid ),
              is_mcast      = rte.is_mcast();
  size_t      mesh_db_len   = 0,
              ucast_db_len  = 0;
  UrlDBFilter mesh_filter( n.uid, true ),
              ucast_filter( n.uid, false );
  Nonce       csum;

  csum.zero();
  if ( in_mesh )
    mesh_db_len = this->mesh_db_size( rte, mesh_filter, csum );
  if ( is_mcast )
    ucast_db_len = this->ucast_db_size( rte, ucast_filter );

  this->events.send_trust( n.uid, n.user_route->rte.tport_id, in_mesh );
  uint64_t uptime = current_monotonic_time_ns() - this->start_mono_time;
  char     cost_buf[ 64 ];
  size_t   cost_len = rte.uid_connected.cost.str_size( cost_buf,
                                                       sizeof( cost_buf ) );

  MsgEst e( ibx.len() );
  e.seqno     ()
   .time      ()
   .uptime    ()
   .interval  ()
   .sub_seqno ()
   .link_state()
   .auth_stage()
   .start     ()
   .adj_cost  ( cost_len )
   .tportid   ()
   .tport     ( rte.transport.tport.len )
   .host_id   ()
   .mesh_url  ( u_ptr->mesh_url.len )
   .mesh_db   ( mesh_db_len )
   .ucast_db  ( ucast_db_len );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno     ( n.auth[ 1 ].seqno  )
   .time      ( n.auth[ 1 ].time   )
   .uptime    ( uptime             )
   .interval  ( this->hb_interval  )
   .sub_seqno ( this->sub_db.sub_seqno )
   .link_state( this->link_state_seqno )
   .auth_stage( AUTH_TRUST         )
   .start     ( this->start_time   );
  if ( rte.uid_connected.is_advertised )
    m.adj_cost( cost_buf, cost_len );
  m.tportid( rte.tport_id )
   .tport   ( rte.transport.tport.val, rte.transport.tport.len )
   .host_id ( this->host_id );
  if ( mesh_db_len != 0 && u_ptr->mesh_url.len > 0 ) {
    m.mesh_url( u_ptr->mesh_url.val, u_ptr->mesh_url.len );
    this->mesh_db_submsg( rte, mesh_filter, m );
  }
  if ( ucast_db_len != 0 && u_ptr->ucast_url.len > 0 ) {
    m.ucast_url( u_ptr->ucast_url.val, u_ptr->ucast_url.len );
    this->ucast_db_submsg( rte, ucast_filter, m );
  }
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );

  m.sign( ibx.buf, ibx.len(), *this->session_key );
  bool b = this->forward_to_inbox( n, ibx, h, m.msg, m.len() );

  uint32_t count = this->transport_tab.count;
  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    if ( tport_id == rte.tport_id )
      continue;
    TransportRoute * rte = this->transport_tab.ptr[ tport_id ];
    if ( rte->is_set( TPORT_IS_SHUTDOWN ) )
      continue;
    if ( ! rte->uid_connected.is_member( n.uid ) )
      continue;
    u_ptr = NULL;
    if ( rte->is_mesh() ) {
      u_ptr = n.user_route_ptr( *this, tport_id );
      if ( ! u_ptr->is_valid() || ! u_ptr->is_set( MESH_URL_STATE ) )
        u_ptr = NULL;
    }
    else if ( rte->is_mcast() ) {
      u_ptr = n.user_route_ptr( *this, tport_id );
      if ( ! u_ptr->is_valid() || ! u_ptr->is_set( UCAST_URL_STATE ) )
        u_ptr = NULL;
    }

    UrlDBFilter mesh_filter2( n.uid, true );
    UrlDBFilter ucast_filter2( n.uid, false );
    csum.zero();
    size_t mesh_db_len   = 0,
           ucast_db_len  = 0,
           mesh_url_len  = 0,
           ucast_url_len = 0;

    if ( u_ptr != NULL ) {
      if ( rte->is_mesh() ) {
        mesh_db_len = this->mesh_db_size( *rte, mesh_filter2, csum );
        mesh_url_len = u_ptr->mesh_url.len;
      }
      else {
        ucast_db_len = this->ucast_db_size( *rte, ucast_filter2 );
        ucast_url_len = u_ptr->ucast_url.len;
      }
    }
    if ( debug_auth )
      n.printf( "send trust tport %s.%u mesh_db %u ucast_db %u\n",
                rte->transport.tport.val, tport_id,
                (uint32_t) mesh_db_len, (uint32_t) ucast_db_len );
    /*if ( mesh_db_len + ucast_db_len != 0 )*/ {
      MsgEst e( ibx.len() );
      cost_len = rte->uid_connected.cost.str_size( cost_buf,
                                                   sizeof( cost_buf ) );
      e.seqno     ()
       .time      ()
       .auth_stage()
       .start     ()
       .adj_cost  ( cost_len )
       .tportid   ()
       .tport     ( rte->transport.tport.len )
       .mesh_url  ( mesh_url_len )
       .mesh_db   ( mesh_db_len )
       .ucast_url ( ucast_url_len )
       .ucast_db  ( ucast_db_len );

      MsgCat m;
      m.reserve( e.sz );

      m.open( this->bridge_id.nonce, ibx.len() )
       .seqno     ( n.auth[ 1 ].seqno  )
       .time      ( n.auth[ 1 ].time   )
       .auth_stage( AUTH_TRUST         )
       .start     ( this->start_time   );

      if ( rte->uid_connected.is_advertised )
        m.adj_cost( cost_buf, cost_len );
      m.tportid( tport_id )
       .tport( rte->transport.tport.val, rte->transport.tport.len )
       .host_id( this->host_id );

      if ( mesh_db_len != 0 && mesh_url_len != 0 ) {
        m.mesh_url( u_ptr->mesh_url.val, u_ptr->mesh_url.len );
        this->mesh_db_submsg( *rte, mesh_filter2, m );
      }
      if ( ucast_db_len != 0 && ucast_url_len != 0 ) {
        m.ucast_url( u_ptr->ucast_url.val, u_ptr->ucast_url.len );
        this->ucast_db_submsg( *rte, ucast_filter2, m );
      }
      m.close( e.sz, h, CABA_INBOX );
      m.sign( ibx.buf, ibx.len(), *this->session_key );
      b |= this->forward_to( n, ibx.buf, ibx.len(), h, m.msg, m.len(), u_ptr);
    }
  }
  return b;
}

bool
UserDB::recv_trusted( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept
{
  if ( ! n.is_set( AUTHENTICATED_STATE ) )
    return true;
  bool in_mesh  = ( dec.test( FID_MESH_DB ) != 0 ),
       is_mcast = ( dec.test( FID_UCAST_DB ) != 0 );
  uint64_t start_time = 0/*, time = 0*/;
  dec.get_ival<uint64_t>( FID_START, start_time );
  /*dec.get_ival<uint64_t>( FID_TIME, time );*/
  if ( n.start_time == start_time /*&& time >= n.hb_time */) {
    this->events.recv_trust( n.uid, pub.rte.tport_id, in_mesh );

    if ( in_mesh )
      this->recv_mesh_db( pub, n, dec );
    if ( is_mcast )
      this->recv_ucast_db( pub, n, dec );
    if ( dec.test( FID_HOST_ID ) )
      this->update_host_id( n, dec );
  }
  /* could be hb between trust, start_time sufficient */
  /*else {
    n.printe( "ignore trusted, time not correct (%lu %lu) %d, (%lu %lu) %d\n",
              n.start_time, start_time, n.start_time == start_time,
              time, n.hb_time, time >= n.hb_time );
  }*/
  return true;
}

/* mark peer down on _X.BYE */
bool
UserDB::on_bye( const MsgFramePublish &pub,  UserBridge &n,
                const MsgHdrDecoder &dec ) noexcept
{
  uint64_t time;
  this->events.recv_bye( n.uid, pub.rte.tport_id );
  /* ignore bye which are not authenticated */
  if ( ! n.is_set( AUTHENTICATED_STATE ) )
    return true;
  if ( ! dec.get_ival<uint64_t>( FID_TIME, time ) )
    return true;
  /* check that it's not a replay */
  if ( dec.seqno > (uint64_t) n.hb_seqno && time >= n.hb_time ) {
    n.hb_seqno = dec.seqno;
    n.hb_time  = time;
    this->remove_authenticated( n, BYE_BYE );
    if ( debug_auth )
      n.printf( "bye\n" );
  }
  return true;
}
