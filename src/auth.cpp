#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
      n.printf( "version diff: %.*s != %.*s\n", (int) fsize,
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
  AuthStage stage = AUTH_UNKNOWN;
  uint32_t  stage_num = stage;

  if ( ! dec.get_ival<uint32_t>( FID_AUTH_STAGE, stage_num ) ||
       ! dec.get_ival<uint64_t>( FID_SEQNO, n.recv_inbox_seqno ) )
    return true;

  stage = (AuthStage) stage_num;
  if ( stage == 1 )
    this->compare_version( n, dec );
  if ( stage != AUTH_TRUST ) {
    if ( ! dec.test_3( FID_CNONCE, FID_AUTH_TIME, FID_AUTH_SEQNO ) )
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
            n.auth[ 1 ].construct( current_realtime_ns(), ++n.send_inbox_seqno,
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
    n.auth[ 1 ].construct( current_realtime_ns(), ++n.send_inbox_seqno,
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
    uint32_t cost[ COST_PATH_COUNT ] = { COST_DEFAULT, COST_DEFAULT,
                                         COST_DEFAULT, COST_DEFAULT };
    if ( dec.get_ival<uint32_t>( FID_COST, cost[ 0 ] ) ) {
      dec.get_ival<uint32_t>( FID_COST2, cost[ 1 ] );
      dec.get_ival<uint32_t>( FID_COST3, cost[ 2 ] );
      dec.get_ival<uint32_t>( FID_COST4, cost[ 3 ] );
      n.user_route->rte.update_cost( n, cost );
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
          n.printf( "auth link_state %lu != link_state %lu || "
                    "auth sub_seqno %lu != sub_seqno %lu\n", n.link_state_seqno,
                    link_state, n.sub_seqno, sub_seqno );
        this->send_adjacency_request( n, AUTH_SYNC_REQ );
      }
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
  
  this->events.send_challenge( n.uid, n.user_route->rte.tport_id, stage );
  if ( debug_auth )
    n.printf( "send stage %u verify(%lu,%lu,0x%08lx)\n", stage,
              n.auth[ 0 ].seqno, n.auth[ 0 ].time,
              n.auth[ 0 ].cnonce.nonce[ 0 ] );
  const char * ver_str = ms_get_version();
  size_t       ver_len = ::strlen( ver_str );

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
   .auth_stage ()
   .start      ()
   .ucast_url  ( rte.ucast_url_len )
   .mesh_url   ( rte.mesh_url_len )
   .cost       ()
   .cost2      ()
   .cost3      ()
   .cost4      ();

  MsgCat m;
  m.reserve( e.sz );
  challenge_ha1.kdf_challenge_secret( n.peer.secret_hmac, n.bridge_id.nonce,
                                      this->bridge_id.nonce,
                                      n.auth[ 0 ].cnonce, n.auth[ 1 ].cnonce,
                                      n.auth[ 0 ].seqno, n.auth[ 0 ].time,
                                      stage );
  encrypted_ha1.encrypt_hash( challenge_ha1, *this->session_key );

  n.challenge_mono_time = current_monotonic_time_ns();
  uint64_t uptime = n.challenge_mono_time - this->start_mono_time;
  m.open( this->bridge_id.nonce, ibx.len() )
   .user_hmac  ( this->bridge_id.hmac )
   .seqno      ( n.auth[ 1 ].seqno  )
   .time       ( n.auth[ 1 ].time   )
   .uptime     ( uptime             )
   .interval   ( this->hb_interval  )
   .sub_seqno  ( this->sub_db.sub_seqno )
   .link_state ( this->link_state_seqno )
   .auth_seqno ( n.auth[ 0 ].seqno  )
   .auth_time  ( n.auth[ 0 ].time   )
   .auth_key   ( encrypted_ha1      )
   .cnonce     ( n.auth[ 1 ].cnonce )
   .auth_stage ( stage              )
   .start      ( this->start_time   )
   .version    ( ver_str, ver_len   );

  if ( rte.ucast_url_len != 0 )
    m.ucast_url( rte.ucast_url_addr, rte.ucast_url_len );
  if ( rte.mesh_url_len != 0 )
    m.mesh_url( rte.mesh_url_addr, rte.mesh_url_len );
  if ( rte.uid_connected.is_advertised ) {
    m.cost( rte.uid_connected.cost[ 0 ] );
    m.cost2( rte.uid_connected.cost[ 1 ] );
    m.cost3( rte.uid_connected.cost[ 2 ] );
    m.cost4( rte.uid_connected.cost[ 3 ] );
  }
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );

  m.sign( ibx.buf, ibx.len(), *this->session_key );
  encrypted_ha1.zero();
  challenge_ha1.zero();
  return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}
/* compute the challenge and match the auth_key field */
bool
UserDB::recv_challenge( const MsgFramePublish &pub,  UserBridge &n,
                        const MsgHdrDecoder &dec,
                        AuthStage stage ) const noexcept
{
  HashDigest challenge_ha1,
             encrypted_ha1;
  Nonce      recv_cnonce;

  this->events.recv_challenge( n.uid, pub.rte.tport_id, stage );
  recv_cnonce.copy_from( dec.mref[ FID_CNONCE ].fptr );
  if ( debug_auth )
    n.printf( "recv stage %u verify(%lu,%lu,0x%08lx)\n", stage,
              n.auth[ 0 ].seqno, n.auth[ 0 ].time,
              n.auth[ 0 ].cnonce.nonce[ 0 ] );
  challenge_ha1.kdf_challenge_secret( n.peer.secret_hmac,
                                      this->bridge_id.nonce,
                                      n.bridge_id.nonce,
                                      n.auth[ 0 ].cnonce, recv_cnonce,
                                      n.auth[ 0 ].seqno, n.auth[ 0 ].time,
                                      stage );
  encrypted_ha1.copy_from( dec.mref[ FID_AUTH_KEY ].fptr );
  n.peer_key.decrypt_hash( challenge_ha1, encrypted_ha1 );
  encrypted_ha1.zero();
  challenge_ha1.zero();
#if 0
  MsgBufVerify m( pub.msg, pub.msg_len, dec.mref[ FID_DIGEST ].fptr,
                  dec.mref[ FID_DIGEST ].fsize );
  return m.verify( n.peer_key, pub.hmac );
#endif
  return dec.msg->verify( n.peer_key );
}
/* notify peer that it is trusted */
bool
UserDB::send_trusted( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept
{
  InboxBuf ibx( n.bridge_id, _AUTH );
  TransportRoute & rte = n.user_route->rte;
  bool         in_mesh     = pub.rte.uid_in_mesh->is_member( n.uid );
  size_t       mesh_db_len = 0;
  MeshDBFilter filter( n.uid, dec );

  if ( in_mesh )
    mesh_db_len = this->mesh_db_size( pub.rte, filter );

  this->events.send_trust( n.uid, n.user_route->rte.tport_id, in_mesh );
  uint64_t uptime = current_monotonic_time_ns() - this->start_mono_time;

  MsgEst e( ibx.len() );
  e.seqno     ()
   .time      ()
   .uptime    ()
   .interval  ()
   .sub_seqno ()
   .link_state()
   .auth_stage()
   .start     ()
   .cost      ()
   .cost2     ()
   .cost3     ()
   .cost4     ()
   .mesh_db   ( mesh_db_len );

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
  if ( rte.uid_connected.is_advertised ) {
    m.cost( rte.uid_connected.cost[ 0 ] );
    m.cost2( rte.uid_connected.cost[ 1 ] );
    m.cost3( rte.uid_connected.cost[ 2 ] );
    m.cost4( rte.uid_connected.cost[ 3 ] );
  }
  if ( mesh_db_len != 0 )
    this->mesh_db_submsg( pub.rte, filter, m );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );

  /*"  challenge : \"" HASH_DIGEST_NAME "-" HMAC_NAME "\",\n"*/
  m.sign( ibx.buf, ibx.len(), *this->session_key );
  return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}

bool
UserDB::recv_trusted( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept
{
  if ( ! n.is_set( AUTHENTICATED_STATE ) )
    return true;
  bool in_mesh = ( dec.test( FID_MESH_DB ) != 0 );
  this->events.recv_trust( n.uid, pub.rte.tport_id, in_mesh );
  if ( in_mesh )
    this->recv_mesh_db( pub, n, dec );
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
