#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define DECLARE_SUB_CONST
#include <raims/session.h>
#include <raims/transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

int rai::ms::dbg_flags; /* TCP_DBG | PGM_DBG | IBX_DBG */

SessionMgr::SessionMgr( EvPoll &p,  Logger &l,  ConfigTree &c,
                        ConfigTree::User &u,  ConfigTree::Service &s,
                        StringTab &st ) noexcept
           : EvSocket( p, p.register_type( "session_mgr" ) ),
             tree( c ), user( u ), svc( s ), next_timer( 1 ), timer_id( 0 ),
             user_db( p, u, s, this->sub_db, st, this->events ),
             sub_db( p, this->user_db, *this ),
             sys_bloom( 0 ), router_bloom( 0 ),
             console( *this ), log( l ), telnet( 0 ), telnet_tport( 0 )
{
  this->sock_opts = OPT_NO_POLL;
  this->tcp_accept_sock_type = p.register_type( "ev_tcp_tport" );
  this->tcp_connect_sock_type = p.register_type( "ev_tcp_tport_client" );
  this->tcp_conn_mgr_sock_type = p.register_type( "tcp_conn_mgr" );
  hello_h = kv_crc_c( X_HELLO, X_HELLO_SZ, 0 );
  hb_h    = kv_crc_c( X_HB,    X_HB_SZ,    0 );
  bye_h   = kv_crc_c( X_BYE,   X_BYE_SZ,   0 );
  add_h   = kv_crc_c( Z_ADD,   Z_ADD_SZ,   0 );
  del_h   = kv_crc_c( Z_DEL,   Z_DEL_SZ,   0 );
  blm_h   = kv_crc_c( Z_BLM,   Z_BLM_SZ,   0 );
  adj_h   = kv_crc_c( Z_ADJ,   Z_ADJ_SZ,   0 );
  md_init_auto_unpack();
  CabaMsg::init_auto_unpack();
}

int
SessionMgr::init_sock( void ) noexcept
{
  int pfd = this->poll.get_null_fd();
  this->events.startup( this->user_db.start_time );
  this->router_set.add( pfd );
  this->PeerData::init_peer( pfd, NULL, "session_mgr" );
  return this->poll.add_sock( this );
}

int
SessionMgr::init_session( const CryptPass &pwd ) noexcept
{
  if ( ! this->in_list( IN_ACTIVE_LIST ) ) {
    int status = this->init_sock();
    if ( status != 0 )
      return status;
  }
  if ( ! this->user_db.init( pwd, this->fd, this->tree ) ) {
    fprintf( stderr, "User DB failed to init\n" );
    return -1;
  }
  this->sub_db.init( this->fd );
  this->console.update_prompt();
  char nonce_buf[ NONCE_B64_LEN + 1 ];
  printf( "session %s.%s[%s] started, start time %lu.%lu\n",
          this->user.user.val,
          this->svc.svc.val,
          this->user_db.bridge_id.nonce.to_base64_str( nonce_buf ),
          this->user_db.start_time / SEC_TO_NS,
          this->user_db.start_time % SEC_TO_NS );
  /*this->sub_seqno = 0;*/

  InboxBuf ibx( this->user_db.bridge_id );
  this->ibx.len = ibx.len();
  this->ibx.init( ibx, _AUTH     , U_INBOX_AUTH );
  this->ibx.init( ibx, _SUBS     , U_INBOX_SUBS );
  this->ibx.init( ibx, _PING     , U_INBOX_PING );
  this->ibx.init( ibx, _PONG     , U_INBOX_PONG );
  this->ibx.init( ibx, _RESUB    , U_INBOX_RESUB );
  this->ibx.init( ibx, _REPSUB   , U_INBOX_REPSUB );
  this->ibx.init( ibx, _ADD_RTE  , U_INBOX_ADD_RTE );
  this->ibx.init( ibx, _SYNC_REQ , U_INBOX_SYNC_REQ );
  this->ibx.init( ibx, _SYNC_RPY , U_INBOX_SYNC_RPY );
  this->ibx.init( ibx, _BLOOM_REQ, U_INBOX_BLOOM_REQ );
  this->ibx.init( ibx, _BLOOM_RPY, U_INBOX_BLOOM_RPY );
  this->ibx.init( ibx, _ADJ_REQ  , U_INBOX_ADJ_REQ );
  this->ibx.init( ibx, _ADJ_RPY  , U_INBOX_ADJ_RPY );
  this->ibx.init( ibx, _MESH_REQ , U_INBOX_MESH_REQ );
  this->ibx.init( ibx, _MESH_RPY , U_INBOX_MESH_RPY );
  this->ibx.init( ibx, _TRACE    , U_INBOX_TRACE );
  this->ibx.init( ibx, _ACK      , U_INBOX_ACK );
  this->ibx.init( ibx, _ANY      , U_INBOX_ANY );

  McastBuf mcb;
  this->mch.len = mcb.len();
  this->mch.init( mcb, _PING     , U_MCAST_PING );

  if ( ! this->ibx.is_full() || ! this->mch.is_full() ) {
    fprintf( stderr, "not fully initialized\n" );
    exit( 1 );
  }
  /*         subscribe to    _I.USER.NONCE.> */
  /* can't add to u_tab[] maybe collision, since it is rand */
  this->ibx.hash = this->add_wildcard_rte( ibx.buf, this->ibx.len, U_INBOX );
  this->mch.hash = this->add_wildcard_rte( mcb.buf, this->mch.len, U_MCAST );

  this->add_rte( X_HELLO, X_HELLO_SZ, hello_h, U_SESSION_HELLO );/*_X.HELLO */
  this->add_rte( X_HB   , X_HB_SZ   , hb_h   , U_SESSION_HB );   /*_X.HB    */
  this->add_rte( X_BYE  , X_BYE_SZ  , bye_h  , U_SESSION_BYE );  /*_X.BYE   */
  this->add_rte( Z_ADD  , Z_ADD_SZ  , add_h  , U_PEER_ADD );     /*_Z.ADD   */
  this->add_rte( Z_DEL  , Z_DEL_SZ  , del_h  , U_PEER_DEL );     /*_Z.DEL   */
  this->add_rte( Z_BLM  , Z_BLM_SZ  , blm_h  , U_BLOOM_FILTER ); /*_Z.BLM   */
  this->add_rte( Z_ADJ  , Z_ADJ_SZ  , adj_h  , U_ADJACENCY );    /*_Z.ADJ   */
  this->add_wildcard_rte( S_JOIN , S_JOIN_SZ , U_SUB_JOIN );     /*_S.JOIN. */
  this->add_wildcard_rte( S_LEAVE, S_LEAVE_SZ, U_SUB_LEAVE );    /*_S.LEAV. */
  this->add_wildcard_rte( P_PSUB , P_PSUB_SZ , U_PSUB_START );   /*_P.PSUB. */
  this->add_wildcard_rte( P_PSTOP, P_PSTOP_SZ, U_PSUB_STOP );    /*_P.PSTP. */

  this->sub_db.bloom.add_route( this->ibx.len, this->ibx.hash );
  this->sub_db.bloom.add_route( this->mch.len, this->mch.hash );

  return 0;
}

void
SessionMgr::add_rte( const char *sub,  size_t sub_len,  uint32_t hash,
                     PublishType type ) noexcept
{
  this->sys_bloom.add( hash );
  if ( ! this->u_tab.set( hash, sub_len, type ) ) {
    fprintf( stderr, "hash %x pref %.*s repeats\n",
             hash, (int) sub_len, sub );
    exit( 1 );
  }
}

uint32_t
SessionMgr::add_wildcard_rte( const char *prefix,  size_t pref_len,
                              PublishType type ) noexcept
{
  uint32_t seed = this->poll.sub_route.prefix_seed( pref_len ),
           hash = kv_crc_c( prefix, pref_len, seed );
  this->sys_bloom.add_route( pref_len, hash );
  if ( type != U_INBOX && type != U_MCAST ) {
    if ( ! this->u_tab.set( hash, pref_len, type ) ) {
      fprintf( stderr, "hash %x pref %.*s repeats\n",
               hash, (int) pref_len, prefix );
      exit( 1 );
    }
  }
  return hash;
}

void
SessionMgr::start( void ) noexcept
{
  this->user_db.hello_hb();
  this->timer_id = ++this->next_timer;
  uint64_t ival = this->user_db.hb_interval * SEC_TO_NS;
  this->user_db.hb_ival_ns = ival;
  this->user_db.hb_ival_mask = ival;
  for ( int i = 1; i <= 32; i *= 2 )
    this->user_db.hb_ival_mask |= ( this->user_db.hb_ival_mask >> i );
  this->poll.timer.add_timer_nanos( this->fd, ival / 1000, this->timer_id, 0 );
}

void
SessionMgr::stop( void ) noexcept
{
  this->user_db.bye_hb();
  this->timer_id = 0;
}

bool
SessionMgr::timer_expire( uint64_t tid,  uint64_t ) noexcept
{
  uint64_t cur_mono = this->poll.timer.current_monotonic_time_ns(),
           cur_time = this->poll.timer.current_time_ns();
  if ( tid != this->timer_id )
    return false;
  this->user_db.interval_hb( cur_mono, cur_time );
  this->user_db.check_user_timeout( cur_mono, cur_time );
  if ( this->console.log_rotate_time <= cur_time )
    this->console.rotate_log();
  this->console.on_log( this->log );
  return true;
}

void
MsgFramePublish::print( const char *what ) const noexcept
{
  char buf[ MAX_NONCE_STATE_STRING ];
  if ( this->n != NULL ) {
    this->n->printf( "%s %.*s, %s\n", what,
                     (int) this->subject_len, this->subject,
                     this->n->state_to_string( buf ) );
  }
  else {
    const MsgHdrDecoder & dec = this->dec;
    ::strcpy( buf, "unkown" );
    if ( dec.test( FID_BRIDGE ) ) {
      Nonce src_bridge_id;
      src_bridge_id.copy_from( dec.mref[ FID_BRIDGE ].fptr );
      src_bridge_id.to_base64_str( buf );
    }
    printf( "%s %.*s, unknown source [%s]\n", what,
             (int) this->subject_len, this->subject, buf );
  }
  MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );
  if ( this->dec.msg != NULL ) {
    this->dec.msg->print( &mout, 1, "%19s : ", NULL );
  }
  else {
    mout.print_hex( this->msg, this->msg_len );
  }
}

const char *
MsgFramePublish::status_string( void ) const noexcept
{
  switch ( this->status ) {
    default:
    case FRAME_STATUS_UNKNOWN:   return "unknown";
    case FRAME_STATUS_OK:        return "ok";
    case FRAME_STATUS_DUP_SEQNO: return "dup_seqno";
    case FRAME_STATUS_NO_AUTH:   return "no_auth";
    case FRAME_STATUS_NO_USER:   return "no_user";
    case FRAME_STATUS_BAD_MSG:   return "bad_msg";
    case FRAME_STATUS_MY_MSG:    return "my_msg";
  }
}

void
SessionMgr::ignore_msg( const MsgFramePublish &fpub ) noexcept
{
  d_sess( "From src_route %d/%s status %d/%s\n", fpub.src_route,
           fpub.rte.name, fpub.status, fpub.status_string() );
  if ( debug_sess )
    fpub.print( "Ignoring" );
}

MsgFrameStatus
SessionMgr::parse_msg_hdr( MsgFramePublish &fpub ) noexcept
{
  MsgHdrDecoder & dec = fpub.dec;

  if ( dec.decode_msg() != 0 ||
       ! dec.get_ival<uint64_t>( FID_SEQNO, dec.seqno ) )
    return fpub.status = FRAME_STATUS_BAD_MSG;

  PublishType  type  = MCAST_SUBJECT;
  CabaTypeFlag tflag = dec.msg->caba.type_flag();
  if ( tflag != CABA_MCAST ) {
    uint8_t i;
    /* an inbox subject */
    if ( tflag == CABA_INBOX ) {
      /* match _I.Nonce. + hash( _I.Nonce. ) */
      for ( i = 0; i < fpub.prefix_cnt; i++ ) {
        if ( fpub.hash[ i ] == this->ibx.hash &&
             fpub.prefix[ i ] == this->ibx.len ) {
          const char * num = &fpub.subject[ this->ibx.len ];
          size_t       len = fpub.subject_len - this->ibx.len;
          if ( len > 0 && num[ 0 ] >= '0' && num[ 0 ] <= '9' ) {
            type = U_INBOX;
            /* if _I.Nonce.<int> */
            uint64_t ret = num[ 0 ] - '0';
            for ( size_t i = 1; i < len; i++ ) {
              if ( num[ i ] >= '0' || num[ i ] <= '9' )
                ret = ( ret * 10 ) + ( num[ i ] - '0' );
            }
            dec.inbox_ret = (uint32_t) ret;
          }
          else {
            /* inbox routing, match subject
             * _I.Nonce.auth, _I.Nonce.subs, _I.Nonce.ping, ... */
            type = this->ibx.lookup( fpub.subj_hash, fpub.subject_len );
          }
          break;
        }
      }
    }
    /* heartbeat: _X.HELLO, _X.HB, _X.BYE */
    else if ( tflag == CABA_HEARTBEAT ) {
      type = this->u_tab.lookup( fpub.subj_hash, fpub.subject_len );
    }
    else if ( tflag == CABA_RTR_ALERT ) {
      /* _Z.ADD, _Z.ADJ */
      type = this->u_tab.lookup( fpub.subj_hash, fpub.subject_len );
      if ( type == U_NORMAL ) {
        /* control message: _S.JOIN. _S.LEAV. _P.PSUB. _P.PSTP. _M. */
        for ( i = 0; i < fpub.prefix_cnt; i++ ) {
          /* match _M. + hash( _M. ) */
          if ( fpub.hash[ i ] == this->mch.hash &&
               fpub.prefix[ i ] == this->mch.len )
            type = this->mch.lookup( fpub.subj_hash, fpub.subject_len );
          else
            type = this->u_tab.lookup( fpub.hash[ i ], fpub.prefix[ i ] );
          if ( type != U_NORMAL )
            break;
        }
      }
    }
    if ( type == U_NORMAL ) {
      printf( "?? %.*s %s %s\n", (int) fpub.subject_len, fpub.subject,
              caba_type_flag_str( tflag ), publish_type_to_string( type ) );
    }
  }
  dec.type = type;

  fpub.n = this->user_db.lookup_user( fpub, dec );
  if ( fpub.status == FRAME_STATUS_MY_MSG )
    return FRAME_STATUS_MY_MSG;

  return fpub.status;
}

bool
SessionMgr::on_msg( EvPublish &pub ) noexcept
{
  if ( pub.src_route == (uint32_t) this->fd )
    return true;
  if ( pub.pub_type != 'X' ) {
    fprintf( stderr, "Publish has no frame %.*s\n",
             (int) pub.subject_len, pub.subject );
    return true;
  }
  MsgFramePublish & fpub = (MsgFramePublish &) pub;
  /* find user and determine message type */
  if ( fpub.dec.type == UNKNOWN_SUBJECT ) {
    if ( fpub.status != FRAME_STATUS_UNKNOWN ) /* bad msg or no user */
      return true;
    if ( this->parse_msg_hdr( fpub ) == FRAME_STATUS_MY_MSG )
      return true;
  }
  const PublishType type = fpub.dec.type;
  /* adj messages may occur before user is known */
  if ( fpub.status == FRAME_STATUS_NO_USER && type == U_ADJACENCY ) {
    this->user_db.save_unauthorized_adjacency( fpub );
    return true;
  }
  /* if other status, can't process it */
  if ( fpub.status != FRAME_STATUS_NO_AUTH && fpub.status != FRAME_STATUS_OK ) {
    this->ignore_msg( fpub );
    return true;
  }
  UserBridge & n = *fpub.n;
  if ( debug_msg ) { /* message recv debug */
    /* skip _X.HB if not debugging hb */
    const bool show_msg = ( debug_hb || pub.subject[ 0 ] != '_' ||
                            pub.subject[ 1 ] != 'X' );
    if ( show_msg && debug_msgr ) {
      n.printf( "### %.*s (len=%lu, flags=%s, type=%s, from %s)\n",
                (int) fpub.subject_len, fpub.subject,
                fpub.msg_len,
                fpub.dec.msg->caba.type_str(),
                publish_type_to_string( type ),
                fpub.rte.name );
      MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );
      fpub.dec.msg->print( &mout, 1, "%19s : ", NULL );
    }
    if ( show_msg && debug_msgh ) {
      MDOutput mout;
      mout.print_hex( fpub.msg, fpub.msg_len );
    }
  }
  MsgHdrDecoder & dec = fpub.dec;
  static const uint64_t session_type =
    ( (uint64_t) 1 << U_SESSION_HELLO ) | ( (uint64_t) 1 << U_SESSION_HB ) |
    ( (uint64_t) 1 << U_SESSION_BYE ) | ( (uint64_t) 1 << U_INBOX_AUTH );

  if ( (( (uint64_t) 1 << type ) & session_type) != 0 ) {
    if ( fpub.status == FRAME_STATUS_NO_AUTH ) {
      const HashDigest * key = &n.peer_key;
      if ( type == U_SESSION_HELLO || type == U_SESSION_HB )
        key = &n.peer.hello_key;
      /* inbox auth has key exchange encrypted, that is used to verify msg */
      if ( type == U_INBOX_AUTH || dec.msg->verify( *key ) )
      /*|| m.verify( *key, fpub.hmac )*/
        fpub.status = FRAME_STATUS_OK;
      else if ( debug_sess ) {
        n.printf( "hello failed %.*s\n", (int) fpub.subject_len, fpub.subject );
      }
    }
    if ( fpub.status == FRAME_STATUS_OK ) {
      if ( type != U_SESSION_BYE ) {
        if ( ! n.is_set( INBOX_ROUTE_STATE ) ) 
          this->user_db.add_inbox_route( n, NULL ); /* need an inbox */
      }
      /* authorize user by verifying the ECDH key exchange */
      if ( type == U_INBOX_AUTH )
        return this->user_db.on_inbox_auth( fpub, n, dec );
      /* maybe authorize if needed by starting ECDH exchange */
      if ( type == U_SESSION_HELLO || type == U_SESSION_HB )
        return this->user_db.on_heartbeat( fpub, n, dec );
      /* ciao frog */
      return this->user_db.on_bye( fpub, n, dec );
    }
  }
  else if ( fpub.status == FRAME_STATUS_NO_AUTH ) {
    /* move from FRAME_STATUS_NO_AUTH -> FRAME_STATUS_OK */
    if ( dec.msg->verify( n.peer_key ) )
      fpub.status = FRAME_STATUS_OK;
    else if ( debug_sess ) {
      n.printf( "verify failed %.*s\n", (int) fpub.subject_len, fpub.subject );
      /*printf( "ha1: " ); n.ha1.print(); printf( "\n" );*/
    }
  }
  /* the _X.HELLO, _X.HB, _X.BYE messages and _I.Nonce.auth message */
  /* authentication happens above, must be authenticated */
  if ( ! n.is_set( AUTHENTICATED_STATE ) || fpub.status != FRAME_STATUS_OK ) {
    /* adj messages may occur before user is authorized */
    if ( fpub.status == FRAME_STATUS_NO_AUTH && type == U_ADJACENCY ) {
      this->user_db.save_unauthorized_adjacency( fpub );
      return true;
    }
    /* ignore other msgs until authenticated */
    this->ignore_msg( fpub );
    return true;
  }
  if ( ( fpub.flags & MSG_FRAME_ACK_CONTROL ) == 0 ) {
    uint16_t opt = dec.msg->caba.opt_flag();
    fpub.flags |= MSG_FRAME_ACK_CONTROL;
    if ( opt != CABA_OPT_NONE ) {
      if ( ( opt & CABA_OPT_ACK ) != 0 )
        this->send_ack( fpub, n, dec, _ACK );
      if ( ( opt & CABA_OPT_TRACE ) != 0 )
        this->send_ack( fpub, n, dec, _TRACE );
    }
  }
  /* dispatch other subject types */
  switch ( type ) {
    case U_SUB_JOIN:      /* _S.JOIN.subject */
    case U_SUB_LEAVE:     /* _S.LEAV.subject */
    case U_PSUB_START:    /* _P.PSUB.wildcard */
    case U_PSUB_STOP:     /* _P.PSTP.wildcard */
      if ( dec.seqno == n.sub_seqno + 1 ) {
        /* the leave, stop must be updated in order, dropping subs which have no
         * start will cause corruption of the bloom */
        n.sub_seqno = dec.seqno;
        n.sub_recv_mono_time = current_monotonic_time_ns();
        this->sub_db.sub_update_mono_time = n.sub_recv_mono_time;
        switch ( type ) {
          case U_SUB_JOIN:   return this->sub_db.recv_sub_start( fpub, n, dec );
          case U_SUB_LEAVE:  return this->sub_db.recv_sub_stop( fpub, n, dec );
          case U_PSUB_START: return this->sub_db.recv_psub_start( fpub, n, dec );
          case U_PSUB_STOP:  return this->sub_db.recv_psub_stop( fpub, n, dec );
          default: break;
        }
      }
      if ( dec.seqno <= n.sub_seqno ) {
        if ( debug_sess )
          n.printf( "%.*s ignoring sub seqno replay %lu -> %lu (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.sub_seqno, dec.seqno, fpub.rte.name );
      }
      else if ( n.sub_seqno != 0 ) {
        n.printf( "%.*s missing sub seqno %lu -> %lu (%s)\n",
                  (int) fpub.subject_len, fpub.subject,
                  n.sub_seqno, dec.seqno, fpub.rte.name );
      }
      fpub.status = FRAME_STATUS_DUP_SEQNO;
      break;

    case U_PEER_ADD:       /* _Z.ADD */
    case U_PEER_DEL:       /* _Z.DEL */
    case U_BLOOM_FILTER:   /* _Z.BLM */
    case U_ADJACENCY: {    /* _Z.ADJ */
      if ( dec.seqno > n.recv_peer_seqno ) {
        n.recv_peer_seqno = dec.seqno;
        /* bloom and adj are sequenced independently (sub_seqno, link_state) */
        switch ( type ) {
          case U_BLOOM_FILTER: return this->sub_db.recv_bloom_result( fpub, n, dec );
          case U_PEER_ADD:     return this->user_db.recv_peer_add( fpub, n, dec, AUTH_FROM_PEER_ADD );
          case U_PEER_DEL:     return this->user_db.recv_peer_del( fpub, n, dec );
          case U_ADJACENCY:    return this->user_db.recv_adjacency_change( fpub, n, dec );
          default: break;
        }
      }
      else {
        if ( debug_sess ) {
          n.printf( "%.*s ignoring peer seqno replay %lu -> %lu (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.recv_peer_seqno, dec.seqno, fpub.rte.name );
        }
        fpub.status = FRAME_STATUS_DUP_SEQNO;
      }
      break;
    }
    case U_INBOX_SUBS:      /* _I.Nonce.subs      */
    case U_INBOX_PING:      /* _I.Nonce.ping      */
    case U_INBOX_PONG:      /* _I.Nonce.pong      */
    case U_INBOX_RESUB:     /* _I.Nonce.resub     */
    case U_INBOX_REPSUB:    /* _I.Nonce.repsub    */
    case U_INBOX_ADD_RTE:   /* _I.Nonce.add_rte   */
    case U_INBOX_SYNC_REQ:  /* _I.Nonce.sync_req  */
    case U_INBOX_SYNC_RPY:  /* _I.Nonce.sync_rpy  */
    case U_INBOX_BLOOM_REQ: /* _I.Nonce.bloom_req */
    case U_INBOX_BLOOM_RPY: /* _I.Nonce.bloom_rpy */
    case U_INBOX_ADJ_REQ:   /* _I.Nonce.adj_req   */
    case U_INBOX_ADJ_RPY:   /* _I.Nonce.adj_rpy   */
    case U_INBOX_MESH_REQ:  /* _I.Nonce.mesh_req   */
    case U_INBOX_MESH_RPY:  /* _I.Nonce.mesh_rpy   */
      if ( dec.seqno > n.recv_inbox_seqno ) {
        if ( n.recv_inbox_seqno != 0 && dec.seqno != n.recv_inbox_seqno + 1 ) {
          n.printf( "%.*s missing inbox seqno %lu -> %lu (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.recv_inbox_seqno, dec.seqno, fpub.rte.name );
        }
        /* these should be in order, otherwise message loss occurred */
        n.recv_inbox_seqno = dec.seqno;
        switch ( type ) {
          case U_INBOX_SUBS:      return this->sub_db.recv_subs_request( fpub, n, dec );
          case U_INBOX_PING:      return this->user_db.recv_ping_request( fpub, n, dec );
          case U_INBOX_PONG:      return this->user_db.recv_pong_result( fpub, n, dec );
          case U_INBOX_RESUB:     return this->sub_db.recv_resub_result( fpub, n, dec );
          case U_INBOX_REPSUB:    return this->sub_db.recv_repsub_result( fpub, n, dec );
          case U_INBOX_ADD_RTE:   return this->user_db.recv_add_route( fpub, n, dec );
          case U_INBOX_SYNC_REQ:  return this->user_db.recv_sync_request( fpub, n, dec );
          case U_INBOX_SYNC_RPY:  return this->user_db.recv_sync_result( fpub, n, dec );
          case U_INBOX_BLOOM_REQ: return this->sub_db.recv_bloom_request( fpub, n, dec );
          case U_INBOX_BLOOM_RPY: return this->sub_db.recv_bloom_result( fpub, n, dec );
          case U_INBOX_ADJ_REQ:   return this->user_db.recv_adjacency_request( fpub, n, dec );
          case U_INBOX_ADJ_RPY:   return this->user_db.recv_adjacency_result( fpub, n, dec );
          case U_INBOX_MESH_REQ:  return this->user_db.recv_mesh_request( fpub, n, dec );
          case U_INBOX_MESH_RPY:  return this->user_db.recv_mesh_result( fpub, n, dec );
          default: break;
        }
      }
      else {
        n.printf( "%.*s ignoring inbox seqno replay %lu -> %lu (%s)\n",
                  (int) fpub.subject_len, fpub.subject,
                  n.recv_inbox_seqno, dec.seqno, fpub.rte.name );
        fpub.status = FRAME_STATUS_DUP_SEQNO;
      }
      break;

    case U_MCAST_PING:
    case U_MCAST:
      if ( dec.seqno > n.recv_mcast_seqno ) {
        if ( n.recv_mcast_seqno != 0 && dec.seqno != n.recv_mcast_seqno + 1 ) {
          n.printf( "%.*s missing mcast seqno %lu -> %lu (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.recv_mcast_seqno, dec.seqno, fpub.rte.name );
        }
        n.recv_mcast_seqno = dec.seqno;
        return this->user_db.recv_ping_request( fpub, n, dec );
      }
      else {
        n.printf( "%.*s ignoring mcast seqno replay %lu -> %lu (%s)\n",
                  (int) fpub.subject_len, fpub.subject,
                  n.recv_mcast_seqno, dec.seqno, fpub.rte.name );
        fpub.status = FRAME_STATUS_DUP_SEQNO;
      }
      break;

    case U_NORMAL:        /* _SUBJECT */
    case U_INBOX:         /* _I.Nonce.<inbox_ret> */
    case U_INBOX_TRACE:   /* _I.Nonce.trace */
    case U_INBOX_ACK:     /* _I.Nonce.ack */
    case U_INBOX_ANY:     /* _I.Nonce.any */
    case MCAST_SUBJECT: { /* SUBJECT */
      void * data    = NULL;
      size_t datalen = 0;
      if ( dec.test( FID_DATA ) ) {
        data    = dec.mref[ FID_DATA ].fptr;
        datalen = dec.mref[ FID_DATA ].fsize;
      }
      SubMsgData  val( fpub, n, data, datalen );
      SubOnMsg  * cb = NULL;
      RouteLoc    loc;
      uint64_t    start_seqno = 0;
      SeqnoStatus status;

      val.seqno = dec.seqno;
      dec.get_ival<uint64_t>( FID_TIME,  val.time );
      dec.get_ival<uint64_t>( FID_TOKEN, val.token );
      dec.get_ival<uint32_t>( FID_RET,   val.reply );

      /* if _I.Nonce.<inbox_ret>, find the inbox_ret */
      if ( dec.inbox_ret != 0 || type == U_INBOX_ANY ) {
        if ( dec.seqno != n.recv_inbox_seqno + 1 ) {
          n.printf( "%.*s missing inbox return seqno %lu -> %lu (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.recv_inbox_seqno, dec.seqno, fpub.rte.name );
        }
        /* these should be in order, otherwise message loss occurred */
        n.recv_inbox_seqno = dec.seqno;
        status = SEQNO_UID_NEXT;
        if ( type != U_INBOX_ANY ) {
          const char * num = &fpub.subject[ this->ibx.len ];
          size_t       len = fpub.subject_len - this->ibx.len;
          InboxSub   * ibx = this->sub_db.inbox_tab.find(
                                     kv_hash_uint( dec.inbox_ret ), num, len );
          if ( ibx == NULL ) {
            n.printf( "%.*s inbox not found (%s)\n", (int) fpub.subject_len,
                      fpub.subject, fpub.rte.name );
            return true;
          }
          cb = ibx->on_data;
        }
        else if ( dec.test( FID_SUBJECT ) ) {
          const char * sub    = (const char *) dec.mref[ FID_SUBJECT ].fptr;
          uint16_t     sublen = dec.mref[ FID_SUBJECT ].fsize;
          cb = this->sub_db.match_any_sub( sub, sublen );
          if ( cb == NULL ) {
            n.printf( "%.*s any match not found (%s)\n", (int) sublen, sub,
                      fpub.rte.name );
            return true;
          }
        }
      }
      /* find the subject and matching subscription */
      else {
        SubSeqno  * seq;
        seq = this->sub_db.seqno_tab.upsert( fpub.subj_hash, fpub.subject,
                                             fpub.subject_len, loc );
        /* find the matching sub */
        if ( seq != NULL ) {
          /* starting a new uid/seqno/time triplet */
          if ( loc.is_new ) {
            if ( ! this->sub_db.match_subscription( fpub, start_seqno, cb ) ) {
              this->sub_db.seqno_tab.remove( loc );
              return true;
            }
            status = seq->init( n.uid, dec.seqno, start_seqno, val.time,
                                this->sub_db.sub_seqno, cb );
          }
          else {
            /* if not inbox, check if subscription modified */
            if ( start_seqno != 0 && seq->sub_seqno != this->sub_db.sub_seqno ) {
              if ( this->sub_db.sub_list.exists( seq->start_seqno ) )
                seq->sub_seqno = this->sub_db.sub_seqno;
              /* if another sub matches */
              else if ( this->sub_db.match_subscription( fpub, start_seqno,
                                                         cb ) ) {
                seq->start_seqno = start_seqno;
                seq->sub_seqno   = this->sub_db.sub_seqno;
                seq->on_data     = cb;
              }
              /* otherwise, no sub matches */
              else {
                seq->release();
                this->sub_db.seqno_tab.remove( loc );
                return true;
              }
            }
            status = seq->update( n.uid, dec.seqno, val.time,
                                  val.last_seqno, val.last_time );
            cb = seq->on_data;
          }
        }
        else {
          fpub.status = FRAME_STATUS_DUP_SEQNO;
          n.printf( "%.*s seqno error (%s)\n", (int) fpub.subject_len,
                    fpub.subject, fpub.rte.name );
          return true;
        }
      }
      if ( status == SEQNO_UID_REPEAT ) {
#define SEQNO_MISSING( x, y ) ( ( x == y ) ? "repeat" : "missing" ), x, y
        fpub.status = FRAME_STATUS_DUP_SEQNO;
        n.printf( "%.*s %s seqno %lu -> %lu (%s)\n",
                  (int) fpub.subject_len, fpub.subject,
                  SEQNO_MISSING( val.seqno, dec.seqno ),
                  fpub.rte.name );
        return true;
      }
      /*n.printf( "%.*s seqno ok (%s)\n",
                (int) fpub.subject_len, fpub.subject,
                fpub.rte.name );*/
      /*if ( status == SEQNO_UID_FIRST )
        n.add_subject_hash( PUB_HT, pub.subj_hash );*/
      if ( dec.test( FID_FMT ) )
        cvt_number<uint32_t>( dec.mref[ FID_FMT ], val.fmt );
      cb->on_data( val );
      break;
    }
    default:
      n.printf( "no sub type\n" );
      break;
  }
  return true;
}

bool
SessionMgr::publish( PubMcastData &mc ) noexcept
{
  if ( ( mc.option & CABA_OPT_ANY ) != 0 )
    return this->publish_any( mc );

  UserBridge * dest_bridge_id = NULL;
  uint32_t     h  = kv_crc_c( mc.sub, mc.sublen, 0 );
  CabaFlags    fl( CABA_MCAST );
  bool         need_seqno = ( mc.seqno == 0 );
  
  if ( mc.sublen > 2 && mc.sub[ 0 ] == '_' ) {
    static const char   inbox_prefix[] = _INBOX ".",
                        mcast_prefix[] = _MCAST ".";
    static const size_t inbox_prefix_len = sizeof( inbox_prefix ) - 1,
                        mcast_prefix_len = sizeof( mcast_prefix ) - 1;
    if ( ::memcmp( inbox_prefix, mc.sub, inbox_prefix_len ) == 0 ) {
      dest_bridge_id = this->user_db.is_inbox_sub( mc.sub, mc.sublen );
      if ( dest_bridge_id != NULL ) {
        mc.seqno = ++dest_bridge_id->send_inbox_seqno;
        need_seqno = false;
        fl.set_type( CABA_INBOX );
      }
    }
    else if ( ::memcmp( mcast_prefix, mc.sub, mcast_prefix_len ) == 0 ) {
      mc.seqno = ++this->user_db.mcast_seqno;
      need_seqno = false;
    }
    if ( caba_rtr_alert( mc.sub ) )
      fl.set_type( CABA_RTR_ALERT );
  }
  if ( need_seqno ) {
    RouteLoc loc;
    Pub * p = this->sub_db.pub_tab.upsert( h, mc.sub, mc.sublen, loc );
    if ( p == NULL )
      return false;
    if ( loc.is_new )
      p->init();
    mc.seqno = p->next_seqno();
  }

  MsgEst e( mc.sublen );
  e.seqno ()
   .ret   ()
   .time  ()
   .token ()
   .fmt   ()
   .data  ( mc.datalen );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, mc.sublen )
   .seqno ( mc.seqno );

  if ( mc.reply != 0 )
    m.ret( mc.reply );
  if ( mc.time != 0 )
    m.time( mc.time );
  if ( mc.token != 0 )
    m.token( mc.token );
  if ( mc.fmt != 0 )
    m.fmt( mc.fmt );
  if ( mc.datalen != 0 )
    m.data( (const char *) mc.data, mc.datalen );
  if ( mc.option != 0 )
    fl.set_opt( mc.option );
  m.close( e.sz, h, fl );

  m.sign( mc.sub, mc.sublen, *this->user_db.session_key );
  bool b = true;
  if ( dest_bridge_id == NULL ) {
    EvPublish pub( mc.sub, mc.sublen, NULL, 0, m.msg, m.len(), this->fd, h,
                   NULL, 0, (uint8_t) MSG_BUF_TYPE_ID, 'p' );
    size_t count = this->user_db.transport_tab.count;
    for ( size_t i = 0; i < count; i++ ) {
      TransportRoute *rte = this->user_db.transport_tab.ptr[ i ];
      if ( rte->connect_count > 0 ) {
        b &= rte->sub_route.forward_except( pub, this->router_set );
      }
    }
  }
  else {
    b = this->user_db.forward_to_inbox( *dest_bridge_id, mc.sub, mc.sublen, h,
                                        m.msg, m.len() );
  }
  return b;
}

bool
SessionMgr::publish_any( PubMcastData &mc ) noexcept
{
  uint32_t     h = kv_crc_c( mc.sub, mc.sublen, 0 );
  UserBridge * n = this->sub_db.any_match( mc.sub, mc.sublen, h );

  if ( n == NULL ) {
    printf( "no match for %.*s\n", (int) mc.sublen, mc.sub );
    return true;
  }
  PubPtpData ptp( *n, mc );
  ptp.option |= CABA_OPT_ANY;
  return this->publish_to( ptp );
}

bool
SessionMgr::publish_to( PubPtpData &ptp ) noexcept
{
  InboxBuf  ibx( ptp.peer.bridge_id );
  CabaFlags fl( CABA_INBOX );

  if ( ptp.reply )
    ibx.i( ptp.reply );
  else
    ibx.s( _ANY );
  ptp.seqno = ++ptp.peer.send_inbox_seqno;

  MsgEst e( ibx.len() );
  e.seqno  ()
   .subject( ptp.sublen )
   .ret    ()
   .time   ()
   .token  ()
   .fmt    ()
   .data   ( ptp.datalen );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno ( ptp.seqno );

  if ( ptp.sublen != 0 )
    m.subject( ptp.sub, ptp.sublen );
  if ( ptp.reply2 != 0 )
    m.ret( ptp.reply2 );
  if ( ptp.time != 0 )
    m.time( ptp.time );
  if ( ptp.token != 0 )
    m.token( ptp.token );
  if ( ptp.fmt != 0 )
    m.fmt( ptp.fmt );
  if ( ptp.option != 0 )
    fl.set_opt( ptp.option );

  uint32_t h = ibx.hash();
  m.data( (const char *) ptp.data, ptp.datalen )
   .close( e.sz, h, fl );

  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );
  return this->user_db.forward_to_inbox( ptp.peer, ibx, h,
                                         m.msg, m.len(), true );
}

void
SessionMgr::send_ack( const MsgFramePublish &pub,  UserBridge &n,
                      const MsgHdrDecoder &dec,  const char *suf ) noexcept
{
  char     ret_buf[ 16 ];
  InboxBuf ibx( n.bridge_id, dec.get_return( ret_buf, suf ) );
  uint64_t time_val, token;
  uint32_t hops;

  MsgEst e( ibx.len() );
  e.seqno    ()
   .time     ()
   .token    ()
   .hops     ()
   .tportid  ()
   .subject  ( pub.subject_len )
   .ref_seqno();

  dec.get_ival<uint64_t>( FID_TOKEN, token );
  if ( ! dec.get_ival<uint64_t>( FID_TIME, time_val ) || time_val == 0 )
    time_val = current_realtime_ns();
  hops = this->user_db.peer_dist.calc_transport_cache( n.uid,
                                                       pub.rte.tport_id,
                                                       pub.rte );
  MsgCat m;
  m.reserve( e.sz );
  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno    ( ++n.send_inbox_seqno )
   .time     ( time_val );
  if ( token != 0 )
    m.token( token );
  m.hops     ( hops )
   .tportid  ( pub.rte.tport_id )
   .subject  ( pub.subject, pub.subject_len )
   .ref_seqno( dec.seqno );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

  this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}

bool
SessionMgr::loop( void ) noexcept
{
  int status;
  if ( this->poll.quit >= 5 )
    return false;
  if ( (status = this->poll.dispatch()) == EvPoll::DISPATCH_IDLE )
    this->poll.wait( 100 );
  if ( ( status & EvPoll::POLL_NEEDED ) != 0 ) {
    this->poll.wait( 0 );
    status = this->poll.dispatch();
  }
  if ( ( status & EvPoll::WRITE_PRESSURE ) != 0 ) {
    for ( int i = 0; i < 10; i++ ) {
      status = this->poll.dispatch();
      if ( ( status & EvPoll::WRITE_PRESSURE ) == 0 )
        break;
    }
  }
  return true;
}

void SessionMgr::write( void ) noexcept {}
void SessionMgr::read( void ) noexcept {}
void SessionMgr::process( void ) noexcept {}

void
SessionMgr::release( void ) noexcept
{
#if 0
  this->sub_tab.release();
  this->pat_tab.release();
  this->sub_list.release();
  this->user_db.release();
#endif
}
#if 0
void
SessionMgr::on_connect( EvSocket &conn ) noexcept
{
  printf( "connected %s %s\n", conn.peer_address, conn.type_string() );
  this->user_db.connected.add( conn.fd );
}

void
SessionMgr::on_shutdown( EvSocket &conn,  const char *,  size_t ) noexcept
{
  printf( "disconnected %s\n", conn.peer_address );
  this->user_db.retire_source( conn.fd );
  this->user_db.connected.remove( conn.fd );
}
#endif
