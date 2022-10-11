#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raims/session.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

SubDB::SubDB( EvPoll &p,  UserDB &udb,  SessionMgr &smg ) noexcept
     : user_db( udb ), mgr( smg ), my_src_fd( -1 ), next_inbox( 0 ),
       sub_seqno( 0 ), sub_update_mono_time( 0 ), sub_tab( this->sub_list ),
       pat_tab( this->sub_list, p.sub_route.pre_seed ),
       bloom( (uint32_t) udb.rand.next(), "(node)", p.g_bloom_db ),
       console( (uint32_t) udb.rand.next(), "(console)", p.g_bloom_db ),
       ipc( (uint32_t) udb.rand.next(), "(ipc)", p.g_bloom_db )
{
}

uint64_t
SubDB::sub_start( SubArgs &ctx ) noexcept
{
  SubStatus status = this->sub_tab.start( ctx );
  if ( status == SUB_OK || status == SUB_UPDATED ) {
    this->update_bloom( ctx );

    if ( ctx.bloom_updated )
      this->fwd_sub( ctx );

    if ( ctx.resize_bloom )
      this->resize_bloom();

    if ( status == SUB_OK )
      return this->sub_seqno;

    if ( status == SUB_UPDATED )
      return ctx.seqno;
  }
  return 0;
}

uint64_t
SubDB::sub_stop( SubArgs &ctx ) noexcept
{
  SubStatus status = this->sub_tab.stop( ctx );
  if ( status == SUB_OK || status == SUB_UPDATED ) {
    this->update_bloom( ctx );

    if ( ctx.bloom_updated )
      this->fwd_sub( ctx );

    if ( ctx.resize_bloom )
      this->resize_bloom();

    if ( status == SUB_OK )
      return this->sub_seqno;

    if ( status == SUB_UPDATED )
      return ctx.seqno;
  }
  return 0;
}

void
SubDB::update_bloom( SubArgs &ctx ) noexcept
{
  this->update_seqno++;
  if ( ctx.is_start ) {
    if ( ctx.sub_count == 1 && ctx.sub_coll == 0 ) {
      ctx.resize_bloom  = this->bloom.add( ctx.hash );
      ctx.bloom_updated = true;
    }
    if ( ( ctx.flags & CONSOLE_SUB ) != 0 &&
         ctx.console_count == 1 && ctx.console_coll == 0 )
      ctx.resize_bloom |= this->console.add( ctx.hash );
    if ( ( ctx.flags & IPC_SUB ) != 0 &&
         ctx.ipc_count == 1 && ctx.ipc_coll == 0 )
      ctx.resize_bloom |= this->ipc.add( ctx.hash );
  }
  else {
    if ( ctx.sub_count == 0 && ctx.sub_coll == 0 ) {
      this->bloom.del( ctx.hash );
      ctx.bloom_updated = true;
    }
    if ( ( ctx.flags & CONSOLE_SUB ) != 0 &&
         ctx.console_count == 0 && ctx.console_coll == 0 )
      this->console.del( ctx.hash );
    if ( ( ctx.flags & IPC_SUB ) != 0 &&
         ctx.ipc_count == 0 && ctx.ipc_coll == 0 )
      this->ipc.del( ctx.hash );
  }
}

/* my subscripion started */
uint64_t
SubDB::console_sub_start( const char *sub,  uint16_t sublen,
                          SubOnMsg *cb ) noexcept
{
  SubArgs ctx( sub, sublen, true, cb, this->sub_seqno + 1, CONSOLE_SUB, 0 );
  return this->sub_start( ctx );
}

/* my subscripion stopped */
uint64_t
SubDB::console_sub_stop( const char *sub,  uint16_t sublen ) noexcept
{
  SubArgs ctx( sub, sublen, false, NULL, 0, CONSOLE_SUB, 0 );
  return this->sub_stop( ctx );
}
/* my subscripion started on an ipc tport */
uint64_t
SubDB::ipc_sub_start( NotifySub &sub,  uint32_t tport_id ) noexcept
{
  SubArgs ctx( sub.subject, sub.subject_len, true, NULL, this->sub_seqno + 1,
               IPC_SUB, tport_id, sub.subj_hash );
  return this->sub_start( ctx );
}
/* my subscripion stopped on an ipc tport */
uint64_t
SubDB::ipc_sub_stop( NotifySub &sub,  uint32_t tport_id ) noexcept
{
  SubArgs ctx( sub.subject, sub.subject_len, false, NULL, 0, IPC_SUB,
               tport_id, sub.subj_hash );
  return this->sub_stop( ctx );
}

/* fwd a sub or unsub */
void
SubDB::fwd_sub( SubArgs &ctx ) noexcept
{
  const char * sub_prefix = ( ctx.is_start ? S_JOIN : S_LEAVE );
  size_t       sub_prelen = ( ctx.is_start ? S_JOIN_SZ : S_LEAVE_SZ );
  SubjectVar s( sub_prefix, sub_prelen, ctx.sub, ctx.sublen );
  TransportRoute * rte;

  d_sub( "%ssub(%.*s)\n", ( ctx.is_start ? "" : "un" ),
         (int) ctx.sublen, ctx.sub );
  MsgEst e( s.len() );
  e.seqno     ()
   .subj_hash ()
   .subject   ( ctx.sublen );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, s.len() )
   .seqno     ( ++this->sub_seqno )
   .subj_hash ( ctx.hash )
   .subject   ( ctx.sub, ctx.sublen );
  uint32_t h = s.hash();
  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( s.msg, s.len(), *this->user_db.session_key );

  if ( ( ctx.flags & CONSOLE_SUB ) != 0 ) {
    rte = this->user_db.ipc_transport;
    if ( rte != NULL ) {
      NotifySub nsub( ctx.sub, ctx.sublen, ctx.hash, this->my_src_fd,
                      false, 'M');
      nsub.bref = &this->console;
      if ( ctx.is_start )
        rte->sub_route.do_notify_sub( nsub );
      else
        rte->sub_route.do_notify_unsub( nsub );
    }
  }
  size_t count = this->user_db.transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * rte = this->user_db.transport_tab.ptr[ i ];
    if ( ! rte->is_set( TPORT_IS_IPC ) ) {
      EvPublish pub( s.msg, s.len(), NULL, 0, m.msg, m.len(),
                     rte->sub_route, this->my_src_fd, h,
                     CABA_TYPE_ID, 'p' );
      rte->forward_to_connected_auth( pub );
    }
  }
}
/* request subs from peer */
bool
SubDB::send_subs_request( UserBridge &n,  uint64_t seqno ) noexcept
{
  if ( ! n.test_set( SUBS_REQUEST_STATE ) ) {
    n.subs_mono_time = current_monotonic_time_ns();
    this->user_db.subs_queue.push( &n );

    InboxBuf ibx( n.bridge_id, _SUBS );

    MsgEst e( ibx.len() );
    e.seqno ()
     .start ()
     .end   ();

    MsgCat m;
    m.reserve( e.sz );

    m.open( this->user_db.bridge_id.nonce, ibx.len() )
     .seqno ( ++n.send_inbox_seqno )
     .start ( n.sub_seqno          )
     .end   ( seqno                );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

    return this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len(), true );
  }
  return true;
}
/* forward sub to peer inbox */
bool
SubDB::fwd_resub( UserBridge &n,  const char *sub,  size_t sublen,
                  uint64_t from_seqno,  uint64_t seqno,  bool is_psub,
                  const char *suf,  uint64_t token ) noexcept
{
  InboxBuf ibx( n.bridge_id, suf );

  MsgEst e( ibx.len() );
  e.seqno ();
  if ( ! is_psub )
    e.subject( sublen );
  else
    e.pattern( sublen );
  e.start ()
   .end   ()
   .token ();

  MsgCat   m;
  m.reserve( e.sz );
  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno( ++n.send_inbox_seqno );
  if ( ! is_psub )
    m.subject( sub, sublen );
  else
    m.pattern( sub, sublen );
  m.start ( from_seqno )
   .end   ( seqno      );
  if ( token != 0 )
    m.token  ( token );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

  return this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}
/* locate sub */
bool
SubDB::find_fwd_sub( UserBridge &n,  uint32_t hash,
                     uint64_t &from_seqno,  uint64_t seqno,
                     const char *suf,  uint64_t token,
                     const char *match,  size_t match_len ) noexcept
{
  SubRoute * sub;
  if ( (sub = this->sub_tab.find_sub( hash, seqno )) == NULL )
    return true;
  bool b = true;
  if ( match_len == 0 ||
       ::memmem( sub->value, sub->len, match, match_len ) != NULL ) {
    b &= this->fwd_resub( n, sub->value, sub->len, from_seqno, seqno, false,
                          suf ? suf : _RESUB, token );
    from_seqno = seqno;
  }
  return b;
}
/* locate psub */
bool
SubDB::find_fwd_psub( UserBridge &n,  uint32_t hash,
                      uint64_t &from_seqno,  uint64_t seqno,
                      const char *suf,  uint64_t token,
                      const char *match,  size_t match_len ) noexcept
{
  PatRoute * sub;
  if ( (sub = this->pat_tab.find_sub( hash, seqno )) == NULL )
    return true;
  bool b = true;
  if ( match_len == 0 ||
       ::memmem( sub->value, sub->len, match, match_len ) != NULL ) {
    b &= this->fwd_resub( n, sub->value, sub->len, from_seqno, seqno, true,
                          suf ? suf : _REPSUB, token );
    from_seqno = seqno;
  }
  return b;
}
/* peer asks for subs in range start -> end */
bool
SubDB::recv_subs_request( const MsgFramePublish &,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept
{
  uint64_t     start     = 0,
               end       = 0,
               token     = 0;
  const char * match     = NULL;
  size_t       match_len = 0;

  if ( dec.test( FID_START ) )
    cvt_number<uint64_t>( dec.mref[ FID_START ], start );
  if ( dec.test( FID_END ) )
    cvt_number<uint64_t>( dec.mref[ FID_END ], end );
  if ( dec.test( FID_TOKEN ) )
    cvt_number<uint64_t>( dec.mref[ FID_TOKEN ], token );
  if ( end == 0 )
    end = this->sub_seqno;
  if ( dec.test( FID_DATA ) ) {
    match     = (const char *) dec.mref[ FID_DATA ].fptr;
    match_len = dec.mref[ FID_DATA ].fsize;
  }

  SubListIter  iter( this->sub_list, start + 1, end );
  uint64_t     from_seqno = start;
  char         ret_buf[ 16 ];
  const char * suf = dec.get_return( ret_buf, NULL );
  bool         b   = true;
  if ( iter.first() ) {
    do {
      if ( iter.action == ACTION_SUB_JOIN )
        b &= this->find_fwd_sub( n, iter.hash, from_seqno, iter.seqno, suf,
                                 token, match, match_len );
      else if ( iter.action == ACTION_PSUB_START )
        b &= this->find_fwd_psub( n, iter.hash, from_seqno, iter.seqno, suf,
                                  token, match, match_len );
    } while ( iter.next() );
  }
  if ( from_seqno < end ) {
    InboxBuf ibx( n.bridge_id, suf ? suf : _RESUB );

    MsgEst e( ibx.len() );
    e.seqno  ()
     .start  ()
     .end    ()
     .token  ();

    MsgCat m;
    m.reserve( e.sz );

    m.open( this->user_db.bridge_id.nonce, ibx.len() )
     .seqno  ( ++n.send_inbox_seqno )
     .start  ( from_seqno           )
     .end    ( end                  );
    if ( token != 0 )
      m.token( token );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

    b &= this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
  }
  return b;
}

void
SubDB::print_bloom( BloomBits &b ) noexcept
{
  printf( "width %" PRIu64 ", count %" PRIu64 ", seed=%x\n",
          b.width, b.count, b.seed );
  for ( size_t i = 0; i < b.width * 8; i++ ) {
    uint8_t shft = i % 64;
    size_t  off  = i / 64;
    uint8_t bit = ( ( b.bits[ off ] >> shft ) & 1 );
    printf( "%u", bit );
  }
  printf( "\n" );
  for ( size_t j = 0; j < 4; j++ ) {
    printf( "ht[ %" PRIu64 " ] = elem_count %" PRIu64 " tab_mask %" PRIx64 "\n",
            j, b.ht[ j ]->elem_count, b.ht[ j ]->tab_mask );
    size_t k;
    if ( b.ht[ j ]->first( k ) ) {
      do {
        uint32_t h, v;
        b.ht[ j ]->get( k, h, v );
        printf( "%" PRIu64 ".%x = %u, ", k, h, v );
      } while ( b.ht[ j ]->next( k ) );
      printf( "\n" );
    }
  }
}

/* request subs from peer */
bool
SubDB::send_bloom_request( UserBridge &n ) noexcept
{
  if ( ! n.test_set( SUBS_REQUEST_STATE ) ) {
    n.subs_mono_time = current_monotonic_time_ns();
    this->user_db.subs_queue.push( &n );

    InboxBuf ibx( n.bridge_id, _BLOOM_REQ );

    MsgEst e( ibx.len() );
    e.seqno();

    MsgCat m;
    m.reserve( e.sz );

    m.open( this->user_db.bridge_id.nonce, ibx.len() )
     .seqno( ++n.send_inbox_seqno );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

    return this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len(), true );
  }
  return true;
}

bool
SubDB::recv_bloom_request( const MsgFramePublish &,  UserBridge &n,
                           const MsgHdrDecoder &dec ) noexcept
{
  BloomCodec  code;
  if ( debug_sub ) {
    n.printf( "bloom request\n" );
    print_bloom( *this->bloom.bits );
  }
  this->bloom.encode( code );

  char     ret_buf[ 16 ];
  InboxBuf ibx( n.bridge_id, dec.get_return( ret_buf, _BLOOM_RPY ) );

  MsgEst e( ibx.len() );
  e.seqno    ()
   .sub_seqno()
   .bloom    ( code.code_sz * 4 );

  MsgCat m;
  m.reserve( e.sz );
  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno    ( ++n.send_inbox_seqno )
   .sub_seqno( this->sub_seqno      )
   .bloom    ( code.ptr, code.code_sz * 4 );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

  return this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}

bool
SubDB::recv_bloom( const MsgFramePublish &pub,  UserBridge &n,
                   const MsgHdrDecoder &dec ) noexcept
{
  if ( debug_sub )
    n.printf( "recv bloom\n" );
  if ( dec.test_2( FID_BLOOM, FID_SUB_SEQNO ) ) {
    uint64_t sub_seqno = 0;
    cvt_number<uint64_t>( dec.mref[ FID_SUB_SEQNO ], sub_seqno );
    d_sub( "sub_seqno %" PRIu64 " >= %" PRIu64 "\n", sub_seqno, n.sub_seqno );
    if ( sub_seqno >= n.sub_seqno ) {
      if ( n.bloom.decode( dec.mref[ FID_BLOOM ].fptr,
                           dec.mref[ FID_BLOOM ].fsize ) ) {
        d_sub( "update_bloom count %" PRIu64 "\n", n.bloom.bits->count );
        if ( debug_sub )
          print_bloom( *n.bloom.bits );

        n.sub_seqno = sub_seqno;
        n.sub_recv_mono_time = current_monotonic_time_ns();
        this->sub_update_mono_time = n.sub_recv_mono_time;
        this->user_db.events.recv_bloom( n.uid, pub.rte.tport_id,
                                         (uint32_t) n.bloom.bits->count );
        this->notify_bloom_update( n.bloom );
      }
      else {
        n.printe( "failed to update bloom\n" );
      }
    }
    return true;
  }
  return false;
}

bool
SubDB::recv_bloom_result( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept
{
  if ( this->recv_bloom( pub, n, dec ) )
    this->user_db.forward_pub( pub, n, dec );
  if ( n.test_clear( SUBS_REQUEST_STATE ) )
    this->user_db.subs_queue.remove( &n );
  return true;
}

bool
SubDB::recv_sub_start( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.test_2( FID_SUBJECT, FID_SUBJ_HASH ) ) {
    size_t       sublen = dec.mref[ FID_SUBJECT ].fsize;
    const char * sub    = (const char *) dec.mref[ FID_SUBJECT ].fptr;
    uint32_t     hash;

    dec.get_ival<uint32_t>( FID_SUBJ_HASH, hash );
    n.bloom.add( hash );
    TransportRoute *rte = this->user_db.ipc_transport;
    if ( rte != NULL ) {
      UserRoute & u_rte = *n.user_route;
      NotifySub   nsub( sub, sublen, hash, u_rte.mcast_fd, false, 'M' );
      nsub.bref = &n.bloom;
      rte->sub_route.do_notify_sub( nsub );
    }
    if ( debug_sub )
      n.printf( "start %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.forward_pub( pub, n, dec );
  }
  return true;
}

bool
SubDB::recv_sub_stop( const MsgFramePublish &pub,  UserBridge &n,
                      const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.test_2( FID_SUBJECT, FID_SUBJ_HASH ) ) {
    size_t       sublen = dec.mref[ FID_SUBJECT ].fsize;
    const char * sub    = (const char *) dec.mref[ FID_SUBJECT ].fptr;
    uint32_t     hash;

    dec.get_ival<uint32_t>( FID_SUBJ_HASH, hash );
    n.bloom.del( hash );
    TransportRoute *rte = this->user_db.ipc_transport;
    if ( rte != NULL ) {
      UserRoute & u_rte = *n.user_route;
      NotifySub   nsub( sub, sublen, hash, u_rte.mcast_fd, false, 'M' );
      nsub.bref = &n.bloom;
      rte->sub_route.do_notify_unsub( nsub );
    }
    if ( debug_sub )
      n.printf( "stop %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.forward_pub( pub, n, dec );
  }
  return true;
}

bool
SubDB::recv_resub_result( const MsgFramePublish &,  UserBridge &,
                          const MsgHdrDecoder & ) noexcept
{
#if 0
  if ( ! dec.test_2( FID_START, FID_END ) ) {
    fprintf( stderr, "missing start end in recv subs request\n" );
     return true;
  }
  uint64_t start = 0, seqno = 0;
  cvt_number<uint64_t>( dec.mref[ FID_START ], start );
  cvt_number<uint64_t>( dec.mref[ FID_END ], seqno );
  if ( start == n.sub_seqno && seqno > start ) {
    n.sub_seqno = seqno;
    if ( dec.test( FID_SUBJECT ) ) {
      UserRoute      & u_rte  = *n.user_route;
      TransportRoute & rte    = u_rte.rte;
      size_t           sublen = dec.mref[ FID_SUBJECT ].fsize;
      const char     * sub    = (const char *) dec.mref[ FID_SUBJECT ].fptr;
      uint32_t         hash   = kv_crc_c( sub, sublen, 0 ),
                       rcnt;
      rcnt = rte.sub_route.get_sub_route_count( hash ) + 1;
      n.bloom.add( hash );
      rte.sub_route.notify_sub( hash, sub, sublen, u_rte.mcast_fd,
                                rcnt, 's' );
    }
    n.printf( "%.*s start %" PRIu64 " end %" PRIu64 "\n",
            (int) pub.subject_len, pub.subject, start, seqno );
  }
  if ( n.test_clear( SUBS_REQUEST_STATE ) )
    this->user_db.subs_queue.remove( &n );
#endif
  return true;
}

void
SubDB::resize_bloom( void ) noexcept
{
  bool bloom_resize   = this->bloom.bits->test_resize(),
       console_resize = this->console.bits->test_resize(),
       ipc_resize     = this->ipc.bits->test_resize();;
  BloomBits * b;

  if ( bloom_resize ) {
    b = this->bloom.bits->resize( this->bloom.bits, this->bloom.bits->seed,
                                  this->bloom.bits->bwidth );
    this->bloom.bits = b;
    this->index_bloom( *b, CONSOLE_SUB | IPC_SUB );
    if ( debug_sub )
      print_bloom( *b );
    this->user_db.events.resize_bloom( (uint32_t) b->count );
    this->notify_bloom_update( this->bloom );
  }
  if ( console_resize ) {
    b = this->console.bits->resize( this->console.bits,
                                    this->console.bits->seed,
                                    this->console.bits->bwidth );
    this->console.bits = b;
    this->index_bloom( *b, CONSOLE_SUB );
    this->notify_bloom_update( this->console );
  }
  if ( ipc_resize ) {
    b = this->ipc.bits->resize( this->ipc.bits, this->ipc.bits->seed,
                                this->ipc.bits->bwidth );
    this->ipc.bits = b;
    this->index_bloom( *b, IPC_SUB );
    this->notify_bloom_update( this->ipc );
  }

  if ( bloom_resize ) {
    BloomCodec code;
    this->bloom.encode( code );

    MsgEst e( Z_BLM_SZ );
    e.seqno    ()
     .sub_seqno()
     .bloom    ( code.code_sz * 4 );

    MsgCat m;
    m.reserve( e.sz );

    m.open( this->user_db.bridge_id.nonce, Z_BLM_SZ )
     .seqno    ( ++this->user_db.send_peer_seqno )
     .sub_seqno( this->sub_seqno      )
     .bloom    ( code.ptr, code.code_sz * 4 );
    m.close( e.sz, blm_h, CABA_RTR_ALERT );
    m.sign( Z_BLM, Z_BLM_SZ, *this->user_db.session_key );

    size_t count = this->user_db.transport_tab.count;
    for ( size_t i = 0; i < count; i++ ) {
      TransportRoute * rte = this->user_db.transport_tab.ptr[ i ];
      if ( ! rte->is_set( TPORT_IS_IPC ) ) {
        EvPublish pub( Z_BLM, Z_BLM_SZ, NULL, 0, m.msg, m.len(),
                       rte->sub_route, this->my_src_fd,
                       blm_h, CABA_TYPE_ID, 'p' );
        rte->forward_to_connected_auth( pub );
      }
    }
  }
}

void
SubDB::notify_bloom_update( BloomRef &ref ) noexcept
{
  for ( uint32_t i = 0; i < ref.nlinks; i++ )
    ((RoutePublish &) ref.links[ i ]->rdb).do_notify_bloom_ref( ref );
}

void
SubDB::index_bloom( BloomBits &bits,  uint32_t flags ) noexcept
{
  RouteLoc   loc;
  SubRoute * rt;
  PatRoute * pat;

  /* bloom route has inbox and mcast, these are not needed in console, ipc
   * because they are routed in sys_bloom */
  if ( flags == ( CONSOLE_SUB | IPC_SUB ) ) {
    bits.add( this->mgr.ibx.hash );
    bits.add( this->mgr.mch.hash );
  }
  /* test() separates console, ipc and also adds to bloom */
  if ( (rt = this->sub_tab.tab.first( loc )) != NULL ) {
    do {
      if ( rt->test( flags ) )
        bits.add( rt->hash );
    } while ( (rt = this->sub_tab.tab.next( loc )) != NULL );
  }

  if ( (pat = this->pat_tab.tab.first( loc )) != NULL ) {
    do {
      if ( pat->test( flags ) )
        bits.add( pat->hash );
    } while ( (pat = this->pat_tab.tab.next( loc )) != NULL );
  }
}

const char *
rai::ms::seqno_status_string( SeqnoStatus status ) noexcept
{
  switch ( status ) {
    case SEQNO_UID_FIRST:  return "first sequence";
    case SEQNO_UID_CYCLE:  return "cycle sequence";
    case SEQNO_UID_NEXT:   return "next sequence";
    case SEQNO_UID_SKIP:   return "skipped sequence";
    case SEQNO_UID_REPEAT: return "sequence repeated";
    case SEQNO_NOT_SUBSCR: return "not subscribed";
    case SEQNO_ERROR:
    default:               return "error";
  }
}

SeqnoStatus
SubDB::match_seqno( SeqnoArgs &ctx ) noexcept
{
  const MsgFramePublish &pub = ctx.pub;
  const uint32_t uid = ( pub.n == NULL ? 0 : pub.n->uid );
  if ( uid != 0 ) {
    int64_t skew = this->user_db.min_skew( *pub.n );
    if ( (uint64_t) ( (int64_t) ctx.time + skew ) <
         this->seqno_tab.trailing_time && ctx.time != 0 )
      return SEQNO_UID_REPEAT;
    /* uint64_t stamp = current_realtime_ns();
    printf( "publish latency %.6f\n",
            (double) ( stamp - (uint64_t) ( (int64_t) ctx.time + skew ) ) /
            1000000000.0 ); */
  }

  SubSeqno * seq;
  RouteLoc   loc, loc2;
  bool       is_old;

  const uint64_t seqno = pub.dec.seqno,
                 time  = ( seqno_frame( seqno ) == time_frame( ctx.time ) ?
                           ctx.time : seqno_time( seqno ) );

  seq = this->seqno_tab.upsert( pub.subj_hash, pub.subject, pub.subject_len,
                                loc, loc2, is_old );
  if ( seq == NULL )
    return SEQNO_ERROR;
  /* starting a new uid/seqno/time triplet */
  if ( loc.is_new ) {
    if ( ! this->match_subscription( ctx ) ) {
      this->seqno_tab.remove( loc, loc2, is_old );
      return SEQNO_NOT_SUBSCR;
    }
    return seq->init( uid, seqno, ctx.start_seqno, time, ctx.stamp,
                      this->update_seqno, ctx.cb, ctx.tport_mask );
  }
  /* check if subscription modified */
  const uint64_t old_start_seqno = seq->start_seqno;
  if ( seq->update_seqno != this->update_seqno ){
    if ( this->match_subscription( ctx ) ) {
      seq->start_seqno  = ctx.start_seqno;
      seq->update_seqno = this->update_seqno;
      seq->on_data      = ctx.cb;
      seq->tport_mask   = ctx.tport_mask;
    }
    /* otherwise, no sub matches */
    else {
      seq->release();
      this->seqno_tab.remove( loc, loc2, is_old );
      return SEQNO_NOT_SUBSCR;
    }
  }
  else {
    ctx.start_seqno = old_start_seqno;
    ctx.cb          = seq->on_data;
    ctx.tport_mask  = seq->tport_mask;
  }
  if ( seq->last_uid != uid &&
       seq->restore_uid( uid, seqno, time, ctx.stamp ) == SEQNO_UID_FIRST )
    return SEQNO_UID_FIRST;

  const bool     new_sub    = ( ctx.start_seqno != old_start_seqno );
  const uint64_t last_seqno = seq->last_seqno;
  const uint64_t last_time  = seq->last_time;

  ctx.last_seqno = last_seqno;
  ctx.last_time  = last_time;
  /* normal case */
  if ( seqno == last_seqno + 1 ) {
    seq->last_seqno = seqno;
    seq->last_stamp = ctx.stamp;
    return SEQNO_UID_NEXT;
  }
  /* if seqno is in the same time frame as last seqno */
  if ( seqno_frame( seqno ) == time_frame( last_time ) ) {
    /* if new subscription */
    if ( new_sub ) {
      if ( seqno > last_seqno ) {
        seq->last_seqno = seqno;
        seq->last_stamp = ctx.stamp;
        return SEQNO_UID_CYCLE; /* new subscription, can skip after resub */
      }
      return SEQNO_UID_REPEAT; /* already seen it */
    }
    if ( seqno > last_seqno ) {
      ctx.msg_loss    = (uint32_t) min_int( seqno - ( last_seqno + 1 ),
                                            (uint64_t) MAX_MSG_LOSS );
      seq->last_seqno = seqno;
      seq->last_stamp = ctx.stamp;
      return SEQNO_UID_SKIP; /* forward msg with loss notification */
    }
    return SEQNO_UID_REPEAT; /* already seen it */
  }
  /* time updated, resequence wanted */
  if ( time > last_time ) {
    const bool chained = ( last_seqno == ctx.chain_seqno );
    seq->last_time  = time;
    seq->last_seqno = seqno;
    seq->last_stamp = ctx.stamp;
    if ( chained ) /* sequentialy chained */
      return SEQNO_UID_NEXT;
    if ( ! new_sub ) {
      /* if last seqno was in the previous frame */
      if ( seqno_frame( ctx.chain_seqno ) == seqno_frame( last_seqno ) ) {
        ctx.msg_loss = (uint32_t) min_int( ctx.chain_seqno - last_seqno,
                                           (uint64_t) MAX_MSG_LOSS );
      }
      else { /* no reference frame */
        ctx.msg_loss = MSG_FRAME_LOSS; /* don't know how many */
      }
      return SEQNO_UID_SKIP;
    }
    /* new sub can skip */
    return SEQNO_UID_CYCLE;
  }
  /* seqno not in last frame, no update time */
  seq->last_time  = time; /* fake a start time */
  seq->last_seqno = seqno;
  seq->last_stamp = ctx.stamp;
  if ( ! new_sub ) { /* if not joining w/new sub */
    ctx.msg_loss = MSG_FRAME_LOSS; /* don't know how many */
    return SEQNO_UID_SKIP;
  }
  return SEQNO_UID_CYCLE; /* joined with a new sub */
}

bool
SubDB::match_subscription( SeqnoArgs &ctx ) noexcept
{
  const MsgFramePublish &pub = ctx.pub;
  bool matched = false;
  for ( uint8_t cnt = 0; cnt < pub.prefix_cnt; cnt++ ) {
    if ( pub.subj_hash == pub.hash[ cnt ] ) {
      SubRoute *rt = this->sub_tab.tab.find( pub.subj_hash,
                                             pub.subject,
                                             pub.subject_len );
      if ( rt != NULL ) {
        if ( ctx.cb == NULL ) {
          ctx.start_seqno = rt->start_seqno;
          ctx.cb          = rt->on_data;
        }
        ctx.tport_mask |= rt->ref.tport_mask;
        matched = true;
      }
    }
    else {
      RouteLoc   loc;
      PatRoute * rt = this->pat_tab.tab.find_by_hash( pub.hash[ cnt ], loc );
      while ( rt != NULL ) {
        if ( rt->match( pub.subject, pub.subject_len ) ) {
          if ( ctx.cb == NULL ) {
            ctx.start_seqno = rt->start_seqno;
            ctx.cb          = rt->on_data;
          }
          ctx.tport_mask |= rt->ref.tport_mask;
          matched = true;
        }
        rt = this->pat_tab.tab.find_next_by_hash( pub.hash[ cnt ], loc );
      }
    }
  }
  return matched;
}

SubOnMsg *
SubDB::match_any_sub( const char *sub,  uint16_t sublen ) noexcept
{
  uint32_t h = kv_crc_c( sub, sublen, 0 );
  SubRoute *rt = this->sub_tab.tab.find( h, sub, sublen );
  if ( rt != NULL )
    return rt->on_data;
  for ( uint16_t i = 0; i <= sublen; i++ ) {
    if ( this->bloom.pref_count[ i ] != 0 ) {
      h = kv_crc_c( sub, i, this->pat_tab.seed[ i ] );

      RouteLoc   loc;
      PatRoute * rt = this->pat_tab.tab.find_by_hash( h, loc );
      while ( rt != NULL ) {
        if ( rt->match( sub, sublen ) )
          return rt->on_data;
        rt = this->pat_tab.tab.find_next_by_hash( h, loc );
      }
    }
  }
  return NULL;
}

SeqnoStatus
SubSeqno::restore_uid( uint32_t uid,  uint64_t seqno,  uint64_t time,
                       uint64_t stamp ) noexcept
{
  SeqnoSave id_val;
  size_t    id_pos;

  if ( this->seqno_ht == NULL )
    this->seqno_ht = UidSeqno::resize( NULL );
  /* save the last uid */
  id_val.update( this->last_seqno, this->last_time, this->last_stamp );
  this->seqno_ht->upsert_rsz( this->seqno_ht, this->last_uid, id_val );
  /*printf( "save %u %lu.%lu frame %lu\n",
          this->last_uid, seqno_frame( this->last_seqno ),
          seqno_base( this->last_seqno ), time_frame( this->last_time ) );*/

  /* find the uid which published */
  if ( ! this->seqno_ht->find( uid, id_pos, id_val ) ) {
    /*printf( "not found %u\n", uid );*/
    this->last_uid   = uid;
    this->last_seqno = seqno;
    this->last_time  = time;
    this->last_stamp = stamp;
    return SEQNO_UID_FIRST;
  }
  /* restore the seqno of the last time uid published */
  this->last_uid = uid;
  id_val.restore( this->last_seqno, this->last_time, this->last_stamp );
  /*printf( "restore %u %lu.%lu frame %lu\n",
          uid, seqno_frame( this->last_seqno ),
          seqno_base( this->last_seqno ), time_frame( this->last_time ) );*/
  return SEQNO_UID_CYCLE;
}

uint32_t
SubDB::inbox_start( uint32_t inbox_num,  SubOnMsg *cb ) noexcept
{
  char       num[ 16 ];
  size_t     len;
  uint32_t   h;
  RouteLoc   loc;
  InboxSub * ibx;

  if ( inbox_num == 0 ) {
    for (;;) {
      inbox_num = ++this->next_inbox;
      len = uint32_to_string( inbox_num, num );
      h   = kv_hash_uint( inbox_num );
      ibx = this->inbox_tab.upsert( h, num, len, loc );
      if ( ibx != NULL && loc.is_new )
        break;
    }
  }
  else {
    len = uint32_to_string( inbox_num, num );
    h   = kv_hash_uint( inbox_num );
    ibx = this->inbox_tab.upsert( h, num, len, loc );
    if ( ibx == NULL )
      return 0;
  }
  if ( loc.is_new ) {
    ibx->init( cb );
    d_sub( "create inbox: %u\n", inbox_num );
    return inbox_num;
  }
  return 0;
}

void
SubOnMsg::on_data( const SubMsgData & ) noexcept
{
}

void
AnyMatch::init_any( const char *s,  uint16_t sublen,  const uint32_t *pre_seed,  
                    uint32_t uid_cnt ) noexcept
{
  size_t off = sizeof( AnyMatch ) - sizeof( kv::BloomMatch ) +
               kv::BloomMatch::match_size( sublen );
  char * ptr = &((char *) (void *) this)[ off ];
  ::memcpy( ptr, s, sublen );
  ptr[ sublen ] = '\0';

  uid_cnt         = ( uid_cnt + 127 ) & ~(uint32_t) 127;
  this->max_uid   = uid_cnt;
  this->set_count = 0;
  this->mono_time = 0;
  this->sub_off   = (uint16_t) ( ptr - (char *) (void *) this );
  this->sub_len   = sublen;
  ptr            += ( ( (size_t) sublen + 8 ) & ~(size_t) 7 );
  this->bits_off  = (uint32_t) ( ptr - (char *) (void *) this );
  ::memset( ptr, 0, uid_cnt / 8 );
  this->match.init_match( sublen, pre_seed );
}

size_t
AnyMatch::any_size( uint16_t sublen,  uint32_t uid_cnt ) noexcept
{
  size_t   len     = ( ( (size_t) sublen + 8 ) & ~(size_t) 7 );
  uint32_t max_uid = ( uid_cnt + 127 ) & ~(uint32_t) 127;
  len += sizeof( AnyMatch ) - sizeof( kv::BloomMatch ) +
         kv::BloomMatch::match_size( sublen ) + (size_t) max_uid / 8;
  return len;
}

void
AnyMatchTab::reset( void ) noexcept
{
  this->tab.reset();
  this->ht->clear_all();
  this->max_off = 0;
}

AnyMatch *
AnyMatchTab::get_match( const char *sub,  uint16_t sublen,  uint32_t h,
                        const uint32_t *pre_seed,  uint32_t max_uid ) noexcept
{
  AnyMatch * any;
  size_t     pos;
  uint32_t   off;
  if ( this->ht->find( h, pos, off ) ) {
    any = (AnyMatch *) (void *) &this->tab.ptr[ off ];
    if ( any->sub_len == sublen && ::memcmp( any->sub(), sub, sublen ) == 0 &&
         any->max_uid >= max_uid )
      return any;
    this->reset();
    this->ht->find( h, pos );
  }
  size_t     sz = AnyMatch::any_size( sublen, max_uid ) / 8;
  uint64_t * p  = this->tab.resize( this->max_off + sz, false );

  any = (AnyMatch *) (void *) &p[ this->max_off ];
  any->init_any( sub, sublen, pre_seed, max_uid );
  this->ht->set_rsz( this->ht, h, pos, (uint32_t) this->max_off );
  this->max_off += sz;
  return any;
}

UserBridge *
AnyMatch::get_destination( UserDB &user_db ) noexcept
{
  if ( this->set_count > 0 ) {
    BitSetT<uint64_t> set( this->bits() );
    bool b = false;
    uint32_t uid, pos = 0;
    if ( this->set_count > 1 )
      pos = user_db.rand.next() % this->set_count;
    if ( pos == 0 )
      b = set.first( uid, this->max_uid );
    else
      b = set.index( uid, pos, this->max_uid );
    if ( b )
      return user_db.bridge_tab[ uid ];
  }
  return NULL;
}

AnyMatch *
SubDB::any_match( const char *sub,  uint16_t sublen,  uint32_t h ) noexcept
{
  uint32_t     max_uid = this->user_db.next_uid;
  AnyMatch   * any;
  any = this->any_tab.get_match( sub, sublen, h, this->pat_tab.seed, max_uid );
  if ( any->mono_time < this->sub_update_mono_time ) {
    BitSetT<uint64_t> set( any->bits() );
    for ( uint32_t uid = 1; uid < max_uid; uid++ ) {
      UserBridge * n = this->user_db.bridge_tab[ uid ];
      if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) {
        if ( any->mono_time < n->sub_recv_mono_time ) {
          if ( any->match.match_sub( h, sub, sublen, n->bloom ) ) {
            if ( ! set.test_set( uid ) )
              any->set_count++;
          }
          else {
            if ( set.test_clear( uid ) )
              any->set_count--;
          }
        }
      }
      else {
        if ( set.test_clear( uid ) )
          any->set_count--;
      }
    }
    any->mono_time = this->sub_update_mono_time;
  }
  return any;
}
