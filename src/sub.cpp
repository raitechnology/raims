#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raims/session.h>
#include <raikv/publish_ctx.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

SubDB::SubDB( EvPoll &p,  UserDB &udb,  SessionMgr &smg ) noexcept
     : user_db( udb ), mgr( smg ), my_src( smg ), next_inbox( 0 ),
       sub_seqno( 0 ), sub_seqno_sum( 0 ), sub_update_mono_time( 0 ),
       sub_tab( this->sub_list ),
       pat_tab( this->sub_list ),
       bloom( (uint32_t) udb.rand.next(), "(node)", p.g_bloom_db ),
       console( (uint32_t) udb.rand.next(), "(console)", p.g_bloom_db ),
       ipc( (uint32_t) udb.rand.next(), "(ipc)", p.g_bloom_db ),
       queue_tab( this->sub_list ),
       uid_route( p.sub_route.get_service( "(uid)", 0, -1 ) )
{
}

QueueSubTab *
QueueSubArray::find_tab( const char *queue,  uint16_t queue_len,
                         uint32_t queue_hash ) noexcept
{
  uint32_t i;
  for ( i = 0; i < this->count; i++ ) {
    if ( this->ptr[ i ]->equals( queue, queue_len, queue_hash ) )
      break;
  }
  if ( i == this->count ) {
    if ( queue_len == 0 )
      return NULL;
    this->push( new ( ::malloc( sizeof( QueueSubTab ) ) )
                QueueSubTab( queue, queue_len, queue_hash, this->sub_list ) );
  }
  return this->ptr[ i ];
}

SubStatus
QueueSubArray::start( SubArgs &ctx ) noexcept
{
  QueueSubTab *t = this->find_tab( ctx.queue, ctx.queue_len, ctx.queue_hash );
  if ( t == NULL )
    return SUB_ERROR;
  SubStatus status = t->sub_tab.start( ctx );
  if ( status == SUB_EXISTS )
    return SUB_UPDATED;
  return status;
}

SubStatus
QueueSubArray::stop( SubArgs &ctx ) noexcept
{
  QueueSubTab *t = this->find_tab( ctx.queue, ctx.queue_len, ctx.queue_hash );
  if ( t == NULL )
    return SUB_NOT_FOUND;
  return t->sub_tab.stop( ctx );
}

QueueSubTab::QueueSubTab( const char *q,  uint16_t qlen,  uint32_t qhash,
                          SubList &l ) noexcept
           : sub_tab( l ), pat_tab( l )
{
  this->queue = (char *) ::malloc( qlen + 1 );
  this->queue_len = qlen;
  ::memcpy( this->queue, q, qlen );
  this->queue[ qlen ] = '\0';
  this->queue_hash = qhash;
}

uint64_t
SubDB::sub_start( SubArgs &ctx ) noexcept
{
  SubStatus status;

  if ( ctx.queue_hash == 0 )
    status = this->sub_tab.start( ctx );
  else
    status = this->queue_tab.start( ctx );

  d_sub( "sub_start %.*s count %u queue_refs %u status %s\n",
          (int) ctx.sublen, ctx.sub, ctx.sub_count, ctx.queue_refs,
          sub_status_string( status ) );

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
  SubStatus status;
  if ( ctx.queue_hash == 0 )
    status = this->sub_tab.stop( ctx );
  else
    status = this->queue_tab.stop( ctx );

  d_sub( "sub_stop %.*s count %u queue_refs %u status %s\n",
          (int) ctx.sublen, ctx.sub, ctx.sub_count, ctx.queue_refs,
          sub_status_string( status ) );

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
  if ( ctx.is_start() ) {
    if ( ctx.queue_hash != 0 ) {
      QueueMatch m = { ctx.queue_hash, ctx.queue_refs,
                       QueueMatch::hash2( ctx.sub, ctx.sublen, ctx.hash ) };
      ctx.bloom_updated = true;
      ctx.resize_bloom = this->bloom.add_queue_route( SUB_RTE, ctx.hash, m );
      if ( ( ctx.flags & CONSOLE_SUB ) != 0 )
        ctx.resize_bloom = this->console.add_queue_route( SUB_RTE, ctx.hash, m );
      else if ( ( ctx.flags & IPC_SUB ) != 0 )
        ctx.resize_bloom = this->ipc.add_queue_route( SUB_RTE, ctx.hash, m );
    }
    else if ( ctx.sub_count == 1 && ctx.sub_coll == 0 ) {
      ctx.resize_bloom  = this->bloom.add( ctx.hash );
      ctx.bloom_updated = true;
      if ( ( ctx.flags & CONSOLE_SUB ) != 0 &&
           ctx.console_count == 1 && ctx.console_coll == 0 )
        ctx.resize_bloom |= this->console.add( ctx.hash );
      if ( ( ctx.flags & IPC_SUB ) != 0 &&
           ctx.ipc_count == 1 && ctx.ipc_coll == 0 )
        ctx.resize_bloom |= this->ipc.add( ctx.hash );
    }
  }
  else {
    if ( ctx.queue_hash != 0 ) {
      QueueMatch m = { ctx.queue_hash, 0, 
                       QueueMatch::hash2( ctx.sub, ctx.sublen, ctx.hash ) };
      ctx.bloom_updated = true;
      this->bloom.del_queue_route( SUB_RTE, ctx.hash, m );
      if ( ( ctx.flags & CONSOLE_SUB ) != 0 )
        this->console.del_queue_route( SUB_RTE, ctx.hash, m );
      else if ( ( ctx.flags & IPC_SUB ) != 0 )
        this->ipc.del_queue_route( SUB_RTE, ctx.hash, m );
    }
    else if ( ctx.sub_count == 0 && ctx.sub_coll == 0 ) {
      this->bloom.del( ctx.hash );
      ctx.bloom_updated = true;

      if ( ( ctx.flags & CONSOLE_SUB ) != 0 &&
           ctx.console_count == 0 && ctx.console_coll == 0 )
        this->console.del( ctx.hash );
      if ( ( ctx.flags & IPC_SUB ) != 0 &&
           ctx.ipc_count == 0 && ctx.ipc_coll == 0 )
        this->ipc.del( ctx.hash );
    }
  }
}

/* my subscripion started */
uint64_t
SubDB::console_sub_start( const char *sub,  uint16_t sublen,
                          const char *inbox,  uint16_t inbox_len,
                          SubOnMsg *cb ) noexcept
{
  SubArgs ctx( sub, sublen, inbox, inbox_len, cb, this->sub_seqno + 1,
               CONSOLE_SUB | IS_SUB_START, 0 );
  return this->sub_start( ctx );
}

/* my subscripion stopped */
uint64_t
SubDB::console_sub_stop( const char *sub,  uint16_t sublen ) noexcept
{
  SubArgs ctx( sub, sublen, NULL, 0, NULL, 0, CONSOLE_SUB, 0 );
  return this->sub_stop( ctx );
}
/* my subscripion started on an ipc tport */
uint64_t
SubDB::ipc_sub_start( NotifySub &sub,  uint32_t tport_id ) noexcept
{
  SubArgs ctx( sub.subject, sub.subject_len, NULL, 0, NULL,
               this->sub_seqno + 1, IPC_SUB | IS_SUB_START,
               tport_id, sub.subj_hash );
  return this->sub_start( ctx );
}
/* my subscripion stopped on an ipc tport */
uint64_t
SubDB::ipc_sub_stop( NotifySub &sub,  uint32_t tport_id ) noexcept
{
  SubArgs ctx( sub.subject, sub.subject_len, NULL, 0, NULL, 0, IPC_SUB,
               tport_id, sub.subj_hash );
  return this->sub_stop( ctx );
}

/* fwd a sub or unsub */
void
SubDB::fwd_sub( SubArgs &ctx ) noexcept
{
  const char * sub_prefix = ( ctx.is_start() ? S_JOIN : S_LEAVE );
  size_t       sub_prelen = ( ctx.is_start() ? S_JOIN_SZ : S_LEAVE_SZ );
  SubjectVar s( sub_prefix, sub_prelen, ctx.sub, ctx.sublen );
  TransportRoute * rte = this->user_db.ipc_transport;

  d_sub( "%ssub(%.*s)\n", ( ctx.is_start() ? "" : "un" ),
         (int) ctx.sublen, ctx.sub );
  MsgEst e( s.len() );
  e.seqno      ()
   .subj_hash  ()
   .subject    ( ctx.sublen )
   .queue      ( ctx.queue_len )
   .queue_hash ()
   .queue_refs ();

  MsgCat m;
  m.reserve( e.sz );

  this->update_sub_seqno( this->sub_seqno, this->sub_seqno + 1 );
  m.open( this->user_db.bridge_id.nonce, s.len() )
   .seqno     ( this->sub_seqno )
   .subj_hash ( ctx.hash )
   .subject   ( ctx.sub, ctx.sublen );

  if ( ctx.queue_hash != 0 ) {
    if ( ctx.queue_len != 0 )
      m.queue ( ctx.queue, ctx.queue_len );
    m.queue_hash ( ctx.queue_hash );
    if ( ctx.queue_refs != 0 )
      m.queue_refs ( ctx.queue_refs );
  }
  uint32_t h = s.hash();
  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( s.msg, s.len(), *this->user_db.session_key );

  this->user_db.msg_send_counter[ ctx.is_start() ? U_SUB_JOIN : U_SUB_LEAVE ]++;
  if ( ( ctx.flags & CONSOLE_SUB ) != 0 ) {
    if ( rte != NULL ) {
      NotifySub nsub( ctx.sub, ctx.sublen, ctx.inbox, ctx.inbox_len, ctx.hash,
                      false, 'C', this->my_src );
      nsub.bref = &this->console;
      if ( ctx.is_start() )
        rte->sub_route.do_notify_sub( nsub );
      else
        rte->sub_route.do_notify_unsub( nsub );
    }
  }
  EvPublish pub( s.msg, s.len(), NULL, 0, m.msg, m.len(),
                 rte->sub_route, this->my_src, h, CABA_TYPE_ID );
  this->user_db.mcast_send( pub, 0 );
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
     .seqno ( n.inbox.next_send( U_INBOX_SUBS ) )
     .start ( n.sub_seqno )
     .end   ( seqno       );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

    return this->user_db.forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
  }
  return true;
}
/* forward sub to peer inbox */
bool
SubDB::fwd_resub( UserBridge &n,  const char *sub,  size_t sublen,
                  uint64_t from_seqno,  uint64_t seqno,  bool is_psub,
                  const char *suf,  uint64_t token,  const char *queue,
                  uint16_t queue_len,  uint32_t queue_hash ) noexcept
{
  InboxBuf ibx( n.bridge_id, suf );

  MsgEst e( ibx.len() );
  e.seqno ();
  if ( ! is_psub )
    e.subject( sublen );
  else
    e.pattern( sublen );
  e.start      ()
   .end        ()
   .token      ()
   .queue      ( queue_len )
   .queue_hash ();

  MsgCat m;
  m.reserve( e.sz );
  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno( n.inbox.next_send( U_INBOX_RESUB ) );
  if ( ! is_psub )
    m.subject( sub, sublen );
  else
    m.pattern( sub, sublen );
  m.start ( from_seqno )
   .end   ( seqno      );
  if ( token != 0 )
    m.token  ( token );
  if ( queue_len != 0 ) {
    m.queue      ( queue, queue_len )
     .queue_hash ( queue_hash );
  }
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

  return this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len() );
}
/* locate sub */
bool
SubDB::find_fwd_sub( UserBridge &n,  uint32_t hash,
                     uint64_t &from_seqno,  uint64_t seqno,
                     const char *suf,  uint64_t token,
                     const char *match,  size_t match_len ) noexcept
{
  SubRoute   * sub;
  const char * queue      = NULL;
  uint16_t     queue_len  = 0;
  uint32_t     queue_hash = 0;
  if ( (sub = this->sub_tab.find_sub( hash, seqno )) == NULL ) {
    for ( uint32_t i = 0; i < this->queue_tab.count; i++ ) {
      SubTab &tab = this->queue_tab.ptr[ i ]->sub_tab;
      if ( (sub = tab.find_sub( hash, seqno )) != NULL ) {
        queue      = this->queue_tab.ptr[ i ]->queue;
        queue_len  = this->queue_tab.ptr[ i ]->queue_len;
        queue_hash = this->queue_tab.ptr[ i ]->queue_hash;
        break;
      }
    }
  }
  if ( sub == NULL )
    return true;
  bool b = true;
  if ( match_len == 0 ||
       kv_memmem( sub->value, sub->len, match, match_len ) != NULL ) {
    b &= this->fwd_resub( n, sub->value, sub->len, from_seqno, seqno, false,
                          suf ? suf : _RESUB, token, queue, queue_len,
                          queue_hash );
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
  PatRoute   * sub;
  const char * queue      = NULL;
  uint16_t     queue_len  = 0;
  uint32_t     queue_hash = 0;
  if ( (sub = this->pat_tab.find_sub( hash, seqno )) == NULL ) {
    for ( uint32_t i = 0; i < this->queue_tab.count; i++ ) {
      PatTab &ptab = this->queue_tab.ptr[ i ]->pat_tab;
      if ( (sub = ptab.find_sub( hash, seqno )) != NULL ) {
        queue      = this->queue_tab.ptr[ i ]->queue;
        queue_len  = this->queue_tab.ptr[ i ]->queue_len;
        queue_hash = this->queue_tab.ptr[ i ]->queue_hash;
        break;
      }
    }
  }
  if ( sub == NULL )
    return true;
  bool b = true;
  if ( match_len == 0 ||
       kv_memmem( sub->value, sub->len, match, match_len ) != NULL ) {
    b &= this->fwd_resub( n, sub->value, sub->len, from_seqno, seqno, true,
                          suf ? suf : _REPSUB, token, queue, queue_len,
                          queue_hash );
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
     .seqno  ( n.inbox.next_send( U_INBOX_RESUB ) )
     .start  ( from_seqno )
     .end    ( end        );
    if ( token != 0 )
      m.token( token );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

    b &= this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len() );
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
     .seqno( n.inbox.next_send( U_INBOX_BLOOM_REQ ) );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

    return this->user_db.forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
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
   .seqno    ( n.inbox.next_send( U_INBOX_BLOOM_RPY ) )
   .sub_seqno( this->sub_seqno            )
   .bloom    ( code.ptr, code.code_sz * 4 );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

  return this->user_db.forward_to_inbox( n, ibx, h, m.msg, m.len() );
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
      QueueNameArray q_arr;
      if ( n.bloom.decode( dec.mref[ FID_BLOOM ].fptr,
                           dec.mref[ FID_BLOOM ].fsize, q_arr ) ) {
        if ( q_arr.count > 0 ) {
          TransportRoute * ipc = this->user_db.ipc_transport;
          for ( size_t i = 0; i < q_arr.count; i++ ) {
            this->uid_route.get_queue_group( *q_arr.ptr[ i ] );
            if ( ipc != NULL )
              ipc->sub_route.get_queue_group( *q_arr.ptr[ i ] );
          }
        }
        d_sub( "update_bloom count %" PRIu64 "\n", n.bloom.bits->count );
        if ( debug_sub )
          print_bloom( *n.bloom.bits );

        this->update_sub_seqno( n.sub_seqno, sub_seqno );
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
    this->user_db.mcast_pub( pub, n, dec );
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
    uint32_t     hash, queue_hash, queue_refs;

    dec.get_ival<uint32_t>( FID_SUBJ_HASH, hash );
    if ( dec.get_ival<uint32_t>( FID_QUEUE_HASH, queue_hash ) &&
         dec.get_ival<uint32_t>( FID_QUEUE_REFS, queue_refs ) &&
         dec.test( FID_QUEUE ) ) {
      size_t       queue_len = dec.mref[ FID_QUEUE ].fsize;
      const char * queue     = (const char *) dec.mref[ FID_QUEUE ].fptr;
      this->uid_route.get_queue_group( queue, queue_len, queue_hash );
      QueueMatch m = { queue_hash, queue_refs,
                       QueueMatch::hash2( sub, sublen, hash ) };
      n.bloom.add_queue_route( SUB_RTE, hash, m );
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifyQueue nsub( sub, sublen, NULL, 0, hash, false, 'M', pub.src_route,
                          queue, queue_len, queue_hash );
        nsub.sub_count = queue_refs;
        nsub.bref = &n.bloom;
        rte->sub_route.do_notify_sub_q( nsub );
      }
    }
    else {
      n.bloom.add( hash );
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifySub   nsub( sub, sublen, hash, false, 'M', pub.src_route );
        nsub.bref = &n.bloom;
        rte->sub_route.do_notify_sub( nsub );
      }
    }
    if ( debug_sub )
      n.printf( "start %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.mcast_pub( pub, n, dec );
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
    uint32_t     hash, queue_hash;

    dec.get_ival<uint32_t>( FID_SUBJ_HASH, hash );
    if ( dec.get_ival<uint32_t>( FID_QUEUE_HASH, queue_hash ) ) {
      QueueMatch m = { queue_hash, 0, QueueMatch::hash2( sub, sublen, hash ) };
      n.bloom.del_queue_route( SUB_RTE, hash, m );
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifyQueue nsub( sub, sublen, NULL, 0, hash, false, 'M',
                          pub.src_route, NULL, 0, queue_hash );
        nsub.sub_count = 0;
        nsub.bref = &n.bloom;
        rte->sub_route.do_notify_unsub_q( nsub );
      }
    }
    else {
      n.bloom.del( hash );
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifySub   nsub( sub, sublen, hash, false, 'M', pub.src_route );
        nsub.bref = &n.bloom;
        rte->sub_route.do_notify_unsub( nsub );
      }
    }
    if ( debug_sub )
      n.printf( "stop %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.mcast_pub( pub, n, dec );
  }
  return true;
}

bool
SubDB::recv_resub_result( const MsgFramePublish &,  UserBridge &,
                          const MsgHdrDecoder & ) noexcept
{
  return true;
}

void
SubDB::reseed_bloom( void ) noexcept
{
  BloomBits * b;
  uint32_t seed;
  this->user_db.msg_send_counter[ U_BLOOM_FILTER ]++;

  seed = (uint32_t) this->user_db.rand.next();
  b = this->bloom.bits->reseed( this->bloom.bits, seed );
  this->bloom.bits = b;
  this->index_bloom( *b, CONSOLE_SUB | IPC_SUB );
  if ( debug_sub )
    print_bloom( *b );
  this->user_db.events.resize_bloom( (uint32_t) b->count );
  this->notify_bloom_update( this->bloom );

  seed = (uint32_t) this->user_db.rand.next();
  b = this->console.bits->reseed( this->console.bits, seed );
  this->console.bits = b;
  this->index_bloom( *b, CONSOLE_SUB );
  this->notify_bloom_update( this->console );

  seed = (uint32_t) this->user_db.rand.next();
  b = this->ipc.bits->reseed( this->ipc.bits, seed );
  this->ipc.bits = b;
  this->index_bloom( *b, IPC_SUB );
  this->notify_bloom_update( this->ipc );

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

  ForwardCache & forward = this->user_db.forward_path[ 0 ];
  uint32_t       tport_id;

  this->user_db.peer_dist.update_forward_cache( forward, 0, 0 );
  if ( forward.first( tport_id ) ) {
    do {
      TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
      EvPublish pub( Z_BLM, Z_BLM_SZ, NULL, 0, m.msg, m.len(),
                     rte->sub_route, this->my_src, blm_h, CABA_TYPE_ID );

      rte->sub_route.forward_except( pub, this->mgr.router_set );
    } while ( forward.next( tport_id ) );
  }
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
    this->user_db.msg_send_counter[ U_BLOOM_FILTER ]++;

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

    ForwardCache & forward = this->user_db.forward_path[ 0 ];
    uint32_t       tport_id;

    this->user_db.peer_dist.update_forward_cache( forward, 0, 0 );
    if ( forward.first( tport_id ) ) {
      do {
        TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
        EvPublish pub( Z_BLM, Z_BLM_SZ, NULL, 0, m.msg, m.len(),
                       rte->sub_route, this->my_src, blm_h, CABA_TYPE_ID );

        rte->sub_route.forward_except( pub, this->mgr.router_set );
      } while ( forward.next( tport_id ) );
    }
  }
}

void
SubDB::notify_bloom_update( BloomRef &ref ) noexcept
{
  TransportRoute * ipc = this->user_db.ipc_transport;
  if ( ipc != NULL )
    ipc->sub_route.do_notify_bloom_ref( ref );
#if 0
  for ( uint32_t i = 0; i < ref.nlinks; i++ ) {
    RoutePublish &sub_route = (RoutePublish &) ref.links[ i ]->rdb;
    if ( ref.links[ i ]->in_list == 1 ) {
      printf( "notofy_bloom_update link[ %u ] fd %u list %u, %s -> %s\n",
              i, ref.links[ i ]->r, ref.links[ i ]->in_list,
              ref.name, sub_route.service_name );
      sub_route.do_notify_bloom_ref( ref );
    }
  }
#endif
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

  for ( uint32_t i = 0; i < this->queue_tab.count; i++ ) {
    SubTab &tab = this->queue_tab.ptr[ i ]->sub_tab;
    PatTab &ptab = this->queue_tab.ptr[ i ]->pat_tab;
    if ( (rt = tab.tab.first( loc )) != NULL ) {
      do {
        if ( rt->test( flags ) )
          bits.add( rt->hash );
      } while ( (rt = tab.tab.next( loc )) != NULL );
    }
    if ( (pat = ptab.tab.first( loc )) != NULL ) {
      do {
        if ( pat->test( flags ) )
          bits.add( pat->hash );
      } while ( (pat = ptab.tab.next( loc )) != NULL );
    }
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
SubDB::match_seqno( const MsgFramePublish &pub,  SeqnoArgs &ctx ) noexcept
{
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
    if ( ! this->match_subscription( pub, ctx ) ) {
      this->seqno_tab.remove( loc, loc2, is_old );
      return SEQNO_NOT_SUBSCR;
    }
    return seq->init( uid, seqno, ctx.start_seqno, time, ctx.stamp,
                      this->update_seqno, ctx.cb, ctx.tport_mask );
  }
  /* check if subscription modified */
  const uint64_t old_start_seqno = seq->start_seqno;
  if ( seq->update_seqno != this->update_seqno ){
    if ( this->match_subscription( pub, ctx ) ) {
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
  if ( seq->last_uid != uid ) {
    size_t sz = 0,
           newsz;
    if ( seq->seqno_ht != NULL )
      sz = seq->seqno_ht->mem_size();
    SeqnoStatus status = seq->restore_uid( uid, seqno, time, ctx.stamp );
    newsz = seq->seqno_ht->mem_size();
    this->seqno_tab.seqno_ht_size =
      ( this->seqno_tab.seqno_ht_size - sz ) + newsz;
    if ( status == SEQNO_UID_FIRST )
      return SEQNO_UID_FIRST;
  }

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
SubDB::match_subscription( const kv::EvPublish &pub,  SeqnoArgs &ctx ) noexcept
{
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
        ctx.tport_mask |= rt->ref.tport_mask();
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
          ctx.tport_mask |= rt->ref.tport_mask();
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
      h = kv_crc_c( sub, i, RouteGroup::pre_seed[ i ] );

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

size_t
AnyMatch::init_any( const char *s,  uint16_t sublen, uint32_t uid_cnt,
                    bool is_queue ) noexcept
{
  size_t off = (char *) (void *) &this->match - (char *) (void *) this;
  char * ptr = (char *) (void *) this;
  ptr = &ptr[ off + BloomMatch::match_size( sublen ) ];
  ::memcpy( ptr, s, sublen );
  ptr[ sublen ] = '\0';

  this->max_uid   = align<uint32_t>( uid_cnt, 64 );
  this->mono_time = 0;
  this->sub_off   = (uint16_t) ( ptr - (char *) (void *) this );
  this->sub_len   = sublen;
  this->is_queue  = is_queue;
  ptr             = &ptr[ align<size_t>( sublen, 8 ) ];
  this->bits_off  = (uint32_t) ( ptr - (char *) (void *) this );
  ptr             = &ptr[ this->max_uid / 8 ];
  this->match.init_match( sublen );
  return ptr - (char *) (void *) this;
}

size_t
AnyMatch::any_size( uint16_t sublen,  uint32_t &uid_cnt ) noexcept
{
  uid_cnt = align<uint32_t>( uid_cnt, 64 );
  return align<size_t>( align<size_t>( sublen, 8 ) +
                        sizeof( AnyMatch ) +
                        kv::BloomMatch::match_size( sublen ) +
                        (size_t) uid_cnt / 8, 8 );
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
                        uint32_t max_uid,  bool is_queue ) noexcept
{
  AnyMatch * any;
  size_t     pos;
  uint32_t   off;
  if ( this->ht->find( h, pos, off ) ) {
    any = (AnyMatch *) (void *) &this->tab.ptr[ off ];
    if ( any->sub_len == sublen && ::memcmp( any->sub(), sub, sublen ) == 0 &&
         any->max_uid >= max_uid && any->is_queue == is_queue )
      return any;
    this->reset();
    this->ht->find( h, pos );
  }
  size_t     sz = AnyMatch::any_size( sublen, max_uid ) / 8, n;
  uint64_t * p  = this->tab.resize( this->max_off + sz, false );

  any = (AnyMatch *) (void *) &p[ this->max_off ];
  n   = any->init_any( sub, sublen, max_uid, is_queue );
  this->ht->set_rsz( this->ht, h, pos, (uint32_t) this->max_off );
  if ( sz < n / 8 ) {
    fprintf( stderr, "get_match is sz %lu %lu\n", sz, n / 8 );
  }
  this->max_off += n / 8;
  return any;
}

UserBridge *
AnyMatch::get_destination( UserDB &user_db ) noexcept
{
  BitSetT<uint64_t> set( this->bits() );
  uint32_t set_count = set.count( this->max_uid );
  uint32_t uid, pos = 0;
  bool b = false;
  if ( set_count > 1 )
    pos = user_db.rand.next() % set_count;
  b = set.index( uid, pos, this->max_uid );
  if ( b )
    return user_db.bridge_tab[ uid ];
  return NULL;
}

static inline uint32_t
hexval( int c )
{
  if ( c >= '0' && c <= '9' )
    return (uint32_t) ( c - '0' );
  if ( c >= 'A' && c <= 'F' )
    return (uint32_t) ( c - 'A' + 10 );
  if ( c >= 'a' && c <= 'f' )
    return (uint32_t) ( c - 'a' + 10 );
  return 16;
}

uint32_t
SubDB::host_match( const char *host,  size_t host_len ) noexcept
{
  if ( host_len != 8 )
    return 0;
  uint32_t host_id = 0;
  for ( int i = 8; i > 0; ) {
    uint32_t v1 = hexval( host[ --i ] ),
             v2 = hexval( host[ --i ] );
    if ( v1 == 16 || v2 == 16 )
      return 0;
    host_id = ( host_id << 8 ) | ( v2 << 4 ) | v1;
  }
  size_t pos;
  uint32_t uid;
  if ( this->user_db.host_ht->find( host_id, pos, uid ) )
    return uid;
  return 0;
}

AnyMatch *
SubDB::any_match( const char *sub,  uint16_t sublen,  uint32_t h ) noexcept
{
  AnyMatch * any;
  any = this->any_tab.get_match( sub, sublen, h, this->user_db.next_uid, false );
  if ( any->mono_time < this->sub_update_mono_time ) {
    BloomMatchArgs args( h, sub, sublen );
    BitSetT<uint64_t> set( any->bits() );
    set.zero( any->max_uid );
    for ( uint32_t uid = 1; uid < this->user_db.next_uid; uid++ ) {
      UserBridge * n = this->user_db.bridge_tab.ptr[ uid ];
      if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) {
        if ( any->mono_time < n->sub_recv_mono_time ) {
          if ( any->match.match_sub( args, n->bloom ) )
            set.add( uid );
        }
      }
    }
    any->mono_time = this->sub_update_mono_time;
  }
  return any;
}

AnyMatch *
SubDB::any_queue( EvPublish &pub ) noexcept
{
  AnyMatch * any;
  any = this->any_tab.get_match( pub.subject, pub.subject_len, pub.subj_hash,
                                 this->user_db.next_uid, true );
  BitSetT<uint64_t> set( any->bits() );
  set.zero( any->max_uid );

  RoutePublishContext ctx( this->uid_route, pub );
  RoutePublishData * rpd = ctx.set.rpd;
  for ( uint32_t i = 0; i < ctx.set.n; i++ ) {
    for ( uint32_t j = 0; j < rpd[ i ].rcount; j++ ) {
      set.add( rpd[ i ].routes[ j ] );
    }
  }
  return any;
}

void
ReplyCache::add_exists( uint32_t h,  uint32_t uid ) noexcept
{
  size_t   pos;
  uint32_t val;
  if ( this->exists_ht->find( h, pos, val ) ) {
    this->exists_ht->remove( pos ); /* collision */
    return;
  }
  this->exists_ht->set( h, pos, uid );
  this->exists_ht->check_resize( this->exists_ht );
}

uint32_t
ReplyCache::add_missing( uint32_t h,  uint32_t uid,  const char *sub,
                         size_t sublen,  uint64_t cur_mono ) noexcept
{
  RouteLoc loc;
  ReplyMissing * m = this->missing.upsert( h, sub, sublen, loc );
  if ( loc.is_new ) {
    m->mono_ns = cur_mono;
    m->ref     = 0;
    m->uid     = uid;
  }
  return m->ref++;
}

void
SubDB::reply_memo( const char *sub,  size_t sublen,  const char *host,
                   size_t hostlen,  UserBridge &n,  uint64_t cur_mono ) noexcept
{
  uint32_t       host_uid = this->host_match( host, hostlen );
  BloomMatchArgs args( 0, sub, sublen );
  BloomMatch     match;

  match.init_match( sublen );
  if ( match.test_prefix( args, n.bloom, n.reply_prefix ) != MAX_RTE ) {
    if ( host_uid == 0 )
      this->reply.add_exists( args.subj_hash, n.uid );
  }
  else {
    n.reply_prefix = match.sub_prefix( args, n.bloom );
    if ( n.reply_prefix != MAX_RTE ) {
      if ( host_uid == 0 ) {
        this->reply.add_exists( args.subj_hash, n.uid );
      }
    }
    else {
      if ( this->reply.add_missing( args.subj_hash, n.uid, sub, sublen,
                                    cur_mono ) == 0 ) {
        TransportRoute * rte;
        if ( (rte = this->user_db.ipc_transport) != NULL )
          rte->sub_route.add_sub_route( args.subj_hash, rte->fd );
      }
    }
  }
}

uint32_t
SubDB::lookup_memo( uint32_t h,  const char *sub,  size_t sublen ) noexcept
{
  size_t   pos;
  uint32_t uid;
  if ( this->reply.exists_ht->find( h, pos, uid ) ) {
    this->reply.exists_ht->remove( pos );
    return uid;
  }
  RouteLoc loc;
  ReplyMissing * m;
  if ( (m = this->reply.missing.find( h, sub, sublen, loc )) != NULL ) {
    uid = m->uid;
    if ( --m->ref == 0 ) {
      TransportRoute * rte;
      if ( (rte = this->user_db.ipc_transport) != NULL )
        rte->sub_route.del_sub_route( h, rte->fd );
      this->reply.missing.remove( loc );
    }
    return uid;
  }
  return 0;
}

void
SubDB::clear_memo( uint64_t cur_mono ) noexcept
{
  RouteLoc loc;
  TransportRoute * rte = this->user_db.ipc_transport;
  uint64_t delta = sec_to_ns( 2 );
  bool has_data = false;
  if ( rte != NULL ) {
    for ( ReplyMissing * m = this->reply.missing.first( loc ); m != NULL; ) {
      if ( m->mono_ns + delta < cur_mono ) {
        m->ref = 0;
        rte->sub_route.del_sub_route( m->hash, rte->fd );
        m = this->reply.missing.remove_and_next( m, loc );
      }
      else {
        m = this->reply.missing.next( loc );
        has_data = true;
      }
    }
  }
  if ( ! has_data )
    this->reply.missing.release();
}

static const char   ipc_queue[] = "_QUEUE";
static const char   ipc_inbox[] = "_INBOX";
static const size_t match_len = sizeof( ipc_inbox ) - 1;

int
SubDB::match_ipc_subject( const char *str,  size_t str_len,
                          const char *&pre,  size_t &pre_len,
                          const char *&name,  size_t &name_len,
                          const char *&subj,  size_t &subj_len,
                          const int match_flag ) noexcept
{
  const char * p;
  /* check for _QUEUE.name.xx or _XYZ._QUEUE.name.xx */
  pre_len = name_len = subj_len = 0;
  if ( str_len < match_len + 1 || str[ 0 ] != '_' )
    return IPC_NO_MATCH;
  bool is_inbox = ( match_flag & IPC_IS_INBOX ) != 0 &&
                  ::memcmp( str, ipc_inbox, match_len ) == 0,
       is_queue = ( match_flag & IPC_IS_QUEUE ) != 0 &&
                  ! is_inbox && ::memcmp( str, ipc_queue, match_len ) == 0;
  if ( is_inbox || is_queue ) {
    if ( str[ match_len ] == '.' ) {
      name     = &str[ match_len + 1 ];
      name_len = str_len - ( match_len + 1 );
    }
    else {
      name     = &str[ match_len ];
      name_len = str_len - match_len;
      if ( is_inbox ) /* _INBOX without '.' */
        return IPC_IS_INBOX_PREFIX;
      return IPC_NO_MATCH;
    }
  }
  else {
    /* skip over service prefix _7500. */
    p = (const char *) ::memchr( str, '.', str_len - match_len );
    /* if no '.' or terminates with '.' or starts with '.' */
    if ( p == NULL || &p[ 1 ] >= &str[ str_len ] || p == str )
      return IPC_NO_MATCH;
    pre      = str;
    pre_len  = p - str;
    str_len -= ( &p[ 1 ] - str );
    str      = &p[ 1 ];
    if ( str_len < match_len + 1 || str[ 0 ] != '_' )
      return IPC_NO_MATCH;
    is_inbox = ( match_flag & IPC_IS_INBOX ) != 0 &&
               ::memcmp( str, ipc_inbox, match_len ) == 0;
    is_queue = ( match_flag & IPC_IS_QUEUE ) != 0 &&
               ! is_inbox && ::memcmp( str, ipc_queue, match_len ) == 0;
    if ( ! is_inbox && ! is_queue ) /* not _INBOX or _QUEUE */
      return IPC_NO_MATCH;
    if ( str[ match_len ] == '.' ) { /* matched _INBOX. */
      name     = &str[ match_len + 1 ];
      name_len = str_len - ( match_len + 1 );
    }
    else { /* match _INBOX with non-'.' suffix */
      name     = &str[ match_len ];
      name_len = str_len - match_len;
      subj_len = 0;
      if ( is_inbox )
        return IPC_IS_INBOX_PREFIX;
      return IPC_NO_MATCH;
    }
  }
  p = (const char *) ::memchr( name, '.', name_len );
  if ( p == NULL ) {
    if ( is_inbox ) { /* _INBOX_xxx without host */
      subj_len = 0;
      return IPC_IS_INBOX_PREFIX;
    }
    return IPC_NO_MATCH;
  }
  subj = &p[ 1 ];
  if ( subj >= &name[ name_len ] ) /* _INBOX. without anything */
    return IPC_NO_MATCH;
  subj_len = &name[ name_len ] - subj;
  name_len = p - name;
  if ( name_len == 0 ) /* _INBOX..subj ?? */
    return IPC_NO_MATCH;
  return is_inbox ? IPC_IS_INBOX : IPC_IS_QUEUE;
}

int
SubDB::match_ipc_any( const char *str,  size_t str_len ) noexcept
{
  const char * pre, * subj, * name;
  size_t pre_len, subj_len, name_len;
  return match_ipc_subject( str, str_len, pre, pre_len, name, name_len,
                            subj, subj_len, IPC_IS_QUEUE | IPC_IS_INBOX );
}

bool
SubDB::match_queue( const char *str,  size_t str_len,
                    const char *&pre,  size_t &pre_len,
                    const char *&name,  size_t &name_len,
                    const char *&subj,  size_t &subj_len ) noexcept
{
  return match_ipc_subject( str, str_len, pre, pre_len, name, name_len,
                            subj, subj_len, IPC_IS_QUEUE ) == IPC_IS_QUEUE;
}

bool
SubDB::match_inbox( const char *str,  size_t str_len,
                    const char *&host,  size_t &host_len ) noexcept
{
  const char * pre, * subj;
  size_t pre_len, subj_len;
  return match_ipc_subject( str, str_len, pre, pre_len, host, host_len,
                            subj, subj_len, IPC_IS_INBOX ) >= IPC_IS_INBOX;
}

void
SubDB::queue_sub_update( NotifyQueue &sub,  uint32_t tport_id,
                         uint32_t refcnt ) noexcept
{
  printf( "queue_sub_update( %.*s, fd=%u, start=%" PRIx64 ", cnt=%u )\n",
          (int) sub.subject_len, sub.subject, sub.src.fd,
          sub.src.start_ns, refcnt );
  uint32_t flags = IPC_SUB | QUEUE_SUB;
  if ( sub.sub_count != 0 )
    flags |= IS_SUB_START;
  SubArgs ctx( sub.subject, sub.subject_len, NULL, 0, NULL,
               this->sub_seqno + 1, flags, tport_id, sub.subj_hash );
  ctx.queue      = sub.queue;
  ctx.queue_len  = sub.queue_len;
  ctx.queue_hash = sub.queue_hash;
  ctx.queue_refs = sub.sub_count;
  if ( ( flags & IS_SUB_START ) != 0 )
    this->sub_start( ctx );
  else
    this->sub_stop( ctx );
}
