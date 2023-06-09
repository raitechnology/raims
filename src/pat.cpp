#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <raims/session.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

SubStatus
QueueSubArray::start( PatternArgs &ctx ) noexcept
{
  QueueSubTab *t = this->find_tab( ctx.queue, ctx.queue_len, ctx.queue_hash );
  if ( t == NULL )
    return SUB_ERROR;
  SubStatus status = t->pat_tab.start( ctx );
  if ( status == SUB_EXISTS )
    return SUB_UPDATED;
  return status;
}

SubStatus
QueueSubArray::stop( PatternArgs &ctx ) noexcept
{
  QueueSubTab *t = this->find_tab( ctx.queue, ctx.queue_len, ctx.queue_hash );
  if ( t == NULL )
    return SUB_NOT_FOUND;
  return t->pat_tab.stop( ctx );
}

uint64_t
SubDB::psub_start( PatternArgs &ctx ) noexcept
{
  SubStatus status;
  if ( ctx.queue_hash == 0 )
    status = this->pat_tab.start( ctx );
  else
    status = this->queue_tab.start( ctx );

  d_sub( "psub_start %.*s count %u queue_refs %u status %s\n",
          (int) ctx.patlen, ctx.pat, ctx.sub_count, ctx.queue_refs,
          sub_status_string( status ) );

  if ( status == SUB_OK || status == SUB_UPDATED ) {
    this->update_bloom( ctx );

    if ( ctx.sub_count == 1 )
      this->fwd_psub( ctx );

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
SubDB::psub_stop( PatternArgs &ctx ) noexcept
{
  SubStatus status;
  if ( ctx.queue_hash == 0 )
    status = this->pat_tab.stop( ctx );
  else
    status = this->queue_tab.stop( ctx );

  d_sub( "psub_stop %.*s count %u queue_refs %u status %s\n",
        (int) ctx.patlen, ctx.pat, ctx.sub_count, ctx.queue_refs,
        sub_status_string( status ) );

  if ( status == SUB_OK || status == SUB_UPDATED ) {
    this->update_bloom( ctx );

    if ( ctx.sub_count == 0 )
      this->fwd_psub( ctx );

    if ( ctx.resize_bloom )
      this->resize_bloom();

    if ( status == SUB_OK ) {
      ctx.tab->remove( ctx );
      return this->sub_seqno;
    }
    if ( status == SUB_UPDATED )
      return ctx.seqno;
  }
  return 0;
}

bool
SubDB::add_bloom( PatternArgs &ctx,  BloomRef &b ) noexcept
{
  uint16_t prelen = (uint16_t) ctx.cvt.prefixlen;
  bool     rsz = false;
  if ( ctx.rt->detail_type == NO_DETAIL )
    rsz = b.add_route( prelen, ctx.hash );
  else if ( ctx.rt->detail_type == SUFFIX_MATCH )
    rsz = b.add_suffix_route( prelen, ctx.hash, ctx.rt->u.suffix );
  else if ( ctx.rt->detail_type == SHARD_MATCH )
    rsz = b.add_shard_route( prelen, ctx.hash, ctx.rt->u.shard );
  else if ( ctx.rt->detail_type == QUEUE_MATCH )
    rsz = b.add_queue_route( prelen, ctx.hash, ctx.rt->u.queue );
  else
    fprintf( stderr, "bad detail\n" );
  return rsz;
}

void
SubDB::del_bloom( PatternArgs &ctx,  BloomRef &b ) noexcept
{
  uint16_t prelen = (uint16_t) ctx.cvt.prefixlen;
  if ( ctx.rt->detail_type == NO_DETAIL )
    b.del_route( prelen, ctx.hash );
  else if ( ctx.rt->detail_type == SUFFIX_MATCH )
    b.del_suffix_route( prelen, ctx.hash, ctx.rt->u.suffix );
  else if ( ctx.rt->detail_type == SHARD_MATCH )
    b.del_shard_route( prelen, ctx.hash, ctx.rt->u.shard );
  else if ( ctx.rt->detail_type == QUEUE_MATCH )
    b.del_queue_route( prelen, ctx.hash, ctx.rt->u.queue );
  else
    fprintf( stderr, "bad detail\n" );
}

void
SubDB::update_bloom( PatternArgs &ctx ) noexcept
{
  bool is_q = ( ctx.flags & QUEUE_SUB ) != 0;
  this->update_seqno++;
  if ( ctx.is_start() ) {
    if ( is_q || ctx.sub_count == 1 ) {
      ctx.resize_bloom  = this->add_bloom( ctx, this->bloom );
      ctx.bloom_updated = true;
    }
    if ( ( ctx.flags & CONSOLE_SUB ) != 0 &&
         ( is_q || ctx.console_count == 1 ) )
      ctx.resize_bloom |= this->add_bloom( ctx, this->console );
    if ( ( ctx.flags & IPC_SUB ) != 0 &&
         ( is_q || ctx.ipc_count == 1 ) )
      ctx.resize_bloom |= this->add_bloom( ctx, this->ipc );
  }
  else {
    if ( ctx.sub_count == 0 ) {
      this->del_bloom( ctx, this->bloom );
      ctx.bloom_updated = true;
    }
    if ( ( ctx.flags & CONSOLE_SUB ) != 0 && ctx.console_count == 0 )
      this->del_bloom( ctx, this->console );
    if ( ( ctx.flags & IPC_SUB ) != 0 && ctx.ipc_count == 0 )
      this->del_bloom( ctx, this->ipc );
  }
}

bool
PatternArgs::cvt_wild( PatternCvt &cvt,  PatternFmt fmt ) noexcept
{
  if ( fmt == RV_PATTERN_FMT ) {
    if ( cvt.convert_rv( this->pat, this->patlen ) != 0 ) {
      fprintf( stderr, "bad pattern: %.*s\n", (int) this->patlen, this->pat );
      return false;
    }
  }
  else if ( fmt == GLOB_PATTERN_FMT ) {
    if ( cvt.convert_glob( this->pat, this->patlen ) != 0 ) {
      fprintf( stderr, "bad pattern: %.*s\n", (int) this->patlen, this->pat );
      return false;
    }
  }
  else {
    fprintf( stderr, "bad pattern fmt(%u): %.*s\n", fmt,
             (int) this->patlen, this->pat );
    return false;
  }
  if ( this->hash == 0 )
    this->hash = kv_crc_c( this->pat, cvt.prefixlen,
                           RouteGroup::pre_seed[ cvt.prefixlen ] );
  return true;
}

uint64_t
SubDB::console_psub_start( const char *pat,  uint16_t patlen,  PatternFmt fmt,
                           SubOnMsg *cb ) noexcept
{
  PatternCvt cvt;
  PatternArgs ctx( pat, patlen, cvt, cb, this->sub_seqno + 1,
                   CONSOLE_SUB | IS_SUB_START, 0 );
  if ( ! ctx.cvt_wild( cvt, fmt ) )
    return 0;
  return this->psub_start( ctx );
}

uint64_t
SubDB::console_psub_stop( const char *pat,  uint16_t patlen,
                          PatternFmt fmt ) noexcept
{
  PatternCvt cvt;
  PatternArgs ctx( pat, patlen, cvt, NULL, 0, CONSOLE_SUB, 0 );
  if ( ! ctx.cvt_wild( cvt, fmt ) )
    return 0;
  return this->psub_stop( ctx );
}

uint64_t
SubDB::ipc_psub_start( NotifyPattern &pat,  uint32_t tport_id ) noexcept
{
  PatternArgs ctx( pat.pattern, pat.pattern_len, pat.cvt, NULL, this->sub_seqno + 1,
                IPC_SUB | IS_SUB_START, tport_id, pat.prefix_hash );
  return this->psub_start( ctx );
}

uint64_t
SubDB::ipc_psub_stop( NotifyPattern &pat,  uint32_t tport_id ) noexcept
{
  PatternArgs ctx( pat.pattern, pat.pattern_len, pat.cvt, NULL, 0,
                   IPC_SUB, tport_id, pat.prefix_hash );
  return this->psub_stop( ctx );
}

void
SubDB::fwd_psub( PatternArgs &ctx ) noexcept
{
  const char * sub_prefix = ( ctx.is_start() ? P_PSUB : P_PSTOP );
  size_t       sub_prelen = ( ctx.is_start() ? P_PSUB_SZ : P_PSTOP_SZ );
  SubjectVar s( sub_prefix, sub_prelen, ctx.pat, ctx.cvt.prefixlen );
  TransportRoute * rte = this->user_db.ipc_transport;

  d_sub( "p%ssub(%.*s) prelen=%u\n", ( ctx.is_start() ? "" : "un" ),
          (int) ctx.patlen, ctx.pat, (uint32_t) ctx.cvt.prefixlen );
  MsgEst e( s.len() );
  e.seqno      ()
   .subj_hash  ()
   .pattern    ( ctx.patlen )
   .fmt        ()
   .queue      ( ctx.queue_len )
   .queue_hash ()
   .queue_refs ()
   .bloom_upd  ();

  MsgCat m;
  m.reserve( e.sz );

  this->update_sub_seqno( this->sub_seqno, this->sub_seqno + 1 );
  m.open( this->user_db.bridge_id.nonce, s.len() )
   .seqno     ( this->sub_seqno )
   .subj_hash ( ctx.hash )
   .pattern   ( ctx.pat, ctx.patlen )
   .fmt       ( (uint32_t) ctx.cvt.fmt );

  if ( ctx.queue_hash != 0 ) {
    if ( ctx.queue_len != 0 )
      m.queue ( ctx.queue, ctx.queue_len );
    m.queue_hash ( ctx.queue_hash );
    if ( ctx.queue_refs != 0 )
      m.queue_refs ( ctx.queue_refs );
  }
  if ( ! ctx.bloom_updated )
    m.bloom_upd( ctx.bloom_updated );
  uint32_t h = s.hash();
  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( s.msg, s.len(), *this->user_db.session_key );

  this->user_db.msg_send_counter[ ctx.is_start() ? U_PSUB_START : U_PSUB_STOP ]++;
  if ( ( ctx.flags & CONSOLE_SUB ) != 0 ) {
    if ( rte != NULL ) {
      NotifyPattern npat( ctx.cvt, ctx.pat, ctx.patlen, ctx.hash,
                          false, 'C', this->my_src );
      npat.bref = &this->console;
      if ( ctx.is_start() )
        rte->sub_route.do_notify_psub( npat );
      else
        rte->sub_route.do_notify_punsub( npat );
    }
  }
  EvPublish pub( s.msg, s.len(), NULL, 0, m.msg, m.len(),
                 rte->sub_route, this->my_src, h, CABA_TYPE_ID );
  this->user_db.mcast_send( pub, 0 );
}

SubStatus
PatTab::start( PatternArgs &ctx ) noexcept
{
  uint32_t hcnt;
  uint16_t preflen = ctx.cvt.prefixlen;
  if ( preflen >= MAX_PRE )
    preflen = MAX_PRE - 1;
  ctx.tab = this;
  ctx.rt = this->tab.upsert2( ctx.hash, ctx.pat, ctx.patlen, ctx.loc, hcnt );
  if ( ctx.rt == NULL )
    return SUB_ERROR;
  if ( ctx.loc.is_new ) {
    if ( ! ctx.rt->start( ctx ) ) {
      this->tab.remove( ctx.loc );
      return SUB_ERROR;
    }
    ctx.sub_coll = ( hcnt > 0 );
    this->pref_count[ preflen ]++;
    this->list.push( ctx.seqno, ctx.hash, ACTION_PSUB_START );
    return SUB_OK;
  }
  ctx.sub_coll = ( hcnt > 1 );
  if ( ctx.rt->add( ctx ) ) {
    this->pref_count[ preflen ]++;
    return SUB_UPDATED;
  }
  return SUB_EXISTS;
}

SubStatus
PatTab::stop( PatternArgs &ctx ) noexcept
{
  uint32_t hcnt;
  uint16_t preflen = ctx.cvt.prefixlen;
  if ( preflen >= MAX_PRE )
    preflen = MAX_PRE - 1;
  ctx.tab = this;
  ctx.rt = this->tab.find2( ctx.hash, ctx.pat, ctx.patlen, ctx.loc, hcnt );
  if ( ctx.rt == NULL )
    return SUB_NOT_FOUND;
  ctx.sub_coll = ( hcnt > 1 );
  this->pref_count[ preflen ]--;
  if ( ! ctx.rt->rem( ctx ) )
    return SUB_UPDATED;
  return SUB_OK;
}

uint16_t
PatTab::prefix_hash( const char *sub,  uint16_t sub_len,
                     uint32_t *hash,  uint8_t *prefix ) noexcept
{
  size_t   keylen[ MAX_PRE ];
  uint16_t x = 0, k = 0;

  for ( uint16_t i = 0; i < MAX_PRE; i++ ) {
    if ( i > sub_len )
      break;
    if ( this->pref_count[ i ] != 0 ) {
      keylen[ x ] = i;
      hash[ x++ ] = RouteGroup::pre_seed[ i ];
    }
  }
  if ( x > 0 ) {
    if ( keylen[ 0 ] == 0 )
      k++;
    kv_crc_c_key_array( sub, &keylen[ k ], &hash[ k ], x-k );
    for ( k = 0; k < x; k++ )
      prefix[ k ] = (uint8_t) keylen[ k ];
  }
  return x;
}

void
PatTab::remove( PatternArgs &ctx ) noexcept
{
  this->list.pop( ctx.rt->start_seqno );
  ctx.rt->release();
  this->tab.remove( ctx.loc );
}
#if 0
void
PatTab::prefix_count( PatternArgs &ctx ) noexcept
{
  RouteLoc   loc;
  PatRoute * rt = this->tab.find_by_hash( ctx.hash, loc );
  ctx.count = 0;
  while ( rt != NULL ) {
    if ( ctx.cvt.prefixlen == rt->prefix_len &&
         ::memcmp( ctx.pat, rt->value, rt->prefix_len ) == 0 ) {
      rt->ref_index = ctx.count++;
    }
    rt = this->tab.find_next_by_hash( ctx.hash, loc );
  }
}
#endif
PatRoute *
PatTab::find_sub( uint32_t hash, uint64_t seqno ) noexcept
{
  kv::RouteLoc loc;
  PatRoute   * rt = this->tab.find_by_hash( hash, loc );
  while ( rt != NULL ) {
    if ( rt->start_seqno == seqno )
      break;
    rt = this->tab.find_next_by_hash( hash, loc );
  }
  return rt;
}

bool
PatTab::prefix_hash_exists( uint16_t prefix_len,  uint32_t hash ) noexcept
{
  kv::RouteLoc loc;
  PatRoute * rt    = this->tab.find_by_hash( hash, loc );
  while ( rt != NULL ) {
    if ( prefix_len == rt->prefix_len /*&&
         ::memcmp( sub, rt->value, prefix_len ) == 0*/ ) {
      return true;
    }
    rt = this->tab.find_next_by_hash( hash, loc );
  }
  return false;
}

void
PatTab::release( void ) noexcept
{
  kv::RouteLoc loc;
  for ( PatRoute *rt = this->tab.first( loc ); rt != NULL;
        rt = this->tab.next( loc ) ) {
    rt->release();
  }
  this->tab.release();
}

bool
PatRoute::start( PatternArgs &ctx ) noexcept
{
  size_t erroff;
  int    error;
  bool   pattern_success = false;
  this->re = NULL;
  this->md = NULL;
  /* if prefix matches, no need for pcre2 */
  if ( ctx.cvt.prefixlen + 1 == ctx.patlen &&
       ( ( ctx.cvt.fmt == RV_PATTERN_FMT &&
           ctx.pat[ ctx.cvt.prefixlen ] == '>' ) ||
         ( ctx.cvt.fmt == GLOB_PATTERN_FMT &&
           ctx.pat[ ctx.cvt.prefixlen ] == '*' ) ) )
    pattern_success = true;
  else {
    this->re = pcre2_compile( (uint8_t *) ctx.cvt.out, ctx.cvt.off, 0, &error,
                              &erroff, 0 );
    if ( this->re == NULL ) {
      fprintf( stderr, "re failed\n" );
    }
    else {
      this->md = pcre2_match_data_create_from_pattern( this->re, NULL );
      if ( this->md == NULL )
        fprintf( stderr, "md failed\n" );
      else
        pattern_success = true;
    }
  }
  if ( pattern_success && this->from_pattern( ctx.cvt ) ) {
    this->prefix_len  = (uint16_t) ctx.cvt.prefixlen;
    this->start_seqno = ctx.seqno;
    this->on_data     = ctx.cb;
    this->ref.init( ctx.flags, ctx.tport_id );
    ctx.sub_count     = 1;
    ctx.console_count = this->ref.console_count();
    ctx.ipc_count     = this->ref.ipc_count();
    if ( ctx.queue_hash != 0 ) {
      QueueMatch m = { ctx.queue_hash, ctx.queue_refs,
                    QueueMatch::hash2( ctx.pat, ctx.cvt.prefixlen, ctx.hash ) };
      this->init_queue( m );
    }
    return true;
  }
  if ( this->md != NULL )
    pcre2_match_data_free( this->md );
  if ( this->re != NULL )
    pcre2_code_free( this->re );
  return false;
}

bool
PatRoute::add( PatternArgs &ctx ) noexcept
{
  if ( ctx.queue_hash != 0 ) {
    QueueMatch m = { ctx.queue_hash, ctx.queue_refs,
                    QueueMatch::hash2( ctx.pat, ctx.cvt.prefixlen, ctx.hash ) };
    this->init_queue( m );
  }
  if ( this->ref.add( ctx.flags, ctx.tport_id ) ) {
    if ( ( ctx.flags & CONSOLE_SUB ) != 0 )
      this->on_data = ctx.cb;
    ctx.sub_count     = this->ref.ref_count();
    ctx.console_count = this->ref.console_count();
    ctx.ipc_count     = this->ref.ipc_count();
    ctx.seqno         = this->start_seqno;
    return true;
  }
  return false;
}

bool
PatRoute::rem( PatternArgs &ctx ) noexcept
{
  if ( this->ref.rem( ctx.flags, ctx.tport_id ) ) {
    if ( ( ctx.flags & CONSOLE_SUB ) != 0 )
      this->on_data = NULL;
    ctx.sub_count     = this->ref.ref_count();
    ctx.console_count = this->ref.console_count();
    ctx.ipc_count     = this->ref.ipc_count();
    if ( ctx.sub_count == 0 )
      return true;
    ctx.seqno = this->start_seqno;
  }
  return false;
}

bool
PatRoute::match( const char *sub,  size_t sublen ) const noexcept
{
  if ( this->re == NULL ) {
    return sublen >= (size_t) this->prefix_len && /* len has > or * suffix */
           ::memcmp( this->value, sub, this->prefix_len ) == 0;
  }
  return pcre2_match( this->re, (const uint8_t *) sub, sublen,
                      0, 0, this->md, 0 ) == 1;
}

void
PatRoute::release( void ) noexcept
{
  if ( this->md != NULL )
    pcre2_match_data_free( this->md );
  if ( this->re != NULL )
    pcre2_code_free( this->re );
}

bool
SubDB::recv_repsub_result( const MsgFramePublish &,  UserBridge &,
                           const MsgHdrDecoder & ) noexcept
{
  return true;
}

bool
SubDB::recv_psub_start( const MsgFramePublish &pub,  UserBridge &n,
                        const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.test_3( FID_PATTERN, FID_SUBJ_HASH, FID_FMT ) ) {
    PatternCvt  cvt;
    BloomDetail d;
    uint32_t    fmt,
                hash, queue_hash, queue_refs;
    bool        bloom_updated = true;

    if ( dec.test( FID_BLOOM_UPD ) )
      cvt_number<bool>( dec.mref[ FID_BLOOM_UPD ], bloom_updated );

    dec.get_ival<uint32_t>( FID_FMT, fmt );
    dec.get_ival<uint32_t>( FID_SUBJ_HASH, hash );

    PatternArgs ctx( (const char *) dec.mref[ FID_PATTERN ].fptr,
                     (uint16_t) dec.mref[ FID_PATTERN ].fsize, cvt,
                     NULL, 0, IS_SUB_START, 0, hash );
    if ( ! ctx.cvt_wild( cvt, (PatternFmt) fmt ) )
      return true;
    if ( dec.get_ival<uint32_t>( FID_QUEUE_HASH, queue_hash ) &&
         dec.get_ival<uint32_t>( FID_QUEUE_REFS, queue_refs ) &&
         dec.test( FID_QUEUE ) ) {
      size_t       queue_len = dec.mref[ FID_QUEUE ].fsize;
      const char * queue     = (const char *) dec.mref[ FID_QUEUE ].fptr;
      uint16_t     preflen   = ctx.cvt.prefixlen;
      this->uid_route.get_queue_group( queue, queue_len, queue_hash );
      if ( bloom_updated ) {
        QueueMatch m = { queue_hash, queue_refs,
                         QueueMatch::hash2( ctx.pat, preflen, hash ) };
        n.bloom.add_queue_route( preflen, ctx.hash, m );
      }
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifyPatternQueue npat( ctx.cvt, ctx.pat, ctx.patlen, ctx.hash,
                                 false, 'M', pub.src_route, queue, queue_len,
                                 queue_hash );
        npat.bref = &n.bloom;
        rte->sub_route.do_notify_psub_q( npat );
      }
    }
    else if ( d.from_pattern( ctx.cvt ) ) {
      if ( bloom_updated ) {
        if ( d.detail_type == NO_DETAIL )
          n.bloom.add_route( (uint16_t) ctx.cvt.prefixlen, ctx.hash );
        else if ( d.detail_type == SUFFIX_MATCH )
          n.bloom.add_suffix_route( (uint16_t) ctx.cvt.prefixlen, ctx.hash,
                                    d.u.suffix );
        else if ( d.detail_type == SHARD_MATCH )
          n.bloom.add_shard_route( (uint16_t) ctx.cvt.prefixlen, ctx.hash,
                                   d.u.shard );
      }
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifyPattern npat( ctx.cvt, ctx.pat, ctx.patlen, ctx.hash,
                            false, 'M', pub.src_route );
        npat.bref = &n.bloom;
        rte->sub_route.do_notify_psub( npat );
      }
    }
    if ( debug_sub )
      n.printf( "psub_start %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.mcast_pub( pub, n, dec );
  }
  return true;
}

bool
SubDB::recv_psub_stop( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.test_3( FID_PATTERN, FID_SUBJ_HASH, FID_FMT ) ) {
    PatternCvt  cvt;
    BloomDetail d;
    uint32_t    fmt,
                hash, queue_hash;
    bool        bloom_updated = true;

    if ( dec.test( FID_BLOOM_UPD ) )
      cvt_number<bool>( dec.mref[ FID_BLOOM_UPD ], bloom_updated );

    dec.get_ival<uint32_t>( FID_FMT, fmt );
    dec.get_ival<uint32_t>( FID_SUBJ_HASH, hash );

    PatternArgs ctx( (const char *) dec.mref[ FID_PATTERN ].fptr,
                     (uint16_t) dec.mref[ FID_PATTERN ].fsize, cvt,
                     NULL, 0, 0, 0, hash );
    if ( ! ctx.cvt_wild( cvt, (PatternFmt) fmt ) )
      return true;
    if ( dec.get_ival<uint32_t>( FID_QUEUE_HASH, queue_hash ) ) {
      if ( bloom_updated ) {
        uint16_t preflen = ctx.cvt.prefixlen;
        QueueMatch m = { queue_hash, 0,
                         QueueMatch::hash2( ctx.pat, preflen, hash ) };
        n.bloom.del_queue_route( preflen, ctx.hash, m );
      }
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifyPatternQueue npat( ctx.cvt, ctx.pat, ctx.patlen, ctx.hash,
                                 false, 'M', pub.src_route, NULL, 0,
                                 queue_hash );
        npat.bref = &n.bloom;
        rte->sub_route.do_notify_punsub_q( npat );
      }
    }
    else if ( d.from_pattern( cvt ) ) {
      if ( bloom_updated ) {
        if ( d.detail_type == NO_DETAIL )
          n.bloom.del_route( (uint16_t) cvt.prefixlen, ctx.hash );
        else if ( d.detail_type == SUFFIX_MATCH )
          n.bloom.del_suffix_route( (uint16_t) cvt.prefixlen, ctx.hash,
                                    d.u.suffix );
        else if ( d.detail_type == SHARD_MATCH )
          n.bloom.del_shard_route( (uint16_t) cvt.prefixlen, ctx.hash,
                                   d.u.shard );
      }
      TransportRoute *rte = this->user_db.ipc_transport;
      if ( rte != NULL ) {
        NotifyPattern npat( cvt, ctx.pat, ctx.patlen, ctx.hash,
                            false, 'M', pub.src_route );
        npat.bref = &n.bloom;
        rte->sub_route.do_notify_punsub( npat );
      }
    }
    if ( debug_sub )
      n.printf( "psub_stop %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.mcast_pub( pub, n, dec );
  }
  return true;
}

void
SubDB::queue_psub_update( NotifyPatternQueue &pat,
                          uint32_t tport_id,  uint32_t refcnt ) noexcept
{
  d_sub( "queue_psub_update( %.*s, fd=%u, start=%" PRIx64 ", cnt=%u )\n",
          (int) pat.pattern_len, pat.pattern, pat.src.fd,
          pat.src.start_ns, refcnt );
  uint32_t flags = IPC_SUB | QUEUE_SUB;
  if ( pat.sub_count != 0 )
    flags |= IS_SUB_START;
  PatternArgs ctx( pat.pattern, pat.pattern_len, pat.cvt, NULL, 0,
                   flags, tport_id, pat.prefix_hash );
  ctx.queue      = pat.queue;
  ctx.queue_len  = pat.queue_len;
  ctx.queue_hash = pat.queue_hash;
  ctx.queue_refs = pat.sub_count;
  if ( ( flags & IS_SUB_START ) != 0 ) 
    this->psub_start( ctx );
  else
    this->psub_stop( ctx );
}
