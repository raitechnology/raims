#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <raims/session.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

uint64_t
SubDB::psub_start( const char *pat,  size_t patlen,  WildFmt fmt,
                   SubOnMsg *cb ) noexcept
{
  PatCtx ctx( pat, patlen, fmt, true, cb, this->sub_seqno + 1 );
  if ( this->pat_tab.start( ctx ) == SUB_OK ) {
    this->fwd_psub( ctx );
    return this->sub_seqno;
  }
  return 0;
}

uint64_t
SubDB::psub_stop( const char *pat,  size_t patlen,  WildFmt fmt ) noexcept
{
  PatCtx ctx( pat, patlen, fmt, false, NULL, 0 );
  if ( this->pat_tab.stop( ctx ) == SUB_OK ) {
    this->fwd_psub( ctx );
    this->pat_tab.remove( ctx );
    return this->sub_seqno;
  }
  return 0;
}

void
SubDB::fwd_psub( PatCtx &ctx ) noexcept
{
  const char * sub_prefix = ( ctx.is_start ? P_PSUB : P_PSTOP );
  size_t       sub_prelen = ( ctx.is_start ? P_PSUB_SZ : P_PSTOP_SZ );
  SubjectVar s( sub_prefix, sub_prelen, ctx.pat, ctx.cvt.prefixlen );

  MsgEst e( s.len() );
  e.seqno    ()
   .pattern  ( ctx.patlen )
   .fmt      ()
   .ref_count();

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, s.len() )
   .seqno    ( ++this->sub_seqno )
   .pattern  ( ctx.pat, ctx.patlen )
   .fmt      ( (uint32_t) ctx.fmt )
   .ref_count( ctx.count );
  uint32_t h = s.hash();
  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( s.msg, s.len(), *this->user_db.session_key );

  EvPublish pub( s.msg, s.len(), NULL, 0, m.msg, m.len(), this->my_src_fd, h,
                 NULL, 0, (uint8_t) MSG_BUF_TYPE_ID, 'p' );
  uint32_t rcnt;
  bool     rsz = false;

  d_sub( "psub(%.*s) %lu", (int) ctx.patlen, ctx.pat, ctx.cvt.prefixlen );
  if ( ctx.is_start ) {
    if ( ctx.rt->detail_type == NO_DETAIL )
      rsz = this->bloom.add_route( ctx.cvt.prefixlen, ctx.hash );
    else if ( ctx.rt->detail_type == SUFFIX_MATCH )
      rsz = this->bloom.add_suffix_route( ctx.cvt.prefixlen, ctx.hash,
                                          ctx.rt->u.suffix );
    else if ( ctx.rt->detail_type == SHARD_MATCH )
      rsz = this->bloom.add_shard_route( ctx.cvt.prefixlen, ctx.hash,
                                         ctx.rt->u.shard );
    else {
      fprintf( stderr, "bad detail\n" );
      rsz = false;
    }
  }
  else {
    if ( ctx.rt->detail_type == NO_DETAIL )
      this->bloom.del_route( ctx.cvt.prefixlen, ctx.hash );
    else if ( ctx.rt->detail_type == SUFFIX_MATCH )
      this->bloom.del_suffix_route( ctx.cvt.prefixlen, ctx.hash,
                                    ctx.rt->u.suffix );
    else if ( ctx.rt->detail_type == SHARD_MATCH )
      this->bloom.del_shard_route( ctx.cvt.prefixlen, ctx.hash,
                                   ctx.rt->u.shard );
    else {
      fprintf( stderr, "bad detail\n" );
    }
  }
  size_t count = this->user_db.transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ i ];
    rcnt = rte->sub_route.get_route_count( ctx.cvt.prefixlen, ctx.hash );
    if ( ctx.is_start ) {
      rte->sub_route.notify_psub( ctx.hash, ctx.cvt.out, ctx.cvt.off,
                                  ctx.pat, ctx.cvt.prefixlen,
                                  this->my_src_fd, ctx.count + rcnt, 's' );
    }
    else {
      rte->sub_route.notify_punsub( ctx.hash, ctx.cvt.out, ctx.cvt.off,
                                    ctx.pat, ctx.cvt.prefixlen,
                                    this->my_src_fd, ctx.count + rcnt, 's' );
    }
    rte->forward_to_connected_auth( pub );
  }
  if ( rsz )
    this->resize_bloom();
}

bool
PatCtx::cvt_wild( const uint32_t *seed ) noexcept
{
  if ( this->fmt == RV_WILD_FMT ) {
    if ( this->cvt.convert_rv( this->pat, this->patlen ) != 0 ) {
      fprintf( stderr, "bad pattern: %.*s\n", (int) this->patlen, this->pat );
      return false;
    }
  }
  else if ( this->fmt == GLOB_WILD_FMT ) {
    if ( this->cvt.convert_glob( this->pat, this->patlen ) != 0 ) {
      fprintf( stderr, "bad pattern: %.*s\n", (int) this->patlen, this->pat );
      return false;
    }
  }
  else {
    fprintf( stderr, "bad pattern fmt(%u): %.*s\n", this->fmt,
             (int) this->patlen, this->pat );
    return false;
  }
  this->hash = kv_crc_c( this->pat, this->cvt.prefixlen,
                         seed[ this->cvt.prefixlen ] );
  return true;
}

SubStatus
PatTab::start( PatCtx &ctx ) noexcept
{
  if ( ! ctx.cvt_wild( this->seed ) )
    return SUB_ERROR;
  ctx.rt = this->tab.upsert( ctx.hash, ctx.pat, ctx.patlen, ctx.loc );
  if ( ctx.rt == NULL )
    return SUB_ERROR;
  if ( ctx.loc.is_new ) {
    if ( ! ctx.rt->start( ctx ) ) {
      this->tab.remove( ctx.loc );
      return SUB_ERROR;
    }
    this->list.push( ctx.seqno, ctx.hash, ACTION_PSUB_START );
    this->prefix_count( ctx );
    return SUB_OK;
  }
  return SUB_EXISTS;
}

SubStatus
PatTab::stop( PatCtx &ctx ) noexcept
{
  if ( ! ctx.cvt_wild( this->seed ) )
    return SUB_ERROR;
  ctx.rt = this->tab.find( ctx.hash, ctx.pat, ctx.patlen, ctx.loc );
  if ( ctx.rt == NULL )
    return SUB_NOT_FOUND;
  this->prefix_count( ctx );
  ctx.count -= 1;
  return SUB_OK;
}

void
PatTab::remove( PatCtx &ctx ) noexcept
{
  this->list.pop( ctx.rt->start_seqno );
  ctx.rt->release();
  this->tab.remove( ctx.loc );
}

void
PatTab::prefix_count( PatCtx &ctx ) noexcept
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
PatRoute::start( PatCtx &ctx ) noexcept
{
  size_t erroff;
  int    error;
  bool   pattern_success = false;
  this->re = NULL;
  this->md = NULL;
  this->on_data = ctx.cb;
  /* if prefix matches, no need for pcre2 */
  if ( ctx.cvt.prefixlen + 1 == ctx.patlen &&
       ( ( ctx.fmt == RV_WILD_FMT && ctx.pat[ ctx.cvt.prefixlen ] == '>' ) ||
         ( ctx.fmt == GLOB_WILD_FMT && ctx.pat[ ctx.cvt.prefixlen ] == '*' ) ) )
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
    this->start_seqno = ctx.seqno;
    this->expires     = 0;
    this->ref_index   = 0;
    this->prefix_len  = ctx.cvt.prefixlen;

    return true;
  }
  if ( this->md != NULL )
    pcre2_match_data_free( this->md );
  if ( this->re != NULL )
    pcre2_code_free( this->re );
  return false;
}

bool
PatRoute::match( const char *sub,  size_t sublen ) const noexcept
{
  if ( this->re == NULL ) {
    return sublen >= this->prefix_len && /* len has > or * suffix */
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
  if ( dec.test_3( FID_PATTERN, FID_REF_COUNT, FID_FMT ) ) {
    UserRoute      & u_rte  = *n.user_route;
    TransportRoute & rte    = u_rte.rte;
    BloomDetail      d;
    uint32_t         rcnt, cnt, fmt;

    dec.get_ival<uint32_t>( FID_REF_COUNT, cnt );
    dec.get_ival<uint32_t>( FID_FMT, fmt );

    PatCtx ctx( (const char *) dec.mref[ FID_PATTERN ].fptr,
                dec.mref[ FID_PATTERN ].fsize, (WildFmt) fmt, true, NULL, 0 );

    if ( ! ctx.cvt_wild( this->pat_tab.seed ) )
      return true;
    rcnt = rte.sub_route.get_route_count( ctx.cvt.prefixlen, ctx.hash ) + 1;
    if ( d.from_pattern( ctx.cvt ) ) {
      if ( d.detail_type == NO_DETAIL )
        n.bloom.add_route( ctx.cvt.prefixlen, ctx.hash );
      else if ( d.detail_type == SUFFIX_MATCH )
        n.bloom.add_suffix_route( ctx.cvt.prefixlen, ctx.hash, d.u.suffix );
      else if ( d.detail_type == SHARD_MATCH )
        n.bloom.add_shard_route( ctx.cvt.prefixlen, ctx.hash, d.u.shard );
    }
    rte.sub_route.notify_psub( ctx.hash, ctx.cvt.out, ctx.cvt.off, ctx.pat,
                               ctx.cvt.prefixlen, u_rte.mcast_fd,
                               rcnt + ctx.count, 's' );
    if ( debug_sub )
      n.printf( "psub_start %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.forward_pub( pub, n, dec );
  }
  return true;
}

bool
SubDB::recv_psub_stop( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.test_3( FID_PATTERN, FID_REF_COUNT, FID_FMT ) ) {
    UserRoute      & u_rte  = *n.user_route;
    TransportRoute & rte    = u_rte.rte;
    BloomDetail      d;
    uint32_t         rcnt, cnt, fmt;

    dec.get_ival<uint32_t>( FID_REF_COUNT, cnt );
    dec.get_ival<uint32_t>( FID_FMT, fmt );

    PatCtx ctx( (const char *) dec.mref[ FID_PATTERN ].fptr,
                dec.mref[ FID_PATTERN ].fsize, (WildFmt) fmt, false, NULL, 0 );

    if ( ! ctx.cvt_wild( this->pat_tab.seed ) )
      return true;
    rcnt = rte.sub_route.get_route_count( ctx.cvt.prefixlen, ctx.hash ) - 1;
    if ( d.from_pattern( ctx.cvt ) ) {
      if ( d.detail_type == NO_DETAIL )
        n.bloom.del_route( ctx.cvt.prefixlen, ctx.hash );
      else if ( d.detail_type == SUFFIX_MATCH )
        n.bloom.del_suffix_route( ctx.cvt.prefixlen, ctx.hash, d.u.suffix );
      else if ( d.detail_type == SHARD_MATCH )
        n.bloom.del_shard_route( ctx.cvt.prefixlen, ctx.hash, d.u.shard );
    }
    rte.sub_route.notify_punsub( ctx.hash, ctx.cvt.out, ctx.cvt.off, ctx.pat,
                                 ctx.cvt.prefixlen,
                                 u_rte.mcast_fd, rcnt + cnt, 's' );
    if ( debug_sub )
      n.printf( "psub_stop %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.forward_pub( pub, n, dec );
  }
  return true;
}

