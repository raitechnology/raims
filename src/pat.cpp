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
SubDB::psub_start( PatternArgs &ctx ) noexcept
{
  SubStatus status = this->pat_tab.start( ctx );
  if ( status == SUB_OK || status == SUB_UPDATED ) {
    this->update_bloom( ctx );
    if ( status == SUB_OK ) {
      this->fwd_psub( ctx );
      return this->sub_seqno;
    }
    if ( status == SUB_UPDATED )
      return ctx.seqno;
  }
  return 0;
}

uint64_t
SubDB::psub_stop( PatternArgs &ctx ) noexcept
{
  SubStatus status = this->pat_tab.stop( ctx );
  if ( status == SUB_OK || status == SUB_UPDATED ) {
    this->update_bloom( ctx );
    if ( status == SUB_OK ) {
      this->fwd_psub( ctx );
      this->pat_tab.remove( ctx );
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
  bool rsz = false;
  if ( ctx.rt->detail_type == NO_DETAIL )
    rsz = b.add_route( ctx.cvt.prefixlen, ctx.hash );
  else if ( ctx.rt->detail_type == SUFFIX_MATCH )
    rsz = b.add_suffix_route( ctx.cvt.prefixlen, ctx.hash, ctx.rt->u.suffix );
  else if ( ctx.rt->detail_type == SHARD_MATCH )
    rsz = b.add_shard_route( ctx.cvt.prefixlen, ctx.hash, ctx.rt->u.shard );
  else
    fprintf( stderr, "bad detail\n" );
  return rsz;
}

void
SubDB::del_bloom( PatternArgs &ctx,  BloomRef &b ) noexcept
{
  if ( ctx.rt->detail_type == NO_DETAIL )
    b.del_route( ctx.cvt.prefixlen, ctx.hash );
  else if ( ctx.rt->detail_type == SUFFIX_MATCH )
    b.del_suffix_route( ctx.cvt.prefixlen, ctx.hash, ctx.rt->u.suffix );
  else if ( ctx.rt->detail_type == SHARD_MATCH )
    b.del_shard_route( ctx.cvt.prefixlen, ctx.hash, ctx.rt->u.shard );
  else
    fprintf( stderr, "bad detail\n" );
}

void
SubDB::update_bloom( PatternArgs &ctx ) noexcept
{
  bool rsz = false;
  this->update_seqno++;
  if ( ctx.is_start ) {
    if ( ctx.sub_count == 1 )
      rsz = this->add_bloom( ctx, this->bloom );
    if ( ( ctx.flags & INTERNAL_SUB ) != 0 && ctx.internal_count == 1 )
      rsz |= this->add_bloom( ctx, this->internal );
    if ( ( ctx.flags & EXTERNAL_SUB ) != 0 && ctx.external_count == 1 )
      rsz |= this->add_bloom( ctx, this->external );
  }
  else {
    if ( ctx.sub_count == 0 )
      this->del_bloom( ctx, this->bloom );
    if ( ( ctx.flags & INTERNAL_SUB ) != 0 && ctx.internal_count == 0 )
      this->del_bloom( ctx, this->internal );
    if ( ( ctx.flags & EXTERNAL_SUB ) != 0 && ctx.external_count == 0 )
      this->del_bloom( ctx, this->external );
  }
  if ( rsz )
    this->resize_bloom();
}

static bool
cvt_wild( PatternCvt &cvt,  const char *pat,  uint16_t patlen,
          const uint32_t *seed,  PatternFmt fmt,  uint32_t &hash ) noexcept
{
  if ( fmt == RV_PATTERN_FMT ) {
    if ( cvt.convert_rv( pat, patlen ) != 0 ) {
      fprintf( stderr, "bad pattern: %.*s\n", (int) patlen, pat );
      return false;
    }
  }
  else if ( fmt == GLOB_PATTERN_FMT ) {
    if ( cvt.convert_glob( pat, patlen ) != 0 ) {
      fprintf( stderr, "bad pattern: %.*s\n", (int) patlen, pat );
      return false;
    }
  }
  else {
    fprintf( stderr, "bad pattern fmt(%u): %.*s\n", fmt,
             (int) patlen, pat );
    return false;
  }
  hash = kv_crc_c( pat, cvt.prefixlen, seed[ cvt.prefixlen ] );
  return true;
}

uint64_t
SubDB::internal_psub_start( const char *pat,  uint16_t patlen,  PatternFmt fmt,
                            SubOnMsg *cb ) noexcept
{
  PatternCvt cvt;
  PatternArgs ctx( pat, patlen, cvt, true, cb, this->sub_seqno + 1,
                   INTERNAL_SUB, 0 );
  if ( ! cvt_wild( cvt, pat, patlen, this->pat_tab.seed, fmt, ctx.hash ) )
    return 0;
  return this->psub_start( ctx );
}

uint64_t
SubDB::internal_psub_stop( const char *pat,  uint16_t patlen,
                           PatternFmt fmt ) noexcept
{
  PatternCvt cvt;
  PatternArgs ctx( pat, patlen, cvt, false, NULL, 0, INTERNAL_SUB, 0 );
  if ( ! cvt_wild( cvt, pat, patlen, this->pat_tab.seed, fmt, ctx.hash ) )
    return 0;
  return this->psub_stop( ctx );
}

uint64_t
SubDB::external_psub_start( NotifyPattern &pat,  uint32_t tport_id ) noexcept
{
  PatternArgs ctx( pat.pattern, pat.pattern_len, pat.cvt, true, NULL,
                   this->sub_seqno + 1, EXTERNAL_SUB, tport_id );
  ctx.hash = pat.prefix_hash;
  return this->psub_start( ctx );
}

uint64_t
SubDB::external_psub_stop( NotifyPattern &pat,  uint32_t tport_id ) noexcept
{
  PatternArgs ctx( pat.pattern, pat.pattern_len, pat.cvt, false, NULL, 0,
                   EXTERNAL_SUB, tport_id );
  ctx.hash = pat.prefix_hash;
  return this->psub_stop( ctx );
}

void
SubDB::fwd_psub( PatternArgs &ctx ) noexcept
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
   .fmt      ( (uint32_t) ctx.cvt.fmt );
  uint32_t h = s.hash();
  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( s.msg, s.len(), *this->user_db.session_key );

  d_sub( "psub(%.*s) %lu\n", (int) ctx.patlen, ctx.pat, ctx.cvt.prefixlen );
  size_t count = this->user_db.transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ i ];
    if ( ! rte->is_set( TPORT_IS_EXTERNAL ) ) {
      NotifyPattern npat( ctx.cvt, ctx.pat, ctx.patlen, ctx.hash,
                          this->my_src_fd, false, 'M' );
      if ( ctx.is_start )
        rte->sub_route.do_notify_psub( npat );
      else
        rte->sub_route.do_notify_punsub( npat );
      EvPublish pub( s.msg, s.len(), NULL, 0, m.msg, m.len(),
                     rte->sub_route, this->my_src_fd, h, CABA_TYPE_ID, 'p' );
      rte->forward_to_connected_auth( pub );
    }
  }
}

SubStatus
PatTab::start( PatternArgs &ctx ) noexcept
{
  ctx.rt = this->tab.upsert( ctx.hash, ctx.pat, ctx.patlen, ctx.loc );
  if ( ctx.rt == NULL )
    return SUB_ERROR;
  if ( ctx.loc.is_new ) {
    if ( ! ctx.rt->start( ctx ) ) {
      this->tab.remove( ctx.loc );
      return SUB_ERROR;
    }
    this->list.push( ctx.seqno, ctx.hash, ACTION_PSUB_START );
    return SUB_OK;
  }
  if ( ctx.rt->add( ctx ) )
    return SUB_UPDATED;
  return SUB_EXISTS;
}

SubStatus
PatTab::stop( PatternArgs &ctx ) noexcept
{
  ctx.rt = this->tab.find( ctx.hash, ctx.pat, ctx.patlen, ctx.loc );
  if ( ctx.rt == NULL )
    return SUB_NOT_FOUND;
  if ( ! ctx.rt->rem( ctx ) )
    return SUB_UPDATED;
  return SUB_OK;
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
    this->prefix_len  = ctx.cvt.prefixlen;
    this->start_seqno = ctx.seqno;
    this->on_data     = ctx.cb;
    this->ref.init( ctx.flags, ctx.tport_id );
    ctx.sub_count      = 1;
    ctx.internal_count = this->ref.internal_ref;
    ctx.external_count = this->ref.external_refs;
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
  if ( this->ref.add( ctx.flags, ctx.tport_id ) ) {
    if ( ( ctx.flags & INTERNAL_SUB ) != 0 )
      this->on_data = ctx.cb;
    ctx.sub_count      = this->ref.ref_count();
    ctx.internal_count = this->ref.internal_ref;
    ctx.external_count = this->ref.external_refs;
    ctx.seqno          = this->start_seqno;
    return true;
  }
  return false;
}

bool
PatRoute::rem( PatternArgs &ctx ) noexcept
{
  if ( this->ref.rem( ctx.flags, ctx.tport_id ) ) {
    if ( ( ctx.flags & INTERNAL_SUB ) != 0 )
      this->on_data = NULL;
    ctx.sub_count      = this->ref.ref_count();
    ctx.internal_count = this->ref.internal_ref;
    ctx.external_count = this->ref.external_refs;
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
  if ( dec.test_2( FID_PATTERN, FID_FMT ) ) {
    UserRoute      & u_rte  = *n.user_route;
    TransportRoute & rte    = u_rte.rte;
    PatternCvt       cvt;
    BloomDetail      d;
    uint32_t         fmt;

    dec.get_ival<uint32_t>( FID_FMT, fmt );

    PatternArgs ctx( (const char *) dec.mref[ FID_PATTERN ].fptr,
                     dec.mref[ FID_PATTERN ].fsize, cvt,
                     true, NULL, 0, 0, 0 );
    if ( ! cvt_wild( cvt, ctx.pat, ctx.patlen, this->pat_tab.seed,
                     (PatternFmt) fmt, ctx.hash ) )
      return true;
    if ( d.from_pattern( ctx.cvt ) ) {
      if ( d.detail_type == NO_DETAIL ) {
        n.bloom.add_route( ctx.cvt.prefixlen, ctx.hash );
      }
      else if ( d.detail_type == SUFFIX_MATCH ) {
        n.bloom.add_suffix_route( ctx.cvt.prefixlen, ctx.hash, d.u.suffix );
      }
      else if ( d.detail_type == SHARD_MATCH ) {
        n.bloom.add_shard_route( ctx.cvt.prefixlen, ctx.hash, d.u.shard );
      }
    }
    NotifyPattern npat( ctx.cvt, ctx.pat, ctx.patlen, ctx.hash,
                        u_rte.mcast_fd, false, 'M' );
    rte.sub_route.do_notify_psub( npat );
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
  if ( dec.test_2( FID_PATTERN, FID_FMT ) ) {
    UserRoute      & u_rte  = *n.user_route;
    TransportRoute & rte    = u_rte.rte;
    PatternCvt       cvt;
    BloomDetail      d;
    uint32_t         fmt;

    dec.get_ival<uint32_t>( FID_FMT, fmt );

    PatternArgs ctx( (const char *) dec.mref[ FID_PATTERN ].fptr,
                     dec.mref[ FID_PATTERN ].fsize, cvt,
                     false, NULL, 0, 0, 0 );
    if ( ! cvt_wild( cvt, ctx.pat, ctx.patlen, this->pat_tab.seed,
                     (PatternFmt) fmt, ctx.hash ) )
      return true;
    if ( d.from_pattern( cvt ) ) {
      if ( d.detail_type == NO_DETAIL )
        n.bloom.del_route( cvt.prefixlen, ctx.hash );
      else if ( d.detail_type == SUFFIX_MATCH )
        n.bloom.del_suffix_route( cvt.prefixlen, ctx.hash, d.u.suffix );
      else if ( d.detail_type == SHARD_MATCH )
        n.bloom.del_shard_route( cvt.prefixlen, ctx.hash, d.u.shard );
    }
    NotifyPattern npat( cvt, ctx.pat, ctx.patlen, ctx.hash,
                        u_rte.mcast_fd, false, 'M' );
    rte.sub_route.do_notify_punsub( npat );
    if ( debug_sub )
      n.printf( "psub_stop %.*s\n", (int) pub.subject_len, pub.subject );
    this->user_db.forward_pub( pub, n, dec );
  }
  return true;
}

