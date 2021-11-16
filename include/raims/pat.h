#ifndef __rai_raims__pat_h__
#define __rai_raims__pat_h__

#include <raikv/pattern_cvt.h>
#include <raikv/route_db.h>

extern "C" {
  struct pcre2_real_code_8;
  struct pcre2_real_match_data_8;
}

namespace rai {
namespace ms {

enum WildFmt {
  RV_WILD_FMT   = 0,
  GLOB_WILD_FMT = 1
};

struct SubOnMsg;
struct PatRoute;

struct PatCtx {
  const char   * pat;
  size_t         patlen;
  WildFmt        fmt;
  bool           is_start;
  kv::PatternCvt cvt;
  uint32_t       count,
                 hash;
  uint64_t       seqno;
  kv::RouteLoc   loc;
  PatRoute     * rt;
  SubOnMsg     * cb;

  PatCtx(  const char *p,  size_t len,  WildFmt f,  bool start,
           SubOnMsg *on_msg,  uint64_t n ) : 
    pat( p ), patlen( len ), fmt( f ), is_start( start ),
    count( 0 ), hash( 0 ), seqno( n ), rt( 0 ), cb( on_msg ) {}

  bool cvt_wild( const uint32_t *seed ) noexcept;
};

struct PatRoute : public kv::BloomDetail {
  uint64_t                  start_seqno, /* sequence of the subscription start */
                            expires;     /* if time limited subscription */
  SubOnMsg                * on_data;
  pcre2_real_code_8       * re;    /* pcre match the subject, null if prefix */
  pcre2_real_match_data_8 * md;
  uint32_t                  ref_index;
  uint16_t                  prefix_len,
                            len;
  char                      value[ 2 ]; /* wildcard used in protocol */

  bool start( PatCtx &ctx ) noexcept;
  bool match( const char *sub,  size_t len ) const noexcept;
  void release( void ) noexcept;
};

struct PatTab {
  kv::RouteVec<PatRoute> tab;

  SubList        & list;
  const uint32_t * seed; /* prefix seeds */

  PatTab( SubList &l,  const uint32_t *s ) : list( l ), seed( s ) {}

  SubStatus start( PatCtx &ctx ) noexcept;
  SubStatus stop( PatCtx &ctx ) noexcept;
  void remove( PatCtx &ctx ) noexcept;
  void prefix_count( PatCtx &ctx ) noexcept;

  PatRoute *find_sub( uint32_t hash, uint64_t seqno ) noexcept;
  bool prefix_hash_exists( uint16_t prefix_len,  uint32_t hash ) noexcept;
  void release( void ) noexcept;
};
}
}
#endif
