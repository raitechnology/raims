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

struct SubOnMsg;
struct PatRoute;

struct PatternArgs {
  const char           * pat;
  uint16_t               patlen;
  uint32_t               hash,
                         flags,
                         tport_id,
                         sub_count,
                         console_count,
                         ipc_count;
  uint64_t               seqno;
  const kv::PatternCvt & cvt;
  kv::RouteLoc           loc;
  PatRoute             * rt;
  SubOnMsg             * cb;
  bool                   bloom_updated,
                         resize_bloom,
                         sub_coll;

  PatternArgs( const char *p,  uint16_t len,  const kv::PatternCvt &c,
               SubOnMsg *on_msg,  uint64_t n,  uint32_t fl,  uint32_t tp,
               uint32_t h = 0 ) : 
    pat( p ), patlen( len ), hash( h ), flags( fl ), tport_id( tp ),
    sub_count( 0 ), console_count( 0 ), ipc_count( 0 ), seqno( n ),
    cvt( c ), rt( 0 ), cb( on_msg ),
    bloom_updated( false ), resize_bloom( false ), sub_coll( false ) {}

  bool cvt_wild( kv::PatternCvt &cvt,  const uint32_t *seed,
                 kv::PatternFmt fmt ) noexcept;
  bool is_start( void ) const {
    return ( this->flags & IS_SUB_START ) != 0;
  }
  bool is_inbox( void ) const {
    return ( this->flags & INBOX_SUB ) != 0;
  }
};

struct PatRoute : public kv::BloomDetail {
  uint64_t                  start_seqno; /* sequence of the subscription start */
  SubOnMsg                * on_data;
  SubRefs                   ref;
  pcre2_real_code_8       * re;    /* pcre match the subject, null if prefix */
  pcre2_real_match_data_8 * md;
  uint16_t                  len;
  char                      value[ 2 ]; /* wildcard used in protocol */

  bool start( PatternArgs &ctx ) noexcept;
  bool add( PatternArgs &ctx ) noexcept;
  bool rem( PatternArgs &ctx ) noexcept;
  bool match( const char *sub,  size_t len ) const noexcept;
  void release( void ) noexcept;
  bool test( uint32_t flags ) const {
    return this->ref.test( flags );
  }
};

struct PatTab {
  kv::RouteVec<PatRoute> tab;

  SubList        & list;
  const uint32_t * seed; /* prefix seeds */
  uint32_t         pref_count[ kv::MAX_PRE ];

  PatTab( SubList &l,  const uint32_t *s ) : list( l ), seed( s ) {
    ::memset( this->pref_count, 0, sizeof( this->pref_count ) );
  }
  uint16_t prefix_hash( const char *sub,  uint16_t sub_len,
                        uint32_t *hash,  uint8_t *prefix ) noexcept;
  SubStatus start( PatternArgs &ctx ) noexcept;
  SubStatus stop( PatternArgs &ctx ) noexcept;
  void remove( PatternArgs &ctx ) noexcept;
  /*void prefix_count( PatternArgs &ctx ) noexcept;*/

  PatRoute *find_sub( uint32_t hash, uint64_t seqno ) noexcept;
  bool prefix_hash_exists( uint16_t prefix_len,  uint32_t hash ) noexcept;
  void release( void ) noexcept;
};
}
}
#endif
