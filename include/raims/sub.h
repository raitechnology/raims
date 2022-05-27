#ifndef __rai_raims__sub_h__
#define __rai_raims__sub_h__

#include <raikv/route_ht.h>
#include <raikv/key_hash.h>
#include <raims/sub_list.h>

namespace rai {
namespace ms {

/*
 * tab[ subject ] -> hash, start_seqno > stop_seqno = sub active
 *                         start_seqno < stop_seqno = sub inactive
 *                   initial : true
 *                   expires : stamp
 *                   return : 2
 *
 * ptab[ prefix ] -> phash, start_seqno, stop_seqno
 *                   subject : SUB.*.HELLO
 *                   pattern : (?s)\ASUB\.*\.HELLO\Z
 *                   expires : stamp
 */
enum SubStatus {
  SUB_OK          = 0, /* subscribe operation success */
  SUB_EXISTS      = 1, /* subject already subscribed */
  SUB_UPDATED     = 2,
  SUB_NOT_FOUND   = 3, /* subject not subscribed */
  SUB_REMOVED     = 4, /* last uid unsubscribed, subject dropped */
  SUB_PAT_OK      = 5, /* pattern subscribe success */
  SUB_PAT_REMOVED = 6, /* pattern unsub removed */
  SUB_ERROR       = 7  /* alloc error */
};

static inline const char *sub_status_string( SubStatus status ) {
  static const char *status_string[] = {
    "OK", "EXISTS", "NOT_FOUND", "REMOVED", "PAT_OK", "PAT_REMOVED", "ERROR"
  };
  if ( (uint8_t) status <= 6 )
    return status_string[ (uint8_t) status ];
  return "BAD";
}

struct SubMsgData;
struct MsgFramePublish;
struct MsgHdrDecoder;
struct SubOnMsg {
  SubOnMsg() {}
  virtual void on_data( const SubMsgData &val ) noexcept;
};

enum SubFlags {
  CONSOLE_SUB = 1,
  IPC_SUB     = 2
};

struct SubRefs {
  static const uint32_t ALL_MASK = ~(uint32_t) 0;
  uint32_t console_ref  : 1,
           ipc_refs : 31;
  uint32_t tport_mask;

  void init( uint32_t flags,  uint32_t tport_id ) {
    this->console_ref = 0;
    this->ipc_refs    = 0;
    this->tport_mask  = 0;
    this->add( flags, tport_id );
  }
  bool add( uint32_t flags,  uint32_t tport_id ) {
    if ( ( flags & CONSOLE_SUB ) != 0 ) {
      if ( this->console_ref != 0 )
        return false;
      this->console_ref = 1;
    }
    else {
      if ( tport_id >= 32 )
        this->tport_mask = ALL_MASK;
      else {
        uint32_t mask = 1U << tport_id;
        if ( ( this->tport_mask & mask ) != 0 )
          return false;
        this->tport_mask |= mask;
      }
      this->ipc_refs++;
    }
    return true;
  }
  bool rem( uint32_t flags,  uint32_t tport_id ) {
    if ( ( flags & CONSOLE_SUB ) != 0 ) {
      if ( this->console_ref == 0 )
        return false;
      this->console_ref = 0;
    }
    else {
      if ( this->ipc_refs == 0 )
        return false;
      if ( this->tport_mask != ALL_MASK && tport_id < 32 ) {
        uint32_t mask = 1U << tport_id;
        if ( ( this->tport_mask & mask ) == 0 )
          return false;
        this->tport_mask &= ~mask;
      }
      this->ipc_refs--;
    }
    return true;
  }
  bool is_empty( void ) const {
    return ( this->console_ref == 0 && this->ipc_refs == 0 );
  }
  bool test( uint32_t flags ) const {
    if ( ( flags & CONSOLE_SUB ) != 0 && this->console_ref != 0 )
      return true;
    if ( ( flags & IPC_SUB ) != 0 && this->ipc_refs != 0 )
      return true;
    return false;
  }
  uint32_t ref_count( void ) const {
    return this->console_ref + this->ipc_refs;
  }
};

struct SubArgs {
  const char * sub;
  uint16_t     sublen;
  bool         is_start;
  SubOnMsg   * cb;
  uint64_t     seqno;
  uint32_t     flags,
               hash,
               tport_id,
               sub_count,
               console_count,
               ipc_count,
               sub_coll,
               console_coll,
               ipc_coll;
  bool         bloom_updated,
               resize_bloom;

  SubArgs( const char *s,  uint16_t len,  bool start,  SubOnMsg *on_msg,
           uint64_t n,  uint32_t fl,  uint32_t tp,  uint32_t h = 0 ) :
    sub( s ), sublen( len ), is_start( start ), cb( on_msg ), seqno( n ),
    flags( fl ), hash( h ), tport_id( tp ),
    sub_count( 0 ), console_count( 0 ), ipc_count( 0 ),
    sub_coll( 0 ), console_coll( 0 ), ipc_coll( 0 ),
    bloom_updated( false ), resize_bloom( false ) {
    if ( h == 0 ) this->hash = kv_crc_c( s, len, 0 );
  }
};

struct SubRoute {
  uint64_t   start_seqno; /* sequence of subscription start */
  SubOnMsg * on_data;
  SubRefs    ref;
  uint32_t   hash;        /* hash crc of the value[] */
  uint16_t   len;
  char       value[ 2 ];

  void start( SubArgs &ctx ) {
    this->start_seqno = ctx.seqno;
    this->on_data     = ctx.cb;
    this->ref.init( ctx.flags, ctx.tport_id );
    ctx.sub_count     = 1;
    ctx.console_count = this->ref.console_ref;
    ctx.ipc_count     = this->ref.ipc_refs;
  }
  bool add( SubArgs &ctx ) {
    if ( this->ref.add( ctx.flags, ctx.tport_id ) ) {
      if ( ( ctx.flags & CONSOLE_SUB ) != 0 )
        this->on_data = ctx.cb;
      ctx.sub_count     = this->ref.ref_count();
      ctx.console_count = this->ref.console_ref;
      ctx.ipc_count     = this->ref.ipc_refs;
      ctx.seqno         = this->start_seqno;
      return true;
    }
    return false;
  }
  bool rem( SubArgs &ctx ) {
    if ( this->ref.rem( ctx.flags, ctx.tport_id ) ) {
      if ( ( ctx.flags & CONSOLE_SUB ) != 0 )
        this->on_data = NULL;
      ctx.sub_count     = this->ref.ref_count();
      ctx.console_count = this->ref.console_ref;
      ctx.ipc_count     = this->ref.ipc_refs;
      if ( ctx.sub_count == 0 )
        return true;
      ctx.seqno = this->start_seqno;
    }
    return false;
  }
  bool test( uint32_t flags ) const {
    return this->ref.test( flags );
  }
};

struct SubTab {
  kv::RouteVec<SubRoute> tab; /* hash indexed SubRoute */
  SubList & list;             /* subscription list for replay */

  SubTab( SubList &l ) : list( l ) {}

  SubStatus start( SubArgs &ctx ) {
    kv::RouteLoc loc;
    uint32_t hcnt;
    SubRoute *rt = this->tab.upsert2( ctx.hash, ctx.sub, ctx.sublen, loc, hcnt);
    if ( rt == NULL )
      return SUB_ERROR;
    if ( hcnt > 0 )
      this->resolve_coll( ctx, rt );
    if ( loc.is_new ) {
      rt->start( ctx );
      this->list.push( ctx.seqno, ctx.hash, ACTION_SUB_JOIN );
      return SUB_OK;
    }
    if ( rt->add( ctx ) )
      return SUB_UPDATED;
    return SUB_EXISTS;
  }

  SubStatus stop( SubArgs &ctx ) {
    kv::RouteLoc loc;
    uint32_t hcnt;
    SubRoute *rt = this->tab.find2( ctx.hash, ctx.sub, ctx.sublen, loc, hcnt );
    if ( rt == NULL ) {
      printf( "\"%.*s\" not found\n", (int) ctx.sublen, ctx.sub );
      return SUB_NOT_FOUND;
    }
    if ( hcnt > 1 )
      this->resolve_coll( ctx, rt );
    if ( rt->rem( ctx ) ) {
      if ( ! this->list.pop( rt->start_seqno ) ) {
        printf( "stop %.*s seqno %u not found\n", 
                (int) ctx.sublen, ctx.sub, (uint32_t) rt->start_seqno );
      }
      this->tab.remove( loc );
      return SUB_OK;
    }
    return SUB_UPDATED;
  }

  SubRoute *find_sub( uint32_t hash, uint64_t seqno ) {
    kv::RouteLoc loc;
    SubRoute *rt = this->tab.find_by_hash( hash, loc );
    while ( rt != NULL ) {
      if ( rt->start_seqno == seqno )
         break;
      rt = this->tab.find_next_by_hash( hash, loc );
    }
    return rt;
  }
  void resolve_coll( SubArgs &ctx,  SubRoute *rt ) {
    kv::RouteLoc loc;
    SubRoute *rt2 = this->tab.find_by_hash( ctx.hash, loc );
    while ( rt2 != NULL ) {
      if ( rt != rt2 ) {
        ctx.sub_coll     += rt->ref.ref_count();
        ctx.console_coll += rt->ref.console_ref;
        ctx.ipc_coll     += rt->ref.ipc_refs;
      }
      rt2 = this->tab.find_next_by_hash( ctx.hash, loc );
    }
  }

  void release( void ) {
    this->tab.release();
  }
};

struct Pub {
  int64_t  seqno;
  uint32_t hash;
  uint16_t len;
  char     value[ 2 ]; /* prefix */
  
  void init( bool is_inbox ) {
    this->seqno = ( is_inbox ? -1 : 0 );
  }
  bool is_inbox( void ) const {
    return this->seqno < 0;
  }
  int64_t next_seqno( void ) {
    return ++this->seqno;
  }
};

typedef kv::RouteVec<Pub> PubTab;

struct SeqnoSave {
  uint32_t save[ 4 ];

  SeqnoSave() {}
  SeqnoSave( const SeqnoSave &sv ) {
    for ( size_t i = 0; i < 4; i++ )
      this->save[ i ] = sv.save[ i ];
  }
  SeqnoSave &operator=( const SeqnoSave &sv ) {
    for ( size_t i = 0; i < 4; i++ )
      this->save[ i ] = sv.save[ i ];
    return *this;
  }

  void update( uint64_t seqno,  uint64_t time ) {
    ::memcpy( &this->save[ 0 ], &seqno, sizeof( uint64_t ) );
    ::memcpy( &this->save[ 2 ], &time, sizeof( uint64_t ) );
  }
  void restore( uint64_t &seqno,  uint64_t &time ) const {
    ::memcpy( &seqno, &this->save[ 0 ], sizeof( uint64_t ) );
    ::memcpy( &time, &this->save[ 2 ], sizeof( uint64_t ) );
  }
};

typedef kv::IntHashTabT<uint32_t,SeqnoSave> UidSeqno;

enum SeqnoStatus {
  SEQNO_UID_FIRST  = 0, /* first time uid published */
  SEQNO_UID_NEXT   = 1, /* is next in the sequnce */
  SEQNO_UID_REPEAT = 2, /* is a repeated sequence */
  SEQNO_NOT_SUBSCR = 3, /* subscription not matched */
  SEQNO_ERROR      = 4
};

const char *seqno_status_string( SeqnoStatus status ) noexcept;

struct SubSeqno {
  uint32_t   hash,        /* hash of subject */
             last_uid;    /* last uid publisher */
  uint64_t   last_seqno,  /* seqno of last msg used by uid */
             last_time,   /* time of last msg */
             start_seqno, /* the seqno of the sub start */
             update_seqno;/* the seqno when the sub was matched */
  SubOnMsg * on_data;     /* callback cached */
  UidSeqno * seqno_ht;    /* uid -> to saved seqno/time pairs */
  uint32_t   tport_mask;  /* tport cached */
  uint16_t   len;         /* len of subject */
  char       value[ 2 ];  /* subject */

  SeqnoStatus init( uint32_t uid,  uint64_t seqno,  uint64_t start,
                    uint64_t time,  uint64_t upd_sno,  SubOnMsg *cb,
                    uint32_t mask ) {
    this->last_uid     = uid;
    this->last_seqno   = seqno;
    this->last_time    = time;
    this->start_seqno  = start;
    this->update_seqno = upd_sno;
    this->on_data      = cb;
    this->seqno_ht     = NULL;
    this->tport_mask   = mask;
    return SEQNO_UID_FIRST;
  }
  /* check that seqno is next published by uid (or first) */
  SeqnoStatus update( uint32_t uid,  uint64_t seqno,  uint64_t time,
                      uint64_t &last_seqno_recvd,
                      uint64_t &last_time_recvd ) {
    /* if not the last uid published */
    if ( this->last_uid != uid ) {
      if ( this->restore_uid( uid, seqno, time ) == SEQNO_UID_FIRST )
        return SEQNO_UID_FIRST;
    }
    return this->update_last( seqno, time, last_seqno_recvd,
                              last_time_recvd );
  }
  SeqnoStatus restore_uid( uint32_t uid,  uint64_t seqno,
                           uint64_t time ) noexcept;
  /* set the next seqno */
  SeqnoStatus update_last( uint64_t seqno,  uint64_t time,
                           uint64_t &last_seqno_recvd,
                           uint64_t &last_time_recvd ) {
    SeqnoStatus status = SEQNO_UID_REPEAT; /* if repeated */
    last_seqno_recvd = this->last_seqno;
    last_time_recvd  = this->last_time;
    if ( seqno > this->last_seqno ) {
      this->last_seqno = seqno;
      status = SEQNO_UID_NEXT;
    }
    if ( time > this->last_time ) {
      this->last_time = time;
      status = SEQNO_UID_NEXT;
    }
    return status;
  }

  void release( void ) {
    if ( this->seqno_ht != NULL )
      delete this->seqno_ht;
  }
};

struct SeqnoArgs {
  const MsgFramePublish & pub;
  uint64_t   time,        /* message time */
             last_seqno,  /* last message seqno */
             last_time,   /* last message time */
             start_seqno; /* subscription start */
  SubOnMsg * cb;          /* callback for subscription */
  uint32_t   tport_mask;  /* tports matched */

  SeqnoArgs( const MsgFramePublish &p )
    : pub( p ), time( 0 ), last_seqno( 0 ), last_time( 0 ), start_seqno( 0 ),
      cb( 0 ), tport_mask( 0 ) {}
};

struct InboxSub {
  SubOnMsg * on_data;
  uint32_t   hash;
  uint16_t   len;
  char       value[ 2 ];

  void init( SubOnMsg *cb ) {
    this->on_data = cb;
  }
};

typedef kv::RouteVec<SubSeqno> SeqnoTab;
typedef kv::RouteVec<InboxSub> InboxTab;

struct AnyMatch {
  uint32_t       max_uid,
                 set_count;
  const char   * sub;
  uint64_t     * bits,
                 mono_time;
  kv::BloomMatch match;

  void init_any( const char *s,  uint16_t sublen,  const uint32_t *pre_seed,
                 uint32_t uid_cnt ) noexcept;
  static size_t any_size( uint16_t sublen,  uint32_t uid_cnt ) noexcept;
};

struct AnyMatchTab {
  kv::ArraySpace<uint64_t, 256> tab;
  kv::UIntHashTab * ht;
  size_t            max_off;

  AnyMatchTab() : ht( 0 ), max_off( 0 ) {
    this->ht = kv::UIntHashTab::resize( NULL );
  }
  AnyMatch *get_match( const char *sub,  uint16_t sublen,  uint32_t h,
                       const uint32_t *pre_seed,  uint32_t max_uid ) noexcept;
};

}
}

#include <raims/pat.h>

namespace rai {
namespace ms {

struct UserDB;
struct SessionMgr;
struct UserBridge;

struct SubDB {
  UserDB     & user_db;
  SessionMgr & mgr;
  uint32_t     my_src_fd,    /* subs routed to my_src_fd */
               next_inbox;   /* next inbox sub free */
  uint64_t     sub_seqno,    /* sequence number for my subs */
               update_seqno, /* sequence number updated for ext and int subs */
               sub_update_mono_time; /* last time any sub recvd */
  SeqnoTab     seqno_tab;    /* sub -> seqno, time */
  InboxTab     inbox_tab;    /* inbox -> seqno, time */
  SubList      sub_list;     /* list of { seqno, subscriptions } */
  SubTab       sub_tab;      /* subject -> { state, seqno } */
  PatTab       pat_tab;      /* pattern -> { state, seqno } */
  PubTab       pub_tab;      /* subject -> seqno */
  AnyMatchTab  any_tab;
  kv::BloomRef bloom,
               console,
               ipc;

  SubDB( kv::EvPoll &p,  UserDB &udb,  SessionMgr &smg ) noexcept;

  void init( uint32_t src_fd ) {
    this->my_src_fd = src_fd;
    this->sub_seqno = 0;
    this->update_seqno = 0;
    this->sub_update_mono_time = 0;
  }
  uint64_t sub_start( SubArgs &ctx ) noexcept;
  uint64_t sub_stop( SubArgs &ctx ) noexcept;
  void update_bloom( SubArgs &ctx ) noexcept;
  /* start a new sub for this session */
  uint64_t console_sub_start( const char *sub,  uint16_t sublen,
                              SubOnMsg *cb ) noexcept;
  uint64_t console_sub_stop( const char *sub,  uint16_t sublen ) noexcept;
  /* start a new pattern sub for this session */
  uint64_t console_psub_start( const char *pat,  uint16_t patlen,
                               kv::PatternFmt fmt,  SubOnMsg *cb ) noexcept;
  uint64_t console_psub_stop( const char *pat,  uint16_t patlen,
                              kv::PatternFmt fmt ) noexcept;

  uint32_t inbox_start( uint32_t inbox_num,  SubOnMsg *cb ) noexcept;

  uint64_t psub_start( PatternArgs &ctx ) noexcept;
  uint64_t psub_stop( PatternArgs &ctx ) noexcept;
  void update_bloom( PatternArgs &ctx ) noexcept;
  bool add_bloom( PatternArgs &ctx,  kv::BloomRef &b ) noexcept;
  void del_bloom( PatternArgs &ctx,  kv::BloomRef &b ) noexcept;

  /* start a new sub for ipc tport */
  uint64_t ipc_sub_start( kv::NotifySub &sub, uint32_t tport_id ) noexcept;
  uint64_t ipc_sub_stop( kv::NotifySub &sub,  uint32_t tport_id ) noexcept;
  /* start a new pattern sub ipc tport */
  uint64_t ipc_psub_start( kv::NotifyPattern &pat, uint32_t tport_id ) noexcept;
  uint64_t ipc_psub_stop( kv::NotifyPattern &pat, uint32_t tport_id ) noexcept;
  SeqnoStatus match_seqno( SeqnoArgs &ctx ) noexcept;
  bool match_subscription( SeqnoArgs &ctx ) noexcept;

  void resize_bloom( void ) noexcept;
  static void notify_bloom_update( kv::BloomRef &ref ) noexcept;

  static void print_bloom( kv::BloomBits &bits ) noexcept;

  void index_bloom( kv::BloomBits &bits,  uint32_t flags ) noexcept;

    /* sub start stop */
  bool recv_sub_start( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec ) noexcept;
  bool recv_sub_stop( const MsgFramePublish &pub,  UserBridge &n,
                      const MsgHdrDecoder &dec ) noexcept;
  bool recv_resub_result( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept;
  /* pattern start stop */
  bool recv_repsub_result( const MsgFramePublish &pub,  UserBridge &n,
                           const MsgHdrDecoder &dec ) noexcept;
  bool recv_psub_start( const MsgFramePublish &pub,  UserBridge &n,
                         const MsgHdrDecoder &dec ) noexcept;
  bool recv_psub_stop( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec ) noexcept;
  /* subscripiont start forward */
  void fwd_sub( SubArgs &ctx ) noexcept;
  void fwd_psub( PatternArgs &ctx ) noexcept;
  /* reassert subscription forward */
  bool fwd_resub( UserBridge &n,  const char *sub,  size_t sublen,
                  uint64_t from_seqno,  uint64_t seqno,  bool is_psub,
                  const char *suf,  uint64_t token ) noexcept;
  bool find_fwd_sub( UserBridge &n,  uint32_t hash,  uint64_t &from_seqno,
                     uint64_t seqno,  const char *suf,
                     uint64_t token ) noexcept;
  bool find_fwd_psub( UserBridge &n,  uint32_t hash,  uint64_t &from_seqno,
                      uint64_t seqno,  const char *suf,
                      uint64_t token ) noexcept;
  /* request subscriptions from node */
  bool send_subs_request( UserBridge &n,  uint64_t seqno ) noexcept;

  /* recv sub request result */
  bool send_bloom_request( UserBridge &n ) noexcept;
  bool recv_bloom_request( const MsgFramePublish &pub,  UserBridge &n,
                           const MsgHdrDecoder &dec ) noexcept;
  bool recv_bloom( const MsgFramePublish &pub,  UserBridge &n,
                   const MsgHdrDecoder &dec ) noexcept;
  bool recv_bloom_result( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept;
  bool recv_subs_request( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept;
  SubOnMsg *match_any_sub( const char *sub,  uint16_t sublen ) noexcept;

  UserBridge *any_match( const char *sub,  uint16_t sublen,
                         uint32_t h ) noexcept;
};

}
}
#endif
