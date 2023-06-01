#ifndef __rai_raims__sub_h__
#define __rai_raims__sub_h__

#include <raikv/route_ht.h>
#include <raikv/route_db.h>
#include <raikv/key_hash.h>
#include <raikv/ev_publish.h>
#include <raikv/uint_ht.h>
#include <raikv/array_space.h>
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
  CONSOLE_SUB  = 1,
  IPC_SUB      = 2,
  IS_SUB_START = 4,
  QUEUE_SUB    = 8
};

struct SubRefs {
  uint32_t refs;

  void init( uint32_t flags,  uint32_t tport_id ) {
    this->refs = 0;
    this->add( flags, tport_id );
  }
  bool add( uint32_t flags,  uint32_t tport_id ) {
    if ( ( flags & CONSOLE_SUB ) != 0 )
      return ! this->test_set( 0 );
    return ! this->test_set( tport_id + 1 );
  }
  bool rem( uint32_t flags,  uint32_t tport_id ) {
    if ( ( flags & CONSOLE_SUB ) != 0 )
      return this->test_clear( 0 );
    return this->test_clear( tport_id + 1 );
  }
  bool test_set( uint32_t id ) {
    uint32_t mask = ( (uint32_t) 1 << id );
    bool b = ( this->refs & mask ) != 0;
    this->refs |= mask;
    return b;
  }
  bool test_clear( uint32_t id ) {
    uint32_t mask = ( (uint32_t) 1 << id );
    bool b = ( this->refs & mask ) != 0;
    this->refs &= ~mask;
    return b;
  }
  bool is_empty( void ) const {
    return this->refs == 0;
  }
  bool test( uint32_t flags ) const {
    if ( ( flags & CONSOLE_SUB ) != 0 )
      return ( this->refs & (uint32_t) 1 ) != 0;
    return ( this->refs >> 1 ) != 0;
  }
  uint32_t ref_count( void ) const {
    return kv_popcountw( this->refs );
  }
  uint32_t console_count( void ) const {
    return this->test( CONSOLE_SUB ) ? 1 : 0;
  }
  uint32_t ipc_count( void ) const {
    return kv_popcountw( this->refs >> 1 );
  }
  uint32_t tport_mask( void ) const {
    return this->refs >> 1;
  }
};

struct SubArgs {
  const char * sub,
             * inbox,
             * queue;
  uint16_t     sublen,
               inbox_len,
               queue_len;
  SubOnMsg   * cb;
  uint64_t     seqno;
  uint32_t     flags,
               hash,
               queue_hash,
               queue_refs,
               tport_id,
               sub_count,
               console_count,
               ipc_count,
               sub_coll,
               console_coll,
               ipc_coll;
  bool         bloom_updated,
               resize_bloom;

  SubArgs( const char *s,  uint16_t len,  const char *i,  uint16_t ilen, 
           SubOnMsg *on_msg,  uint64_t n,  uint32_t fl,
           uint32_t tp,  uint32_t h = 0 ) :
    sub( s ), inbox( i ), queue( 0 ), sublen( len ), inbox_len( ilen ),
    queue_len( 0 ), cb( on_msg ), seqno( n ), flags( fl ),
    hash( h ), queue_hash( 0 ), queue_refs( 0 ), tport_id( tp ), sub_count( 0 ),
    console_count( 0 ), ipc_count( 0 ), sub_coll( 0 ), console_coll( 0 ),
    ipc_coll( 0 ), bloom_updated( false ), resize_bloom( false ) {
    if ( h == 0 ) this->hash = kv_crc_c( s, len, 0 );
  }
  bool is_start( void ) const {
    return ( this->flags & IS_SUB_START ) != 0;
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
    ctx.console_count = this->ref.console_count();
    ctx.ipc_count     = this->ref.ipc_count();
  }
  bool add( SubArgs &ctx ) {
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
  bool rem( SubArgs &ctx ) {
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
        ctx.console_coll += rt->ref.console_count();
        ctx.ipc_coll     += rt->ref.ipc_count();
      }
      rt2 = this->tab.find_next_by_hash( ctx.hash, loc );
    }
  }

  void release( void ) {
    this->tab.release();
  }
};

struct QueueSubTab;
struct PatternArgs;
struct QueueSubArray : public kv::ArrayCount<QueueSubTab *, 4> {
  SubList & sub_list;
  QueueSubArray( SubList &l ) : sub_list( l ) {}
  QueueSubTab *find_tab( const char *queue,  uint16_t queue_len, 
                         uint32_t queue_hash ) noexcept;
  SubStatus start( SubArgs &ctx ) noexcept;
  SubStatus stop( SubArgs &ctx ) noexcept;
  SubStatus start( PatternArgs &ctx ) noexcept;
  SubStatus stop( PatternArgs &ctx ) noexcept;
};

/* 33 is ~10 second frames, 35 is 32 billion sequences, 9 hours at 1 mill/sec */
static inline uint64_t seqno_init( uint64_t time ) {
  return ( time >> 33 ) << 35;
}
static inline uint64_t seqno_frame( uint64_t seqno ) {
  return seqno >> 35;
}
static inline uint64_t time_frame( uint64_t time ) {
  return ( ( time >> 33 ) << 35 ) >> 35;
}
static inline uint64_t seqno_time( uint64_t seqno ) {
  return ( seqno >> 35 ) << 33;
}
static inline uint64_t seqno_base( uint64_t seqno ) {
  return seqno & ( ( (uint64_t) 1 << 35 ) - 1 );
}

struct Pub {
  uint64_t seqno,
           stamp;
  uint32_t hash;
  uint16_t len;
  char     value[ 2 ]; /* prefix */
  
  void init( uint64_t time ) {
    this->seqno = seqno_init( time );
    this->stamp = 0;
  }
  void copy( Pub &p ) {
    this->seqno = p.seqno;
    this->stamp = p.stamp;
    p.stamp = 0;
  }
  uint64_t next_seqno( bool next_timeframe,  uint64_t &time,
                       uint64_t cur_frame,  uint64_t converge_seqno,
                       uint64_t &last_frame_seqno ) {
    uint64_t sequence;

    last_frame_seqno = 0;
    time        = cur_frame;
    this->stamp = cur_frame;

    if ( ! next_timeframe ) {
      sequence = this->seqno + 1;
      if ( sequence <= converge_seqno || seqno_base( sequence ) == 0 ) {
        last_frame_seqno = this->seqno;
        next_timeframe = true;
      }
    }
    if ( next_timeframe ) {
      this->init( cur_frame );
      sequence = this->seqno + 1;
    }
    this->seqno = sequence;
    return sequence;
  }
};

typedef kv::RouteVec<Pub> PubT;

struct PubTab {
  PubT     pub1,
           pub2,
         * pub,
         * pub_old;
  uint64_t flip_time,
           trailing_time;
  size_t   max_size;
  PubTab() {
    this->pub           = &this->pub1;
    this->pub_old       = &this->pub2;
    this->flip_time     = 0;
    this->trailing_time = 0;
    this->max_size      = 0;
  }
  Pub *upsert( uint32_t h,  const char *sub,  uint16_t sublen,
               kv::RouteLoc &loc ) {
    Pub * p = this->pub->upsert( h, sub, sublen, loc ), * p2;
    if ( ! loc.is_new )
      return p;
    kv::RouteLoc loc2;
    if ( (p2 = this->pub_old->find( h, sub, sublen, loc2 )) != NULL ) {
      p->copy( *p2 );
      loc.is_new = false;
    }
    return p;
  }
  Pub *find( uint32_t h,  const char *sub,  uint16_t sublen ) {
    Pub * p = this->pub->find( h, sub, sublen );
    if ( p == NULL )
      p = this->pub_old->find( h, sub, sublen );
    return p;
  }
  Pub *first( kv::RouteLoc &loc,  bool &is_old ) {
    Pub *p = this->pub->first( loc );
    if ( p != NULL )
      is_old = false;
    else {
      p = this->pub_old->first( loc );
      is_old = true;
      if ( p != NULL && p->stamp == 0 )
        return this->next( loc, is_old );
    }
    return p;
  }
  Pub *next( kv::RouteLoc &loc,  bool &is_old ) {
    Pub *p;
    if ( ! is_old ) {
      p = this->pub->next( loc );
      if ( p != NULL )
        return p;
      is_old = true;
      p = this->pub_old->first( loc );
    }
    else {
      p = this->pub_old->next( loc );
    }
    while ( p != NULL && p->stamp == 0 )
      p = this->pub_old->next( loc );
    return p;
  }
  /* limit size of pub sequences */
  bool flip( size_t win_size,  uint64_t cur_time ) {
    PubT * p = this->pub;
    size_t sz = p->mem_size();
    if ( sz > win_size ) {
      if ( sz > this->max_size )
        this->max_size = sz;
      this->pub_old->release();
      this->pub           = this->pub_old;
      this->pub_old       = p;
      this->trailing_time = this->flip_time;
      this->flip_time     = cur_time;
      return true;
    }
    return false;
  }
};

struct SeqnoSave {
  static const size_t SAVE_INTS = 6;
  uint32_t save[ SAVE_INTS ];

  SeqnoSave() {}
  SeqnoSave( const SeqnoSave &sv ) {
    for ( size_t i = 0; i < SAVE_INTS; i++ )
      this->save[ i ] = sv.save[ i ];
  }
  SeqnoSave &operator=( const SeqnoSave &sv ) {
    for ( size_t i = 0; i < SAVE_INTS; i++ )
      this->save[ i ] = sv.save[ i ];
    return *this;
  }

  void update( uint64_t seqno,  uint64_t time,  uint64_t stamp ) {
    ::memcpy( &this->save[ 0 ], &seqno, sizeof( uint64_t ) );
    ::memcpy( &this->save[ 2 ], &time, sizeof( uint64_t ) );
    ::memcpy( &this->save[ 4 ], &stamp, sizeof( uint64_t ) );
  }
  void restore( uint64_t &seqno,  uint64_t &time,  uint64_t &stamp ) const {
    ::memcpy( &seqno, &this->save[ 0 ], sizeof( uint64_t ) );
    ::memcpy( &time, &this->save[ 2 ], sizeof( uint64_t ) );
    ::memcpy( &stamp, &this->save[ 4 ], sizeof( uint64_t ) );
  }
};

typedef kv::IntHashTabT<uint32_t,SeqnoSave> UidSeqno;

enum SeqnoStatus {
  SEQNO_UID_FIRST  = 0, /* first time uid published */
  SEQNO_UID_CYCLE  = 1, /* reinitialized seqno  */
  SEQNO_UID_NEXT   = 2, /* is next in the sequnce */
  SEQNO_UID_SKIP   = 3, /* is next skipped sequnce */
  SEQNO_UID_REPEAT = 4, /* is a repeated sequence */
  SEQNO_NOT_SUBSCR = 5, /* subscription not matched */
  SEQNO_ERROR      = 6
};

const char *seqno_status_string( SeqnoStatus status ) noexcept;

static const uint32_t MAX_MSG_LOSS   = kv::EV_MAX_LOSS,
                      MSG_FRAME_LOSS = kv::EV_PUB_RESTART;

struct SeqnoArgs {
  uint64_t   time,        /* message time */
             last_seqno,  /* last message seqno */
             last_time,   /* last message time */
             start_seqno, /* subscription start */
             stamp,       /* last publish recvd */
             chain_seqno; /* previous seqno published */
  SubOnMsg * cb;          /* callback for subscription */
  uint32_t   tport_mask;  /* tports matched */
  uint16_t   msg_loss;

  SeqnoArgs( uint64_t time )
    : time( 0 ), last_seqno( 0 ), last_time( 0 ), start_seqno( 0 ),
     stamp( time ), chain_seqno( 0 ), cb( 0 ), tport_mask( 0 ), msg_loss( 0 ) {}
};

struct SubSeqno {
  uint32_t   hash,        /* hash of subject */
             last_uid;    /* last uid publisher */
  uint64_t   last_seqno,  /* seqno of last msg used by uid */
             last_time,   /* time of last msg */
             last_stamp,  /* stamp of recv */
             start_seqno, /* the seqno of the sub start */
             update_seqno;/* the seqno when the sub was matched */
  SubOnMsg * on_data;     /* callback cached */
  UidSeqno * seqno_ht;    /* uid -> to saved seqno/time pairs */
  uint32_t   tport_mask;  /* tport cached */
  uint16_t   len;         /* len of subject */
  char       value[ 2 ];  /* subject */

  SeqnoStatus init( uint32_t uid,  uint64_t seqno,  uint64_t start,
                    uint64_t time,  uint64_t stamp,  uint64_t upd_sno,
                    SubOnMsg *cb,  uint32_t mask ) {
    this->last_uid     = uid;
    this->last_seqno   = seqno;
    this->last_time    = time;
    this->last_stamp   = stamp;
    this->start_seqno  = start;
    this->update_seqno = upd_sno;
    this->on_data      = cb;
    this->seqno_ht     = NULL;
    this->tport_mask   = mask;
    return SEQNO_UID_FIRST;
  }
  void copy( SubSeqno &sub ) {
    this->last_uid     = sub.last_uid;
    this->last_seqno   = sub.last_seqno;
    this->last_time    = sub.last_time;
    this->last_stamp   = sub.last_stamp; sub.last_stamp = 0;
    this->start_seqno  = sub.start_seqno;
    this->update_seqno = sub.update_seqno;
    this->on_data      = sub.on_data;
    this->seqno_ht     = sub.seqno_ht; sub.seqno_ht = NULL;
    this->tport_mask   = sub.tport_mask;
  }
  SeqnoStatus restore_uid( uint32_t uid,  uint64_t seqno,
                           uint64_t time,  uint64_t stamp ) noexcept;
  void release( void ) {
    if ( this->seqno_ht != NULL )
      delete this->seqno_ht;
  }
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

typedef kv::RouteVec<SubSeqno> SeqnoT;

struct SeqnoTab {
  SeqnoT   tab1,
           tab2,
         * tab,
         * tab_old;
  uint64_t flip_time,
           trailing_time;
  size_t   seqno_ht_size,
           old_ht_size,
           max_size;

  SeqnoTab() {
    this->tab     = &this->tab1;
    this->tab_old = &this->tab2;
    this->flip_time     = 0;
    this->trailing_time = 0;
    this->seqno_ht_size = 0;
    this->old_ht_size   = 0;
    this->max_size      = 0;
  }
  SubSeqno *upsert( uint32_t h,  const char *sub,  uint16_t sublen,
                    kv::RouteLoc &loc, kv::RouteLoc &loc2,
                    bool &is_old ) {
    loc2.init();
    is_old = false;

    SubSeqno * p = this->tab->upsert( h, sub, sublen, loc );
    if ( ! loc.is_new )
      return p;

    SubSeqno * p2 = this->tab_old->find( h, sub, sublen, loc2 );
    if ( p2 != NULL ) {
      p->copy( *p2 );
      loc.is_new = false;
      is_old = true;
    }
    return p;
  }
  SubSeqno *find( uint32_t h,  const char *sub,  uint16_t sublen ) {
    SubSeqno * p = this->tab->find( h, sub, sublen );
    if ( p == NULL )
      p = this->tab_old->find( h, sub, sublen );
    return p;
  }
  SubSeqno *first( kv::RouteLoc &loc,  bool &is_old ) {
    SubSeqno *p = this->tab->first( loc );
    if ( p != NULL )
      is_old = false;
    else {
      p = this->tab_old->first( loc );
      is_old = true;
      if ( p != NULL && p->last_stamp == 0 )
        return this->next( loc, is_old );
    }
    return p;
  }
  SubSeqno *next( kv::RouteLoc &loc,  bool &is_old ) {
    SubSeqno *p;
    if ( ! is_old ) {
      p = this->tab->next( loc );
      if ( p != NULL )
        return p;
      is_old = true;
      p = this->tab_old->first( loc );
    }
    else {
      p = this->tab_old->next( loc );
    }
    while ( p != NULL && p->last_stamp == 0 )
      p = this->tab_old->next( loc );
    return p;
  }
  void remove( kv::RouteLoc &loc,  kv::RouteLoc &loc2,  bool is_old ) {
    this->tab->remove( loc );
    if ( is_old )
      this->tab_old->remove( loc2 );
  }
  /* limit size of pub sequences */
  bool flip( size_t win_size,  uint64_t cur_time ) {
    SeqnoT * p = this->tab;
    size_t sz = p->mem_size() + this->seqno_ht_size;
    if ( sz > win_size ) {
      if ( sz > this->max_size )
        this->max_size = sz;
      kv::RouteLoc loc;
      if ( this->old_ht_size > 0 ) {
        for ( SubSeqno *s = this->tab_old->first( loc ); s != NULL;
              s = this->tab_old->next( loc ) )
          s->release();
      }
      this->tab_old->release();
      this->tab           = this->tab_old;
      this->old_ht_size   = this->seqno_ht_size;
      this->seqno_ht_size = 0;
      this->tab_old       = p;
      this->trailing_time = this->flip_time;
      this->flip_time     = cur_time;
      return true;
    }
    return false;
  }
};

typedef kv::RouteVec<InboxSub> InboxTab;

struct UserDB;
struct SessionMgr;
struct UserBridge;

struct AnyMatch {
  uint64_t       mono_time;
  uint32_t       max_uid,
                 bits_off;
  uint16_t       sub_off,
                 sub_len;
  bool           is_queue;
  kv::BloomMatch match;

  size_t init_any( const char *s,  uint16_t sublen,  uint32_t uid_cnt,
                   bool is_queue ) noexcept;
  UserBridge * get_destination( UserDB &user_db ) noexcept;
  static size_t any_size( uint16_t sublen,  uint32_t &uid_cnt ) noexcept;
  const char *sub( void ) {
    return &((char *) (void *) this)[ this->sub_off ];
  }
  uint64_t *bits( void ) {
    return (uint64_t *) &((char *) (void *) this)[ this->bits_off ];
  }
};

struct AnyMatchTab {
  kv::ArraySpace<uint64_t, 256> tab;
  kv::UIntHashTab * ht;
  size_t            max_off;
  uint64_t          gc_time;

  AnyMatchTab() : ht( 0 ), max_off( 0 ), gc_time( 0 ) {
    this->ht = kv::UIntHashTab::resize( NULL );
  }
  void reset( void ) noexcept;
  void gc( uint64_t cur_time ) {
    if ( this->max_off * 8 > 1024 * 1024 ) {
      this->reset();
      this->gc_time = cur_time;
    }
  }
  AnyMatch *get_match( const char *sub,  uint16_t sublen,  uint32_t h,
                       uint32_t max_uid,  bool is_queue ) noexcept;
};
#if 0
struct QueueGrp {
  uint32_t   workers,    /* number of queue workers */
             hash;       /* hash of gropu name */
  uint16_t   len;        /* len of group name */
  char       value[ 2 ]; /* queue group name */
};

struct QueueSub {
  uint64_t   start_ns;   /* session id of connection */
  uint32_t   refcnt,     /* number of queue subscriptions active */
             fd,         /* connection fd */
             queue_id,   /* hash of the queue name */
             hash;       /* hash of queue subscription */
  uint16_t   len;        /* len of queue subscription */
  char       value[ 2 ]; /* queue subscription */
};

typedef kv::RouteVec<QueueSub> QueueSubTab;
typedef kv::RouteVec<QueueGrp> QueueGrpTab;
#endif
struct ReplyMissing {
  uint64_t mono_ns;
  uint32_t hash, uid, ref;
  uint16_t len;
  char     value[ 2 ];
};

struct ReplyCache {
  kv::UIntHashTab          * exists_ht;
  kv::RouteVec<ReplyMissing> missing;
  uint64_t                   gc_time;

  ReplyCache() : gc_time( 0 ) {
    this->exists_ht = kv::UIntHashTab::resize( NULL );
  }
  void add_exists( uint32_t h,  uint32_t uid ) noexcept;
  uint32_t add_missing( uint32_t h,  uint32_t uid,  const char *sub,
                        size_t sublen,  uint64_t cur_mono ) noexcept;
  bool gc( uint64_t cur_mono ) {
    this->gc_time = cur_mono;
    if ( this->exists_ht->elem_count > 0 )
      this->exists_ht->clear_all();
    return ! this->missing.is_empty();
  }
};
}
}

#include <raims/pat.h>

namespace rai {
namespace ms {

struct QueueSubTab {
  SubTab   sub_tab;
  PatTab   pat_tab;
  char   * queue;
  uint32_t queue_len,
           queue_hash;
  bool equals( const char *q,  uint32_t l,  uint32_t h )  const {
    if ( h != this->queue_hash ) return false;
    return ( l == this->queue_len && ::memcmp( this->queue, q, l ) == 0 ) ||
           l == 0;
  }
  void * operator new( size_t, void *ptr ) { return ptr; }
  QueueSubTab( const char *q,  uint16_t qlen,  uint32_t qhash,
               SubList &l ) noexcept;
};

struct SubDB {
  UserDB           & user_db;
  SessionMgr       & mgr;
  const kv::PeerId & my_src;
  uint32_t           next_inbox;   /* next inbox sub free */
  uint64_t           sub_seqno,    /* sequence number for my subs */
                     sub_seqno_sum,/* sum of all sub_seqno */
                     update_seqno, /* sequence number updated for ext and int subs */
                     sub_update_mono_time; /* last time any sub recvd */
  SeqnoTab           seqno_tab;    /* sub -> seqno, time */
  InboxTab           inbox_tab;    /* inbox -> seqno, time */
  SubList            sub_list;     /* list of { seqno, subscriptions } */
  SubTab             sub_tab;      /* subject -> { state, seqno } */
  PatTab             pat_tab;      /* pattern -> { state, seqno } */
  PubTab             pub_tab;      /* subject -> seqno */
  AnyMatchTab        any_tab;
  ReplyCache         reply;
  kv::BloomRef       bloom,
                     console,
                     ipc;
  QueueSubArray      queue_tab;
  kv::RoutePublish & uid_route;

  SubDB( kv::EvPoll &p,  UserDB &udb,  SessionMgr &smg ) noexcept;

  void init( void ) {
    this->sub_seqno     = 0;
    this->sub_seqno_sum = 0;
    this->update_seqno  = 0;
    this->sub_update_mono_time = 0;
  }
  void update_sub_seqno( uint64_t &old_val,  uint32_t new_val ) {
    this->sub_seqno_sum -= old_val;
    this->sub_seqno_sum += new_val;
    old_val = new_val;
  }
  uint64_t sub_start( SubArgs &ctx ) noexcept;
  uint64_t sub_stop( SubArgs &ctx ) noexcept;
  void update_bloom( SubArgs &ctx ) noexcept;
  /* start a new sub for this session */
  uint64_t console_sub_start( const char *sub,  uint16_t sublen,
                              const char *inbox,  uint16_t inbox_len,
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
  SeqnoStatus match_seqno( const MsgFramePublish &pub,SeqnoArgs &ctx ) noexcept;
  bool match_subscription( const kv::EvPublish &pub,  SeqnoArgs &ctx ) noexcept;

  void resize_bloom( void ) noexcept;
  void reseed_bloom( void ) noexcept;
  void notify_bloom_update( kv::BloomRef &ref ) noexcept;

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
                  const char *suf,  uint64_t token,  const char *queue,
                  uint16_t queue_len,  uint32_t queue_hash ) noexcept;
  bool find_fwd_sub( UserBridge &n,  uint32_t hash,  uint64_t &from_seqno,
                     uint64_t seqno,  const char *suf,  uint64_t token,
                     const char *match,  size_t match_len ) noexcept;
  bool find_fwd_psub( UserBridge &n,  uint32_t hash,  uint64_t &from_seqno,
                      uint64_t seqno,  const char *suf, uint64_t token,
                      const char *match,  size_t match_len ) noexcept;
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

  uint32_t host_match( const char *host,  size_t host_len ) noexcept;

  AnyMatch *any_match( const char *sub,  uint16_t sublen, uint32_t h ) noexcept;
  AnyMatch *any_queue( kv::EvPublish &fwd ) noexcept;

  void reply_memo( const char *sub,  size_t sublen,  const char *host,
                   size_t hostlen,  UserBridge &n, uint64_t cur_mono ) noexcept;
  uint32_t lookup_memo( uint32_t h,  const char *sub,  size_t sublen ) noexcept;
  void clear_memo( uint64_t cur_mono ) noexcept;
  void gc_memo( uint64_t cur_mono ) {
    if ( this->reply.gc( cur_mono ) )
      this->clear_memo( cur_mono );
  }

  enum {
  IPC_NO_MATCH = 0, IPC_IS_QUEUE = 1, IPC_IS_INBOX = 2, IPC_IS_INBOX_PREFIX = 3
  };
  static int match_ipc_subject( const char *str,  size_t str_len,
                                const char *&pre,  size_t &pre_len,
                                const char *&name,  size_t &name_len,
                                const char *&subj,  size_t &subj_len,
              const int match_flag /* IPC_IS_QUEUE | IPC_IS_INBOX */ ) noexcept;
  static int match_ipc_any( const char *str,  size_t str_len ) noexcept;
  static bool match_inbox( const char *str,  size_t str_len,
                           const char *&host,  size_t &host_len ) noexcept;
  static bool match_queue( const char *str,  size_t str_len,
                           const char *&pre,  size_t &pre_len,
                           const char *&name,  size_t &name_len,
                           const char *&subj,  size_t &subj_len ) noexcept;
  void queue_sub_update( kv::NotifyQueue &sub,  uint32_t tport_id,
                         uint32_t refcnt ) noexcept;
  void queue_psub_update( kv::NotifyPatternQueue &pat,  uint32_t tport_id,
                          uint32_t refcnt ) noexcept;
};

}
}
#endif
