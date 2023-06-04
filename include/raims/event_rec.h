#ifndef __rai__raims__event_rec_h__
#define __rai__raims__event_rec_h__

#include <raikv/array_space.h>
#include <raikv/util.h>
#include <raims/msg.h>
#include <raims/auth.h>
#include <raims/string_tab.h>

namespace rai {
namespace ms {

enum EventType {
  NULL_EVENT        = 0,
  STARTUP           = 1,
  ON_CONNECT        = 2,
  ON_SHUTDOWN       = 3,
  ON_TIMEOUT        = 4,
  AUTH_ADD          = 5,
  AUTH_REMOVE       = 6,
  SEND_CHALLENGE    = 7,
  RECV_CHALLENGE    = 8,
  SEND_TRUST        = 9,
  RECV_TRUST        = 10,
  ADD_USER_ROUTE    = 11,
  HB_QUEUE          = 12,
  HB_TIMEOUT        = 13,
  SEND_HELLO        = 14,
  RECV_BYE          = 15,
  RECV_ADD_ROUTE    = 16,
  RECV_PEER_DB      = 17,
  SEND_ADD_ROUTE    = 18,
  SEND_OTHER_PEER   = 19,
  SEND_PEER_DELETE  = 20,
  RECV_SYNC_RESULT  = 21,
  SEND_SYNC_REQUEST = 22,
  RECV_SYNC_REQUEST = 23,
  RECV_SYNC_FAIL    = 24,
  SEND_ADJ_CHANGE   = 25,
  RECV_ADJ_CHANGE   = 26,
  SEND_ADJ_REQUEST  = 27,
  RECV_ADJ_REQUEST  = 28,
  SEND_ADJ          = 29,
  RECV_ADJ_RESULT   = 30,
  RESIZE_BLOOM      = 31,
  RECV_BLOOM        = 32,
  CONVERGE          = 33,
  INBOUND_MSG_LOSS  = 34,
  BAD_EVENT         = 35,
  MAX_EVENT         = 36
};

static const uint32_t MASK_EVENT =   0x3f, /* 63 */
                      HAS_TPORT  =   0x40,
                      HAS_PEER   =   0x80,
                      HAS_DATA   =  0x100,
                      HAS_STRING =  0x200,
                      HAS_REASON =  0x400,
                      IS_FLOOD   =  0x800,
                      IS_ECDH    = 0x1000,
                      IS_ENCRYPT = 0x2000;

#ifdef IMPORT_EVENT_DATA
#define EVSZ( s ) { s, sizeof( s ) - 1 }
static const struct {
  const char * val;
  size_t       len;
} event_strings[] = {
  EVSZ( "null" ),            /* 0  */
  EVSZ( "startup" ),         /* 1  */
  EVSZ( "on_connect" ),      /* 2  */
  EVSZ( "on_shutdown" ),     /* 3  */
  EVSZ( "on_timeout" ),      /* 4  */
  EVSZ( "auth_add" ),        /* 5  */
  EVSZ( "auth_remove" ),     /* 6  */
  EVSZ( "send_challenge" ),  /* 7  */
  EVSZ( "recv_challenge" ),  /* 8  */
  EVSZ( "send_trust" ),      /* 9  */
  EVSZ( "recv_trust" ),      /* 10  */
  EVSZ( "add_user_route" ),  /* 11 */
  EVSZ( "hb_queue" ),        /* 12 */
  EVSZ( "hb_timeout" ),      /* 13 */
  EVSZ( "send_hello" ),      /* 14 */
  EVSZ( "recv_bye" ),        /* 15 */
  EVSZ( "recv_add_route" ),  /* 16 */
  EVSZ( "recv_peer_db" ),    /* 17 */
  EVSZ( "send_add_route" ),  /* 18 */
  EVSZ( "send_other_peer" ), /* 19 */
  EVSZ( "send_peer_del" ),   /* 20 */
  EVSZ( "sync_result" ),     /* 21 */
  EVSZ( "send_sync_req" ),   /* 22 */
  EVSZ( "recv_sync_req" ),   /* 23 */
  EVSZ( "recv_sync_fail" ),  /* 24 */
  EVSZ( "send_adj_change" ), /* 25 */
  EVSZ( "recv_adj_change" ), /* 26 */
  EVSZ( "send_adj_req" ),    /* 27 */
  EVSZ( "recv_adj_req" ),    /* 28 */
  EVSZ( "send_adj" ),        /* 29 */
  EVSZ( "recv_adj_result" ), /* 30 */
  EVSZ( "resize_bloom" ),    /* 31 */
  EVSZ( "recv_bloom" ),      /* 32 */
  EVSZ( "converge" ),        /* 33 */
  EVSZ( "inbound_msg_loss" ),/* 34 */
  EVSZ( "bad_event" )        /* 35 */
};
#if __cplusplus >= 201103L
static_assert( MAX_EVENT == ( sizeof( event_strings ) / sizeof( event_strings[ 0 ] ) ), "max_events" );
#endif
#undef EVSZ
#endif

struct EventRec {
  uint64_t stamp;
  uint32_t source_uid,
           tport_id,
           peer_uid,
           data;
  uint16_t event_flags,
           reason;
  EventType event_type( void ) const {
    uint32_t e = this->event_flags & MASK_EVENT;
    if ( e >= MAX_EVENT )
      return BAD_EVENT;
    return (EventType) e;
  }
  const char *data_tag( StringTab &tab,  char *buf ) const {
    if ( ( this->event_flags & HAS_DATA ) != 0 ) {
      if ( ( this->event_flags & HAS_STRING ) != 0 ) {
        StringVal sv;
        if ( this->data != 0 && tab.get_string( this->data, sv ) )
          return sv.val;
      }
      else {
        switch ( this->event_type() ) {
          case ON_CONNECT:
            if ( ( this->data & TPORT_IS_MCAST ) != 0 ) {
              if ( ( this->data & TPORT_IS_LISTEN ) != 0 )
                return "mcast_listen";
              return "mcast_connect";
            }
            if ( ( this->data & TPORT_IS_MESH ) != 0 ) {
              if ( ( this->data & TPORT_IS_CONNECT ) != 0 )
                return "mesh_connect";
              return "mesh_accept";
            }
            if ( ( this->data & TPORT_IS_CONNECT ) != 0 )
              return "connect";
            if ( ( this->data & TPORT_IS_LISTEN ) != 0 )
              return "listen";
            return "accept";
          case ON_SHUTDOWN:
            if ( this->data )
              return "disconnect";
            return "failed";
          case SEND_TRUST:
          case RECV_TRUST:
            return this->data == 0 ? "" : "in_mesh";
          case AUTH_ADD:
          case SEND_CHALLENGE:
          case RECV_CHALLENGE:
          case RECV_PEER_DB:
            return auth_stage_string( (AuthStage) this->data );
          case HB_QUEUE:
            return this->data == 0 ? "neighbor" : "hb";
          case AUTH_REMOVE:
            return auth_stage_string( (AuthStage) this->data );
          case CONVERGE:
            return invalidate_reason_string( (InvalidReason) this->data );
          case ADD_USER_ROUTE:
          case SEND_ADD_ROUTE:
          case SEND_OTHER_PEER:
          case RECV_SYNC_REQUEST:
            return this->data == 0 ? "neighbor" : "distant";
          case SEND_ADJ_CHANGE:
            return this->data == 0 ? "remove" : "add";
          case RECV_ADJ_CHANGE:
            return adjacency_change_string( (AdjacencyChange) this->data );
          case SEND_ADJ_REQUEST:
          case RECV_ADJ_REQUEST:
          case RECV_ADJ_RESULT:
          case SEND_ADJ:
            return adjacency_request_string( (AdjacencyRequest) this->data );
            /*return sync_kind_string( (SyncKind) this->data );*/
          case RESIZE_BLOOM:
          case RECV_BLOOM:
          case INBOUND_MSG_LOSS: {
            size_t len = kv::uint32_to_string( this->data, buf );
            buf[ len ] = '\0';
            return buf;
          }
          default: break;
        }
      }
    }
    return NULL;
  }
  const char *reason_str( void ) const {
    if ( ( this->event_flags & HAS_REASON ) != 0 ) {
      switch ( this->event_type() ) {
        case SEND_SYNC_REQUEST:
          return peer_sync_reason_string( (PeerSyncReason) this->reason );
        default: break;
      }
    }
    return NULL;
  }
  bool has_peer( uint32_t &uid ) const {
    if ( ( this->event_flags & HAS_PEER ) != 0 ) {
      uid = this->peer_uid;
      return true;
    }
    return false;
  }
  bool has_tport( uint32_t &tid ) const {
    if ( ( this->event_flags & HAS_TPORT ) != 0 ) {
      tid = this->tport_id;
      return true;
    }
    return false;
  }
  bool is_flood( void ) const {
    return ( this->event_flags & IS_FLOOD ) != 0;
  }
  bool is_ecdh( void ) const {
    return ( this->event_flags & IS_ECDH ) != 0;
  }
  bool is_encrypt( void ) const {
    return ( this->event_flags & IS_ENCRYPT ) != 0;
  }
};

struct EventRecord {
  static const uint32_t MAX_EVENTS = 4096;
  EventRec * ptr;
  uint32_t hd, count;
  uint64_t * cur_time;

  EventRecord( uint64_t *now_ns ) : ptr( 0 ), hd( 0 ), count( 0 ),
    cur_time( now_ns ) {}
  ~EventRecord() {
    if ( this->ptr != NULL ) 
      ::free( this->ptr );
  }

  uint32_t num_events( void ) const {
    return ( this->count % MAX_EVENTS );
  }
  const EventRec *first( uint32_t &i ) const {
    i = 0;
    if ( this->count >= MAX_EVENTS )
      i = ( this->hd + 1 ) % MAX_EVENTS;
    return this->next( i );
  }
  const EventRec *next( uint32_t &i ) const {
    if ( i == this->hd )
      return NULL;
    const EventRec *ev = &this->ptr[ i ];
    i = ( i + 1 ) % MAX_EVENTS;
    return ev;
  }
  EventRec *prev( uint32_t &i ) const {
    uint32_t first = 0;
    if ( this->count >= MAX_EVENTS )
      first = ( this->hd + 1 ) % MAX_EVENTS;
    if ( i == first )
      return NULL;
    i = ( i - 1 ) % MAX_EVENTS;
    return &this->ptr[ i ];
  }
  void startup( uint64_t t ) {
    this->ptr = (EventRec *) ::malloc( sizeof( EventRec ) * MAX_EVENTS );
    EventRec & ev = this->next_event();
    ev.stamp       = t;
    ev.source_uid  = 0;
    ev.event_flags = STARTUP;
  }
  EventRec &next_event( void ) {
    EventRec & ev = this->ptr[ this->hd ];
    this->hd = ( this->hd + 1 ) % MAX_EVENTS;
    this->count++;
    return ev;
  }
  EventRec &tid_event( uint32_t uid,  uint32_t tid,  uint16_t fl ) {
    EventRec &ev = this->next_event();
    ev.stamp       = *this->cur_time;
    ev.event_flags = fl;
    ev.source_uid  = uid;
    ev.tport_id    = tid;
    return ev;
  }
  EventRec &uid_event( uint32_t uid,  uint16_t fl ) {
    return this->tid_event( uid, 0, fl );
  }
  void on_connect( uint32_t tid,  uint32_t state,  bool is_encrypt ) {
    this->tid_event( 0, tid, ON_CONNECT | HAS_TPORT | HAS_DATA |
                             ( is_encrypt ? IS_ENCRYPT : 0 ) ).data = state;
  }
  void on_shutdown( uint32_t tid,  bool was_active ) {
    this->tid_event( 0, tid,
                     ON_SHUTDOWN | HAS_TPORT | HAS_DATA ).data = was_active;
  }
  void on_timeout( uint32_t tid,  uint32_t tries ) {
    this->tid_event( 0, tid, ON_TIMEOUT | HAS_TPORT | HAS_DATA ).data = tries;
  }
  void send_hello( void ) {
    this->uid_event( 0, SEND_HELLO | IS_FLOOD );
  }
  void send_trust( uint32_t uid,  uint32_t tid,  bool in_mesh ) {
    this->tid_event( uid, tid,
                    SEND_TRUST | HAS_TPORT | HAS_DATA ).data = in_mesh;
  }
  void recv_trust( uint32_t uid,  uint32_t tid,  bool in_mesh ) {
    this->tid_event( uid, tid,
                     RECV_TRUST | HAS_TPORT | HAS_DATA ).data = in_mesh;
  }
  void add_user_route( uint32_t uid,  uint32_t tid,  uint32_t peer,
                       uint16_t hops ) {
    EventRec & ev = this->tid_event( uid, tid, ADD_USER_ROUTE | HAS_TPORT |
                                               HAS_PEER | HAS_DATA );
    ev.peer_uid = peer;
    ev.data     = hops;
  }
  void recv_bye( uint32_t uid,  uint32_t tid ) {
    this->tid_event( uid, tid, RECV_BYE | HAS_TPORT );
  }
  void auth_add( uint32_t uid,  uint32_t src,  uint16_t stage ) {
    uint32_t event_type = AUTH_ADD | HAS_DATA;
    if ( uid != src )
      event_type |= HAS_PEER;
    else
      event_type |= IS_ECDH;
    EventRec & ev = this->uid_event( uid, event_type );
    ev.peer_uid = src;
    ev.data     = stage;
  }
  void auth_remove( uint32_t uid,  uint16_t reason ) {
    this->uid_event( uid, AUTH_REMOVE | HAS_DATA ).data = reason;
  }
  void hb_queue( uint32_t uid,  uint16_t where = 0 ) {
    this->uid_event( uid, HB_QUEUE | HAS_DATA ).data = where;
  }
  void hb_timeout( uint32_t uid ) {
    this->uid_event( uid, HB_TIMEOUT );
  }
  void recv_challenge( uint32_t uid,  uint32_t tid,  uint16_t stage ) {
    this->tid_event( uid, tid, RECV_CHALLENGE | HAS_TPORT |
                               HAS_DATA ).data = stage;
  }
  void send_challenge( uint32_t uid,  uint32_t tid,  uint16_t stage ) {
    EventRec & ev = this->tid_event( 0, tid, SEND_CHALLENGE | HAS_TPORT |
                                             HAS_PEER | HAS_DATA );
    ev.peer_uid = uid;
    ev.data     = stage;
  }
  void recv_peer_add( uint32_t uid,  uint32_t tid,  uint32_t peer,
                      uint16_t stage,  uint32_t user_str_id ) {
    EventType event_type;
    if ( stage == AUTH_FROM_ADD_ROUTE )
      event_type = RECV_ADD_ROUTE;
    else
      event_type = RECV_SYNC_RESULT;
    EventRec & ev = this->tid_event( uid, tid, event_type | HAS_TPORT |
                                             HAS_PEER | HAS_DATA | HAS_STRING );
    ev.peer_uid = peer;
    ev.data     = user_str_id;
  }
  void recv_peer_db( uint32_t uid,  uint32_t tid,  uint16_t stage ) {
    this->tid_event( uid, tid, RECV_PEER_DB | HAS_TPORT |
                               HAS_DATA ).data = stage;
  }
  void send_add_route( uint32_t uid,  uint32_t tid,  uint16_t hops ) {
    EventRec & ev = this->tid_event( 0, tid, SEND_ADD_ROUTE | HAS_TPORT |
                                             HAS_PEER | HAS_DATA );
    ev.peer_uid = uid;
    ev.data     = hops;
  }
  void send_other_peer( uint32_t uid,  uint32_t tid,  uint32_t peer,
                        uint16_t hops ) {
    EventRec & ev = this->tid_event( uid, tid, SEND_OTHER_PEER | HAS_TPORT |
                                               HAS_PEER | HAS_DATA );
    ev.peer_uid = peer;
    ev.data     = hops;
  }
  void send_sync_req( uint32_t uid,  uint32_t tid,  uint32_t user_str_id,
                      uint16_t reason ) {
    EventRec & ev = this->tid_event( 0, tid, SEND_SYNC_REQUEST | HAS_TPORT |
                                             HAS_PEER | HAS_DATA | HAS_STRING |
                                             HAS_REASON );
    ev.peer_uid = uid;
    ev.data     = user_str_id;
    ev.reason   = reason;
  }
  void send_peer_delete( uint32_t uid,  uint32_t tid ) {
    this->tid_event( 0, tid, SEND_PEER_DELETE | HAS_TPORT |
                             HAS_PEER ).peer_uid = uid;
  }
  void recv_sync_req( uint32_t uid,  uint32_t tid,  uint32_t peer,
                      uint16_t hops ) {
    EventRec & ev = this->tid_event( uid, tid, RECV_SYNC_REQUEST | HAS_TPORT |
                                               HAS_PEER | HAS_DATA );
    ev.peer_uid = peer;
    ev.data     = hops;
  }
  void recv_sync_fail( uint32_t uid,  uint32_t tid,  uint32_t user_str_id ) {
    EventRec & ev = this->tid_event( uid, tid, RECV_SYNC_FAIL | HAS_TPORT |
                                               HAS_DATA | HAS_STRING);
    ev.data     = user_str_id;
  }
  void send_adjacency_change( uint32_t uid,  bool add ) {
    EventRec & ev = this->uid_event( 0, SEND_ADJ_CHANGE | HAS_PEER | HAS_DATA |
                                        IS_FLOOD );
    ev.peer_uid = uid;
    ev.data     = add;
  }
  void recv_adjacency_change( uint32_t uid,  uint32_t tid,
                              uint32_t chg /* AdjacencyChange */ ) {
    this->tid_event( uid, tid, RECV_ADJ_CHANGE | HAS_TPORT | HAS_PEER |
                               HAS_DATA ).data = chg;
  }
  void send_adjacency_request( uint32_t uid, uint32_t tid, uint32_t sync,
                               uint32_t chg /* AdjacencyRequest */ ) {
    this->adjacency_op( SEND_ADJ_REQUEST, uid, tid, sync, chg );
  }
  void recv_adjacency_request( uint32_t uid,  uint32_t tid,  uint32_t sync,
                               uint32_t chg /* AdjacencyRequest */ ) {
    this->adjacency_op( RECV_ADJ_REQUEST, uid, tid, sync, chg );
  }
  void recv_adjacency_result( uint32_t uid,  uint32_t tid,  uint32_t sync,
                              uint32_t chg/* AdjacencyRequest */ ) {
    this->adjacency_op( RECV_ADJ_RESULT, uid, tid, sync, chg );
  }
  void send_adjacency( uint32_t uid,  uint32_t tid,  uint32_t sync,
                       uint32_t chg/* AdjacencyRequest */ ) {
    this->adjacency_op( SEND_ADJ, uid, tid, sync, chg );
  }
  void adjacency_op( uint32_t event_type,  uint32_t uid,  uint32_t tid,
                     uint32_t sync,  uint32_t chg/* AdjacencyRequest */ ) {
    event_type |= HAS_TPORT | HAS_DATA;
    if ( sync != 0 )
      event_type |= HAS_PEER;
    EventRec & ev = this->tid_event( uid, tid, event_type );
    ev.peer_uid = sync;
    ev.data     = chg;
  }
  void resize_bloom( uint32_t count ) {
    this->uid_event( 0, RESIZE_BLOOM | HAS_DATA ).data = count;
  }
  void recv_bloom( uint32_t uid,  uint32_t tid,  uint32_t count ) {
    this->tid_event( uid, tid, RECV_BLOOM | HAS_TPORT | HAS_DATA ).data = count;
  }
  void converge( uint16_t inv,  uint32_t uid ) {
    this->uid_event( uid, CONVERGE | HAS_DATA ).data = inv;
  }
  void inbound_msg_loss( uint32_t uid,  uint32_t tid,  uint32_t lost ) {
    uint64_t   nowish = *this->cur_time >> 30;
    uint32_t   i      = this->hd;
    EventRec * ev;
    while ( (ev = this->prev( i )) != NULL ) {
      if ( ( ev->stamp >> 30 ) != nowish )
        break;
      if ( ev->event_type() == INBOUND_MSG_LOSS &&
           ev->source_uid == uid && ev->tport_id == tid ) {
        ev->data += lost;
        return;
      }
    }
    this->tid_event( uid, tid,
                     INBOUND_MSG_LOSS | HAS_TPORT | HAS_DATA ).data = lost;
  }
};

}
}

#endif
