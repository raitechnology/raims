#ifndef __rai_raims__msg_h__
#define __rai_raims__msg_h__

#include <raikv/ev_publish.h>
#include <raimd/md_msg.h>
#include <raimd/tib_sass_msg.h>
#include <raimd/hex_dump.h>
#include <raims/crypt.h>

namespace rai {
namespace ms {
/*
bytes 0 -> 3 are type, opt, message size
 1               8               16              24              32   
|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|
|0 0 1|0 0 0 0|0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 1 0 0 0 0 0|
 ^...^ ^.... ^ ^...............................................^
   |      |                         |     
   |      opt(0)                27 bit size(160)
   type(1)
bytes 4 -> 7 are the routing key hash
 1               8               16              24              32   
+-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|
|0 0 0 0 0 0 0 1 1 0 0 1 0 0 0 1 1 1 0 0 0 0 1 0 0 0 0 0 0 1 1 0|
 ^.............................................................^
                                   |
                               hash(0x191c206) = crc_c("CABA")
bytes 8 -> 25 are the bridge source 
fid = BRIDGE(3), type = OPAQUE_16(4) ( opaque 16 bytes )            144
|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+.. +
|1 1 x x 0 1 0 0 0 0 0 0 0 0 1 1|                                     |
 ^ ^     ^.....^ ^.............^ ^....................................
 | |         |        |                        |
 | primitive type(4)  fid(3)               128 bit bridge
 fixed

bytes 26 -> 43 are the hmac digest
bytes 44 -> X are the subject of the routing key
fid = SUB(0), type = SHORT_STRING(7) ( int16 string data )
|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|...      ....+
|0 1 x x 0 1 1 1 0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0|  CABA       |
   ^     ^.....^ ^.............^ ^.............................^ ^......
   |         |         |                       |                    |
   primitive type(7)   fid(0)             16 bit length(4)       string data  |

more fields, a seqno is always included
fid = SEQNO(17), type = U_SHORT(2) ( uint16 )                  32
|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|
|1 1 x x 0 0 1 0 0 0 0 0 1 0 0 1|0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1|
 ^ ^     ^.....^ ^.............^ ^.............................^
 | |         |         |                      |
 | primitive type(2)   fid(17)            16 bit seqno(1)
 fixed

the last bytes are the data payload
fid = DATA(1), type = LONG_OPAQUE(8) ( int32 opaque data )
|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+- ...     ...  +
|0 1 x x 1 0 0 0 0 0 0 0 0 0 0 1|                                             |
   ^     ^.....^ ^.............^ ^..............................
   |         |         |                      |
   primitive type(8)   fid(1)             message payload

*/
enum CabaTypeFlag {
  CABA_MCAST     = 0, /* multicast msg */
  CABA_INBOX     = 1, /* inbox msg */
  CABA_RTR_ALERT = 2, /* router alert (_M, _P, _S, _Z) */
  CABA_HEARTBEAT = 3, /* heartbeat (_X) */
};
enum CabaOptFlag {
  CABA_OPT_NONE  = 0,
  CABA_OPT_ACK   = 1, /* recver ack messages */
  CABA_OPT_TRACE = 2, /* routers trace messages */
  CABA_OPT_ANY   = 4  /* any of many */
};
                      /* <type:2><opt:3><length bits:27> */
static const int      CABA_TYPE_BITS   = 2,
                      CABA_OPT_BITS    = 3,
                      CABA_LENGTH_BITS = 32 - (CABA_TYPE_BITS + CABA_OPT_BITS);
static const uint16_t CABA_TYPE_MASK   = ( (uint16_t) 1 << CABA_TYPE_BITS ) - 1,
                      CABA_OPT_MASK    = ( (uint16_t) 1 << CABA_OPT_BITS ) - 1;
static const uint32_t CABA_LENGTH_MASK = ( (uint32_t) 1 << CABA_LENGTH_BITS )-1;

static inline const char *caba_type_flag_str( CabaTypeFlag fl ) {
  if ( fl == CABA_INBOX ) return "inbox";
  if ( fl == CABA_RTR_ALERT ) return "rtr_alert";
  if ( fl == CABA_HEARTBEAT ) return "heartbeat";
  return "mcast";
}
/* mask out _M. _P. _S. _Z. subjects */
static inline bool caba_rtr_alert( const char *sub ) {
  static const uint32_t mask =
    ( 1U << ( 'M' - 'M' ) ) | ( 1U << ( 'P' - 'M' ) ) |
    ( 1U << ( 'S' - 'M' ) ) | ( 1U << ( 'Z' - 'M' ) );
  if ( sub[ 0 ] != '_' || sub[ 1 ] < 'M' || sub[ 1 ] > 'Z' || sub[ 2 ] != '.' )
    return false;
  return ( mask & ( 1U << ( sub[ 1 ] - 'M' ) ) ) != 0;
}

struct CabaFlags {
  uint16_t flags; /* low bits <type>, high bits <opt> */
  CabaFlags( CabaTypeFlag t ) : flags( t ) {}
  CabaTypeFlag type_flag( void ) const { /* mcast, ibx, rtr_alert, hb */
    return (CabaTypeFlag) ( this->flags & CABA_TYPE_MASK );
  }
  uint16_t opt_flag( void ) const {
    return ( this->flags >> CABA_TYPE_BITS ) & CABA_OPT_MASK;
  }
  const char *type_str( void ) const {
    return caba_type_flag_str( this->type_flag() );
  }
  void set_type( CabaTypeFlag fl ) {
    this->flags = ( this->flags & ~CABA_TYPE_MASK ) | (uint16_t) fl;
  }
  void set_opt( uint16_t fl ) {
    this->flags = ( this->flags & ~( CABA_OPT_MASK << CABA_TYPE_BITS ) ) |
                  ( (uint16_t) fl << CABA_TYPE_BITS );
  }
};

struct CabaMsg : public md::TibSassMsg {
  const char * sub;    /* pointer into the message after sub fid and length */
  uint32_t     subhash;/* second word of the message, unless length is large */
  uint16_t     sublen; /* length attached to the sub fid */
  CabaFlags    caba;   /* first bits of the message */

  void * operator new( size_t, void *ptr ) { return ptr; }
  CabaMsg( void *bb,  size_t off,  size_t end,  md::MDDict *d, md::MDMsgMem *m )
    : md::TibSassMsg( bb, off, end, d, m ),
      sub( 0 ), subhash( 0 ), sublen( 0 ), caba( CABA_MCAST ) {}

  virtual const char *get_proto_string( void ) noexcept final;
  virtual uint32_t get_type_id( void ) noexcept final;
  /* may return tibmsg, sass qform or rv */
  static bool is_cabamsg( void *bb,  size_t off,  size_t end,
                          uint32_t h ) noexcept;
  static CabaMsg *unpack( void *bb,  size_t off,  size_t end,  uint32_t h,
                          md::MDDict *d,  md::MDMsgMem *m ) noexcept;
  static int unpack2( uint8_t *bb,  size_t off,  size_t &end,  md::MDMsgMem *m,
                      CabaMsg *&msg ) noexcept;
  CabaMsg *submsg( void *bb,  size_t len ) noexcept;
  static void init_auto_unpack( void ) noexcept;
  bool verify( const HashDigest &key ) const noexcept;
};

struct MsgFrameDecoder {
  static md::MDDict * msg_dict;      /* fid index for type and size info */
  md::MDMsgMem mem;      /* memory for message unpacking and subject */
  CabaMsg    * msg;      /* msg data, has the following fields */

  MsgFrameDecoder();

  void init( void ) {
    this->msg = NULL;
  }
  void release( void ) {
    this->init();
    this->mem.reuse();
  }
  int unpack( const void *msgbuf,  size_t &msglen ) noexcept;
  void print( void ) noexcept;
  static md::MDDict *build_msg_dict( void ) noexcept;
};

/* msg fields */
enum MsgFid {
  FID_SUB          =  0 , /* publish subject or inbox */
  FID_DATA         =  1 , /* opaque data */

  FID_SESSION      =  2 , /* Hmac.Nonce field */
  FID_BRIDGE       =  3 , /* Bridge id nonce */
  FID_USER_HMAC    =  4 , /* User hmac */
  FID_DIGEST       =  5 , /* message digest, signed by auth key */
  FID_AUTH_KEY     =  6 , /* authentication key response to challenge */
  FID_SESS_KEY     =  7 , /* session key = hmac + bridge */
  FID_PEER_DB      =  8 , /* sync peer db */
  FID_MESH_DB      =  9 , /* mesh urls */
  FID_CNONCE       = 10 , /* challenge nonce */
  FID_SYNC_BRIDGE  = 11 , /* request target of sync request */
  FID_UID_CSUM     = 12 , /* bridge checksum of all nodes */
  FID_MESH_CSUM    = 13 , /* route checksum of all mesh nodes */
  FID_MESH_FILTER  = 14 , /* filter mesh db requests */
  FID_ADJACENCY    = 15 , /* adjacency links map */
  FID_BLOOM        = 16 , /* bloom sub map */

  FID_SEQNO        = 17 , /* integer fields */
  FID_SUB_SEQNO    = 18 , /* subscription seqno */
  FID_TIME         = 19 , /* time of message */
  FID_UPTIME       = 20 , /* how long node is up */
  FID_INTERVAL     = 21 , /* heartbeat interval */
  FID_REF_COUNT    = 22 , /* count of sub refs */
  FID_TOKEN        = 23 , /* token passed through by rpc */
  FID_RET          = 24 , /* return inbox number */
  FID_LINK_STATE   = 25 , /* link state seqno */
  FID_START        = 26 , /* start seqno of subs request */
  FID_END          = 27 , /* end seqno of subs request */
  FID_ADJ_INFO     = 28 , /* why peer requested adjacency */
  FID_AUTH_SEQNO   = 29 , /* seqno of message used by auth */
  FID_AUTH_TIME    = 30 , /* time of message used by auth */
  FID_FMT          = 31 , /* msg format of data, wildcard format */
  FID_HOPS         = 32 , /* whether directly attached to same tport */
  FID_REF_SEQNO    = 33 , /* ack or trace reference seqno */
  FID_TPORTID      = 34 , /* which transport adjacency belongs to */
  FID_UID          = 35 , /* uid reference */
  FID_UID_COUNT    = 36 , /* how many peers, sent with hello */
  FID_SUBJ_HASH    = 37 , /* hash of subject */

  FID_SUBJECT      = 38 , /* subject of subscription */
  FID_PATTERN      = 39 , /* pattern subject wildcard */
  FID_REPLY        = 40 , /* publish reply */
  FID_WILDCARD     = 41 , /* XXX */
  FID_UCAST_URL    = 42 , /* unicast route for inbox data */
  FID_MESH_URL     = 43 , /* mesh route for interconnecting uids */
  FID_FORMAT       = 44 , /* XXX */
  FID_DICTIONARY   = 45 , /* XXX */
  FID_TPORT        = 46 , /* tport name */

  FID_USER         = 47 , /* name of user */
  FID_SERVICE      = 48 , /* service of user to add */
  FID_CREATE       = 49 , /* create time of user to add */
  FID_EXPIRES      = 50 , /* expire time of user to add */

  FID_DICT_CSUM    = 51 , /* XXX */
  FID_ENTI_CSUM    = 52 , /* XXX */

  FID_LINK_ADD     = 53 , /* whether to add or delete link in adjacency */
  FID_START_ACK    = 54 , /* XXX */
  FID_STOP_ACK     = 55 , /* XXX */
  FID_INITIAL      = 56 , /* XXX */
  FID_DATABASE     = 57 , /* XXX */
  FID_AUTH_STAGE   = 58   /* what stage of authentication */
};
static const int FID_TYPE_SHIFT = 8,
                 FID_MAX        = 1 << FID_TYPE_SHIFT; /* 64 */

inline uint16_t fid_value( uint16_t fid ) {
  return fid & ( FID_MAX - 1 );
}
/* class ids used:  fid = ( FldTypeClass << FID_TYPE_SHIFT ) | FID_xxx */
enum FldTypeClass {
  BOOL_CLASS         = 0, /* bool 1 byte */
  U_SHORT_CLASS      = 1, /* uint8_t */
  U_INT_CLASS        = 2, /* uint16_t */
  U_LONG_CLASS       = 3, /* uint64_t */
  OPAQUE_16_CLASS    = 4, /* 16 byte opaque */
  OPAQUE_32_CLASS    = 5, /* 32 byte opaque */
  OPAQUE_64_CLASS    = 6, /* 64 byte opaque */
  SHORT_STRING_CLASS = 7, /* veriable, 0 -> 64K */
  LONG_OPAQUE_CLASS  = 8  /* veriable, 0 -> 4G */
};
#ifdef INCLUDE_MSG_CONST
static inline md::MDType cls_to_md( FldTypeClass cl ) {
  #define X( x, y ) ( (uint64_t) x << ( y * 4 ) )
  static const uint64_t bits =
  X( md::MD_BOOLEAN, BOOL_CLASS      ) | X( md::MD_UINT, U_SHORT_CLASS     ) |
  X( md::MD_UINT,    U_INT_CLASS     ) | X( md::MD_UINT, U_LONG_CLASS      ) |
  X( md::MD_OPAQUE,  OPAQUE_16_CLASS ) | X( md::MD_OPAQUE, OPAQUE_32_CLASS ) |
  X( md::MD_OPAQUE,  OPAQUE_64_CLASS ) |
  X( md::MD_STRING,  SHORT_STRING_CLASS ) |
  X( md::MD_OPAQUE,  LONG_OPAQUE_CLASS );
  #undef X
  return (md::MDType) ( ( bits >> ( (int) cl * 4 ) ) & 0xf );
};
static inline FldTypeClass fid_type( uint16_t fid ) {
  return (FldTypeClass) ( ( fid >> FID_TYPE_SHIFT ) & 0xf );
}
static inline uint32_t fid_size( FldTypeClass cl ) {
  if ( cl <= OPAQUE_64_CLASS )
    return 1U << cl;
  return 0;
}
#endif

/* type masks that a field can be */
enum FldTypeBit {
  BOOL_1       = 1 << BOOL_CLASS,         /* bool 1 byte */
  U_SHORT      = 1 << U_SHORT_CLASS,      /* uint8_t */
  U_INT        = 1 << U_INT_CLASS,        /* uint16_t */
  U_LONG       = 1 << U_LONG_CLASS,       /* uint64_t */
  OPAQUE_16    = 1 << OPAQUE_16_CLASS,    /* 16 byte opaque */
  OPAQUE_32    = 1 << OPAQUE_32_CLASS,    /* 32 byte opaque */
  OPAQUE_64    = 1 << OPAQUE_64_CLASS,    /* 64 byte opaque */
  SHORT_STRING = 1 << SHORT_STRING_CLASS, /* veriable, 0 -> 64K */
  LONG_OPAQUE  = 1 << LONG_OPAQUE_CLASS   /* veriable, 0 -> 4G */
};

enum PublishType {
  U_NORMAL          = 0,  /* other _ABC */
  U_SESSION_HELLO   = 1,  /* _X.HELLO   */
  U_SESSION_HB      = 2,  /* _X.HB      */
  U_SESSION_BYE     = 3,  /* _X.BYE     */
  U_PEER_ADD        = 4,  /* _Z.ADD     */
  U_PEER_DEL        = 5,  /* _Z.DEL     */
  U_BLOOM_FILTER    = 6,  /* _Z.BLM     */
  U_ADJACENCY       = 7,  /* _Z.ADJ     */
  U_SUB_JOIN        = 8,  /* _S.JOIN.>  */
  U_SUB_LEAVE       = 9,  /* _S.LEAV.>  */
  U_PSUB_START      = 10, /* _P.PSUB.>  */
  U_PSUB_STOP       = 11, /* _P.PSTP.>  */
  /* unused bits, 12 -> 15 */
  U_INBOX_AUTH      = 16, /* _I.Nonce.auth (not a wildcard) */
  U_INBOX_SUBS      = 17, /* _I.Nonce.subs */
  U_INBOX_PING      = 18, /* _I.Nonce.ping */
  U_INBOX_PONG      = 19, /* _I.Nonce.pong */
  U_INBOX_RESUB     = 20, /* _I.Nonce.resub */
  U_INBOX_REPSUB    = 21, /* _I.Nonce.repsub */
  U_INBOX_ADD_RTE   = 22, /* _I.Nonce.add_rte */
  U_INBOX_SYNC_REQ  = 23, /* _I.Nonce.sync_req */
  U_INBOX_SYNC_RPY  = 24, /* _I.Nonce.sync_rpy */
  U_INBOX_BLOOM_REQ = 25, /* _I.Nonce.bloom_req */
  U_INBOX_BLOOM_RPY = 26, /* _I.Nonce.bloom_rpy */
  U_INBOX_ADJ_REQ   = 27, /* _I.Nonce.adj_req */
  U_INBOX_ADJ_RPY   = 28, /* _I.Nonce.adj_rpy */
  U_INBOX_MESH_REQ  = 29, /* _I.Nonce.adj_req */
  U_INBOX_MESH_RPY  = 30, /* _I.Nonce.adj_rpy */
  U_INBOX_TRACE     = 31, /* _I.Nonce.trace */
  U_INBOX_ACK       = 32, /* _I.Nonce.ack */
  U_INBOX_ANY       = 33, /* _I.Nonce.any */
  U_INBOX           = 34, /* _I.Nonce.X reply subject, X is integer */

  U_MCAST_PING      = 35, /* _M.ping */
  U_MCAST           = 36, /* _M.> */
  /* other subject */
  U_INBOX_ANY_RTE   = 37, /* _I.Nonce.any, ipc inbox */
  MCAST_SUBJECT     = 38, /* not _XX subject */
  UNKNOWN_SUBJECT   = 39  /* init, not resolved */
};
#ifdef INCLUDE_MSG_CONST
static const char *publish_type_str[] = {
  "u_normal",
  "u_session_hello",
  "u_session_hb",
  "u_session_bye",
  "u_peer_add",
  "u_peer_del",
  "u_bloom_filter",
  "u_adjacency",
  "u_sub_join",
  "u_sub_leave",
  "u_psub_start",
  "u_psub_stop",
  "unused12", "unused13", "unused14", "unused15",
  "u_inbox_auth",
  "u_inbox_subs",
  "u_inbox_ping",
  "u_inbox_pong",
  "u_inbox_resub",
  "u_inbox_repsub",
  "u_inbox_add_rte",
  "u_inbox_sync_req",
  "u_inbox_sync_rpy",
  "u_inbox_bloom_req",
  "u_inbox_bloom_rpy",
  "u_inbox_adj_req",
  "u_inbox_adj_rpy",
  "u_inbox_mesh_req",
  "u_inbox_mesh_rpy",
  "u_inbox_trace",
  "u_inbox_ack",
  "u_inbox_any",
  "u_inbox",
  "u_mcast_ping",
  "u_mcast",
  "u_inbox_any_rte",
  "mcast_subject",
  "unknown_subject"
};
#if __cplusplus >= 201103L
static_assert( UNKNOWN_SUBJECT + 1 == ( sizeof( publish_type_str ) / sizeof( publish_type_str[ 0 ] ) ), "publish_type_str" );
#endif
#endif
const char *publish_type_to_string( PublishType t ) noexcept;

struct MsgFldSet {
  uint64_t is_set;          /* a bit for each FID indexed */

  MsgFldSet() : is_set( 0 ) {}

  /* does not tolerate repeated fields, last one wins */
  static uint64_t bit( int opt ) { return (uint64_t) 1 << opt; }
  void set( int opt )            { this->is_set |= bit( opt ); }
  bool test( int opt ) const     { return ( this->is_set & bit( opt ) ) != 0; }
  bool btst( uint64_t bits ) const { return ( this->is_set & bits ) == bits; }
  bool test_2( int opt,  int opt2 ) const {
    return this->btst( bit( opt ) | bit( opt2 ) );
  }
  bool test_3( int opt,  int opt2,  int opt3 ) const {
    return this->btst( bit( opt ) | bit( opt2 ) | bit( opt3 ) );
  }
  bool test_4( int opt,  int opt2,  int opt3,  int opt4 ) const {
    return this->btst( bit( opt ) | bit( opt2 ) | bit( opt3 ) | bit( opt4 ) );
  }
  bool test_5( int opt, int opt2, int opt3, int opt4,int opt5 ) const {
    return this->btst( bit( opt ) | bit( opt2 ) | bit( opt3 ) | bit( opt4 ) |
                       bit( opt5 ) );
  }
  bool test_6( int opt, int opt2, int opt3, int opt4,int opt5, int opt6 ) const{
    return this->btst( bit( opt ) | bit( opt2 ) | bit( opt3 ) | bit( opt4 ) |
                       bit( opt5 ) | bit( opt6 ) );
  }
};

/* iterate through the fields and create references for them */
struct MsgHdrDecoder : public MsgFldSet {
  CabaMsg       * msg;
  uint64_t        seqno;
  uint32_t        inbox_ret;
  PublishType     type;
  md::MDReference mref[ FID_MAX ]; /* reference for the fields found */
  md::MDMsgMem    mem;

  MsgHdrDecoder( CabaMsg *m ) : msg( m ), seqno( 0 ), inbox_ret( 0 ),
                                type( UNKNOWN_SUBJECT ) {}
  bool is_ucast_type( void ) const {
    return this->type >= U_INBOX_AUTH && this->type <= U_INBOX;
  }
  bool is_mcast_type( void ) const {
    return ! this->is_ucast_type();
  }
  bool get_bridge( Nonce &bridge ) const noexcept;
  int decode_msg( void ) noexcept;
  const char *get_return( char *ret_buf,
                          const char *default_suf ) const noexcept;
  const char *get_type_string( void ) const {
    return publish_type_to_string( this->type );
  }
  bool get_nonce( MsgFid fid,  Nonce &nonce ) const {
    if ( this->test( fid ) ) {
      nonce.copy_from( this->mref[ fid ].fptr );
      return true;
    }
    nonce.zero();
    return false;
  }
  bool get_hmac( MsgFid fid,  HmacDigest &hmac ) const {
    if ( this->test( fid ) ) {
      hmac.copy_from( this->mref[ fid ].fptr );
      return true;
    }
    hmac.zero();
    return false;
  }
  template <class T>
  bool get_ival( MsgFid fid,  T &ival ) const {
    ival = 0;
    if ( this->test( fid ) ) {
      md::cvt_number<T>( this->mref[ fid ], ival );
      return true;
    }
    return false;
  }
  template <class T>
  T * decode_rec_list( MsgFid fid ) {
    void       * data    = this->mref[ fid ].fptr;
    size_t       datalen = this->mref[ fid ].fsize;
    CabaMsg    * m       = this->msg->submsg( data, datalen );
    md::MDFieldIter * iter;
    md::MDReference   mref;
    md::MDName        nm;

    if ( m == NULL || m->get_field_iter( iter ) != 0 ) 
      return NULL;
    if ( iter->first() != 0 ||
         iter->get_name( nm ) != 0 ||
         iter->get_reference( mref ) != 0 ) 
      return NULL;
      
    T * hd  = new ( this->mem.make( sizeof( T ) ) ) T(),
      * rec = hd;
    uint32_t opt;
    do {
      opt = fid_value( nm.fid );
      if ( rec->test( opt ) ) {
        rec->next = new ( this->mem.make( sizeof( T ) ) ) T();
        rec = rec->next;
      }
      rec->set( opt );
      rec->set_field( opt, mref );
    } while ( iter->next() == 0 &&
              iter->get_name( nm ) == 0 &&
              iter->get_reference( mref ) == 0 );
    return hd;
  }
};

enum MsgFrameStatus {
  FRAME_STATUS_UNKNOWN   = 0,
  FRAME_STATUS_OK        = 1,
  FRAME_STATUS_DUP_SEQNO = 2,
  FRAME_STATUS_NO_AUTH   = 3,
  FRAME_STATUS_NO_USER   = 4,
  FRAME_STATUS_BAD_MSG   = 5,
  FRAME_STATUS_MY_MSG    = 6
};

enum MsgFrameFlags {
  MSG_FRAME_ACK_CONTROL     = 1, /* if ack / trace was handled */
  MSG_FRAME_TPORT_CONTROL   = 2, /* if transport routing was handled */
  MSG_FRAME_IPC_CONTROL     = 4, /* if ipc routing was handled */
  MSG_FRAME_CONSOLE_CONTROL = 8  /* if console routing was handled */
};

struct TransportRoute;
struct UserBridge;
/* msg decoding is expensive, pass along the codec with the msg publish */
struct MsgFramePublish : public kv::EvPublish {
  UserBridge     * n;     /* bridge of sender */
  TransportRoute & rte;   /* where msg came from */
  MsgFrameStatus   status;/* what to do with msg */
  uint32_t         flags; /* MsgFrameFlags */
  MsgHdrDecoder    dec;   /* hdr field decoder */

  MsgFramePublish( const char *subj,  size_t subj_len,  CabaMsg *m,
                   uint32_t src_fd,  uint32_t hash,  uint32_t enc,
                   TransportRoute &r,  kv::RoutePublish &sub_rt ) :
    EvPublish( subj, subj_len, NULL, 0,
               &((uint8_t *) m->msg_buf)[ m->msg_off ], m->msg_end - m->msg_off,
               sub_rt, src_fd, hash, enc, 'X' ),
    n( 0 ), rte( r ), status( FRAME_STATUS_UNKNOWN ), flags( 0 ), dec( m ) {}

  MsgFramePublish( kv::EvPublish &pub,  CabaMsg *m, TransportRoute &r ) :
    EvPublish( pub ),
    n( 0 ), rte( r ), status( FRAME_STATUS_OK ), flags( 0 ), dec( m ) {
    this->msg        = &((uint8_t *) m->msg_buf)[ m->msg_off ];
    this->msg_len    = m->msg_end - m->msg_off,
    this->pub_type   = 'X';
    this->hash       = pub.hash;
    this->prefix     = pub.prefix;
    this->prefix_cnt = pub.prefix_cnt;
  }
  void print( const char *what ) const noexcept;
  const char *status_string( void ) const noexcept;
};

template <class T>
struct MsgBufT {
  char * out, * msg;
  MsgBufT( void *m ) : out( (char *) m ), msg( (char *) m ) {}
  T &nil( void ) { *this->out++ = '\0'; return (T &) *this; }
  T &s( const char *in ) { /* string out, does not copy null char */
    while ( *in != 0 ) { *this->out++ = *in++; }
    return (T &) *this;
  }
  T &b( const char *in, size_t in_len ) { /* buffer out */
    while ( in_len != 0 ) { *this->out++ = *in++; in_len -= 1; }
    return (T &) *this;
  }
  T &u( uint64_t n ) { /* uint out */
    this->out += kv::uint64_to_string( n, this->out );
    return (T &) *this;
  }
  T &i( uint32_t n ) { /* small uint out */
    this->out += kv::uint32_to_string( n, this->out );
    return (T &) *this;
  }
  T &n( const Nonce &val ) { /* digest out */
    this->out += val.to_base64( this->out );
    return (T &) *this;
  }
  T &h( const HmacDigest &val ) { /* digest out */
    this->out += val.to_base64( this->out );
    return (T &) *this;
  }
  T &k( const HashDigest &val ) { /* digest out */
    this->out += val.to_base64( this->out );
    return (T &) *this;
  }
  T &y( uint8_t n ) {
    if ( n ) return this->s( "true" );
    return this->s( "false" );
  }
  T &o( const void *in, size_t in_len ) { /* opaque out */
    this->out += kv::bin_to_base64( in, in_len, this->out, false );
    return (T &) *this;
  }
  size_t len( void ) const { return this->out - this->msg; }
  void set_len( size_t len ) { this->out = &this->msg[ len ]; }
  uint32_t hash( void ) const { return kv_crc_c( this->msg, this->len(), 0 ); }
};

#include <raims/caba_msg_buf.h>

struct MsgBuf : public MsgBufT<MsgBuf> {
  MsgBuf( void *m ) : MsgBufT( m ) {}
};
struct MsgCat : public md::MDMsgMem, public MsgBufDigestT<MsgCat> {
  MsgCat() : MsgBufDigestT( this->mem_ptr() ) {}
  void reserve( size_t len ) {
    this->reuse();
    this->out = this->msg = (char *) this->make( len );
  }
  void print( void ) noexcept;
  void close( size_t rsz,  uint32_t h,  CabaFlags fl ) {
    this->MsgBufDigestT<MsgCat>::close_msg( h, fl );
    if ( rsz < this->len() )
      this->reserve_error( rsz );
  }
  void reserve_error( size_t rsz ) noexcept;
};
struct SubMsgBuf : public MsgBufDigestT<SubMsgBuf> {
  SubMsgBuf( MsgCat &msg ) : MsgBufDigestT( msg.out ) {}
  void close( MsgCat &msg,  uint8_t opt ) {
    this->close_submsg( opt );
    msg.out = this->out;
  }
};

/* define fields and dictionary */
#ifdef INCLUDE_MSG_CONST

struct FidTypeName {
  MsgFid       fid;
  int          type_mask;
  const char * type_name;
};

static FidTypeName fid_type_name[] = {
{ FID_SUB         , SHORT_STRING                     , "sub" },
{ FID_DATA        , LONG_OPAQUE                      , "data" },

{ FID_SESSION     , OPAQUE_32                        , "session" },
{ FID_BRIDGE      , OPAQUE_16                        , "bridge" },
{ FID_USER_HMAC   , OPAQUE_16                        , "user_hmac" },
{ FID_DIGEST      , OPAQUE_16                        , "digest" },
{ FID_AUTH_KEY    , OPAQUE_64                        , "auth_key" },
{ FID_SESS_KEY    , OPAQUE_64                        , "sess_key" },
{ FID_PEER_DB     , LONG_OPAQUE                      , "peer_db" },
{ FID_MESH_DB     , LONG_OPAQUE                      , "mesh_db" },
{ FID_CNONCE      , OPAQUE_16                        , "cnonce" },
{ FID_SYNC_BRIDGE , OPAQUE_16                        , "sync_bridge" },
{ FID_UID_CSUM    , OPAQUE_16                        , "uid_csum" },
{ FID_MESH_CSUM   , OPAQUE_16                        , "mesh_csum" },
{ FID_MESH_FILTER , LONG_OPAQUE                      , "mesh_filter" },
{ FID_ADJACENCY   , LONG_OPAQUE                      , "adjacency" },
{ FID_BLOOM       , LONG_OPAQUE                      , "bloom" },

{ FID_SEQNO       , U_SHORT | U_INT | U_LONG         , "seqno" },
{ FID_SUB_SEQNO   , U_SHORT | U_INT | U_LONG         , "sub_seqno" },
{ FID_TIME        , U_SHORT | U_INT | U_LONG         , "time" },
{ FID_UPTIME      , U_SHORT | U_INT | U_LONG         , "uptime" },
{ FID_INTERVAL    , U_SHORT | U_INT                  , "interval" },
{ FID_REF_COUNT   , U_SHORT | U_INT                  , "ref_count" },
{ FID_TOKEN       , U_SHORT | U_INT | U_LONG         , "token" },
{ FID_RET         , U_SHORT | U_INT                  , "ret" },
{ FID_LINK_STATE  , U_SHORT | U_INT | U_LONG         , "link_state" },
{ FID_START       , U_SHORT | U_INT | U_LONG         , "start" },
{ FID_END         , U_SHORT | U_INT | U_LONG         , "end" },
{ FID_ADJ_INFO    , U_SHORT | U_INT                  , "adj_info" },
{ FID_AUTH_SEQNO  , U_SHORT | U_INT | U_LONG         , "auth_seqno" },
{ FID_AUTH_TIME   , U_SHORT | U_INT | U_LONG         , "auth_time" },
{ FID_FMT         , U_SHORT | U_INT | U_LONG         , "fmt" },
{ FID_HOPS        , U_SHORT | U_INT                  , "hops" },
{ FID_REF_SEQNO   , U_SHORT | U_INT | U_LONG         , "ref_seqno" },
{ FID_TPORTID     , U_SHORT | U_INT                  , "tportid" },
{ FID_UID         , U_SHORT | U_INT                  , "uid" },
{ FID_UID_COUNT   , U_SHORT | U_INT                  , "uid_count" },
{ FID_SUBJ_HASH   , U_INT                            , "subj_hash" },

{ FID_SUBJECT     , SHORT_STRING                     , "subject" },
{ FID_PATTERN     , SHORT_STRING                     , "pattern" },
{ FID_REPLY       , SHORT_STRING                     , "reply" },
{ FID_WILDCARD    , SHORT_STRING                     , "wildcard" },
{ FID_UCAST_URL   , SHORT_STRING                     , "ucast_url" },
{ FID_MESH_URL    , SHORT_STRING                     , "mesh_url" },
{ FID_FORMAT      , SHORT_STRING                     , "format" },
{ FID_DICTIONARY  , SHORT_STRING                     , "dictionary" },
{ FID_TPORT       , SHORT_STRING                     , "tport" },

{ FID_USER        , SHORT_STRING                     , "user" },
{ FID_SERVICE     , SHORT_STRING                     , "service" },
{ FID_CREATE      , SHORT_STRING                     , "create" },
{ FID_EXPIRES     , SHORT_STRING                     , "expires" },

{ FID_DICT_CSUM   , U_SHORT | U_INT                  , "dict_csum" },
{ FID_ENTI_CSUM   , U_SHORT | U_INT                  , "enti_csum" },

{ FID_LINK_ADD    , BOOL_1                           , "ack" },
{ FID_START_ACK   , BOOL_1                           , "link_add" },
{ FID_STOP_ACK    , BOOL_1                           , "stop_ack" },
{ FID_INITIAL     , BOOL_1                           , "initial" },
{ FID_DATABASE    , U_SHORT                          , "database" },
{ FID_AUTH_STAGE  , U_SHORT                          , "auth_stage" }
};

#endif

}
}

#endif
