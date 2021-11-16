#ifndef __rai_raims__session_h__
#define __rai_raims__session_h__

#include <raims/user_db.h>
#include <raims/sub_const.h>
#include <raims/console.h>
#include <raims/event_rec.h>

namespace rai {
namespace ms {

/* quick lookup of PublishType to resolve _subscripions:
 *  _X.HELLO -> U_SESSION_HELLO
 *  _X.HB    -> U_SESSION_HB
 *  _X.BYE   -> U_SESSION_BYE
 *  _Z.ADD   -> U_PEER_ADD
 *  _Z.DEL   -> U_PEER_DEL
 *  _Z.BLM   -> U_BLOOM_FILTER
 *  _Z.ADJ   -> U_ADJACENCY
 *  _S.JOIN. -> U_SUB_JOIN
 *  _S.LEAV. -> U_SUB_LEAV
 *  _P.PSUB. -> U_PSUB_START
 *  _P.STOP. -> U_PSUB_STOP
 */
struct UScoreTab {
  uint8_t tab[ 64 ];
  uint64_t len_valid;
  UScoreTab() { this->init(); }

  void init( void ) { memset( this->tab, 0, sizeof( this->tab ) );
                      this->len_valid = 0; }

  PublishType lookup( uint32_t h,  size_t len ) {
    if ( len <= 63 && ( this->len_valid & ( (uint64_t) 1 << len ) ) != 0 ) {
      size_t  pos   = ( h & 127 ) >> 1;
      uint8_t shift = ( h & 1 ) * 4;
      uint8_t mask  = 0xf << shift;
      return (PublishType) ( ( this->tab[ pos ] & mask ) >> shift );
    }
    return U_NORMAL;
  }
  bool set( uint32_t h,  size_t len,  PublishType t ) {
    if ( len > 63 || t > 15 ) return false;       /* no longer than 63 */
    this->len_valid |= ( (uint64_t) 1 << len );   /* 6,7,8,10,11,12,15 valid */
    if ( this->lookup( h, len ) != U_NORMAL ) return false; /* unique entry */
    size_t  pos   = ( h & 127 ) >> 1;             /* only need 4 bits */
    uint8_t shift = ( h & 1 ) * 4;                /* shift is 0 or 4 */
    this->tab[ pos ] = ( this->tab[ pos ] | ( (uint8_t) t << shift ) );
    return true;
  }
};
/* varialbe length subject */
struct SubjectVar : public md::MDMsgMem, public MsgBuf {
  SubjectVar( const char *pre,  size_t pre_len,  const char *suf,  size_t len )
      : MsgBuf( (char *) this->make( pre_len + len ) ) {
    this->b( pre, pre_len );
    if ( len > 0 ) this->b( suf, len );
  }
};

template < PublishType max, PublishType min, class Subject >
struct HashPub {
  uint32_t hash; /* hash( _INBOX.Nonce. ) */
  uint16_t len;  /* len ( _INBOX.Nonce. ) */
  uint64_t sub[ max - min ];

  HashPub() : hash( 0 ), len( 0 ) {
    ::memset( this->sub, 0, sizeof( this->sub ) );
  }
  void init( Subject &subj,  const char *sub,  PublishType val ) {
    size_t len = subj.len();
    subj.s( sub );
    this->sub[ val - min ] = _U64( subj.hash(), subj.len() );
    subj.set_len( len );
  }
  bool is_full( void ) {
    for ( uint8_t i = 0; i < max - min; i++ )
      if ( this->sub[ i ] == 0 )
        return false;
    return true;
  }
  PublishType lookup( uint32_t h,  uint16_t l ) const {
    uint64_t val = _U64( h, l );
    for ( uint8_t i = 0; i < max - min; i++ )
      if ( this->sub[ i ] == val )
        return PublishType ( i + min );
    return min;
  }
};

typedef HashPub< U_INBOX, U_INBOX_AUTH, InboxBuf > InboxHash;
typedef HashPub< U_MCAST, U_MCAST_PING, McastBuf > McastHash;

/* subscribed message recvd, either mcast or point to point */
struct SubMsgData {
  MsgFramePublish & pub;
  UserBridge      & src_bridge; /* which peer it's from */
  uint64_t          seqno,   /* the seqno of the published message */
                    time,    /* the optional time of message at the publisher */
                    last_seqno,/* previous seqno recvd */
                    last_time, /* previous time */
                    token;     /* rpc token */
  const void      * data;    /* message data */
  size_t            datalen; /* message data length */
  uint32_t          fmt,     /* format of data */
                    reply;   /* non-zero when peer wants a ptp reply */
  /* start_seqno : seqno of subscripton */
  /* sub2, sublen2 : subject of inbox */

  SubMsgData( MsgFramePublish &p,  UserBridge &n,  const void *d,
              size_t dl )
    : pub( p ), src_bridge( n ), seqno( 0 ), time( 0 ),
      last_seqno( 0 ), last_time( 0 ),
      data( d ), datalen( dl ), fmt( 0 ), reply( 0 ) {}
};
/* a publish sent to all subscribers */
struct PubMcastData {
  const char * sub;       /* subject to publish */
  size_t       sublen;    /* subject length */
  uint64_t     seqno,     /* seqno filled in by the publish */
               time,      /* optional time of publish */
               option,    /* message options for the opt field */
               token;     /* token rpc val */
  const void * data;      /* data to publish */
  size_t       datalen;   /* data length */
  uint32_t     fmt,       /* format of data */
               reply;     /* if rpc style point to point reply wanted */

  PubMcastData( const char *s,  size_t sl,  const void *d,  size_t dl,
                uint32_t f,  uint32_t rep = 0 )
    : sub( s ), sublen( sl ), seqno( 0 ), time( 0 ), option( 0 ), token( 0 ),
      data( d ), datalen( dl ), fmt( f ), reply( rep ) {}
  PubMcastData( const PubMcastData &mc ) :
    sub( mc.sub ), sublen( mc.sublen ), seqno( mc.seqno ), time( mc.time ),
    option( mc.option ), token( mc.token ), data( mc.data ),
    datalen( mc.datalen ), fmt( mc.fmt ), reply( mc.reply ) {}
};
/* a publish sent point to point to an inbox */
struct PubPtpData : public PubMcastData {
  UserBridge & peer;
  uint32_t     reply2;

  PubPtpData( UserBridge &p,  uint32_t rep,  const void *d,  size_t dl,
              uint32_t f )
    : PubMcastData( NULL, 0, d, dl, f, rep ), peer( p ), reply2( 0 ) {}
  PubPtpData( UserBridge &p,  const PubMcastData &mc )
    : PubMcastData( mc ), peer( p ), reply2( mc.reply ) {
    this->reply = 0;
  }
  /* same as mcast without a subject, message is sent to _INBOX.Nonce.<rep> */
};
struct EvTcpTransport;
struct StringTab;
struct TelnetListen;

struct SessionMgr : public kv::EvSocket {
  ConfigTree            & tree;           /* config db */
  ConfigTree::User      & user;           /* my user */
  ConfigTree::Service   & svc;            /* this transport */
  UScoreTab               u_tab;          /* table of _subscriptions */
  uint32_t                next_timer,     /* session start gets a timer_id */
                          timer_id;       /* timer_id for this session */
  InboxHash               ibx;            /* match inbox hashes */
  McastHash               mch;            /* match mcast hashes */
  UserDB                  user_db;        /* db of user nonce routes */
  SubDB                   sub_db;         /* track subscriptions */
  kv::BitSpace            router_set;
  kv::BloomRef            sys_bloom,
                          router_bloom;
  EventRecord             events;
  Console                 console;
  kv::Logger            & log;
  TelnetListen          * telnet;
  ConfigTree::Transport * telnet_tport;
  uint8_t                 tcp_accept_sock_type, /* free list sock types */
                          tcp_connect_sock_type,
                          tcp_conn_mgr_sock_type;

  SessionMgr( kv::EvPoll &p,  kv::Logger &l,  ConfigTree &c,
              ConfigTree::User &u,  ConfigTree::Service &s,
              StringTab &st ) noexcept;
  int init_sock( void ) noexcept;
  bool add_transport( ConfigTree::Service &s,  ConfigTree::Transport &t,
                      bool is_service ) noexcept;
  bool start_transport( TransportRoute &rte,  bool is_service ) noexcept;
  bool add_startup_transports( ConfigTree::Service &s ) noexcept;
  uint32_t shutdown_transport( ConfigTree::Service &s,
                               ConfigTree::Transport &t ) noexcept;
  bool add_mesh_accept( TransportRoute &listen_rte,
                        EvTcpTransport &conn ) noexcept;
  bool add_tcp_accept( TransportRoute &listen_rte,
                       EvTcpTransport &conn ) noexcept;
  bool add_mesh_connect( TransportRoute &mesh_rte,  const char *mesh_url,
                         uint32_t mesh_hash ) noexcept;
  int init_session( const CryptPass &pwd ) noexcept;
  void add_rte( const char *sub, size_t sub_len, uint32_t hash,
                PublishType type ) noexcept;
  uint32_t add_wildcard_rte( const char *prefix, size_t pref_len,
                             PublishType type ) noexcept;
  bool loop( void ) noexcept;
  void start( void ) noexcept;
  void stop( void ) noexcept;
  bool is_running( void ) {
    return this->timer_id != 0;
  }
  /* EvSocket */
  virtual void write( void ) noexcept;
  virtual void read( void ) noexcept;
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual bool timer_expire( uint64_t tid,  uint64_t eid ) noexcept;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept;
  MsgFrameStatus parse_msg_hdr( MsgFramePublish &fpub ) noexcept;
  void ignore_msg( const MsgFramePublish &fpub ) noexcept;
  /* publish data on a subject */
  bool publish( PubMcastData &mc ) noexcept;
  bool publish_any( PubMcastData &mc ) noexcept;
  bool publish_to( PubPtpData &ptp ) noexcept;
  void send_ack( const MsgFramePublish &pub,  UserBridge &,
                 const MsgHdrDecoder &dec,  const char *suf ) noexcept;
  bool create_telnet( ConfigTree::Transport &t ) noexcept;
  uint32_t shutdown_telnet( void ) noexcept;
  /* subscribed data recvd */
  /*void on_data( const SubMsgData &val ) noexcept;*/
};

}
}
#endif
