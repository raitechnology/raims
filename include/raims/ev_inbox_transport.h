#ifndef __rai_raims__ev_inbox_transport_h__
#define __rai_raims__ev_inbox_transport_h__

#include <raikv/ev_net.h>
#include <raikv/ev_cares.h>
#include <raims/msg.h>
#include <raims/send_window.h>

namespace rai {
namespace ms {

static const uint8_t  IBX_MAGIC = 0x33;
static const uint8_t  IBX_DATA = 0, /* data packet */
                      IBX_RACK = 1, /* recv ack */
                      IBX_SACK = 2; /* send ack */
static const uint32_t IBX_IDENT_MAX = ( 1 << 10 );

struct InboxCode {
  uint32_t magic       : 6,
           type        : 3, /* data or ack type */
           is_repair   : 1, /* data repair, retransmit */
           is_fragment : 1, /* data fragment */
           is_rollup   : 1, /* data rollup, last fragment */
           ident       : 10,
           dest_id     : 10;

  void zero( void ) {
    ::memset( this, 0, sizeof( *this ) );
  }
  bool is_valid( void ) const { return this->magic == IBX_MAGIC; }
  bool is_data( void ) const  { return this->type  == IBX_DATA;  }
  void set_message( uint32_t id,  uint32_t did ) {
    this->zero();
    this->magic   = IBX_MAGIC;
    this->type    = IBX_DATA;
    this->ident   = id;
    this->dest_id = did;
  }
  void set_rack( uint32_t id,  uint32_t did ) {
    this->zero();
    this->magic   = IBX_MAGIC;
    this->type    = IBX_RACK;
    this->ident   = id;
    this->dest_id = did;
  }
  void set_sack( uint32_t id,  uint32_t did ) {
    this->zero();
    this->magic   = IBX_MAGIC;
    this->type    = IBX_SACK;
    this->ident   = id;
    this->dest_id = did;
  }
  void set_fragment( void ) { this->is_fragment = 1; }
  void set_rollup( void )   { this->is_fragment = 1; this->is_rollup = 1; }
  void set_repair( void )   { this->is_repair   = 1; }

  const char *to_str( void ) const;
};

struct InboxPkt {
  InboxCode code;       /* above code: message, repair, recv ack, send ack */
  uint32_t  src_uid,     /* unique id at source */
            dest_uid,    /* unique id at dest */
            src_seqno,   /* send sequence number, tells peer to ack */
            dest_seqno,  /* recv sequence number, allows peer to release window*/
            msg_len;     /* bytes of message follows */
  void * msg( void ) const {
    return (void *) &this[ 1 ];
  }
  bool is_valid( uint32_t len ) const { /* check pkt geom and header on recv */
    if ( len < sizeof( InboxPkt ) )
      return false;
    if ( len < sizeof( InboxPkt ) + this->msg_len )
      return false;
    if ( ! this->code.is_valid() )
      return false;
    return true;
  }
};

struct InboxPeer;
static const size_t INBOX_WBUF_SIZE = 16 * 1024;
struct InboxWindow : public SendWindow {  /* pkts are allocated in a window */
  InboxPeer & peer;
  void * operator new( size_t, void *ptr ) { return ptr; }
  InboxWindow( InboxPeer &p,  size_t av )
    : SendWindow( &this[ 1 ], av ), peer( p ) {}
  static void *new_window_mem( InboxPeer &p,  size_t len ) noexcept;
};

struct InboxPktElem {
  InboxPktElem * next,   /* list of pkts in a window */
               * back;
  InboxWindow  & window; /* deref window after pkt no longer needed */
  InboxPkt       pkt;    /* pkt data */

  void * operator new( size_t, void *ptr ) { return ptr; }
  InboxPktElem( InboxWindow &w )
    : next( 0 ), back( 0 ), window( w ) {};
};

static const uint32_t NO_UID = 0xffffffffU;

enum PeerState {
  RESOLVE_SRC   = 1,  /* source is known */
  RESOLVE_DEST  = 2,  /* dest is known */
  RESOLVED      = RESOLVE_SRC | RESOLVE_DEST,
  ACTIVE_RECV   = 4,  /* pending recv ack */
  ACTIVE_SEND   = 8,  /* pending send request ack */
  ACTIVE_WINDOW = 16, /* send window retransmit */
  ACTIVE        = ACTIVE_RECV | ACTIVE_SEND | ACTIVE_WINDOW,
  DUP_RECV      = 32
};

typedef kv::DLinkList<InboxPeer>    InboxPeerList;
typedef kv::DLinkList<InboxPktElem> InboxPktList;

struct InboxPeer {
  InboxPeer       * next,          /* peer links for timer traversal */
                  * back;
  const struct sockaddr * addr;    /* the peer address */
  const uint32_t addrlen;          /* the peer address len */
  uint32_t       peer_id,          /* peer conn id (1 -> IBX_IDENT_MAX) */
                 url_hash,         /* dest url hash */
                 dest_peer_id,     /* dest peers conn id */
                 src_uid,          /* uid used by source, unique for addr */
                 dest_uid,         /* uid used by peer, not unique */
                 out_seqno,        /* next sequence for send */
                 out_ack_seqno,    /* send window acked */
                 out_window_seqno, /* trailing edge of send window */
                 in_seqno,         /* current leading edge of recv window */
                 in_ack_seqno,     /* recv window acked to peer */
                 in_window_seqno,  /* recv window sequence from peer */
                 state,            /* PeerState bits */
                 window_timer_cnt, /* backoff retransmit */
                 send_timer_cnt;   /* backoff send */
  uint64_t       window_timer,     /* retransmit sends after timeout */
                 send_timer,       /* ask sender for ack */
                 recv_timer;       /* ack recv after a timeout */
  InboxWindow  * window;           /* ref count memory for pkts */
  InboxPktList   out,              /* send window */
                 in,               /* recv window */
                 frag_list;        /* recv fragmented messages */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  InboxPeer( struct sockaddr *a,  uint32_t l,  uint32_t id,  uint32_t h )
      : next( 0 ), back( 0 ), addr( a ), addrlen( l ), peer_id( id ),
        url_hash( h ), src_uid( NO_UID ), dest_uid( NO_UID ), window( 0 ) {
    this->zero();
  }
  void zero( void ) {
    this->dest_peer_id     = 0;
    this->out_seqno        = 0;
    this->out_ack_seqno    = 0;
    this->out_window_seqno = 0;
    this->in_seqno         = 0;
    this->in_ack_seqno     = 0;
    this->in_window_seqno  = 0;
    this->state            = 0;
    this->window_timer_cnt = 0;
    this->send_timer_cnt   = 0;
    this->window_timer     = 0;
    this->send_timer       = 0;
    this->recv_timer       = 0;
  }
  /* on send, copy to send window */
  InboxPktElem *alloc_window( uint32_t msg_len ) noexcept;
  /* on recv, save to recv window, when out of order */
  InboxPktElem *copy_pkt_to_window( const InboxPkt &pkt ) noexcept;
  /* adjust send window, remove acked packets */
  void adjust_send_window( void ) noexcept;
  /* find peer by dest address */
  bool match_addr( const struct sockaddr *a,  uint32_t len ) const {
    return this->addrlen == len && ::memcmp( a, this->addr, len ) == 0;
  }
  /* both sides are connected */
  bool resolved( void ) const {
    return ( this->state & RESOLVED ) == RESOLVED;
  }
  /* if in active list for acking, retransmitting */
  bool active( void ) const {
    return ( this->state & ACTIVE ) != 0;
  }
  /* push to an active list */
  void push_active( InboxPeerList &active,  uint32_t add_state ) {
    const uint32_t old_state = this->state;
    if ( ( old_state & add_state ) == 0 ) {
      this->state |= add_state;
      if ( ( old_state & ACTIVE ) == 0 ) {
        active.push_tl( this );
      }
    }
  }
  /* pop from active */
  void pop_active( InboxPeerList &active ) {
    this->state &= ~ACTIVE;
    active.pop( this );
  }
  void reset( void ) noexcept;

  static uint64_t us_to_ns( uint64_t t,  uint32_t cnt ) {
    return (uint64_t) ( t * 1000 ) << cnt;
  }
  /* timeout for retransmit */
  bool window_timer_expire( uint64_t t ) {
    if ( t > this->window_timer + us_to_ns( 50000, this->window_timer_cnt ) ) {
      if ( this->window_timer_cnt < 8 )
        this->window_timer_cnt++;
      this->window_timer = t;
      return true;
    }
    return false;
  }
  /* timeout for send ack */
  bool send_timer_expire( uint64_t t ) {
    if ( t > this->send_timer + us_to_ns( 20000, this->send_timer_cnt ) ) {
      if ( this->send_timer_cnt < 8 )
        this->send_timer_cnt++;
      this->send_timer = t;
      return true;
    }
    return false;
  }
  /* timeout for recv ack */
  bool recv_timer_expire( uint64_t t ) {
    if ( t > this->recv_timer + us_to_ns( 10000, 0 ) ) {
      this->recv_timer = t;
      return true;
    }
    return false;
  }
};
/* source peers indexied by uid, dest peers by address */
struct InboxPeerArray : public kv::ArraySpace<InboxPeer *,8> {
  const uint32_t state; /* either RESOLVE_SRC or RESOVLE_DEST */

  InboxPeerArray( uint32_t st ) : state( st ) {}
  bool insert( InboxPeer &p,  uint32_t idx,  uint32_t uid ) noexcept;
  InboxPeer *resolve( const struct sockaddr *addr,  uint32_t addrlen ) noexcept;
};
/* source peers indexed by unique id */
struct InboxSrcArray : public InboxPeerArray {
  InboxSrcArray( uint32_t st ) : InboxPeerArray( st ) {}

  InboxPeer *match( uint32_t uid,  uint32_t my_peer_id,
                    uint32_t dest_peer_id ) const {
    if ( uid >= this->size || this->ptr[ uid ] == NULL )
      return NULL;
    InboxPeer *p = this->ptr[ uid ];
    if ( p->src_uid == uid ) {
      if ( dest_peer_id != 0 ) {
        if ( p->dest_peer_id == 0 )
          p->dest_peer_id = dest_peer_id;
        else if ( p->dest_peer_id != dest_peer_id )
          return NULL;
      }
      if ( my_peer_id != 0 ) {
        if ( p->peer_id != my_peer_id )
          return NULL;
      }
      return p;
    }
    return NULL;
  }
  void remove( InboxPeer &p ) {
    p.state &= ~RESOLVE_SRC;
    this->ptr[ p.src_uid ] = NULL;
  }
  InboxPeer *resolve2( const struct sockaddr *addr,  uint32_t addrlen,
                       uint32_t uid ) noexcept;
};
/* dest peers are a list, resolved from the end by address */
struct InboxDestArray : public InboxPeerArray {
  InboxDestArray( uint32_t st ) : InboxPeerArray( st ) {}

  void remove( InboxPeer &p ) noexcept;
  void insert( InboxPeer &p,  uint32_t dest_uid ) noexcept;
  InboxPeer *resolve2( const struct sockaddr *addr,  uint32_t addrlen,
                       uint32_t uid ) noexcept;
};
struct TransportRoute;
/* the socket and peers */
struct EvInboxTransport : public kv::EvUdp {
  TransportRoute & rte;
  uint64_t         timer_id;
  uint32_t         mtu,     /* mtu of pkts */
                   id;
  InboxSrcArray    src;     /* peer by uid, peer in both arrays when resolved */
  InboxDestArray   dest;    /* peer by dest address */
  MsgFrameDecoder  msg_in;  /* decodes messages when ready */
  size_t           out_count; /* count of packets ready for sending */
  uint64_t         total_sent_count,
                   total_recv_count,
                   duplicate_count, /* count of duplicate pkts received */
                   repair_count,    /* count of retransmitted pkts */
                   cur_mono_time,  /* updated when timer expires */
                   last_mono_time;  /* for stats ival */
  InboxPktList     out;     /* packets ready to send */
  InboxPeerList    active;  /* list of peers for acks and retransmits */

  void * operator new( size_t, void *ptr ) { return ptr; }
  EvInboxTransport( kv::EvPoll &p,  TransportRoute &r )
    : kv::EvUdp( p, p.register_type( "inbox_sock" ) ),
      rte( r ), mtu( 1500 ), id( (uint32_t) kv_current_realtime_ms() ),
      src( RESOLVE_SRC ), dest( RESOLVE_DEST ), out_count( 0 ),
      total_sent_count( 0 ), total_recv_count( 0 ),
      duplicate_count( 0 ), repair_count( 0 ), 
      cur_mono_time( 0 ), last_mono_time( 0 ) {}

  void push_active_send( InboxPeer &p ) { /* send ack after timer */
    p.send_timer     = this->cur_mono_time;
    p.send_timer_cnt = 0;
    p.push_active( this->active, ACTIVE_SEND );
  }
  void push_active_recv( InboxPeer &p ) { /* recv ack after timer */
    if ( ( p.state & ACTIVE_RECV ) == 0 ) {
      p.recv_timer = this->cur_mono_time;
      p.push_active( this->active, ACTIVE_RECV );
    }
  }
  void push_active_window( InboxPeer &p ) { /* retransmit after timer */
    p.window_timer     = this->cur_mono_time;
    p.window_timer_cnt = 0;
    p.push_active( this->active, ACTIVE_WINDOW );
  }

  bool listen( const char *ip, int port ) noexcept; /* open socket */
  void post_msg( InboxPeer &p,  const void *msg, uint32_t msg_len ) noexcept;
  void post_frag_msg( InboxPeer &p,  MsgFragPublish &fpub ) noexcept;
  bool repair_window( InboxPeer &p ) noexcept;
  bool check_window( InboxPeer &p ) noexcept;
  void dispatch_msg( InboxPeer &p,  InboxPkt &pkt ) noexcept;
  void dispatch_frag_msg( InboxPeer &p,  InboxPkt *pkt ) noexcept;
  void dispatch_msg2( const void *msg,  size_t msg_len ) noexcept;
  bool reassign_peer( InboxPeer &p,  uint32_t src_uid,
                      const char *url,  uint32_t url_hash ) noexcept;
  void reset_peer( InboxPeer &peer ) noexcept;
  InboxPeer *alloc_peer( struct sockaddr *addr, uint32_t addrlen,
                         uint32_t url_hash ) noexcept;
  InboxPeer *resolve_dest_uid( uint32_t src_uid,  struct sockaddr *addr,
                               uint32_t addrlen,  uint32_t url_hash ) noexcept;
  InboxPeer *resolve_dest_url( uint32_t src_uid,  const char *url,
                               uint32_t url_hash ) noexcept;
  void url_to_addrinfo( const char *url,  kv::CaresAddrInfo &addr_info ) noexcept;
  InboxPeer *resolve_src_uid( uint32_t dest_uid,  uint32_t my_peer_id,
                              uint32_t dest_peer_id,  struct sockaddr *addr,
                              uint32_t addrlen ) noexcept;
  void shutdown_peer( uint32_t peer_uid,  uint32_t url_hash ) noexcept;
  /* EvUdp */
  virtual void write( void ) noexcept final;
  virtual void process( void ) noexcept final;
  virtual void release( void ) noexcept final;
  virtual bool timer_expire( uint64_t tid, uint64_t eid ) noexcept final;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept final;
  virtual void process_shutdown( void ) noexcept final;
  virtual void process_close( void ) noexcept final;
};

struct InboxPublish : public MsgFragPublish {
  const char * peer_url;
  uint32_t     peer_uid,
               url_hash;

  InboxPublish( const char *subj,  size_t subj_len,  const void *data,
                size_t data_len,  kv::RoutePublish &src_rt,
                const kv::PeerId &src, uint32_t hash, uint32_t enc,
                const char *url,  uint32_t uid,  uint32_t url_h,
                const void *tr = NULL,  size_t tsz = 0 ) :
    MsgFragPublish( subj, subj_len, data, data_len, src_rt, src, hash,
               enc, tr, tsz ),
      peer_url( url ), peer_uid( uid ), url_hash( url_h ) {
    this->publish_type = kv::PUB_TYPE_INBOX;
  }
};

}
}
#endif
