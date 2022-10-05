#ifndef __rai_raims__ev_pgm_transport_h__
#define __rai_raims__ev_pgm_transport_h__

#include <raikv/ev_net.h>
#include <raims/msg.h>
#include <raims/pgm_sock.h>
#include <raims/config_tree.h>

namespace rai {
namespace ms {

struct TransportRoute;

struct EvPgmTransportParameters {
  const char * network;    /* netork:  interface;recv-mcast[,mc];send-mcast */
  int          port;       /* service port */
  uint32_t     mtu,        /* max size of a pgm data frame */
               txw_sqns,   /* size in sequences of the send window */
               rxw_sqns,   /* size in sequences of the recv window */
               txw_secs,   /* size of send window in secs */
               mcast_loop; /* if send loops back to the recv port permitted */

  void * operator new( size_t, void *ptr ) { return ptr; }
  EvPgmTransportParameters( const char *n = NULL,  int p = 9000 )
    : network( n ), port( p ),
      mtu( 16384 ), txw_sqns( 4 * 1024 ), rxw_sqns( 4 * 1024 ),
      txw_secs( 15 ), mcast_loop( 2 ) {}

  void parse_tport( const char *name,  ConfigTree::Transport &tport,
                    char net_buf[ 1024 ],  uint32_t reliability ) noexcept;
};

struct EvPgmTransport : public kv::EvSocket {
  TransportRoute         & rte;
  PgmSock                  pgm;
  MsgFrameDecoder          msg_in;
  FragList                 frag_list;
  uint32_t                 recv_highwater,
                           send_highwater;
  uint64_t                 timer_id,
                           stats_timer;
  /*size_t                 * tport_count;
  uint32_t                 not_fd2;*/
  kv::EvConnectionNotify * notify;
  bool                     backpressure,
                           fwd_all_msgs;

  void * operator new( size_t, void *ptr ) { return ptr; }
  EvPgmTransport( kv::EvPoll &p,  TransportRoute &r ) noexcept;

  bool connect( EvPgmTransportParameters &p,
                kv::EvConnectionNotify *n ) noexcept;
  void start( void ) noexcept;
  bool fwd_msg( kv::EvPublish &pub ) noexcept;
  void process_fragment( const uint8_t *data,  size_t len ) noexcept;
  void dispatch_data( const uint8_t *data,  size_t off,  size_t len ) noexcept;
  void dispatch_msg( void ) noexcept;

  /* EvSocket */
  virtual void write( void ) noexcept final;
  virtual void read( void ) noexcept final;
  virtual void process( void ) noexcept final;
  virtual void release( void ) noexcept final;
  virtual bool timer_expire( uint64_t timer_id, uint64_t event_id ) noexcept;
  virtual void process_shutdown( void ) noexcept final;
  virtual void process_close( void ) noexcept final;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept;
};

}
}
#endif
