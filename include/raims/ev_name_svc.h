#ifndef __rai_raims__ev_name_svc_h__
#define __rai_raims__ev_name_svc_h__

#include <raikv/ev_tcp.h>
#include <raims/msg.h>
#include <raims/config_tree.h>

namespace rai {
namespace ms {

struct SessionMgr;
struct UserDB;
struct NameSvc;
struct TransportRoute;

union NameInbox {
  uint64_t val;
  struct {
    uint32_t in_addr;  /* my inbox recv addr */
    uint16_t sin_port, /* my inbox recv port */
             zero;
  } ip;
};

struct EvNameSock : public kv::EvUdp {
  NameSvc       & name;
  MsgFrameDecoder msg_in;
  EvNameSock( kv::EvPoll &p, NameSvc &n,  const char *k )
    : EvUdp( p, p.register_type( k )  ), name( n ) {}
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual void process_close( void ) noexcept;
};

struct EvNameListen : public EvNameSock {
  EvNameListen( kv::EvPoll &p, NameSvc &n )
    : EvNameSock( p, n, "name_listen" ) {}
  void send_msg( const void *data,  size_t len,  NameInbox &inbox ) noexcept;
};

struct EvNameConnect : public EvNameSock {
  EvNameConnect( kv::EvPoll &p, NameSvc &n )
    : EvNameSock( p, n, "name_connect" ) {}
  void send_msg( const void *data,  size_t len ) noexcept;
};

struct Advert {
  TransportRoute *rte;
  uint64_t        last_start_time[ 2 ];
  uint32_t        ad_counter;
  void init( TransportRoute *r ) {
    this->rte = r;
    this->last_start_time[ 0 ] = this->last_start_time[ 1 ] = 0;
    this->ad_counter = 0;
  }
  void update_start_recv( uint64_t start ) { /* when new publishes are recvd */
    if ( start > this->last_start_time[ 0 ] )
      this->last_start_time[ 0 ] = start;
  }
  void rotate_start_recv( void ) {           /* on interval, rotate */
    this->last_start_time[ 1 ] = this->last_start_time[ 0 ];
    this->last_start_time[ 0 ] = 0;
  }
  bool is_newer( uint64_t start ) const {    /* if i am the newest advertiser */
    if ( start > this->last_start_time[ 0 ] &&
         start > this->last_start_time[ 1 ] )
      return true;
    return false;
  }
};

struct AdvertList : public kv::ArrayCount< Advert, 4 > {
  void push( TransportRoute *rte ) {
    for ( size_t i = 0; i < this->count; i++ ) {
      if ( rte == this->ptr[ i ].rte )
        return;
    }
    Advert a;
    a.init( rte );
    this->kv::ArrayCount< Advert, 4 >::push( a );
  }
};

struct NameSvc {
  static const char * default_name_mcast( void ) { return ";239.23.22.217"; }
  static int          default_name_port( void )  { return 8327; }

  SessionMgr            & mgr;
  UserDB                & user_db;
  ConfigTree::Transport & tport;
  EvNameListen            mcast_recv,
                          inbox_recv;
  EvNameConnect           mcast_send;
  AdvertList              adverts;
  NameInbox               inbox;
  uint32_t                connect_fail_count,
                          name_id;
  bool                    is_connected,
                          is_closed;
  void * operator new( size_t, void *ptr ) { return ptr; }
  NameSvc( kv::EvPoll &p,  SessionMgr &m,  UserDB &u,
           ConfigTree::Transport &tp,  uint32_t id ) noexcept;
  bool connect( void ) noexcept;
  void close( void ) noexcept;
  void start_transports( void ) noexcept;
  void send_msg( const void *data,  size_t len,  NameInbox *inbox ) {
    if ( inbox == NULL )
      this->mcast_send.send_msg( data, len );
    else
      this->mcast_recv.send_msg( data, len, *inbox );
  }
  void print_addr( const char *what,  const void *sa ) noexcept;
};

}
}

#endif
