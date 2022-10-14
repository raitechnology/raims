#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/transport.h>
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>

using namespace rai;
using namespace ms;
using namespace kv;

void
TransportRoute::on_connect( kv::EvSocket &conn ) noexcept
{
  uint32_t connect_type = 0;
  bool     is_encrypt   = false;
  this->clear( TPORT_IS_SHUTDOWN );
  if ( ! this->is_mcast() ) {
    EvTcpTransport &tcp = (EvTcpTransport &) conn;
    is_encrypt = tcp.encrypt;
    this->printf( "connect %s %s %s using %s fd %u\n",
                  tcp.encrypt ? "encrypted" : "clear",
                  conn.peer_address.buf, conn.type_string(),
                  this->sub_route.service_name, conn.fd );
    if ( this->is_mesh() ) {
      if ( ! tcp.is_connect ) {
        this->mgr.add_mesh_accept( *this, tcp );
        return;
      }
      connect_type = TPORT_IS_CONNECT | TPORT_IS_MESH;
    }
    else {
      if ( ! tcp.is_connect ) {
        if ( ! this->is_edge() ) {
          this->mgr.add_tcp_accept( *this, tcp );
          return;
        }
        connect_type = TPORT_IS_TCP;
      }
      else {
        connect_type = TPORT_IS_CONNECT | TPORT_IS_TCP;
      }
    }
  }
  else {
    connect_type = TPORT_IS_MCAST;
    this->printf( "connect %s %s using %s fd %u\n",
                  conn.peer_address.buf, conn.type_string(),
                  this->sub_route.service_name, conn.fd );
  }
  this->mgr.events.on_connect( this->tport_id, connect_type, is_encrypt );
  if ( ! this->connected.test_set( conn.fd ) )
    this->connect_count++;
}

void
TransportRoute::on_shutdown( EvSocket &conn,  const char *err,
                             size_t errlen ) noexcept
{
  const char *s = "disconnected";
  char errbuf[ 256 ];
  if ( &conn == (EvSocket *) this->listener )
    s = "listener stopped";
  else if ( errlen >= 15 && ::memcmp( err, "already connect", 15 ) == 0 )
    s = "stopped trying";
  if ( errlen == 0 ) {
    errlen = conn.print_sock_error( errbuf, sizeof( errbuf ) );
    if ( errlen > 0 )
      err = errbuf;
  }
  if ( errlen > 0 )
    this->printf( "%s %s (%.*s)\n", s, conn.peer_address.buf,
                  (int) errlen, err );
  else
    this->printf( "%s %s (count=%u)\n", s, conn.peer_address.buf,
                  this->connect_count );
  this->mgr.events.on_shutdown( this->tport_id, conn.fd >= 0 );
  if ( conn.fd >= 0 ) {
    this->user_db.retire_source( *this, conn.fd );
    if ( this->connected.test_clear( conn.fd ) ) {
      if ( --this->connect_count == 0 )
        if ( ! this->is_set( TPORT_IS_LISTEN ) )
          this->set( TPORT_IS_SHUTDOWN );
    }
    else if ( &conn == (EvSocket *) this->listener )
      this->set( TPORT_IS_SHUTDOWN );
  }
  else if ( this->connect_count == 0 ) {
    this->set( TPORT_IS_SHUTDOWN );
  }
  d_tran( "%s connect_count %u\n", this->name, this->connect_count );
}

void
ConnectionMgr::connect_failed( EvSocket &conn ) noexcept
{
  this->rte.on_shutdown( conn, NULL, 0 );
  if ( ! this->setup_reconnect() ) {
    printf( "reconnected failed (connect_failed)\n" );
  }
  else {
    printf( "reconnect timer running (connect_failed)\n" );
  }
}

void
ConnectionMgr::on_connect( EvSocket &conn ) noexcept
{
  this->connect_time = current_monotonic_time_s();
  this->rte.on_connect( conn );
}

void
ConnectionMgr::on_shutdown( EvSocket &conn,  const char *err,
                           size_t errlen ) noexcept
{
  this->rte.on_shutdown( conn, err, errlen );
  if ( ! this->setup_reconnect() ) {
    printf( "reconnect failed (on_shutdown)\n" );
  }
  else {
    printf( "reconnect timer running (on_shutdown)\n" );
  }
}

bool
ConnectionMgr::setup_reconnect( void ) noexcept
{
  if ( this->is_reconnecting || this->is_shutdown || this->rte.poll.quit )
    return true;

  this->is_reconnecting = true;
  if ( this->connect_count < MAX_TCP_HOSTS &&
       this->parameters->host[ this->connect_count ] != NULL ) {
    this->rte.poll.timer.add_timer_millis( *this, 100, 0, 0 );
    return true;
  }
  double now    = current_monotonic_time_s(),
         period = 60;
  if ( this->connect_timeout_secs > 0 )
    period = this->connect_timeout_secs + 15;
  /* if connected for 1 second, restart timers */
  if ( ( this->connect_time + 1 < now &&
         this->connect_time > this->reconnect_time ) ||
       this->reconnect_time + period < now ) {
    this->reconnect_timeout_secs = 1;
    this->reconnect_time = now;
    this->connect_time = 0;
  }
  else {
    this->reconnect_timeout_secs =
      min_int<uint16_t>( this->reconnect_timeout_secs + 2, 10 );
  }
  if ( this->connect_timeout_secs > 0 ) {
    if ( now - this->reconnect_time > (double) this->connect_timeout_secs ) {
      this->is_reconnecting = false;
      this->is_shutdown = true;
      return false;
    }
  }
  printf( "reconnect in %u seconds\n", this->reconnect_timeout_secs );
  this->rte.poll.timer.add_timer_seconds( *this, this->reconnect_timeout_secs,
                                          0, 0 );
  return true;
}

bool
ConnectionMgr::do_connect( void ) noexcept
{
  EvTcpTransportClient     & client = *this->conn;
  EvTcpTransportParameters & parm   = *this->parameters;
  this->is_shutdown = false;

  size_t index;
  for ( index = 0; index < MAX_TCP_HOSTS; index++ ) {
    if ( parm.hash[ index ] != 0 ) {
      if ( this->rte.mgr.find_mesh( this->rte, parm.host[ index ],
                                    parm.port[ index ], parm.hash[ index ] ) ) {
        const char s[] = "already connected to mesh";
        this->rte.on_shutdown( client, s, sizeof( s ) - 1 );
        this->is_shutdown = true;
        return false;
      }
    }
  }
  for (;;) {
    index = this->connect_count++ % MAX_TCP_HOSTS;
    if ( index == 0 || parm.host[ index ] != NULL )
      break;
  }
  d_tran( "do_connect index %u host %s:%d (%x)\n",
          (uint32_t) index, parm.host[ index ],
          parm.port[ index ], parm.hash[ index ] );
  /* non-blocking connect should always succeed unless socket error */
  if ( ! client.connect( parm, this, index ) ) {
    this->connect_failed( client );
    this->is_shutdown = true;
    return false;
  }
  return true;
}

bool
ConnectionMgr::timer_cb( uint64_t, uint64_t ) noexcept
{
  if ( this->is_reconnecting ) {
    this->is_reconnecting = false;
    if ( ! this->is_shutdown && ! this->rte.poll.quit )
      this->do_connect();
  }
  return false;
}

