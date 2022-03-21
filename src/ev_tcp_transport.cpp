#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <raims/ev_tcp_transport.h>
#include <raims/session.h>
#include <raims/transport.h>
#include <raimd/json_msg.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

EvTcpTransport::EvTcpTransport( EvPoll &p,  uint8_t t ) noexcept
  : EvConnection( p, t ), rte( 0 ), /*tport_count( 0 ), not_fd2( 0 ),*/
    fwd_all_msgs( false ), is_connect( false )
{
}

EvTcpTransportListen::EvTcpTransportListen( EvPoll &p,
                                            TransportRoute &r ) noexcept
  : EvTcpListen( p, "ev_tcp_tport_listen", "ev_tcp_tport" ),
    rte( r )
{
  this->notify = &r;
}

int
EvTcpTransportListen::listen( const char *ip,  int port,  int opts ) noexcept
{
  return this->kv::EvTcpListen::listen2( ip, port, opts, "tcp_listen" );
}

bool
EvTcpTransportListen::accept( void ) noexcept
{
  EvTcpTransportService *c =
    this->poll.get_free_list<EvTcpTransportService>( this->accept_sock_type );
  if ( c == NULL )
    return false;
  c->rte = &this->rte;
  c->notify = this->notify;
  if ( ! this->accept2( *c, "tcp_accept" ) )
    return false;
  c->start();
  return true;
}


void
EvTcpTransportListen::release( void ) noexcept
{
}

void
EvTcpTransportListen::process_close( void ) noexcept
{
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
}

bool
EvTcpTransportClient::connect( EvTcpTransportParameters &p,
                               EvConnectionNotify *n ) noexcept
{
  if ( this->fd != -1 )
    return false;
  this->is_connect = true;
  this->EvConnection::release_buffers();
  if ( EvTcpConnection::connect( *this, p.host, p.port, p.opts ) != 0 )
    return false;
  this->notify = n;
  this->start();
  return true;
}

void
EvTcpTransport::start( void ) noexcept
{
  if ( this->fwd_all_msgs ) {
    uint32_t h = this->rte->sub_route.prefix_seed( 0 );
    this->rte->sub_route.add_pattern_route( h, this->fd, 0 );
  }
  if ( this->notify != NULL )
    this->notify->on_connect( *this );
}

void
EvTcpTransport::process( void ) noexcept
{
  size_t  buflen;
  int32_t status = 0;
  do {
    buflen = this->len - this->off;
    if ( buflen > 0 ) {
      const char * buf = &this->recv[ off ];
      status = this->msg_in.unpack( buf, buflen );
      if ( status != 0 ) {
        MDOutput mout;
        printf( "tcp msg_in status %d buflen %lu\n", status, buflen );
        mout.print_hex( buf, buflen > 256 ? 256 : buflen );
      }
      this->off += buflen;
      if ( buflen > 0 && this->msg_in.msg != NULL ) {
        /* if backpressure, push messages to write side */
        if ( ! this->dispatch_msg() ) {
          if ( this->pending() > 0 )
            this->push( EV_WRITE_HI );
          if ( this->test( EV_READ ) )
            this->pushpop( EV_READ_LO, EV_READ );
          /* EV_PROCESS is still set, so will return after writing others */
          return;
        }
      }
    }
  } while ( status == 0 && buflen > 0 );
  this->pop( EV_PROCESS );
  this->push_write();
  if ( status != 0 ) {
    this->push( EV_CLOSE );
  }
}

bool
EvTcpTransport::dispatch_msg( void ) noexcept
{
  const char * sub    = this->msg_in.msg->sub;
  uint16_t     sublen = this->msg_in.msg->sublen;
  uint32_t     h      = this->msg_in.msg->subhash;
  MsgFramePublish pub( sub, sublen, this->msg_in.msg, this->fd, h,
                       (uint8_t) CABA_TYPE_ID, *this->rte,
                       this->rte->sub_route );
  d_tcp( "ev_tcp(%s) dispatch( %.*s )\n", this->rte->name,
         (int) pub.subject_len, pub.subject );
  this->msgs_recv++;
  /*if ( *this->tport_count == 1 )
    return this->rte->sub_route.forward_not_fd2( pub, this->fd, this->not_fd2 );*/
  return this->rte->sub_route.forward_not_fd( pub, this->fd );
}

void
EvTcpTransport::release( void ) noexcept
{
  if ( this->fwd_all_msgs ) {
    uint32_t h = this->rte->sub_route.prefix_seed( 0 );
    this->rte->sub_route.del_pattern_route( h, this->fd, 0 );
  }
  this->msg_in.release();
  this->EvConnection::release_buffers();
}

void
EvTcpTransport::process_close( void ) noexcept
{
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
}

bool
EvTcpTransport::fwd_msg( EvPublish &pub ) noexcept
{
  d_tcp( "> ev_tcp(%s) fwd %.*s\n", this->rte->name,
          (int) pub.subject_len, pub.subject );
  char * buf = this->alloc( pub.msg_len );
  ::memcpy( buf, pub.msg, pub.msg_len );
  this->sz += pub.msg_len;
  this->msgs_sent++;

  bool flow_good = ( this->pending() <= this->send_highwater );
  this->idle_push( flow_good ? EV_WRITE : EV_WRITE_HI );
  return flow_good;
}

bool
EvTcpTransport::on_msg( EvPublish &pub ) noexcept
{
  if ( pub.src_route == (uint32_t) this->fd )
    return true;
  return this->fwd_msg( pub );
}
