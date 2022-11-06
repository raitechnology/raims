#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/ev_tcp_transport.h>
#include <raims/session.h>
#include <raims/transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

int rai::ms::no_tcp_aes;

size_t
EvTcpTransportParameters::copy_string( char buf[ MAX_TCP_HOST_LEN ], size_t off,
                                       const char * str,  size_t len ) noexcept
{
  if ( off + len >= MAX_TCP_HOST_LEN )
    len = MAX_TCP_HOST_LEN - ( off + 1 );
  ::memcpy( &buf[ off ], str, len );
  buf[ off + len ] = '\0';
  return off + len;
}

size_t
EvTcpTransportParameters::copy_host_buf( char buf[ MAX_TCP_HOST_LEN ],
                                        size_t off, const char * host ) noexcept
{
  return copy_string( buf, off, host, ::strlen( host ) );
}


void
EvTcpTransportOpts::parse( ConfigTree::Transport &tport,
                           int ptype,  SessionMgr &mgr ) noexcept
{
  bool ip4, ip6;
  if ( ! tport.get_route_int( R_TIMEOUT, this->timeout ) )
    this->timeout = mgr.tcp_timeout;
  if ( ! tport.get_route_bool( R_EDGE, this->edge ) )
    this->edge = false;
  if ( ! tport.get_route_bool( R_IPV4ONLY, ip4 ) )
    ip4 = mgr.tcp_ip4;
  if ( ! tport.get_route_bool( R_IPV6ONLY, ip6 ) )
    ip6 = mgr.tcp_ip6;
  if ( ! tport.get_route_bool( R_NOENCRYPT, this->noencrypt ) )
    this->noencrypt = mgr.tcp_noencrypt;
  if ( ! this->noencrypt )
    this->opts |= TCP_OPT_ENCRYPT;
  if ( ip4 )
    this->opts = ( this->opts & ~OPT_AF_INET6 ) | OPT_AF_INET;
  else if ( ip4 )
    this->opts = ( this->opts & ~OPT_AF_INET ) | OPT_AF_INET6;
  if ( ( ptype & PARAM_LISTEN ) != 0 )
    this->opts |= kv::OPT_REUSEADDR;
  if ( ( ptype & PARAM_REUSEPORT ) != 0 )
    this->opts |= kv::OPT_REUSEPORT;
  else
    this->opts &= ~kv::OPT_REUSEPORT;
  if ( ( ptype & PARAM_NB_CONNECT ) != 0 )
    this->opts |= kv::OPT_CONNECT_NB;
  else
    this->opts &= ~kv::OPT_CONNECT_NB;
}

void
EvTcpTransportParameters::parse_tport( ConfigTree::Transport &tport,
                                       int ptype,  SessionMgr &mgr ) noexcept
{
  char         tmp[ MAX_TCP_HOSTS ][ MAX_TCP_HOST_LEN ];
  size_t       len[ MAX_TCP_HOSTS ];
  const char * host[ MAX_TCP_HOSTS ];
  int          port[ MAX_TCP_HOSTS ], port2 = 0;
  bool         is_device = false;

  ConfigTree::StringPair * el[ MAX_TCP_HOSTS ];
  if ( ( ptype & PARAM_LISTEN ) == 0 )
    tport.get_route_pairs( R_CONNECT, el, MAX_TCP_HOSTS );
  else {
    tport.get_route_pairs( R_LISTEN, el, MAX_TCP_HOSTS );
    if ( el[ 0 ] == NULL ) {
      tport.get_route_pairs( R_DEVICE, el, MAX_TCP_HOSTS );
      is_device = true;
    }
  }
  tport.get_route_int( R_PORT, port2 );
  for ( size_t i = 0; i < MAX_TCP_HOSTS; i++ ) {
    host[ i ] = ( el[ i ] == NULL ? NULL : el[ i ]->value.val );
    tmp[ i ][ 0 ] = '\0';
    len[ i ] = sizeof( tmp[ i ] );
    port[ i ] = tport.get_host_port( host[ i ], tmp[ i ], len[ i ] );
    if ( port[ i ] == 0 )
      port[ i ] = port2;
    if ( tport.is_wildcard( tmp[ i ] ) ) {
      host[ i ] = NULL;
      tmp[ i ][ 0 ] = '\0';
    }
  }
  this->set_host_port( host, port );
  this->EvTcpTransportOpts::parse( tport, ptype, mgr );
  if ( is_device )
    this->opts |= OPT_NO_DNS;
}


EvTcpTransport::EvTcpTransport( EvPoll &p,  uint8_t t ) noexcept
  : AES_Connection( p, t ), rte( 0 ), /*tport_count( 0 ), not_fd2( 0 ),*/
    fwd_all_msgs( false ), is_connect( false ), encrypt( true )
{
}

EvTcpTransportListen::EvTcpTransportListen( EvPoll &p,
                                            TransportRoute &r ) noexcept
  : EvTcpListen( p, "ev_tcp_tport_listen", "ev_tcp_tport" ),
    rte( r ), encrypt( true )
{
  this->notify = &r;
}

int
EvTcpTransportListen::listen( const char *ip,  int port,  int opts ) noexcept
{
  int res = this->kv::EvTcpListen::listen2( ip, port, opts, "tcp_listen",
                                            this->rte.sub_route.route_id );
  if ( res == 0 ) {
    this->rte.set_peer_name( *this, "tcp_list" );
  }
  return res;
}

EvSocket *
EvTcpTransportListen::accept( void ) noexcept
{
  EvTcpTransportService *c =
    this->poll.get_free_list<EvTcpTransportService>( this->accept_sock_type );
  if ( c == NULL )
    return NULL;
  c->rte = &this->rte;
  c->notify = this->notify;
  c->encrypt = this->encrypt;
  if ( ! this->accept2( *c, "tcp_accept" ) )
    return NULL;
  c->start();
  return c;
}


void
EvTcpTransportListen::release( void ) noexcept
{
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
}

void
EvTcpTransportListen::process_close( void ) noexcept
{
  this->client_stats( this->rte.sub_route.peer_stats );
  this->EvSocket::process_close();
}
#if 0
bool
EvTcpTransportClient::connect( EvTcpTransportParameters &p,
                               EvConnectionNotify *n,  int index ) noexcept
{
  if ( this->fd != -1 )
    return false;
  this->is_connect = true;
  if ( this->encrypt )
    this->AES_Connection::release_aes();
  this->EvConnection::release_buffers();
  if ( EvTcpConnection::connect2( *this, p.host[ index ], p.port[ index ],
                                  p.opts, "ev_tcp_tport",
                                  this->rte->sub_route.route_id ) != 0 )
    return false;
  this->notify = n;
  this->start();
  return true;
}
#endif
bool
EvTcpTransportClient::connect( int opts,  EvConnectionNotify *n,
                               struct addrinfo *addr_list ) noexcept
{
  if ( this->fd != -1 )
    return false;
  this->is_connect = true;
  if ( EvTcpConnection::connect3( *this, addr_list, opts, "ev_tcp_tport",
                                  this->rte->sub_route.route_id ) != 0 )
    return false;
  this->notify = n;
  this->start();
  return true;
}

void
EvTcpTransport::start( void ) noexcept
{
  const char * name;
  if ( this->is_connect )
    name = "tcp_conn";
  else
    name = "tcp_acc";
  this->rte->set_peer_name( *this, name );

  if ( this->encrypt && ! no_tcp_aes ) {
    this->init_exchange( NULL, 0 );
    this->send_key();
  }
  else {
    this->encrypt = false;
    this->init_noencrypt();
  }
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
        printf( "tcp msg_in status %d buflen %u\n", status, (uint32_t) buflen );
        mout.print_hex( buf, buflen > 256 ? 256 : buflen );
      }
      this->off += (uint32_t) buflen;
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
  d_tcp( "< ev_tcp(%s) dispatch %.*s (%lu)\n", this->rte->name,
         (int) pub.subject_len, pub.subject, this->msgs_recv + 1 );
  this->msgs_recv++;
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
  if ( this->encrypt )
    this->AES_Connection::release_aes();
  this->EvConnection::release_buffers();
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
}

void
EvTcpTransport::process_close( void ) noexcept
{
  this->client_stats( this->rte->sub_route.peer_stats );
  this->EvSocket::process_close();
}

bool
EvTcpTransport::fwd_msg( EvPublish &pub ) noexcept
{
  d_tcp( "> ev_tcp(%s) fwd %.*s (%lu)\n", this->rte->name,
          (int) pub.subject_len, pub.subject, this->msgs_sent + 1 );
  char * buf = this->alloc( pub.msg_len );
  ::memcpy( buf, pub.msg, pub.msg_len );
  this->sz += pub.msg_len;
  this->msgs_sent++;

  return this->idle_push_write();
}

bool
EvTcpTransport::on_msg( EvPublish &pub ) noexcept
{
  if ( pub.src_route == (uint32_t) this->fd )
    return true;
  return this->fwd_msg( pub );
}
