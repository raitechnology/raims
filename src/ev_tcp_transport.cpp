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
#if 0
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
#endif

void
EvTcpTransportOpts::parse( ConfigTree::Transport &tport,
                           int ptype,  SessionMgr &mgr ) noexcept
{
  bool ipv4, ipv6;
  if ( ! tport.get_route_int( R_TIMEOUT, this->timeout ) )
    this->timeout = mgr.tcp_timeout;
  if ( ! tport.get_route_bool( R_EDGE, this->edge ) )
    this->edge = false;
  if ( ! tport.get_route_bool( R_IPV4ONLY, ipv4 ) )
    ipv4 = mgr.tcp_ipv4;
  if ( ! tport.get_route_bool( R_IPV6ONLY, ipv6 ) )
    ipv6 = mgr.tcp_ipv6;
  if ( ! tport.get_route_bool( R_NOENCRYPT, this->noencrypt ) )
    this->noencrypt = mgr.tcp_noencrypt;
  if ( ! this->noencrypt )
    this->opts |= TCP_OPT_ENCRYPT;
  if ( ipv4 )
    this->opts = ( this->opts & ~OPT_AF_INET6 ) | OPT_AF_INET;
  else if ( ipv4 )
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
  char tmp[ MAX_TCP_HOST_LEN ];
  int  port2 = 0;
  bool is_device = false;

  ConfigTree::StringPairArray el;
  if ( ( ptype & PARAM_LISTEN ) == 0 )
    tport.get_route_pairs( R_CONNECT, el );
  else {
    tport.get_route_pairs( R_LISTEN, el );
    if ( el.count == 0 ) {
      tport.get_route_pairs( R_DEVICE, el );
      is_device = true;
    }
  }
  tport.get_route_int( R_PORT, port2 );
  this->default_port = port2;
  for ( size_t i = 0; i < el.count; i++ ) {
    const char * hostp;
    if ( i < el.count )
      hostp = el[ i ]->value.val;
    else
      hostp = NULL;
    tmp[ 0 ] = '\0';
    size_t len  = sizeof( tmp );
    int    port = tport.get_host_port( hostp, tmp, len );
    if ( port == 0 )
      port = port2;
    if ( tport.is_wildcard( hostp ) )
      hostp = NULL;
    this->hosts.append( hostp, port );
  }
  this->EvTcpTransportOpts::parse( tport, ptype, mgr );
  if ( is_device )
    this->opts |= OPT_NO_DNS;
}


EvTcpTransport::EvTcpTransport( EvPoll &p,  uint8_t t ) noexcept
  : AES_Connection( p, t ), rte( 0 ), /*tport_count( 0 ), not_fd2( 0 ),*/
    timer_id( 0 ), tcp_state( 0 ),
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
  c->start( ++this->timer_id );
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
                               struct addrinfo *addr_list,
                               uint64_t timer_id ) noexcept
{
  if ( this->fd != -1 )
    return false;
  this->is_connect = true;
  if ( EvTcpConnection::connect3( *this, addr_list, opts, "ev_tcp_tport",
                                  this->rte->sub_route.route_id ) != 0 )
    return false;
  this->notify = n;
  this->start( timer_id );
  return true;
}

void
EvTcpTransport::start( uint64_t tid ) noexcept
{
  const char * name;
  if ( this->is_connect )
    name = "tcp_conn";
  else
    name = "tcp_acc";
  this->timer_id  = tid;
  this->tcp_state = 0;
  this->bp_flags  = BP_NOTIFY;
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
  int     flow;

  buflen = this->len - this->off;
  if ( buflen > this->recv_highwater )
    this->tcp_state |= TCP_BUFFERSIZE;
  else
    this->tcp_state &= ~TCP_BUFFERSIZE;
  while ( buflen > 0 ) {
    const char * buf = &this->recv[ off ];
    status = this->msg_in.unpack( buf, buflen );
    if ( status != 0 ) {
      if ( status == Err::BAD_BOUNDS )
        this->recv_need( buflen );
      else {
        MDOutput mout;
        printf( "tcp msg_in status %d buflen %u\n", status, (uint32_t) buflen );
        mout.print_hex( buf, buflen > 256 ? 256 : buflen );
        this->push( EV_CLOSE );
      }
      break;
    }
    this->off += (uint32_t) buflen;
    flow = this->dispatch_msg();
    if ( flow == TCP_FLOW_GOOD )
      this->tcp_state &= ~TCP_BACKPRESSURE;
    else {
      this->tcp_state |= TCP_BACKPRESSURE;
      if ( flow == TCP_FLOW_STALLED ) {
        this->off -= buflen;
        this->pop( EV_PROCESS );
        this->pop3( EV_READ, EV_READ_LO, EV_READ_HI );
        if ( ! this->push_write_high() )
          this->clear_write_buffers();
        return;
      }
    }
    buflen = this->len - this->off;
  }
  this->pop( EV_PROCESS );
  if ( ! this->push_write() )
    this->clear_write_buffers(); 
}

int
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
  BPData * data = NULL;
  if ( ( this->tcp_state & ( TCP_BACKPRESSURE | TCP_BUFFERSIZE ) ) != 0 )
    data = this;
  if ( this->rte->sub_route.forward_not_fd( pub, this->fd, data ) )
    return TCP_FLOW_GOOD;
  if ( ! this->bp_in_list() )
    return TCP_FLOW_BACKPRESSURE;
  return TCP_FLOW_STALLED;
}

bool
EvTcpTransport::timer_expire( uint64_t tid, uint64_t ) noexcept
{
  if ( tid == this->timer_id ) {
    this->tcp_state &= ~TCP_HAS_TIMER;
    this->push( EV_PROCESS );
    this->idle_push( EV_READ_LO );
  }
  return false;
}

void
EvTcpTransport::on_write_ready( void ) noexcept
{
  this->push( EV_PROCESS );
  this->pop2( EV_READ, EV_READ_HI );
  this->idle_push( EV_READ_LO );
}

void
EvTcpTransport::read( void ) noexcept
{
  if ( ! this->bp_in_list() ) {
    this->AES_Connection::read();
    return;
  }
  this->pop3( EV_READ, EV_READ_HI, EV_READ_LO );
}

void
EvTcpTransport::release( void ) noexcept
{
  if ( this->fwd_all_msgs ) {
    uint32_t h = this->rte->sub_route.prefix_seed( 0 );
    this->rte->sub_route.del_pattern_route( h, this->fd, 0 );
  }
  this->msg_in.release();
  if ( ( this->tcp_state & TCP_HAS_TIMER ) != 0 )
    this->poll.timer.remove_timer( this->fd, this->timer_id, 0 );
  if ( this->bp_in_list() )
    this->bp_retire( *this );
  if ( this->encrypt )
    this->AES_Connection::release_aes();
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
  this->EvConnection::release_buffers();
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
  uint32_t idx = 0;
  d_tcp( "> ev_tcp(%s) fwd %.*s (%lu)\n", this->rte->name,
          (int) pub.subject_len, pub.subject, this->msgs_sent + 1 );
  if ( pub.pub_type != 'f' ) {
    if ( pub.msg_len > this->recv_highwater ) {
      idx = this->poll.zero_copy_ref( pub.src_route, pub.msg, pub.msg_len );
      if ( idx != 0 )
        this->append_ref_iov( NULL, 0, pub.msg, pub.msg_len, idx, 0 );
    }
    if ( idx == 0 )
      this->append( pub.msg, pub.msg_len );
  }
  else {
    MsgFragPublish & fpub = (MsgFragPublish &) pub;
    if ( fpub.trail_sz > this->recv_highwater ) {
      idx = this->poll.zero_copy_ref( fpub.src_route, fpub.trail,
                                      fpub.trail_sz );
      if ( idx != 0 )
        this->append_ref_iov( fpub.msg, fpub.msg_len, fpub.trail, fpub.trail_sz,
                              idx, fpub.trail_sz & 1 );
    }
    if ( idx == 0 )
      this->append3( fpub.msg, fpub.msg_len, fpub.trail, fpub.trail_sz,
                     fpub.trail_sz & 1 );
  }
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
