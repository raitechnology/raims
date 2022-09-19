#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/ev_pgm_transport.h>
#include <raims/session.h>
#include <raims/transport.h>
#include <raikv/ev_publish.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

EvPgmTransport::EvPgmTransport( EvPoll &p,  TransportRoute &r ) noexcept
    : EvSocket( p, p.register_type( "pgm" ) ), rte( r ),
      recv_highwater( 15 * 1024 ), send_highwater( 31 * 1024 ),
      stats_timer( 0 ), notify( 0 ), backpressure( false ),
      fwd_all_msgs( false )
{
  static kv_atom_uint64_t pgm_timer_id;
  this->sock_opts = OPT_NO_CLOSE;
  this->timer_id = ( (uint64_t) this->sock_type << 56 ) |
    kv_sync_add( &pgm_timer_id, (uint64_t) 1 );
}

bool
EvPgmTransport::connect( EvPgmTransportParameters &p,
                         EvConnectionNotify *n ) noexcept
{
  const char * net  = ";239.192.0.1";
  uint16_t     port = 7239;
  this->notify         = n;
  this->pgm.mtu        = p.mtu;
  this->pgm.txw_sqns   = p.txw_sqns;
  this->pgm.rxw_sqns   = p.rxw_sqns;
  this->pgm.txw_secs   = p.txw_secs;
  this->pgm.mcast_loop = p.mcast_loop;
  if ( this->pgm.mcast_loop )
    this->pgm.mcast_loop = 2;
  if ( p.port != 0 )
    port = p.port;
  if ( p.network != NULL )
    net = p.network;
  if ( ! this->pgm.start_pgm( net, port, this->fd ) )
    return false;
  this->PeerData::init_peer( this->fd, this->rte.sub_route.route_id,
                             NULL, "pgm" );
  char peer[ 256 ];
  ::snprintf( peer, sizeof( peer ), "%s:%u", p.network, p.port );
  this->PeerData::set_peer_address( peer, ::strlen( peer ) );
  if ( this->poll.add_sock( this ) < 0 ) {
    fprintf( stderr, "failed to add sock %d\n", this->fd );
    return false;
  }
  this->rte.set_peer_name( *this, "pgm" );
  d_pgm( "pgm fd %u\n", this->fd );
  this->start();
  return true;
}

void
EvPgmTransport::start( void ) noexcept
{
  if ( this->fwd_all_msgs ) {
    uint32_t h = this->rte.sub_route.prefix_seed( 0 );
    this->rte.sub_route.add_pattern_route( h, this->fd, 0 );
  }
  this->poll.timer.add_timer_micros( this->fd,
                                     this->pgm.heartbeat_spm[ 0 ] / 4,
                                     this->timer_id, 0 );
  if ( this->notify != NULL )
    this->notify->on_connect( *this );
}

bool
EvPgmTransport::on_msg( EvPublish &pub ) noexcept
{
  if ( pub.src_route == (uint32_t) this->fd )
    return true;
  d_pgm( "pgm on_msg( %.*s )\n", (int) pub.subject_len, pub.subject );
  this->msgs_sent++;
  this->bytes_sent += pub.msg_len;
  if ( pub.msg_len <= this->pgm.geom.max_tsdu ) {
    this->pgm.put_send_window( pub.msg, pub.msg_len );
  }
  else {
    const uint8_t * msg       = (const uint8_t *) pub.msg;
    size_t          frag_size = this->pgm.geom.max_tsdu - sizeof( FragTrailer );
    FragTrailer     trl( this->pgm.my_tsi(), current_realtime_ns(),
                         pub.msg_len );
    for ( trl.off = 0; trl.off < pub.msg_len;
          trl.off += (uint32_t) frag_size ) {
      if ( trl.off + frag_size > pub.msg_len )
        frag_size = pub.msg_len - trl.off;
      this->pgm.put_send_window( msg, frag_size, &trl, sizeof( FragTrailer ) );
      msg = &msg[ frag_size ];
    }
  }
  bool flow_good = ( this->pgm.pending <= this->send_highwater );
  this->idle_push( flow_good ? EV_WRITE : EV_WRITE_HI );
  return flow_good;
}
/* send the messages queued */
void
EvPgmTransport::write( void ) noexcept
{
  if ( this->pgm.push_send_window() ) {
    this->pop3( EV_WRITE, EV_WRITE_HI, EV_WRITE_POLL );
    this->push( EV_READ_LO );
  }
}
/* recv_msgs then process */
void
EvPgmTransport::read( void ) noexcept
{
  if ( this->pgm.recv_msgs() ) {
    this->push( EV_PROCESS );
    this->pushpop( EV_READ_LO, EV_READ );
    return;
  }
  this->pop3( EV_READ, EV_READ_HI, EV_READ_LO );
}

void
EvPgmTransport::process( void ) noexcept
{
  this->backpressure = false;
  if ( this->pgm.len > 0 ) {
    size_t nbytes = 0;
    for ( uint32_t i = 0; i < PgmSock::MSG_VEC_SIZE; i++ ) {
      /* may need to unfragment these */
      for ( uint32_t j = 0; j < this->pgm.msgv[ i ].msgv_len; j++ ) {
        const struct pgm_sk_buff_t* pskb = this->pgm.msgv[ i ].msgv_skb[ j ];
        uint8_t * data = (uint8_t *) pskb->data;

        if ( ! this->frag_list.is_empty() ||
             FragTrailer::is_trailer( data, pskb->len ) ) {
          this->process_fragment( data, pskb->len );
        }
        else {
          this->dispatch_data( data, 0, pskb->len );
        }
        nbytes += pskb->len;
        if ( nbytes == this->pgm.len ) {
          this->pgm.len = 0;
          goto break_loop;
        }
      }
    }
  }
break_loop:;
  if ( this->pgm.pending > 0 ) {
    /* if need to write right now, push high and move read to low */
    if ( this->backpressure || this->pgm.pending > this->send_highwater ) {
      this->pushpop( EV_WRITE_HI, EV_WRITE );
      if ( this->test( EV_READ ) )
        this->pushpop( EV_READ_LO, EV_READ );
    }
    /* normal write condition */
    else {
      this->push( EV_WRITE );
    }
  }
  /* done processing this batch */
  this->pop( EV_PROCESS );
}

void
EvPgmTransport::process_fragment( const uint8_t *data,  size_t len ) noexcept
{
  Fragment * frag;
  /* possible to have a message after the end of a fragment */
  for ( frag = this->frag_list.hd; frag != NULL; frag = frag->next ) {
    size_t end_frag = frag->left + sizeof( FragTrailer );
    if ( len >= end_frag ) {
      FragTrailer trl( data, end_frag );
      if ( frag->merge( trl, data, frag->left ) ) {
        this->dispatch_data( frag->msg_ptr(), 0, frag->msg_len );
        this->frag_list.pop( frag );
        delete frag;
        if ( end_frag < len )
          this->dispatch_data( data, end_frag, len );
        return;
      }
    }
  }
  /* only whole fragments here */
  if ( FragTrailer::is_trailer( data, len ) ) {
    FragTrailer trl( data, len );
    size_t      datalen = len - sizeof( FragTrailer );

    if ( trl.is_first_fragment( datalen ) ) {
      void * p = ::malloc( sizeof( Fragment ) + trl.msg_len );
      this->frag_list.push_tl( new ( p ) Fragment( trl, data, datalen ) );
      return;
    }
    for ( frag = this->frag_list.hd; frag != NULL; frag = frag->next ) {
      if ( frag->merge( trl, data, datalen ) )
        return;
    }
  }
  /* no frags, normal data */
  this->dispatch_data( data, 0, len );
}

void
EvPgmTransport::dispatch_data( const uint8_t *data,  size_t off,
                               size_t len ) noexcept
{
  while ( off < len ) {
    size_t          buflen = len - off;
    const uint8_t * buf = &data[ off ];
    int             status = this->msg_in.unpack( buf, buflen );
    off += buflen;
    if ( status != 0 ) {
      MDOutput mout;
      printf( "pgm msg_in status %d buflen %u\n", status, (uint32_t) buflen );
      mout.print_hex( buf, buflen > 256 ? 256 : buflen );
    }
    if ( buflen == 0 )
      return;
    this->msgs_recv++;
    this->bytes_recv += buflen;
    this->dispatch_msg();
  }
}

void
EvPgmTransport::dispatch_msg( void ) noexcept
{
  const char * sub    = this->msg_in.msg->sub;
  uint16_t     sublen = this->msg_in.msg->sublen;
  uint32_t     h      = this->msg_in.msg->subhash;
  MsgFramePublish pub( sub, sublen, this->msg_in.msg, this->fd, h,
                       CABA_TYPE_ID, this->rte, this->rte.sub_route );
  d_pgm( "pgm dispatch( %.*s )\n", (int) pub.subject_len, pub.subject );
  this->backpressure = this->rte.sub_route.forward_not_fd( pub, this->fd );
}

/* shutdown pgm */
void
EvPgmTransport::process_shutdown( void ) noexcept
{
  this->pushpop( EV_CLOSE, EV_SHUTDOWN );
}

void
EvPgmTransport::process_close( void ) noexcept
{
  d_pgm( "pgm close\n" );
  this->client_stats( this->rte.sub_route.peer_stats );
  this->pgm.close_pgm();
  this->EvSocket::process_close();
}

void
EvPgmTransport::release( void ) noexcept
{
  this->pgm.release();
  this->msg_in.release();
  while ( ! this->frag_list.is_empty() ) {
    Fragment * frag = this->frag_list.pop_hd();
    delete frag;
  }
  this->backpressure = false;
  this->msgs_sent    = 0;
  this->bytes_sent   = 0;
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
}
/* timer based events, poll for new messages, send heartbeats,
 * check for session timeouts  */
bool
EvPgmTransport::timer_expire( uint64_t tid,  uint64_t ) noexcept
{
  if ( tid != this->timer_id )
    return false;
  this->idle_push( EV_READ_LO );
  if ( this->pgm.lost_count > 0 )
    this->pgm.print_lost();
  if ( debug_pgm ) {
    uint64_t now = this->poll.current_coarse_ns();
    if ( this->stats_timer < now ) {
      static const uint64_t NS = 1000 * 1000 * 1000;
      this->stats_timer = now + NS;
      this->pgm.print_stats();
    }
  }
  return true;
}
