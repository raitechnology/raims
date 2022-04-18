#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#ifndef _MSC_VER
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#else
#include <raikv/win.h>
#endif
#include <raims/ev_inbox_transport.h>
#include <raims/transport.h>
#include <raikv/ev_publish.h>
#include <raimd/md_types.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

bool
EvInboxTransport::listen( const char *ip,  int port ) noexcept
{
  if ( this->EvUdp::listen2( ip, port, DEFAULT_UDP_CONNECT_OPTS,
                             "inbox_listen" ) == 0 ) {
    static kv_atom_uint64_t inbox_timer_id;
    this->timer_id = ( (uint64_t) this->sock_type << 56 ) |
      kv_sync_add( &inbox_timer_id, (uint64_t) 1 );
    this->cur_mono_time = current_monotonic_time_ns();
    this->poll.timer.add_timer_micros( this->fd, 250, this->timer_id, 0 );
    d_ibx( "inbox fd %u (%s)\n", this->fd, this->peer_address.buf );
    return true;
  }
  return false;
}

static void
print_peer( const char *s,  InboxPeer &p ) noexcept
{
  char host[NI_MAXHOST], service[NI_MAXSERV];

  printf( "%s %d.%d src=%x dest=%x out=%u in=%u out_ack=%u, in_ack=%u ",
          s != NULL ? s : ">", p.peer_id, p.dest_peer_id,
          p.src_uid, p.dest_uid, p.out_seqno, p.in_seqno, p.out_ack_seqno,
          p.in_ack_seqno );
  if ( getnameinfo( p.addr, p.addrlen, host, NI_MAXHOST,
                    service, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV) == 0 )
    printf( "%s:%s\n", host, service );
  else
    printf( "no name info\n" );
}

static inline int32_t
seqno_cmp( uint32_t s1,  uint32_t s2 )
{
  return (int32_t) s1 - (int32_t) s2;
}

void
EvInboxTransport::process( void ) noexcept
{
  MDOutput mout;
  while ( this->in_moff < this->in_nmsgs ) {
    uint32_t i   = this->in_moff,
             len = this->in_mhdr[ i ].msg_len;
    iovec  & iov = this->in_mhdr[ i ].msg_hdr.msg_iov[ 0 ];
    InboxPkt * pkt = (InboxPkt *) (void *) iov.iov_base;

    /*mout.print_hex( this->in_mhdr[ i ].msg_hdr.msg_name,
                    this->in_mhdr[ i ].msg_hdr.msg_namelen );*/
    if ( pkt->is_valid( len ) ) {
      uint32_t src_uid      = pkt->dest_uid, /* switch uid endpoints */
               dest_uid     = pkt->src_uid,
               dest_peer_id = pkt->code.ident,
               my_peer_id   = pkt->code.dest_id;
      InboxPeer * p;
      p = this->src.match( src_uid, my_peer_id, dest_peer_id );
      if ( p == NULL ) {
        struct sockaddr * addr    = (struct sockaddr *)
                                    this->in_mhdr[ i ].msg_hdr.msg_name;
        socklen_t         addrlen = (socklen_t)
                                    this->in_mhdr[ i ].msg_hdr.msg_namelen;
        p = this->resolve_src_uid( dest_uid, my_peer_id, dest_peer_id, addr,
                                   addrlen );
      }
      if ( p != NULL ) {
        d_ibx( "%d.%d recv[%s] "
            "d_no %u s_no %u in_no %u src %u dest %u(%d)(%d) p.src %u p.dest %u r %u\n",
            p->peer_id, dest_peer_id, pkt->code.to_str(),
            pkt->dest_seqno, p->out_window_seqno, p->out_ack_seqno,
            pkt->src_seqno, p->in_seqno, src_uid, dest_uid,
            p->src_uid, p->dest_uid, p->resolved()?1:0 );
        /*d_ibx( "recv[%.4s] rcv seqno %u (snd %u)\n",
            (char *) &pkt->code, pkt->src_seqno, pkt->dest_seqno );*/
        if ( ! p->resolved() ) {
          if ( src_uid != NO_UID && p->src_uid == NO_UID )
            this->src.insert( *p, src_uid, src_uid );
          if ( dest_uid != NO_UID && p->dest_uid == NO_UID )
            this->dest.insert( *p, dest_uid );
        }
        bool chg = false;
        if ( seqno_cmp( pkt->dest_seqno, p->out_window_seqno ) > 0 ) {
          p->out_window_seqno = pkt->dest_seqno;
          if ( seqno_cmp( p->out_ack_seqno, p->out_window_seqno ) < 0 )
            p->adjust_send_window();
        }
        if ( seqno_cmp( pkt->dest_seqno, p->out_seqno ) < 0 )
          chg = true;
        if ( seqno_cmp( pkt->src_seqno, p->in_window_seqno ) > 0 ) {
          p->in_window_seqno = pkt->src_seqno;
          chg = true;
        }
        if ( chg )
          this->push_active_window( *p );
        if ( pkt->code.is_data() )
          this->dispatch_msg( *p, *pkt );
      }
      else {
        d_ibx( "0.%u no peer %s (src=%u,dest=%u)\n",
            dest_peer_id, pkt->code.to_str(), src_uid, dest_uid );
      }
    }
    this->in_moff = i + 1;
  }
  this->pop( EV_PROCESS );
  if ( ! this->push_write() ) {
    if ( this->out_nmsgs == 0 )
      this->clear_buffers();
  }
}

void
EvInboxTransport::process_shutdown( void ) noexcept
{
  this->pushpop( EV_CLOSE, EV_SHUTDOWN );
}

void
EvInboxTransport::process_close( void ) noexcept
{
  d_ibx( "close inbox\n" );
}

void
InboxPeer::adjust_send_window( void ) noexcept
{
  while ( ! this->out.is_empty() ) {
    InboxPktElem * el = this->out.hd;
    int32_t diff = seqno_cmp( el->pkt.src_seqno, this->out_window_seqno );
    if ( diff > 0 )
      break;
    this->out.pop_hd();
    el->window.deref_delete();
  }
  this->out_ack_seqno = this->out_window_seqno;
}
/* retransmit packets from the send window */
bool
EvInboxTransport::repair_window( InboxPeer &p ) noexcept
{
  InboxPktElem * el = p.out.tl;
  InboxPktList   rexmit;
  size_t         cnt = 0;
  if ( el == NULL )
    return false;
  uint32_t seqno = el->pkt.src_seqno;
  while ( seqno_cmp( seqno, p.out_window_seqno ) > 0 ) {
    p.out.pop_tl();
    el->pkt.code.set_repair();
    /*el->pkt.src_seqno  = p.out_seqno;*/
    el->pkt.dest_seqno = p.in_seqno;
    d_ibx( "%d.%d rexmit s_no %u d_no %u win %u cnt %" PRId64 "\n",
            el->window.peer.peer_id, el->window.peer.dest_peer_id,
            seqno, p.in_seqno, p.out_window_seqno, cnt );
    rexmit.push_hd( el );
    cnt++;
    if ( p.out.is_empty() ) {
      for (;;) {
        seqno -= 1;
        if ( seqno_cmp( seqno, p.out_window_seqno ) <= 0 )
          break;
        printf( "%d.%d lost s_no %u win %u\n",
                el->window.peer.peer_id, el->window.peer.dest_peer_id,
                seqno, p.out_window_seqno );
      }
      break;
    }
    el = p.out.tl;
    seqno = el->pkt.src_seqno;
  }
  if ( ! rexmit.is_empty() ) {
    el = rexmit.hd;
    this->out.push_tl( rexmit );
    this->out_count += cnt;
    this->repair_count += cnt;
    this->idle_push( EV_WRITE );
    return true;
  }
  return false;
}
/* check ack seqno, if window needs repairing */
bool
EvInboxTransport::check_window( InboxPeer &p ) noexcept
{
  bool b = false;
  /*d_ibx( "check_window( out=%u > out_window=%u )\n",
          p.out_seqno, p.out_window_seqno );*/
  if ( seqno_cmp( p.out_seqno, p.out_window_seqno ) > 0 )
    b = this->repair_window( p );

  if ( seqno_cmp( p.in_seqno, p.in_window_seqno ) < 0 ) {
    p.in_ack_seqno = p.in_window_seqno;
    this->push_active_recv( p );
  }
  return b;
}
/* if packet is next in sequence, deliver it, otherwise add to recv queue */
void
EvInboxTransport::dispatch_msg( InboxPeer &p,  InboxPkt &pkt ) noexcept
{
  InboxPktElem * el;

  this->push_active_recv( p );
  if ( seqno_cmp( p.in_seqno + 1, pkt.src_seqno ) == 0 ) {
    p.in_seqno = pkt.src_seqno;
    this->total_recv_count++;

    if ( ! pkt.code.is_fragment ) {
      /* latest seq, no need to put in recv window */
      this->dispatch_msg2( pkt.msg(), pkt.msg_len );
    }
    else {
      if ( pkt.code.is_rollup )
        this->dispatch_frag_msg( p, &pkt );
      else {
        InboxPktElem *x = p.copy_pkt_to_window( pkt );
        p.frag_list.push_tl( x ); /* out of order, save to recv window */
      }
    }
  }
  else if ( seqno_cmp( p.in_seqno, pkt.src_seqno ) < 0 ) {
    for ( el = p.in.hd; el != NULL; el = el->next ) {
      if ( seqno_cmp( el->pkt.src_seqno, pkt.src_seqno ) >= 0 ) {
        if ( seqno_cmp( el->pkt.src_seqno, pkt.src_seqno ) == 0 ) {
          d_ibx( "%d.%d repeated in pkt %u, before edge\n",
                 p.peer_id, p.dest_peer_id, pkt.src_seqno );
          p.state |= DUP_RECV;
          this->duplicate_count++;
          return;
        }
        break;
      }
    }
    this->total_recv_count++;
    InboxPktElem *x = p.copy_pkt_to_window( pkt );
    p.in.insert_before( x, el ); /* out of order, save to recv window */
  }
  else {
    d_ibx( "%d.%d repeated in pkt %u, consumed %u\n",
           p.peer_id, p.dest_peer_id, pkt.src_seqno, p.in_seqno );
    p.state |= DUP_RECV;
    this->duplicate_count++;
    return;
  }
  /* check if pkt sequences are in order and ready to dispatch */
  while ( ! p.in.is_empty() ) {
    if ( seqno_cmp( p.in_seqno + 1, p.in.hd->pkt.src_seqno ) != 0 )
      break;
    el = p.in.pop_hd();
    p.in_seqno = el->pkt.src_seqno;

    if ( ! el->pkt.code.is_fragment ) {
      this->dispatch_msg2( el->pkt.msg(), el->pkt.msg_len );
      el->window.deref_delete();
    }
    else {
      p.frag_list.push_tl( el );
      if ( el->pkt.code.is_rollup )
        this->dispatch_frag_msg( p, NULL );
    }
  }
}
/* combine fragments and deliver msg */
void
EvInboxTransport::dispatch_frag_msg( InboxPeer &p, InboxPkt *pkt ) noexcept
{
  InboxPktElem * el;
  size_t off = 0;

  for ( el = p.frag_list.hd; el != NULL; el = el->next )
    off += el->pkt.msg_len;
  if ( pkt != NULL )
    off += pkt->msg_len;
  /* merge pkts to a single mem area */
  uint8_t * msg_buf = (uint8_t *) InboxWindow::new_window_mem( p, off ),
          * data    = msg_buf;

  while ( ! p.frag_list.is_empty() ) {
    el = p.frag_list.pop_hd();
    ::memcpy( data, el->pkt.msg(), el->pkt.msg_len );
    data = &data[ el->pkt.msg_len ];
    el->window.deref();
  }
  if ( pkt != NULL )
    ::memcpy( data, pkt->msg(), pkt->msg_len );

  this->dispatch_msg2( msg_buf, off );

  p.window->deref(); /* release msg_buf */
}
/* deliver message */
void
EvInboxTransport::dispatch_msg2( const void *msg,  size_t msg_len ) noexcept
{
  const uint8_t * data = (const uint8_t *) msg;
  size_t          off  = 0;

  for (;;) {
    size_t len = msg_len - off;
    if ( len == 0 )
      return;
    int status = this->msg_in.unpack( &data[ off ], len );
    if ( status != 0 || len == 0 )
      return;
    off += len;

    const char * sub    = this->msg_in.msg->sub;
    uint16_t     sublen = this->msg_in.msg->sublen;
    uint32_t     h      = this->msg_in.msg->subhash;
    this->msgs_recv++;
    MsgFramePublish pub( sub, sublen, this->msg_in.msg, this->fd, h,
                         CABA_TYPE_ID, this->rte, this->rte.sub_route );
    d_ibx( "ibx dispatch( %.*s )\n", (int) pub.subject_len, pub.subject );
    this->rte.sub_route.forward_msg( pub );
  }
}

const char *
InboxCode::to_str( void ) const
{
  if ( this->type == IBX_DATA ) {
    if ( this->is_repair )
      return "Repair";
    if ( this->is_rollup )
      return "Rollup";
    if ( this->is_fragment )
      return "Fragment";
    return "Message";
  }
  if ( this->type == IBX_RACK )
    return "Recv-ack";
  if ( this->type == IBX_SACK )
    return "Send-ack";
  return "Other";
}
/* push send queue to the network */
void
EvInboxTransport::write( void ) noexcept
{
  this->out_mhdr = (struct mmsghdr *) (void *)
    this->alloc_temp( this->out_count * sizeof( struct mmsghdr ) );
  struct iovec * iov = (struct iovec *) (void *)
    this->alloc_temp( this->out_count * sizeof( struct iovec ) );

  size_t i = 0, o;
  for ( o = 0; o < this->out_count; ) {
    if ( this->out.is_empty() )
      break;
    InboxPktElem * el = this->out.pop_hd();
    iov[ i ].iov_base = &el->pkt;
    iov[ i ].iov_len  = el->pkt.msg_len + sizeof( InboxPkt );
    InboxPeer      & p        = el->window.peer;
    struct mmsghdr & oh       = this->out_mhdr[ o ];
    oh.msg_hdr.msg_name       = (void *) p.addr;
    oh.msg_hdr.msg_namelen    = p.addrlen;
    oh.msg_hdr.msg_iov        = &iov[ i++ ];
    oh.msg_hdr.msg_iovlen     = 1;
    oh.msg_hdr.msg_control    = NULL;
    oh.msg_hdr.msg_controllen = 0;
    oh.msg_hdr.msg_flags      = 0;
    oh.msg_len                = 0;
    d_ibx( "%d.%d send[%s] s_no %u r_no %u src %d dest %d\n",
           p.peer_id, p.dest_peer_id, el->pkt.code.to_str(), el->pkt.src_seqno,
           el->pkt.dest_seqno, p.src_uid, p.dest_uid );
    if ( el->pkt.code.is_data() ) {
      this->push_active_send( p );
      p.out.push_tl( el );
    }
    else {
      el->window.deref_delete();
    }
    o++;
  }
  this->out_nmsgs = (uint32_t) o;
  this->out_count = 0;
  if ( this->out_nmsgs > 0 )
    this->EvUdp::write();
  else
    this->pop3( EV_WRITE, EV_WRITE_HI, EV_WRITE_POLL );
}

void
EvInboxTransport::release( void ) noexcept
{
  InboxPeer * p;
  size_t      i;

  this->msg_in.release();
  this->timer_id++;
  this->out_count = 0;

  while ( ! this->out.is_empty() ) {
    InboxPktElem * el = this->out.pop_hd();
    el->window.deref_delete();
  }

  for ( i = 0; i < this->dest.size; i++ ) {
    p = this->dest.ptr[ i ];
    if ( p != NULL ) {
      p->state &= ~RESOLVE_DEST;
      this->dest.ptr[ i ] = NULL;
      this->reset_peer( *p );
      delete p;
    }
  }
  for ( i = 0; i < this->src.size; i++ ) {
    p = this->src.ptr[ i ];
    if ( p != NULL ) {
      this->reset_peer( *p );
      delete p;
    }
  }
  this->src.reset();
  this->dest.reset();
}
/* check send and recv windows for acks and retransmits */
bool
EvInboxTransport::timer_expire( uint64_t tid, uint64_t ) noexcept
{
  if ( tid != this->timer_id )
    return false;
  int ack_cnt = 0;
  this->cur_mono_time = current_monotonic_time_ns();
  if ( debug_ibx ) {
    if ( this->cur_mono_time - this->last_mono_time > 1000000000ULL * 10 ) {
      printf( "duplicate pkt count %" PRIu64 "\n", this->duplicate_count );
      printf( "repair    pkt count %" PRIu64 "\n", this->repair_count );
      printf( "total     pkt sent  %" PRIu64 "\n", this->total_sent_count );
      printf( "total     pkt recv  %" PRIu64 "\n", this->total_recv_count );
      this->last_mono_time = this->cur_mono_time;
    }
  }
  for ( InboxPeer *p = this->active.hd; p != NULL; ) {
    InboxPeer * next    = p->next;
    bool        is_sack = false,
                is_rack = false;

    if ( ( p->state & ACTIVE_WINDOW ) != 0 ) {
      if ( p->window_timer_expire( this->cur_mono_time ) ) {
        if ( ! this->check_window( *p ) )
          p->state &= ~ACTIVE_WINDOW;
      }
    }
    if ( ( p->state & ACTIVE_RECV ) != 0 ) {
      if ( p->recv_timer_expire( this->cur_mono_time ) ) {
        if ( seqno_cmp( p->in_ack_seqno, p->in_seqno ) != 0 ||
             ( p->state & DUP_RECV ) != 0 )
          is_rack = true;
        p->state &= ~( ACTIVE_RECV | DUP_RECV );
      }
    }
    if ( ( p->state & ACTIVE_SEND ) != 0 ) {
      if ( p->send_timer_expire( this->cur_mono_time ) ) {
        if ( seqno_cmp( p->out_ack_seqno, p->out_seqno ) != 0 )
          is_sack = true;
        else
          p->state &= ~ACTIVE_SEND;
      }
    }
    if ( is_rack || is_sack ) {
      InboxPktElem * el = p->alloc_window( 0 );
      if ( is_rack )
        el->pkt.code.set_rack( p->peer_id, p->dest_peer_id );
      else
        el->pkt.code.set_sack( p->peer_id, p->dest_peer_id );
      el->pkt.src_uid    = p->src_uid;
      el->pkt.dest_uid   = p->dest_uid;
      el->pkt.src_seqno  = p->out_seqno;
      el->pkt.dest_seqno = p->in_seqno;
      el->pkt.msg_len    = 0;
      this->out.push_tl( el );
      this->out_count++;
      /*print_peer( "active ack", *p );*/
      p->in_ack_seqno = p->in_seqno;
      ack_cnt++;
    }
    if ( ( p->state & ACTIVE ) == 0 )
      p->pop_active( this->active );
    p = next;
  }
  if ( ack_cnt > 0 )
    this->idle_push( EV_WRITE );
  return true;
}
/* find the destination peer and add to send queue */
bool
EvInboxTransport::on_msg( kv::EvPublish &pub ) noexcept
{
  if ( pub.pub_type == 'I' ) {
    InboxPublish & ipub = (InboxPublish &) pub;
    InboxPeer    * p;

    d_ibx( "on_msg( %.*s ) -> %u (%s)\n", (int) ipub.subject_len, ipub.subject,
            ipub.peer_uid, ipub.peer_url );
    this->msgs_sent++;
    if ( (p = this->src.match( ipub.peer_uid, 0, 0 )) != NULL ) {
      if ( p->url_hash != ipub.url_hash ) {
        d_ibx( "resolve url_hash %x (!= %x)\n", ipub.url_hash, p->url_hash );
        if ( p->url_hash == 0 )
          p->url_hash = ipub.url_hash;
        else if ( ! this->reassign_peer( *p, ipub.peer_uid, ipub.peer_url,
                                         ipub.url_hash ) )
          return true;
      }
      else {
        d_ibx( "resolved peer_uid %u\n", ipub.peer_uid );
      }
    }
    else {
      d_ibx( "resolve url %u -> %s\n", ipub.peer_uid, ipub.peer_url );
      p = this->resolve_dest_url( ipub.peer_uid, ipub.peer_url, ipub.url_hash );
    }
    if ( p == NULL ) {
      fprintf( stderr, "unable to resolve peer: %s\n", ipub.peer_url );
      return true;
    }
    this->post_msg( *p, pub.msg, pub.msg_len );
    this->idle_push( EV_WRITE );
  }
  else {
    d_ibx( "ignoring on_msg( %.*s ), type '%c'\n",
             (int) pub.subject_len, pub.subject, pub.pub_type );
  }
  return true;
}

void
EvInboxTransport::shutdown_peer( uint32_t peer_uid, uint32_t url_hash ) noexcept
{
  InboxPeer *p;
  d_ibx( "shutdown_peer( %u, %x )\n", peer_uid, url_hash );
  if ( (p = this->src.match( peer_uid, 0, 0 )) != NULL &&
       p->url_hash == url_hash ) {
    this->reset_peer( *p );
  }
}

/* add to send window at the next sequence */
void
EvInboxTransport::post_msg( InboxPeer &p,  const void *msg,
                            uint32_t msg_len ) noexcept
{
  static const size_t max_payload = this->mtu - sizeof( InboxPktElem );
  InboxPktElem * el;

  if ( msg_len <= max_payload ) {
    el = p.alloc_window( msg_len );
    el->pkt.code.set_message( p.peer_id, p.dest_peer_id );
    el->pkt.src_uid    = p.src_uid;
    el->pkt.dest_uid   = p.dest_uid;
    el->pkt.src_seqno  = ++p.out_seqno;
    el->pkt.dest_seqno = p.in_seqno;
    el->pkt.msg_len    = msg_len;
    ::memcpy( el->pkt.msg(), msg, msg_len );

    this->out.push_tl( el );
    this->out_count++;
    this->total_sent_count++;
    return;
  }
  const uint8_t * msg_ptr = (const uint8_t *) msg;
  
  bool is_last = false;
  for ( size_t off = 0; ! is_last; off += max_payload ) {
    size_t  frag_size = max_payload;
    if ( off + max_payload >= msg_len ) {
      frag_size = msg_len - off;
      is_last = true;
    }
    el = p.alloc_window( (uint32_t) frag_size );
    el->pkt.code.set_message( p.peer_id, p.dest_peer_id );
    el->pkt.src_uid    = p.src_uid;
    el->pkt.dest_uid   = p.dest_uid;
    el->pkt.src_seqno  = ++p.out_seqno;
    el->pkt.dest_seqno = p.in_seqno;
    el->pkt.msg_len    = (uint32_t) frag_size;
    if ( ! is_last )
      el->pkt.code.set_fragment();
    else
      el->pkt.code.set_rollup();
    ::memcpy( el->pkt.msg(), msg_ptr, frag_size );
    msg_ptr = &msg_ptr[ frag_size ];
    this->out.push_tl( el );
    this->out_count++;
    this->total_sent_count++;
  }
}

void *
InboxWindow::new_window_mem( InboxPeer &p,  size_t len ) noexcept
{
  InboxWindow *w = p.window;
  for (;;) {
    if ( w == NULL ) {
      size_t wsize = WBUF_SIZE;
      if ( len > WBUF_SIZE )
        wsize = SendWindow::align( len );
      w = new ( ::malloc( sizeof( InboxWindow ) + wsize ) ) /* more space */
          InboxWindow( p, wsize );
      p.window = w;
      break;
    }
    if ( w->fits_deref( len ) ) /* if fits, otherwise deref window */
      break;
    w = NULL;
  }
  return w->alloc( len ); /* return ptr to packet space */
};

InboxPktElem *
InboxPeer::alloc_window( uint32_t msg_len ) noexcept
{
  size_t len = sizeof( InboxPktElem ) + msg_len;
  return new ( InboxWindow::new_window_mem( *this, len ) )
         InboxPktElem( *this->window );
}

InboxPktElem *
InboxPeer::copy_pkt_to_window( const InboxPkt &pkt ) noexcept
{
  InboxPktElem * el = this->alloc_window( pkt.msg_len );
  el->pkt = pkt;
  ::memcpy( el->pkt.msg(), pkt.msg(), pkt.msg_len );
  return el;
}
/* insert peer into array */
bool
InboxPeerArray::insert( InboxPeer &p,  uint32_t idx,  uint32_t uid ) noexcept
{
  bool b = true;
  if ( idx >= this->size )
    this->make( idx + 1, true );

  if ( this->ptr[ idx ] != NULL ) {
    if ( this->ptr[ idx ] != &p ) {
      print_peer( "recylce", *this->ptr[ idx ] );
      b = false;
    }
  }
  this->ptr[ idx ] = &p;
  p.state |= this->state;
  if ( this->state == RESOLVE_SRC )
    p.src_uid = uid;
  else /* state == RESOLVE_DEST */
    p.dest_uid = uid;
  /*print_peer( "insert", p );*/
  return b;
}
/* find peer by address */
InboxPeer *
InboxPeerArray::resolve( const struct sockaddr *addr,
                         uint32_t addrlen ) noexcept
{
  for ( size_t i = this->size; i != 0; ) {
    if ( this->ptr[ --i ] != NULL &&
         ! this->ptr[ i ]->resolved() &&
         this->ptr[ i ]->match_addr( addr, addrlen ) ) {
      return this->ptr[ i ];
    }
  }
  return NULL;
}
/* find by (source) uid and address */
InboxPeer *
InboxSrcArray::resolve2( const struct sockaddr *addr,
                         uint32_t addrlen,  uint32_t uid ) noexcept
{
  InboxPeer *p = this->match( uid, 0, 0 );
  if ( p != NULL && p->match_addr( addr, addrlen ) )
    return p;
  return NULL;
}

InboxPeer *
InboxDestArray::resolve2( const struct sockaddr *addr,
                          uint32_t addrlen,  uint32_t uid ) noexcept
{
  InboxPeer *p = NULL;
  for ( size_t i = 0; i < this->size; i++ ) {
    if ( this->ptr[ i ] != NULL &&
         this->ptr[ i ]->dest_uid == uid ) {
      p = this->ptr[ i ];
      if ( p->match_addr( addr, addrlen ) )
        return p;
    }
  }
  return NULL;
}
/* drop peer */
void
InboxDestArray::remove( InboxPeer &p ) noexcept
{
  for ( size_t i = 0; i < this->size; i++ ) {
    if ( this->ptr[ i ] == &p ) {
      p.state &= ~RESOLVE_DEST;
      this->ptr[ i ] = NULL;
      return;
    }
  }
}
/* add peer to dest */
void
InboxDestArray::insert( InboxPeer &p,  uint32_t dest_uid ) noexcept
{
  this->InboxPeerArray::insert( p, (uint32_t) this->size, dest_uid );
}

InboxPeer *
EvInboxTransport::alloc_peer( struct sockaddr *addr, uint32_t addrlen,
                              uint32_t url_hash ) noexcept
{
  size_t peer_len = sizeof( InboxPeer ) + 64;
  if ( addrlen > 64 ) {
    peer_len += addrlen - 64;
    fprintf( stderr, "warning, inbox peer addrlen is %u > 64\n", addrlen );
  }
  void *m = ::malloc( peer_len );
  struct sockaddr * a = (struct sockaddr *) (void *)
                        &((uint8_t *) m)[ sizeof( InboxPeer ) ];
  uint32_t ident = this->id++ % IBX_IDENT_MAX;
  if ( ident == 0 ) ident = this->id++ % IBX_IDENT_MAX;
  ::memcpy( a, addr, addrlen );
  return new ( m ) InboxPeer( a, addrlen, ident, url_hash );
}

/* find peer by source uid, which uniquely identifies peer */
InboxPeer *
EvInboxTransport::resolve_src_uid( uint32_t dest_uid,  uint32_t my_peer_id,
                                   uint32_t dest_peer_id, struct sockaddr *addr,
                                   uint32_t addrlen ) noexcept
{
  InboxPeer * p = this->src.resolve( addr, addrlen );
  bool reset = false;
  if ( p == NULL )
    p = this->dest.resolve2( addr, addrlen, dest_uid );
  if ( p == NULL ) {
    p = this->alloc_peer( addr, addrlen, 0 );
    p->dest_peer_id = dest_peer_id;
    printf( "%d.%d New SRC dest_uid=%u ", p->peer_id, dest_peer_id, dest_uid );
    print_peer( NULL, *p );
  }
  if ( p->dest_uid != dest_uid )
    reset = true;
  else if ( my_peer_id != 0 && my_peer_id != p->peer_id )
    reset = true;
  if ( ! reset ) {
    if ( p->dest_peer_id == 0 )
      p->dest_peer_id = dest_peer_id;
    else if ( p->dest_peer_id != dest_peer_id )
      reset = true;
  }
  if ( reset ) {
    if ( p->dest_uid != NO_UID ) {
      printf( "%u.x Reset SRC dest_uid=%u dest_peer_id=%u != %u ", p->peer_id,
              p->dest_uid, p->dest_peer_id, dest_peer_id );
      this->reset_peer( *p );
    }
    p->dest_peer_id = dest_peer_id;
    this->dest.insert( *p, dest_uid );
  }
  return p;
}
/* find peer by destination */
InboxPeer *
EvInboxTransport::resolve_dest_uid( uint32_t src_uid,  struct sockaddr *addr,
                                    uint32_t addrlen,
                                    uint32_t url_hash ) noexcept
{
  InboxPeer * p = this->dest.resolve( addr, addrlen );
  if ( p == NULL )
    p = this->src.resolve2( addr, addrlen, src_uid );
  if ( p == NULL ) {
    p = this->alloc_peer( addr, addrlen, url_hash );
    printf( "%u.x New DEST src_uid=%u ", p->peer_id, src_uid );
    print_peer( NULL, *p );
  }
  if ( p->src_uid != src_uid ) {
    if ( p->src_uid != NO_UID ) {
      printf( "%u.x Reset DEST src_uid=%u != %u ", p->peer_id, p->src_uid,
              src_uid );
      this->reset_peer( *p );
    }
    this->src.insert( *p, src_uid, src_uid );
  }
  if ( p->url_hash == 0 )
    p->url_hash = url_hash;
  return p;
}
bool
EvInboxTransport::reassign_peer( InboxPeer &p,  uint32_t src_uid,
                                 const char *url,  uint32_t url_hash ) noexcept
{
  struct addrinfo * a  = NULL,
                  * ai = this->url_to_addrinfo( url, a );

  if ( ai == NULL || a == NULL ) {
    fprintf( stderr, "unable to resolve peer: %s\n", url );
    if ( ai != NULL )
      ::freeaddrinfo( ai );
    return false;
  }
  this->reset_peer( p );
  this->src.insert( p, src_uid, src_uid );
  ::memcpy( (void *) p.addr, a->ai_addr, a->ai_addrlen );
  p.url_hash = url_hash;
  ::freeaddrinfo( ai );
  printf( "%u.x Reassign DEST src_uid=%u ", p.peer_id, src_uid );
  print_peer( NULL, p );
  return true;
}

/* reset peer state */
void
EvInboxTransport::reset_peer( InboxPeer & p ) noexcept
{
  print_peer( "reset_peer", p );
  if ( ( p.state & ACTIVE ) != 0 )
    p.pop_active( this->active );
  if ( p.dest_uid != NO_UID ) {
    this->dest.remove( p );
    p.dest_uid = NO_UID;
  }
  if ( p.src_uid != NO_UID ) {
    this->src.remove( p );
    p.src_uid = NO_UID;
  }
  p.reset();
}
/* free peer send and recv windows */
void
InboxPeer::reset( void ) noexcept
{
  InboxPktElem * el;
  while ( ! this->out.is_empty() ) {
    el = this->out.pop_hd();
    el->window.deref_delete();
  }
  while ( ! this->in.is_empty() ) {
    el = this->in.pop_hd();
    el->window.deref_delete();
  }
  while ( ! this->frag_list.is_empty() ) {
    el = this->frag_list.pop_hd();
    el->window.deref_delete();
  }
  this->zero();
}
/* convert a url into a destination and index by uid */
InboxPeer *
EvInboxTransport::resolve_dest_url( uint32_t src_uid, const char *url,
                                    uint32_t url_hash ) noexcept
{
  d_ibx( "getaddrinfo( %s ) -> %u\n", url, src_uid );
  struct addrinfo * a  = NULL,
                  * ai = this->url_to_addrinfo( url, a );
  InboxPeer       * p  = NULL;

  if ( ai == NULL )
    return NULL;
  if ( a != NULL )
    p = this->resolve_dest_uid( src_uid, a->ai_addr, (uint32_t) a->ai_addrlen,
                                url_hash );
  ::freeaddrinfo( ai );
  return p;
}

struct addrinfo *
EvInboxTransport::url_to_addrinfo( const char *url,
                                   struct addrinfo *&a ) noexcept
{
  const char * port;
  char         ip[ 1024 ];

  if ( ::strncmp( url, "inbox://", 8 ) != 0 )
    return NULL;

  url = &url[ 8 ];
  if ( (port = ::strrchr( url, ':' )) == NULL ||
       (size_t) ( port - url ) >= sizeof( ip ) )
    return NULL;

  ::memcpy( ip, url, port - url );
  ip[ port - url ] = '\0';

  struct addrinfo hints, * ai = NULL;

  ::memset( &hints, 0, sizeof( struct addrinfo ) );
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags    = AI_PASSIVE;
  hints.ai_family   = AF_UNSPEC;
  if ( ::getaddrinfo( ip, port + 1, &hints, &ai ) != 0 ) {
    perror( "getaddrinfo" );
    return NULL;
  }
  /* try inet6 first, since it can listen to both ip stacks */
  for ( a = ai; a != NULL; a = a->ai_next )
    if ( a->ai_family == AF_INET6 )
      return ai;
  for ( a = ai; a != NULL; a = a->ai_next )
    if ( a->ai_family == AF_INET )
      return ai;
  fprintf( stderr, "no addrinfo for url %s\n", url );
  ::freeaddrinfo( ai );
  return NULL;
}

