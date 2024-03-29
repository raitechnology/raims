#include <stdio.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <raims/pgm_sock.h>
#else
#include <raims/pgm_sock.h>
#include <raikv/win.h>
#endif
#include <raims/debug.h>
#include <raikv/util.h>

using namespace rai;
using namespace ms;
using namespace kv;

PgmSock::PgmSock() noexcept
    : sock          ( 0 ),
      timeout_usecs ( 0 ),
      len           ( 0 ),
      skb_count     ( 0 ),
      txw_sqns      ( 4 * 1024 ),
      pending       ( 0 ),
      lost_tstamp   ( 0 ),
      lost_count    ( 0 ),
      pgm_err       ( 0 ),
      res           ( 0 ),
      mtu           ( 16 * 1024 ),
      rxw_sqns      ( 4 * 1024 ),
      txw_secs      ( 60 ),
      ambient_spm   ( pgm_secs( 5 ) ),
      peer_expiry   ( pgm_secs( 60 ) ),
      spmr_expiry   ( pgm_msecs( 100 ) ),
      nak_bo_ivl    ( pgm_msecs( 50 ) ),
      nak_rpt_ivl   ( pgm_msecs( 200 ) ),
      nak_rdata_ivl ( pgm_msecs( 500 ) ),
      nak_data_retry( 10 ),
      nak_ncf_retry ( 10 ),
      mcast_loop    ( 0 ),
      mcast_hops    ( 16 ),
      status        ( 0 ),
      is_connected  ( false )
{
  int hb_spm[ 9 ] =
    { pgm_msecs( 10 ),  pgm_msecs( 100 ),  pgm_msecs( 250 ),
      pgm_msecs( 500 ), pgm_secs( 1 ),     pgm_secs( 2 ),
      pgm_secs( 4 ),    pgm_secs( 7 ),     pgm_secs( 10 ) };
  ::memset( &this->my_addr, 0, sizeof( this->my_addr ) );
  ::memset( &this->lost_tsi, 0, sizeof( this->lost_tsi ) );
  ::memcpy( this->heartbeat_spm, hb_spm, sizeof( hb_spm ) );
  ::memset( this->src_stats, 0, sizeof( this->src_stats ) );
  ::memset( this->recv_stats, 0, sizeof( this->recv_stats ) );
  this->gsr_addr[ 0 ] = '\0';
}
/* extract the recv ip addr into gsr_addr */
bool
PgmSock::find_gsr_addr( void ) noexcept
{
  char   text[ 1024 ];
  char * s,
       * e;
  if ( this->res->ai_recv_addrs_len == 0 )
    return false;
  pgm_gsr_to_string( &this->res->ai_recv_addrs[ 0 ], text, sizeof( text ) );
  if ( (s = ::strstr( text, "gsr_addr = \"" )) == NULL )
    return false;
  s += 12;
  if ( (e = ::strchr( s, '\"' )) == NULL )
    return false;
  if ( (size_t) ( e - s ) >= sizeof( this->gsr_addr ) )
    return false;
  ::memcpy( this->gsr_addr, s, e - s );
  this->gsr_addr[ e - s ] = '\0';
  return true;
}
/* setup the pgm socket */
bool
PgmSock::start_pgm( const char *network,  int svc,  int &fd ) noexcept
{
  this->status = 0;
  if ( this->pgm_err != NULL ) {
    pgm_error_free( this->pgm_err );
    this->pgm_err = NULL;
  }
  if ( this->res != NULL ) {
    pgm_freeaddrinfo( this->res );
    this->res = NULL;
  }
  if ( ! pgm_init( &this->pgm_err ) ) {
    this->status = 1;
    return false;
  }
  if ( ! pgm_getaddrinfo( network, NULL, &this->res, &this->pgm_err ) ) {
    fprintf( stderr, "parsing network \"%s\": %s\n", network,
             this->pgm_err->message );
    this->status = 2;
    return false;
  }
  char addrs[ 2 * 1024 ];
  pgm_addrinfo_to_string( res, addrs, sizeof( addrs ) );
  printf( "%s\n", addrs );
  this->find_gsr_addr();
  sa_family_t sa_family = this->res->ai_send_addrs[ 0 ].gsr_group.ss_family;
  if ( ! pgm_socket( &this->sock, sa_family, SOCK_SEQPACKET, IPPROTO_UDP,
                     &this->pgm_err ) ) {
    fprintf( stderr, "socket: %s\n", this->pgm_err->message );
    this->status = 3;
    return false;
  }
  bool b;
  b = pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_UDP_ENCAP_UCAST_PORT,
                      &svc, sizeof( svc ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_UDP_ENCAP_MCAST_PORT,
                      &svc, sizeof( svc ) );

  int is_uncontrolled = 1; /* uncontrolled odata, rdata */

  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_MTU, &this->mtu,
                      sizeof( this->mtu ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_UNCONTROLLED_ODATA,
                      &is_uncontrolled, sizeof( is_uncontrolled ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_UNCONTROLLED_RDATA,
                      &is_uncontrolled, sizeof( is_uncontrolled ) );
  int txw_secs = (int) this->txw_secs;
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_TXW_SECS, &txw_secs,
                      sizeof( txw_secs ) );
  int txw_size = (int) this->txw_sqns;
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_TXW_SQNS, &txw_size,
                      sizeof( txw_size ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_AMBIENT_SPM,
                      &this->ambient_spm, sizeof( this->ambient_spm ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_HEARTBEAT_SPM,
                      this->heartbeat_spm, sizeof( this->heartbeat_spm ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_RXW_SQNS, &this->rxw_sqns,
                      sizeof( this->rxw_sqns ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_PEER_EXPIRY,
                      &this->peer_expiry, sizeof( this->peer_expiry ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_SPMR_EXPIRY,
                      &this->spmr_expiry, sizeof( this->spmr_expiry ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_NAK_BO_IVL,
                      &this->nak_bo_ivl, sizeof( this->nak_bo_ivl ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_NAK_RPT_IVL,
                      &this->nak_rpt_ivl, sizeof( this->nak_rpt_ivl ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_NAK_RDATA_IVL,
                      &this->nak_rdata_ivl, sizeof( this->nak_rdata_ivl ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_NAK_DATA_RETRIES,
                      &this->nak_data_retry, sizeof( this->nak_data_retry ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_NAK_NCF_RETRIES,
                      &this->nak_ncf_retry, sizeof( this->nak_ncf_retry ) );
  uint32_t rcvbufsz = 16 * 1024 *
             ( this->rxw_sqns < 1024 ? this->rxw_sqns : 1024 );
  b&= pgm_setsockopt( this->sock, SOL_SOCKET, SO_RCVBUF,
                      &rcvbufsz, sizeof( rcvbufsz ) );
#if 0
  const struct pgm_fecinfo_t fecinfo = { .block_size              = 255,
                                         .proactive_packets       = 16,
                                         .group_size              = 64,
                                         .ondemand_parity_enabled = true,
                                         .var_pktlen_enabled      = true };
  b &= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_USE_FEC,
                       &fecinfo, sizeof( fecinfo ) );
#endif
  if ( !b ) {
    this->status = 4;
    return false;
  }
  /* create global session identifier */
  struct pgm_sockaddr_t & addr = this->my_addr;
  memset( &addr, 0, sizeof( addr ) );
  addr.sa_port       = svc;
  addr.sa_addr.sport = DEFAULT_DATA_SOURCE_PORT;
  rand::fill_urandom_bytes( &addr.sa_addr.gsi, sizeof( addr.sa_addr.gsi ) );
#if 0
  if ( ! pgm_gsi_create_from_hostname( &addr.sa_addr.gsi, &this->pgm_err ) ) {
    fprintf( stderr, "creating GSI: %s\n", this->pgm_err->message );
    this->status = 5;
    return false;
  }
#endif
  /* assign socket to specified address */
  struct pgm_interface_req_t if_req;
  memset( &if_req, 0, sizeof( if_req ) );
  if_req.ir_interface = this->res->ai_recv_addrs[ 0 ].gsr_interface;
  if_req.ir_scope_id  = 0;
  if ( AF_INET6 == sa_family ) {
    struct sockaddr_in6 sa6;
    memcpy( &sa6, &this->res->ai_recv_addrs[ 0 ].gsr_group, sizeof( sa6 ) );
    if_req.ir_scope_id = sa6.sin6_scope_id;
  }
  if ( ! pgm_bind3( this->sock, &addr, sizeof( addr ), &if_req,
                    sizeof( if_req ),          /* tx interface */
                    &if_req, sizeof( if_req ), /* rx interface */
                    &this->pgm_err ) ) {
    fprintf( stderr, "binding PGM socket: %s\n", this->pgm_err->message );
    this->status = 6;
    return false;
  }
  socklen_t addrlen = sizeof( this->my_addr );
  uint32_t  i;
  if ( pgm_getsockname( this->sock, &this->my_addr, &addrlen ) ) {
    if ( debug_pgm ) {
      printf( "sockname: [" );
      for ( i = 0; i < sizeof( this->my_addr.sa_addr.gsi.identifier ); i++ )
        printf( "%02x", this->my_addr.sa_addr.gsi.identifier[ i ] );
      printf( "]:%u:%u\n", ntohs( this->my_addr.sa_addr.sport ),
                        ntohs( this->my_addr.sa_port ) );
    }
  }
  /* join IP multicast groups */
  for ( i = 0; i < this->res->ai_recv_addrs_len; i++ ) {
    if ( ! pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_JOIN_GROUP,
                           &this->res->ai_recv_addrs[ i ],
                           sizeof( struct group_req ) ) ) {
      char group[ INET6_ADDRSTRLEN ];
      getnameinfo( (struct sockaddr*) &this->res->ai_recv_addrs[ i ].gsr_group,
                   sizeof( struct sockaddr_in ), group, sizeof( group ), NULL,
                   0, NI_NUMERICHOST );
      fprintf( stderr, "setting PGM_JOIN_GROUP = { #%u %s }\n",
               (unsigned) this->res->ai_recv_addrs[ i ].gsr_interface, group );
      this->status = 7;
      return false;
    }
  }
  if ( ! pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_SEND_GROUP,
                         &this->res->ai_send_addrs[ 0 ],
                         sizeof( struct group_req ) ) ) {
    char group[ INET6_ADDRSTRLEN ];
    getnameinfo( (struct sockaddr*) &this->res->ai_send_addrs[ 0 ].gsr_group,
                 sizeof( struct sockaddr_in ), group, sizeof( group ), NULL, 0,
                 NI_NUMERICHOST );
    fprintf( stderr, "setting PGM_SEND_GROUP = { #%u %s }\n",
             (unsigned) this->res->ai_send_addrs[ 0 ].gsr_interface, group );
    this->status = 8;
    return false;
  }
  /* set IP parameters */
  const int nonblocking = 1;
  int max_tsdu = 0;

  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_MULTICAST_LOOP,
                      &this->mcast_loop, sizeof( this->mcast_loop ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_MULTICAST_HOPS,
                      &this->mcast_hops, sizeof( this->mcast_hops ) );
  b&= pgm_setsockopt( this->sock, IPPROTO_PGM, PGM_NOBLOCK, &nonblocking,
                      sizeof( nonblocking ) );
  socklen_t sz = sizeof( max_tsdu );
  b&= pgm_getsockopt( this->sock, IPPROTO_PGM, PGM_MSS, &max_tsdu, &sz );

  this->geom.max_tsdu    = max_tsdu;
  this->geom.header_size = pgm_pkt_offset( FALSE, 0 );

  if ( b ) {
    if ( ! pgm_connect( this->sock, &this->pgm_err ) ) {
      fprintf( stderr, "connect PGM socket: %s\n", this->pgm_err->message );
      this->status = 9;
      b = false;
    }
  }
  this->is_connected = b;
  if ( b ) {
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
    struct pollfd fds[ 5 ];
    int           n_fds = 5;
    if ( pgm_poll_info( this->sock, fds, &n_fds, POLLIN ) < 1 ) {
      this->status = 9;
      b = false;
    }
    else {
      fd = fds[ 0 ].fd;
    }
#else
    WSAPOLLFD fds[ 5 ];
    ULONG     n_fds;
    if ( pgm_wsapoll_info( this->sock, fds, &n_fds, POLLRDNORM ) < 1 ) {
      this->status = 9;
      b = false;
    }
    else {
      fd = wp_register_fd( fds[ 0 ].fd );
    }
#endif
  }

  return b;
}
/* queue data in the send window */
void
PgmSock::put_send_window( const void *data,  size_t size,
                          const void *data2,  size_t size2,
                          const void *data3,  size_t size3,
                          const void *data4,  size_t size4 ) noexcept
{
  PgmSendWindow        * w   = this->send_list.tl;
  struct pgm_sk_buff_t * skb;
  /* try to put data into the last skb */
  skb = this->send_buf.last_skb();
  if ( skb != NULL ) {
    if ( w->extend_skb( this->geom, skb, data, size, data2, size2,
                        data3, size3, data4, size4 ) ) {
      this->pending += size + size2 + size3 + size4;
      return;
    }
    this->send_buf.next_skb();
  }
  /* if need a new skb */
  this->send_buf.resize_if_full();
  /* alloc a new skb from window */
  for (;;) {
    /* find a free window */
    if ( w == NULL ) {
      if ( this->skb_count >= this->txw_sqns ) {
        for (;;) {
          size_t cnt = this->send_list.hd->is_window_free();
          if ( cnt == 0 )
            break;
          if ( w != NULL )
            delete w;
          w = this->send_list.pop_hd();
          this->skb_count -= cnt;
          if ( this->skb_count < this->txw_sqns )
            break;
        }
      }
      if ( w == NULL ) {
        size_t sz = sizeof( PgmSendWindow ) + PgmSendWindow::SEND_BUF_SIZE;
        w = new ( ::malloc( sz ) ) PgmSendWindow();
      }
      this->send_list.push_tl( w );
    }
    /* alloc skb from the window */
    if ( (skb = w->alloc_skb( this->geom, data, size, data2, size2,
                              data3, size3, data4, size4 )) != NULL) {
      this->send_buf.put_last( skb );
      this->skb_count++;
      this->pending += size + size2 + size3 + size4;
      return;
    }
    w = NULL;
  }
}
/* push the send window to the network */
bool
PgmSock::push_send_window( void ) noexcept
{
  struct pgm_sk_buff_t * skb;
  struct timeval         tv;
  socklen_t              optlen;
  size_t                 bytes_written;
  /* seal the queue, last skb must not be modified */
  if ( this->send_buf.last_skb() != NULL )
    this->send_buf.next_skb();
  /* send all skbs in the queue */
  skb = this->send_buf.send_skb();
  for (;;) {
    if ( skb == NULL ) {
      this->status = 0;
      this->pending = 0;
      this->send_buf.reset();
      return true;
    }
    this->status = pgm_send_skbv( this->sock, &skb, 1, TRUE, &bytes_written );
    /* must resend the same skb if not sent, leave queue ptr */
    if ( this->status != PGM_IO_STATUS_NORMAL )
      break;
    /* if send was ok, go to next */
    skb = this->send_buf.advance_send();
    this->timeout_usecs = 0;
  }

  switch ( this->status ) {
    /* thse require sending the same data again */
    case PGM_IO_STATUS_RATE_LIMITED:
      optlen = sizeof( tv );
      pgm_getsockopt( this->sock, IPPROTO_PGM, PGM_TIME_REMAIN, &tv,
                      &optlen );
      this->timeout_usecs = tv.tv_sec * 1000000 + tv.tv_usec;
      break;

    case PGM_IO_STATUS_CONGESTION:
    case PGM_IO_STATUS_WOULD_BLOCK:
      this->timeout_usecs = 0;
      break;

    default:
      fprintf( stderr, "pgm_send_skbv failed, status:%d", this->status );
      break;
  }
  return false;
}
/* recv from network, this->len bytes indicates amount of data recvd */
bool
PgmSock::recv_msgs( void ) noexcept
{
  size_t         bytes_read = 0;
  socklen_t      optlen;
  struct timeval tv;

  for (;;) {
#ifndef MSG_ERRQUEUE
/* pgm/include/impl/sockaddr.h */
#define MSG_ERRQUEUE 0x2000
#endif
    this->status = pgm_recvmsgv( this->sock, this->msgv, MSG_VEC_SIZE,
                                 MSG_ERRQUEUE, &bytes_read, &this->pgm_err );
    this->timeout_usecs = 0;
    this->len = 0;
    switch ( this->status ) {
      case PGM_IO_STATUS_NORMAL: {
        if ( debug_pgm ) {
          if ( bytes_read > 0 )
            printf( "pgm normal, bytss %" PRIu64 "\n", bytes_read );
        }
        this->len = bytes_read;
        this->status = 0;
        return true;
      }
      case PGM_IO_STATUS_TIMER_PENDING:
        optlen = sizeof( tv );
        pgm_getsockopt( this->sock, IPPROTO_PGM, PGM_TIME_REMAIN, &tv,
                        &optlen );
        this->timeout_usecs = tv.tv_sec * 1000000 + tv.tv_usec;
        return false;

      case PGM_IO_STATUS_RATE_LIMITED:
        optlen = sizeof( tv );
        pgm_getsockopt( this->sock, IPPROTO_PGM, PGM_TIME_REMAIN, &tv,
                        &optlen );
        this->timeout_usecs = tv.tv_sec * 1000000 + tv.tv_usec;
        return false;

      case PGM_IO_STATUS_WOULD_BLOCK:
        this->timeout_usecs = 1000;
        return false;

      case PGM_IO_STATUS_RESET: {
        struct pgm_sk_buff_t* skb = msgv[ 0 ].msgv_skb[ 0 ];
        if ( ! pgm_tsi_equal( &skb->tsi, &this->lost_tsi ) ) {
          memcpy( &this->lost_tsi, &skb->tsi, sizeof( pgm_tsi_t ) );
          this->lost_tstamp = skb->tstamp;
          this->lost_count  = skb->sequence;
        }
        else {
          this->lost_count += skb->sequence;
        }
/*        pgm_tsi_print_r( &this->lost_tsi, tsi_buf, sizeof( tsi_buf ) );
        fprintf( stderr, "lost %" PRIu64 " seq @ %s\n", this->lost_count, tsi_buf );*/
        pgm_free_skb( skb );
      }
      /* fall thru */
      default:
        if ( this->pgm_err != NULL ) {
          fprintf( stderr, "%s", this->pgm_err->message );
          pgm_error_free( this->pgm_err );
          this->pgm_err = NULL;
        }
        break;
    }
  }
}

void
PgmSock::print_lost( void ) noexcept
{
  if ( this->lost_tstamp + (pgm_time_t) 1000000 < pgm_time_update_now() ) {
    char tsi_buf[ 32 ];
    char addr_buf[ 128 ];
    pgm_tsi_print_r( &this->lost_tsi, tsi_buf, sizeof( tsi_buf ) );
    pgm_tsi_to_address_string( this->sock, &this->lost_tsi, addr_buf,
                               sizeof( addr_buf ) );
    fprintf( stderr, "lost %" PRIu64 " seq tsi[%s] @ %s\n", this->lost_count, tsi_buf,
             addr_buf );
    this->lost_count = 0;
    ::memset( &this->lost_tsi, 0, sizeof( this->lost_tsi ) );
  }
}

void
PgmSock::print_stats( void ) noexcept
{
  printf( "-+-+-+-\n" );
  pgm_printstats( this->sock, this->src_stats, this->recv_stats );
}

void
PgmSock::close_pgm( void ) noexcept
{
  if ( this->sock != NULL ) {
    pgm_close( this->sock, this->is_connected );
    this->sock = NULL;
    this->is_connected = false;
    this->pending   = 0;
    this->skb_count = 0;
    if ( this->pgm_err != NULL ) {
      pgm_error_free( this->pgm_err );
      this->pgm_err = NULL;
    }
    if ( this->res != NULL ) {
      pgm_freeaddrinfo( this->res );
      this->res = NULL;
    }
    this->send_buf.release();
    while ( ! this->send_list.is_empty() ) {
      PgmSendWindow * w = this->send_list.pop_hd();
      delete w;
    }
    ::memset( &this->my_addr, 0, sizeof( this->my_addr ) );
    ::memset( &this->lost_tsi, 0, sizeof( this->lost_tsi ) );
    this->gsr_addr[ 0 ] = '\0';
    this->status = 0;
  }
}

void
PgmSock::release( void ) noexcept
{
}
