#ifndef __rai_raims__pgm_sock_h__
#define __rai_raims__pgm_sock_h__

#include <pgm/pgm.h>
#include <raims/send_window.h>
#include <raikv/dlinklist.h>

struct pgm_sk_buff_t;

namespace rai {
namespace ms {

struct PktGeom {
  size_t max_tsdu,
         header_size;

  PktGeom() : max_tsdu( 0 ), header_size( 0 ) {}

  size_t num_fragments( size_t len,  size_t &trail_size ) {
    size_t cnt = 1;
    while ( len > this->max_tsdu ) {
      len -= this->max_tsdu;
      cnt++;
    }
    trail_size = len;
    return cnt;
  }
};

struct PgmSendWindow : public SendWindow {
  static const size_t SEND_BUF_SIZE = 128 * 1024;
  void * operator new( size_t, void *ptr ) { return ptr; }
  PgmSendWindow * next;
  PgmSendWindow()
    : SendWindow( &this[ 1 ], SEND_BUF_SIZE ), next( 0 ) {}

  static void * skb_end( struct pgm_sk_buff_t *skb,  size_t size ) {
    return &((char *) (void *) skb)[ size ];
  }
  struct pgm_sk_buff_t *alloc_skb( PktGeom &geom,
                                   const void *data,  size_t size,
                                   const void *data2,  size_t size2,
                                   const void *data3,  size_t size3,
                                   const void *data4,  size_t size4 ) {
    size_t truesize =
      this->align( geom.header_size + size + size2 + size3 + size4 +
                   sizeof( struct pgm_sk_buff_t ) );
    if ( this->fits( truesize ) ) {
      struct pgm_sk_buff_t *skb = (struct pgm_sk_buff_t *)
                                  this->alloc( truesize );
      ::memset( skb, 0, sizeof( struct pgm_sk_buff_t ) );
      pgm_atomic_write32( &skb->users, 2 );
      skb->truesize = (uint32_t) truesize;
      skb->head     = &skb[ 1 ];
      skb->data     = skb->head;
      skb->tail     = skb->head;
      skb->end      = skb_end( skb, truesize );
      pgm_skb_reserve( skb, (uint16_t) geom.header_size );
      uint8_t * pkt = (uint8_t *)
        pgm_skb_put( skb, (uint16_t) ( size + size2 + size3 + size4 ) );
      if ( size > 0 )
        ::memcpy( pkt, data, size );
      if ( size2 > 0 )
        ::memcpy( &pkt[ size ], data2, size2 );
      if ( size3 > 0 )
        ::memcpy( &pkt[ size + size2 ], data3, size3 );
      if ( size4 > 0 )
        ::memcpy( &pkt[ size + size2 + size3 ], data4, size4 );
      return skb;
    }
    return NULL;
  }
  size_t is_window_free( void ) {
    void * start = this->buf_ptr( 0 ),
         * end   = this->off_ptr();
    size_t cnt   = 0;
    for (;;) {
      if ( start == end ) {
        this->reset();
        return cnt;
      }
      struct pgm_sk_buff_t *skb = (struct pgm_sk_buff_t *) start;
      if ( pgm_atomic_read32( &skb->users ) != 1 )
        return 0;
      cnt++;
      start = skb->end;
    }
  }
  bool extend_skb( PktGeom &geom,  struct pgm_sk_buff_t *skb,
                   const void *data,  size_t size,
                   const void *data2,  size_t size2,
                   const void *data3,  size_t size3,
                   const void *data4,  size_t size4 ) {
    size_t new_len  = (size_t) skb->len + size + size2 + size3 + size4;
    if ( new_len > geom.max_tsdu )
      return false;
    size_t new_truesize = this->align( geom.header_size + new_len +
                                       sizeof( struct pgm_sk_buff_t ) );
    void * start   = this->buf_ptr( 0 ),
         * new_end = skb_end( skb, new_truesize );
    if ( new_end <= start || new_end > this->end_ptr() )
      return false;
    this->set_end( new_end );
    skb->truesize = (uint32_t) new_truesize;
    skb->end      = new_end;
    uint8_t * pkt = (uint8_t *)
                    pgm_skb_put( skb, (uint16_t) ( size + size2 + size3 ) );
    if ( size > 0 )
      ::memcpy( pkt, data, size );
    if ( size2 > 0 )
      ::memcpy( &pkt[ size ], data2, size2 );
    if ( size3 > 0 )
      ::memcpy( &pkt[ size + size2 ], data3, size3 );
    if ( size4 > 0 )
      ::memcpy( &pkt[ size + size2 + size3 ], data4, size4 );
    return true;
  }
};

typedef kv::SLinkList<PgmSendWindow> PgmWindowList;

struct PgmSendBuf {
  struct pgm_sk_buff_t ** buf;
  size_t                  off,
                          len,
                          size;
  PgmSendBuf() : buf( 0 ), off( 0 ), len( 0 ), size( 0 ) {}

  void release( void ) {
    if ( this->buf != NULL )
      ::free( this->buf );
    this->buf  = NULL;
    this->off  = 0;
    this->len  = 0;
    this->size = 0;
  }
  void resize_if_full( void ) {
    if ( this->len == this->size ) {
      const size_t elsz     = sizeof( this->buf[ 0 ] );
      const size_t new_size = ( this->len + 4 ) * elsz;
      void       * new_buf  = ::realloc( this->buf, new_size );
      this->buf = (struct pgm_sk_buff_t **) new_buf;
      this->buf[ this->len ] = NULL;
      this->size += 4;
    }
  }
  void reset( void ) {
    this->off = this->len = 0;
    if ( this->size > 0 )
      this->buf[ 0 ] = NULL;
  }
  struct pgm_sk_buff_t *last_skb( void ) const {
    return ( this->len < this->size ? this->buf[ this->len ] : NULL );
  }
  void next_skb( void ) {
    if ( ++this->len < this->size )
      this->buf[ this->len ] = NULL;
  }
  struct pgm_sk_buff_t *send_skb( void ) const {
    return ( this->off < this->len ? this->buf[ this->off ] : NULL );
  }
  struct pgm_sk_buff_t *advance_send( void ) {
    return ( ++this->off < this->len ? this->buf[ this->off ] : NULL );
  }
  void put_last( struct pgm_sk_buff_t *skb ) { this->buf[ this->len ] = skb; }
};

struct PgmSock {
  static const size_t MSG_VEC_SIZE = 16;
  pgm_sock_t            * sock;                /* pgm protocol sock */
  pgm_time_t              timeout_usecs;       /* set to current timeout */
  struct pgm_msgv_t       msgv[ MSG_VEC_SIZE ];/* vector of recv bufs */
  size_t                  len;                 /* recv len */
  PgmWindowList           send_list;           /* hd oldest msgs, tl newest */
  PgmSendBuf              send_buf;            /* buffered skb sends */
  size_t                  skb_count,           /* count of skbs in window */
                          txw_sqns,            /* transmit window */
                          pending;             /* pending send size */
  pgm_sockaddr_t          my_addr;             /* tsi, sport, sa_port */
  pgm_tsi_t               lost_tsi;            /* the tsi of lost */
  pgm_time_t              lost_tstamp;         /* the time lost */
  uint64_t                lost_count;          /* sequence lost */
  pgm_error_t           * pgm_err;             /* last error */
  pgm_addrinfo_t        * res;                 /* pgm address resolve */
  char                    gsr_addr[ 48 ];      /* recv interface */
  PktGeom                 geom;                /* hdr + unfragmented size */
  uint32_t                mtu,                 /* ip + udp + pgm + data */
                          rxw_sqns,            /* receive widnow */
                          txw_secs,            /* send window timer */
                          ambient_spm,         /* SPM at this interval */
                          heartbeat_spm[ 9 ],  /* HB after sends */
                          peer_expiry,         /* peers expire after last pkt/SPM */
                          spmr_expiry,         /* interval for SPMR peer requests */
                          nak_bo_ivl,          /* back off interval */
                          nak_rpt_ivl,         /* repeat interval */
                          nak_rdata_ivl,       /* wait for repair data */
                          nak_data_retry,      /* count of repair retries */
                          nak_ncf_retry,       /* count of nak confirm retries */
                          mcast_loop,          /* loopback to host */
                          mcast_hops;          /* ttl */
  int                     status;              /* current status */
  bool                    is_connected;        /* success opening transport */
  uint32_t                src_stats[ 64 ],
                          recv_stats[ 64 ];

  PgmSock() noexcept;
  uint64_t my_tsi( void ) const {
    uint64_t x = 0;
    ::memcpy( &x, &this->my_addr.sa_addr, sizeof( x ) );
    return x;
  }
  bool find_gsr_addr( void ) noexcept;
  bool start_pgm( const char *network,  int svc,  int &fd ) noexcept;
  bool fwd_msg( const void *data,  size_t size ) noexcept;
  bool recv_msgs( void ) noexcept;
  void print_lost( void ) noexcept;
  void print_stats( void ) noexcept;
  void close_pgm( void ) noexcept;
  void release( void ) noexcept;
  void put_send_window( const void *data,  size_t size,
                        const void *data2 = NULL,  size_t size2 = 0,
                        const void *data3 = NULL,  size_t size3 = 0,
                        const void *data4 = NULL,  size_t size4 = 0 ) noexcept;
  bool push_send_window( void ) noexcept;
};

}
}

#endif
