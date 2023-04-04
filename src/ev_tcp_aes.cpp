#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <raims/ev_tcp_aes.h>
#include <raims/debug.h>
#include <raimd/md_types.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

/*
#include <raimd/md_msg.h>
using namespace md;
static void
print_bytes( const char *where,  const void *b,  size_t b_len ) noexcept
{
  printf( "%s:\n", where );
  MDOutput mout;
  mout.print_hex( b, b_len );
}*/

bool
AES_Connection::recv_key( void ) noexcept
{
  if ( this->len < KEY_EXCH_SIZE ) {
    this->pop( EV_PROCESS );
    return false;
  }
  ECDH_Exchange & ex = *this->exch;
  uint64_t check, check2;
  bool ok = true;

  ::memcpy( &check, this->recv, CHECK_SIZE );
  check = kv_bswap64( check );
  if ( ( check >> 32 ) != 0 ) {
    d_tcp( "ignoring, zero prefix missing\n" );
    this->pushpop( EV_CLOSE, EV_PROCESS );
    ok = false;
  }
  else {
    ex.recv_nonce.copy_from( &this->recv[ CHECK_SIZE ] );
    ex.ecdh.pub.copy_from( &this->recv[ CHECK_SIZE + NONCE_SIZE ] );

    check2 = kv_crc_c( ex.ecdh.pub.key, EC25519_KEY_LEN, 
                       kv_crc_c( ex.recv_nonce.digest(), NONCE_SIZE,
                       kv_crc_c( ex.psk, ex.psk_len, AES_CONN_VER ) ) );
    if ( check != check2 ) {
      d_tcp( "ignoring, failed crc check\n" );
      this->pushpop( EV_CLOSE, EV_PROCESS );
      ok = false;
    }
    else {
      ex.ecdh.shared_secret();
      this->recv_aes.init_secret( ex.recv_nonce, ex.ecdh.secret, KEY_EXCH_SIZE);
      this->send_aes.init_secret( ex.send_nonce, ex.ecdh.secret, KEY_EXCH_SIZE);

      this->off      = KEY_EXCH_SIZE;
      this->have_key = true;

      if ( ex.save_len != 0 ) {
        void * ptr = this->alloc_temp( ex.save_len );
        ::memcpy( ptr, ex.save, ex.save_len );
        this->insert_iov( 0, ptr, ex.save_len );
        this->push( EV_WRITE );
      }
    }
    /*printf( "recv aes key, bytes recv %lu, bytes_sent %lu, recv_off %lu, send_off %lu\n",
            this->bytes_recv, this->bytes_sent,
            this->recv_aes.off, this->send_aes.off );*/
  }
  this->done_exchange();
  this->exch = NULL;
  return ok;
}

void
AES_Connection::read( void ) noexcept
{
  this->EvConnection::read();
  if ( this->exch != NULL ) {
    if ( ! this->recv_key() )
      return;
    if ( this->have_key ) { /* should make this a callback to ev_tcp_transport*/
      if ( this->notify != NULL )
        this->notify->on_connect( *this );
    }
  }
  if ( this->have_key ) {
    size_t enc_len = this->bytes_recv - this->recv_aes.off;
    if ( enc_len > 0 ) {
      if ( enc_len > this->len ) {
        printf( "bad enc_len\n" );
        this->pushpop( EV_CLOSE, EV_PROCESS );
        return;
      }
      size_t moff = this->len - enc_len;
      /*print_bytes( "recv before_crypt", &this->recv[ moff ], enc_len );*/
      this->recv_aes.crypt( &this->recv[ moff ], enc_len );
      /*print_bytes( "recv after_crypt", &this->recv[ moff ], enc_len );*/
      this->recv_aes.off = this->bytes_recv;
    }
  }
}

void
AES_Connection::send_key( void ) noexcept
{
  uint64_t check;
  ECDH_Exchange & ex = *this->exch;
  check = kv_crc_c( ex.ecdh.pub.key, EC25519_KEY_LEN, 
                    kv_crc_c( ex.send_nonce.digest(), NONCE_SIZE,
                    kv_crc_c( ex.psk, ex.psk_len, AES_CONN_VER ) ) );
  check = kv_bswap64( check );
  this->append( &check, CHECK_SIZE );
  this->append2( ex.send_nonce.digest(), NONCE_SIZE,
                 ex.ecdh.pub.key, EC25519_KEY_LEN );
  this->idle_push( EV_WRITE );
}

void
AES_Connection::save_write( void ) noexcept
{
  this->concat_iov();

  size_t wr_len = this->bytes_sent + this->wr_pending;
  if ( wr_len > KEY_EXCH_SIZE ) {
    size_t          iov_len = this->iov[ 0 ].iov_len;
    const uint8_t * base    = (const uint8_t *) this->iov[ 0 ].iov_base;

    if ( this->bytes_sent < KEY_EXCH_SIZE ) {
      iov_len -= ( KEY_EXCH_SIZE - this->bytes_sent );
      base     = &base[ KEY_EXCH_SIZE - this->bytes_sent ];
    }

    ECDH_Exchange & ex = *this->exch;
    ex.save = (uint8_t *)
      ::realloc( ex.save, ex.save_len + iov_len );
    ::memcpy( &ex.save[ ex.save_len ], base, iov_len );
    ex.save_len += iov_len;

    if ( this->iov[ 0 ].iov_len == iov_len ) {
      this->reset();
      this->pop3( EV_WRITE, EV_WRITE_HI, EV_WRITE_POLL );
      return;
    }
    this->iov[ 0 ].iov_len = KEY_EXCH_SIZE - this->bytes_sent;
    this->wr_pending = this->iov[ 0 ].iov_len;
  }
  this->EvConnection::write();
}
#if 0
struct DBGOutput : public MDOutput {
  FILE * fp;
  DBGOutput( FILE *x ) : fp( x ) {}
  virtual int puts( const char *s ) noexcept;
  virtual int printf( const char *fmt, ... ) noexcept
    __attribute__((format(printf,2,3)));
};

int
DBGOutput::printf( const char *fmt, ... ) noexcept
{
  va_list ap;
  int n;
  va_start( ap, fmt );
  n = vfprintf( this->fp, fmt, ap );
  va_end( ap );
  return n;
}

int
DBGOutput::puts( const char *s ) noexcept
{
  if ( s != NULL ) {
    int n = fputs( s, this->fp );
    if ( n > 0 )
      return (int) ::strlen( s );
  }
  return 0;
}

static void
debug_aes_write( const char *name,  const char *paddr,  uint64_t &bytes_off,
                 char *buf,  size_t len ) noexcept
{
  if ( len <= 0x38 || ::memcmp( &buf[ 0x30 ], "_X.HB", 5 ) != 0 )
    return;

  static FILE * ht[ 8 * 1024 ];
  static uint32_t ht_id[ 8 * 1024 ];
  char   path[ 256 ];
  CatPtr p( path );
  p.s( name ).s( "_" ).s( paddr ).s( ".txt" ).end();
  uint32_t id, h = kv_crc_c( path, p.len(), 0 ) % ( 8 * 1024 );

  ::memcpy( &id, &buf[ 0xa ], 4 );
  if ( ht_id[ h ] == 0 ) {
    ht_id[ h ] = id;
    return;
  }
  if ( ht_id[ h ] != id ) {
    FILE * fp;
    if ( (fp = ht[ h ]) == NULL ) {
      fp = ht[ h ] = ::fopen( path, "w" );
    }
    fprintf( fp, "%lu %s\n", bytes_off, path );
    bytes_off += len;
    DBGOutput mout( fp );
    mout.print_hex( buf, len );
    fflush( fp );
  }
}
#endif
void
AES_Connection::write( void ) noexcept
{
  if ( this->exch != NULL ) {
    this->save_write();
    return;
  }

  if ( this->have_key ) {
    size_t i;
    if ( this->sz > 0 )
      this->flush();
    size_t enc_off = this->send_aes.off - this->bytes_sent;

    /* check refs, make sure bufs are not shared with another writer,
     * since encryption occurs inline on the buffers being sent */
    for ( i = 0; i < this->ref_cnt; i++ ) {
      if ( this->poll.zero_copy_ref_count( this->refs[ i ] ) != 1 )
        break;
    }
    /* copy refs if ref_count != 1 (just this) */
    if ( i != this->ref_cnt ) {
      for ( i = 0; i < this->idx; i++ ) {
        iovec & io = this->iov[ i ];
        if ( io.iov_len > this->recv_highwater ) {
          char * tmp = this->alloc_temp( io.iov_len );
          ::memcpy( tmp, io.iov_base, io.iov_len );
          io.iov_base = tmp;
        }
      }
      /* deref after copy */
      for ( i = 0; i < this->ref_cnt; i++ )
        this->poll.zero_copy_deref( this->refs[ i ], false );
      this->ref_cnt = 0;
    }
    /* encrypt */
    /*size_t bytes_off = this->bytes_sent;*/
    for ( i = 0; i < this->idx; i++ ) {
      iovec & io = this->iov[ i ];
      char  * base = (char *) io.iov_base;
      if ( io.iov_len > enc_off ) {
        size_t enc_len = io.iov_len - enc_off;
        /*debug_aes_write( this->name, this->peer_address.buf, bytes_off, &base[ enc_off ], enc_len ); */
        /*print_bytes( "send before_crypt", &base[ enc_off ], enc_len );*/
        this->send_aes.crypt( &base[ enc_off ], enc_len );
        /*print_bytes( "send after_crypt", &base[ enc_off ], enc_len );*/
        this->send_aes.off += enc_len;
        enc_off = 0;
      }
      else {
        enc_off -= io.iov_len;
      }
    }
  }
  this->EvConnection::write();
}

