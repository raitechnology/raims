#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/ev_tcp_aes.h>

using namespace rai;
using namespace ms;
using namespace kv;

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
    printf( "ignoring, zero prefix missing\n" );
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
      printf( "ignoring, failed crc check\n" );
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
  delete this->exch;
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

void
AES_Connection::write( void ) noexcept
{
  if ( this->exch != NULL ) {
    this->save_write();
    return;
  }

  if ( this->have_key ) {
    if ( this->sz > 0 )
      this->flush();
    size_t enc_off = this->send_aes.off - this->bytes_sent;

    for ( size_t i = 0; i < this->idx; i++ ) {
      iovec & io = this->iov[ i ];
      char  * base = (char *) io.iov_base;
      if ( io.iov_len > enc_off ) {
        size_t enc_len = io.iov_len - enc_off;
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

