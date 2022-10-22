#ifndef __rai_raims__ev_tcp_aes_h__
#define __rai_raims__ev_tcp_aes_h__

#include <raikv/ev_net.h>
#include <raims/crypt.h>
#include <raims/aes.h>

namespace rai {
namespace ms {

struct CounterMode_AES {
  AES128   aes;
  uint64_t ctr[ 2 ];
  uint8_t  mask[ AES128::BLOCK_SIZE * 8 ];
  size_t   avail,
           off;

  void init( void ) {
    this->avail = 0;
    this->off   = 0;
  }

  void release( void ) volatile {
    this->aes.zero();
    this->ctr[ 0 ] = 0;
    this->ctr[ 1 ] = 0;
  }

  void init_secret( const Nonce &nonce,  const ec25519_key &secret,
                    size_t exchange_offset ) {
    HashDigest digest;
    uint64_t key[ 2 ];
    digest.kdf_bytes( nonce.digest(), NONCE_SIZE,
                      secret.key, EC25519_KEY_LEN );
    key[ 0 ]       = digest.dig[ 0 ] ^ digest.dig[ 4 ];
    key[ 1 ]       = digest.dig[ 1 ] ^ digest.dig[ 5 ];
    this->ctr[ 0 ] = digest.dig[ 2 ] ^ digest.dig[ 6 ];
    this->ctr[ 1 ] = digest.dig[ 3 ] ^ digest.dig[ 7 ];
    this->aes.expand_key( key );
    this->avail = 0;
    this->off   = exchange_offset;
  }

  void crypt( void *buf,  size_t len ) {
    size_t moff = AES128::BLOCK_SIZE * 8 - this->avail;
    for (;;) {
      size_t n = ( this->avail < len ? this->avail : len );
      if ( n > 0 ) {
        this->aes.byte_xor( &this->mask[ moff ], buf, n );
        this->avail -= n;
        len -= n;
        if ( len == 0 )
          return;
        buf = &((char *) buf)[ n ];
      }
      this->aes.encrypt_ctr( this->ctr, this->mask, 8 );
      this->avail = AES128::BLOCK_SIZE * 8;
      moff = 0;
    }
  }
};

struct ECDH_Exchange {
  EC25519   ecdh;
  Nonce     send_nonce, recv_nonce;
  uint8_t * save;
  size_t    save_len;
  void    * psk;
  size_t    psk_len;

  void init( void *k,  size_t k_len ) {
    this->ecdh.gen_key();
    this->send_nonce.seed_random();
    this->save     = NULL;
    this->save_len = 0;
    this->psk      = k;
    this->psk_len  = k_len;
  }
  void release( void ) volatile {
    this->ecdh.zero();
    this->send_nonce.zero();
    this->recv_nonce.zero();
    if ( this->save != NULL )
      ::free( this->save );
    this->save     = NULL;
    this->save_len = 0;
    this->psk      = NULL;
    this->psk_len  = 0;
  }
};

struct AES_Connection : public kv::EvConnection {
  static const size_t CHECK_SIZE    = 8,
                      KEY_EXCH_SIZE = CHECK_SIZE + NONCE_SIZE + EC25519_KEY_LEN;
  static const uint32_t AES_CONN_VER = 1;
  CounterMode_AES send_aes,
                  recv_aes;
  ECDH_Exchange * exch;
  bool            have_key;

  AES_Connection( kv::EvPoll &p,  uint8_t st )
    : kv::EvConnection( p, st ), exch( 0 ), have_key( false ) {}

  void init_exchange( void *k, size_t k_len ) {
    this->send_aes.init();
    this->recv_aes.init();
    if ( this->exch == NULL )
      this->exch = (ECDH_Exchange *)
        kv::aligned_malloc( sizeof( ECDH_Exchange ) );
    this->exch->init( k, k_len );
    this->have_key = false;
  }
  void init_noencrypt( void ) {
    this->release_aes();
  }
  void release_aes( void ) {
    if ( this->exch != NULL ) {
      this->exch->release();
      kv::aligned_free( this->exch );
      this->exch = NULL;
    }
    this->send_aes.release();
    this->recv_aes.release();
    this->have_key = false;
  }
  virtual void read( void ) noexcept;
  virtual void write( void ) noexcept;
  void save_write( void ) noexcept;
  bool recv_key( void ) noexcept;
  void send_key( void ) noexcept;
};

}
}

#endif
