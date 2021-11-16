#ifndef __rai_raims__kdf_h__
#define __rai_raims__kdf_h__

namespace rai {
namespace ms {

/*#define USE_SHA512*/
#ifdef KDF_DEBUG
static void
show_work( const char *where,  void *buf,  size_t buflen )
{
  printf( "---> %s\n", where );
  md::MDOutput mout;
  mout.print_hex( buf, buflen );
}
#endif

static inline void
swap( uint8_t &a,  uint8_t &b )
{
  uint8_t c = a; a = b; b = c;
}

static inline uint32_t
update_block( uint32_t j,  uint8_t s[ 256 ] )
{
  uint32_t i;
#ifdef KDF_DEBUG
    show_work( "update_block", s, 256 );
#endif
  for ( i = 0; i < 256; i++ ) {
    j = ( j + (uint32_t) s[ i ] + (uint32_t) T[ i ] ) % 256;
    swap( s[ i ], s[ j ] );
  }
#ifdef KDF_DEBUG
    show_work( "update_block_rc4", s, 256 );
#endif
#ifndef USE_SHA512
  uint64_t *u = (uint64_t *) (void *) U;
  uint64_t x[ 8 ];
  for ( i = 0; i < 256; i += 64 ) {
    ::memcpy( x, u, sizeof( x ) ); u += 8;
    kv_hash_meow128_4_same_length_4_seed( &s[ i ], &s[ i + 16 ],
                                          &s[ i + 32 ], &s[ i + 48 ], 16, x );
    ::memcpy( &s[ i ], x, sizeof( x ) );
  }
#ifdef KDF_DEBUG
    show_work( "update_block_meow", s, 256 );
#endif
#endif
#if 0
  /* slightly slower */
  for ( i = 0; i < 256; i += 16 ) {
    AES_KEY key;
    AES_set_encrypt_key( &s[ i ], 128, &key );
    AES_encrypt( &U[ i ], &s[ i ], &key );
  }
#endif
  return j;
}

#ifndef USE_SHA512
static inline void
complete_block( uint32_t j,  uint8_t s[ 256 ],  void *digest )
{
  uint64_t x[ 8 ];
  j &= ~63;
  ::memcpy( x, &U[ j ] , sizeof( x ) );
  kv_hash_meow128_4_same_length_4_seed( s, &s[ 64 ], &s[ 128 ], &s[ 192 ], 64,
                                        x );
  ::memcpy( digest, x, sizeof( x ) );
}
#endif

#ifdef KDF_DEBUG
#define KeyDeriveFun KeyDeriveFunDebug
#endif
struct KeyDeriveFun
{
  uint8_t    S[ 256 ];
#ifdef USE_SHA512
  SHA512_CTX ctx;
#endif
  uint32_t   off, j;
  static const size_t start = ' ',
                      full  = 127;
  /* strech key, fill from 32 -> 127, leaving previous data mixed in */
  KeyDeriveFun() : off( start ), j( 0 ) {
    if ( ! kdf_hash_ready )
      init_kdf();
    for ( size_t i = 0; i < 256; i++ )
      this->S[ i ] = (uint8_t) i;
#ifdef USE_SHA512
    SHA512_Init( &this->ctx );
#endif
  }
  /* update in 95 byte chunks and merge in between */
  void update( const void *in,  size_t len ) {
    for (;;) {
      size_t n = len;
      if ( this->off + n > full )
        n = full - this->off;
      ::memcpy( &this->S[ this->off ], in, n );
      this->off += n;
      if ( this->off == full ) {
        this->merge();
        this->off = start;
      }
      if ( n == len )
        return;
      in   = &((const uint8_t *) in)[ n ];
      len -= n;
    }
  }
  /* digest should be 64 bytes (512 bits / 8 = 64) */
  void complete( void *digest ) {
    if ( this->off > start )
      this->merge();
#ifdef USE_SHA512
    SHA512_Final( (uint8_t *) digest, &this->ctx );
#else
    complete_block( this->j, this->S, digest );
#endif
#ifdef KDF_DEBUG
    show_work( "complete", digest, 512 / 8 );
#endif
  }
  /* do RC4 swaps and update state */
  void merge( void ) {
    this->j = update_block( this->j, this->S );
#ifdef USE_SHA512
    SHA512_Update( &this->ctx, this->S, 256 );
#endif
  }
  /* pass buffer through hash digest mixer several times */
  void mix( void *p,  size_t len,  size_t times ) {
    for ( size_t cnt = 0; cnt < times; cnt++ ) {
      void * buf    = p;
      size_t buflen = len;
      while ( buflen > 0 ) {
        size_t k = ( buflen > 64 ? 64 : buflen );
#ifdef USE_SHA512
        SHA512_Init( &this->ctx );
#endif
        this->update( buf, k );
        if ( k < 64 ) {
          uint8_t tmp[ 64 ];
          this->complete( tmp );
          ::memcpy( buf, tmp, k );
        }
        else {
          this->complete( buf );
        }
        buf = &((uint8_t *) buf)[ k ];
        buflen -= k;
      }
    }
  }
};

}
}
#endif
