#ifndef __rai__raims__sha512_h__
#define __rai__raims__sha512_h__

namespace rai {
namespace ms {

static const size_t SHA512_HASH_SIZE = ( 512 / 8 );

struct Sha512Context {
  uint64_t length;
  uint64_t state[ 8 ];
  uint32_t curlen;
  uint8_t  buf[ 128 ];

  ~Sha512Context() { this->zero(); }
  void initialize( void ) noexcept;
  void update( const void *buf,  size_t buflen ) noexcept;
  void finalize( void *digest ) noexcept;
  void zero( void ) volatile {
    ::memset( (void *) this, 0, sizeof( *this ) );
  }
};

static inline void
Sha512_hash( const void *buf,  size_t buflen,  void *digest ) {
  Sha512Context sha;
  sha.initialize();
  sha.update( buf, buflen );
  sha.finalize( digest );
}

}
}

#endif
