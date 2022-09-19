/*
 * from Andrew Moon, https://github.com/floodyberry/curve25519-donna
 */
#ifndef __rai__raims__ec25519_h__
#define __rai__raims__ec25519_h__

#include <raikv/util.h>

namespace rai {
namespace ms {

static const size_t EC25519_KEY_LEN     = 32,
                    EC25519_KEY_B64_LEN = KV_BASE64_SIZE( 32 );

template <class T, size_t KEY_LEN>
struct KeyT {
  uint8_t key[ KEY_LEN ];
  KeyT( const void *k ) {
    if ( k != NULL )
      ::memcpy( this->key, k, sizeof( this->key ) );
  }
  ~KeyT() {
    this->zero();
  }
  T & copy_from( const void *x ) {
    ::memcpy( this->key, x, sizeof( this->key ) );
    return (T &) *this;
  }
  void copy_to( void *out ) const {
    ::memcpy( out, this->key, sizeof( this->key ) );
  }
  operator uint8_t *() { return this->key; }
  operator const uint8_t *() const { return this->key; }
  void zero( void ) volatile {
    ::memset( (void *) this->key, 0, sizeof( this->key ) );
  }
  bool is_zero( void ) const {
    uint64_t tmp[ KEY_LEN / 8 ];
    ::memcpy( tmp, this->key, KEY_LEN );
    uint64_t j = 0;
    for ( size_t i = 0; i < KEY_LEN / 8; i++ )
      j |= tmp[ i ];
    return j == 0;
  }
};

struct ec25519_key : public KeyT<ec25519_key, EC25519_KEY_LEN> {
  ec25519_key( const void *k = NULL ) : KeyT( k ) {}
  ec25519_key & operator=( const uint8_t *x ) { return this->copy_from( x ); }
};

/* ECx25519 Diffie Hellman exchange */
struct EC25519 {
  ec25519_key pub, pri, secret;

  void zero( void ) volatile {
    this->pub.zero();
    this->pri.zero();
    this->secret.zero();
  }
  void shared_secret( void ) noexcept;
  void gen_key( const void *r = NULL,  size_t rlen = 0 ) noexcept;
  static void donna( ec25519_key &mypublic, const ec25519_key &secret,
                     const ec25519_key &basepoint ) noexcept;
  static void donna_basepoint( ec25519_key &mypublic,
                               const ec25519_key &secret ) noexcept;
};

typedef struct EC25519 ECDH;

}
}
#endif
