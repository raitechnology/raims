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
  KeyT( const uint8_t *k ) {
    if ( k != NULL )
      ::memcpy( this->key, k, sizeof( this->key ) );
  }
  ~KeyT() {
    this->zero();
  }
  T & copy_from( const uint8_t *x ) {
    ::memcpy( this->key, x, sizeof( this->key ) );
    return (T &) *this;
  }
  void copy_to( uint8_t *out ) const {
    ::memcpy( out, this->key, sizeof( this->key ) );
  }
  operator uint8_t *() { return this->key; }
  operator const uint8_t *() const { return this->key; }
  void zero( void ) volatile {
    ::memset( (void *) this->key, 0, sizeof( this->key ) );
  }
};

struct ec25519_key : public KeyT<ec25519_key, EC25519_KEY_LEN> {
  ec25519_key( const uint8_t *k = NULL ) : KeyT( k ) {}
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
  void gen_key( void ) noexcept;
  static void donna( ec25519_key &mypublic, const ec25519_key &secret,
                     const ec25519_key &basepoint ) noexcept;
  static void donna_basepoint( ec25519_key &mypublic,
                               const ec25519_key &secret ) noexcept;
};

}
}
#endif
