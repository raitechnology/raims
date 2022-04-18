/*
 * from Andrew Moon, https://github.com/floodyberry/ed25519-donna
 */
#ifndef __rai__raims__ed25519_h__
#define __rai__raims__ed25519_h__

#include <raikv/util.h>
#include <raims/ec25519.h>

namespace rai {
namespace ms {

static const size_t ED25519_SIG_LEN     = 64,
                    ED25519_SIG_B64_LEN = KV_BASE64_SIZE( 64 ),
                    ED25519_KEY_LEN     = 32,
                    ED25519_KEY_B64_LEN = KV_BASE64_SIZE( 32 );

struct ed25519_signature : public KeyT<ed25519_signature, ED25519_SIG_LEN> {
  ed25519_signature( const uint8_t *k = NULL ) : KeyT( k ) {}
  ed25519_signature & operator=( const uint8_t *x ) { return this->copy_from( x ); }
};

struct ed25519_public_key : public KeyT<ed25519_public_key, ED25519_KEY_LEN> {
  ed25519_public_key( const uint8_t *k = NULL ) : KeyT( k ) {}
  ed25519_public_key & operator=( const uint8_t *x ) { return this->copy_from( x ); }
};

struct ed25519_secret_key : public KeyT<ed25519_secret_key, ED25519_KEY_LEN> {
  ed25519_secret_key( const uint8_t *k = NULL ) : KeyT( k ) {}
  ed25519_secret_key & operator=( const uint8_t *x ) { return this->copy_from( x ); }
};

struct ED25519 {
   ed25519_secret_key sk;
   ed25519_public_key pk;
   ed25519_signature  sig;

  void gen_key( void ) noexcept;
  void publickey( void ) noexcept;
  void sign( const void *m,  size_t mlen ) noexcept;
  int  sign_open( const void *m,  size_t mlen ) const noexcept;
  bool verify( const void *m,  size_t mlen ) const {
    return this->sign_open( m, mlen ) == 0;
  }
  static void scalarmult_basepoint( ec25519_key &pk,
                                    const ec25519_key &e ) noexcept;
};

}
}

#endif
