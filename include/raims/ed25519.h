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
  ed25519_signature( const void *k = NULL ) : KeyT( k ) {}
  ed25519_signature & operator=( const void *x ) { return this->copy_from( x ); }
};

struct ed25519_public_key : public KeyT<ed25519_public_key, ED25519_KEY_LEN> {
  ed25519_public_key( const void *k = NULL ) : KeyT( k ) {}
  ed25519_public_key & operator=( const void *x ) { return this->copy_from( x ); }
};

struct ed25519_secret_key : public KeyT<ed25519_secret_key, ED25519_KEY_LEN> {
  ed25519_secret_key( const void *k = NULL ) : KeyT( k ) {}
  ed25519_secret_key & operator=( const void *x ) { return this->copy_from( x ); }
};

struct ED25519 {
  ed25519_secret_key sk;
  ed25519_public_key pk;
  ed25519_signature  sig;

  void * operator new( size_t, void *ptr ) { return ptr; }
  ED25519() {}
  void zero( void ) volatile {
    this->sk.zero();
    this->pk.zero();
    this->sig.zero();
  }
  void gen_key( const void *r = NULL,  size_t rlen = 0,
                const void *s = NULL,  size_t slen = 0,
                const void *t = NULL,  size_t tlen = 0 ) noexcept;
  void publickey( void ) noexcept;
  void sign( const void *m,  size_t mlen ) noexcept;
  int  sign_open( const void *m,  size_t mlen ) const noexcept;
  bool verify( const void *m,  size_t mlen ) const {
    return this->sign_open( m, mlen ) == 0;
  }
  static void scalarmult_basepoint( ec25519_key &pk,
                                    const ec25519_key &e ) noexcept;
};

typedef ED25519 DSA;

}
}

#endif
