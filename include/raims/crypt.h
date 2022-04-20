#ifndef __rai_raims__crypt_h__
#define __rai_raims__crypt_h__

/*
 * hash routines used to constructed signed messages:
 *
 * HA2_msg     = AES_HMAC( IV:HA1_session_head, msg + HA1_session_tail )
 * HA1_session = SHA512( HA0_auth + nonce )
 *
 * HA2_auth    = AES_HMAC( IV:HA1_auth_head, msg + HA1_auth_tail )
 * HA1_auth    = SHA512( HA0_auth + nonce + cnonce + seqno + time )
 *
 * HA0_auth    = SHA512( user + service + pass )
 *
 * The AES_HMAC is a faster HMAC like construction where the HA1_hash
 * is sandwiched around the message.
 *
 * HA2_msg is used to authenticate each message sent by the user to a service
 * for multiple parties.  Each party can verify given they know either HA0_auth
 * or HA1_session
 *
 * HA2_auth is used to authenticate the HA2_msg from the user to another party.
 * The second party provides a cnonce + seqno + time to the user which uses
 * this one time value with the HA2_msg nonce to create a unique value that
 * both sides can compute given they both know HA0_auth.
 */
#include <raikv/key_hash.h>
#include <raims/poly1305.h>
#include <raikv/util.h>
#include <raikv/atom.h>

namespace rai {
namespace ms {

struct CryptPass {
  char    * pass;
  size_t    pass_len;

  CryptPass() : pass( 0 ), pass_len( 0 ) {}
  bool init_pass( const char *pass ) noexcept;
  void clear_pass( void ) noexcept;
  bool gen_pass( void ) noexcept;
  static void *gen_salt( size_t &salt_len ) noexcept;
  bool init_pass_file( const char *path ) noexcept;
  static bool init_salt_file( const char *path ) noexcept;
};

extern kv_atom_uint32_t kdf_hash_init;
extern kv_atom_uint32_t kdf_hash_ready;
extern uint8_t * T;
extern uint8_t * U;

static const size_t
  /* Nonce constants */
  NONCE_SIZE           = 16, /* bytes in a nonce / cnonce */
  NONCE_WORDS          = NONCE_SIZE * 8 / 64, /* 64 bit words */
  NONCE_B64_LEN        = KV_BASE64_SIZE( 16 ), /* base64 length, no '=' */

  /* AES constants */
  HMAC_SIZE            = 16, /* bytes in a hmac */
  HMAC_WORDS           = HMAC_SIZE * 8 / 64, /* 64 bit words */
  HMAC_B64_LEN         = KV_BASE64_SIZE( 16 ), /* base64 length, no '=' */

  /* SHA512 hash contants */
  HASH_DIGEST_SIZE     = 64, /* bytes in a 512 bit digest */
  HASH_DIGEST_WORDS    = HASH_DIGEST_SIZE * 8 / 64, /* 64 bit words */
  HASH_DIGEST_B64_LEN  = KV_BASE64_SIZE( 64 ); /* base64 length, no '=' */

struct UserBuf;
struct ServiceBuf;
struct HmacDigest;

/* mmap with MADV_DONTDUMP to prevent data leaking into core dumps */
void * alloc_secure_mem( size_t len ) noexcept;
void free_secure_mem( void *p,  size_t len ) noexcept;
/* load secure mem from env or file */
bool load_secure_env( const char *env,  const char *unlnk_env,
                      const char *data,  void *&mem,  size_t &mem_sz ) noexcept;
bool load_secure_file( const char *fn,  void *&mem,  size_t &sz ) noexcept;
/* used internally to init if not already init */
bool init_kdf( const void *mem = NULL,  size_t mem_sz = 0 ) noexcept;

/* random nonce values */
struct Nonce {
  uint64_t nonce[ NONCE_WORDS ];
  void * operator new( size_t, void *ptr ) { return ptr; }

  void seed_random( void ) noexcept;
  void zero( void ) volatile { /* make the compiler execute */
    for ( size_t i = 0; i < NONCE_WORDS; i++ )
      this->nonce[ i ] = 0;
  }
  Nonce() {}
  Nonce( const Nonce &x ) {
    ::memcpy( this->nonce, x.nonce, NONCE_SIZE );
  }
  Nonce & operator=( const Nonce &x ) {
    ::memcpy( this->nonce, x.nonce, NONCE_SIZE );
    return *this;
  }
  Nonce operator^( const Nonce &x ) const {
    Nonce z;
    for ( size_t i = 0; i < NONCE_WORDS; i++ )
      z.nonce[ i ] = this->nonce[ i ] ^ x.nonce[ i ];
    return z;
  }
  Nonce operator^( const uint64_t *ptr ) const {
    Nonce z;
    for ( size_t i = 0; i < NONCE_WORDS; i++ )
      z.nonce[ i ] = this->nonce[ i ] ^ ptr[ i ];
    return z;
  }
  Nonce &operator^=( const Nonce &x ) {
    for ( size_t i = 0; i < NONCE_WORDS; i++ )
      this->nonce[ i ] ^= x.nonce[ i ];
    return *this;
  }
  bool operator==( const Nonce &x ) const { return this->cmp( x ) == 0; }
  bool operator!=( const Nonce &x ) const { return this->cmp( x ) != 0; }
  bool operator>( const Nonce &x )  const { return this->cmp( x ) > 0; }
  bool operator<( const Nonce &x )  const { return this->cmp( x ) < 0; }
  int cmp( const Nonce &x ) const {
    return ::memcmp( this->nonce, x.nonce, NONCE_SIZE );
  }
  uint8_t * digest( void ) const {
    return (uint8_t *) (void *) this->nonce;
  }
  size_t to_base64( char *buf ) const {
    return kv::bin_to_base64( this->digest(), NONCE_SIZE, buf, false );
  }
  char *to_base64_str( char *buf ) const {
    size_t sz = this->to_base64( buf );
    buf[ sz ] = '\0';
    return buf;
  }
  void from_base64( const char *buf ) {
    kv::base64_to_bin( buf, NONCE_B64_LEN, this->digest() );
  }
  bool get_base64( const char *buf,  size_t len ) {
    if ( len != NONCE_B64_LEN )
      return false;
    kv::base64_to_bin( buf, NONCE_B64_LEN, this->digest() );
    /* could check if random */
    return true;
  }
  void copy_from( const void *p ) {
    ::memcpy( this->nonce, p, NONCE_SIZE );
  }
  void print( void ) const noexcept;
};
/* SHA512 hashes */
struct HashDigest {
  uint64_t dig[ HASH_DIGEST_WORDS ];
  void * operator new( size_t, void *ptr ) { return ptr; }

  HashDigest() {}

  void zero( void ) volatile { /* make the compiler excute this */
    for ( size_t i = 0; i < HASH_DIGEST_WORDS; i++ )
      this->dig[ i ] = 0;
  }
  HashDigest & operator=( const HashDigest &x ) {
    ::memcpy( this->dig, x.dig, HASH_DIGEST_SIZE );
    return *this;
  }
  bool operator==( const HashDigest &x ) const { return this->cmp( x ) == 0; }
  bool operator!=( const HashDigest &x ) const { return this->cmp( x ) != 0; }
  bool operator>( const HashDigest &x )  const { return this->cmp( x ) > 0; }
  bool operator<( const HashDigest &x )  const { return this->cmp( x ) < 0; }
  int cmp( const HashDigest &x ) const {
    return ::memcmp( this->dig, x.dig, HASH_DIGEST_SIZE );
  }
  uint8_t * digest( void ) const {
    return (uint8_t *) (void *) this->dig;
  }
  /* for the IV of HMAC sandwidch */
  void get_hmac( size_t start,  uint64_t *out ) const {
    for ( size_t i = 0; i < HMAC_WORDS; i++ )
      out[ i ] = this->dig[ i + start ];
  }
  /* for the trailer of HMAC sandwich */
  const uint8_t * hmac_tail( size_t head_words ) const {
    return (uint8_t *) (void *) &this->dig[ head_words ];
  }
  size_t hmac_tail_sz( size_t head_words ) const {
    const uint8_t * end = (uint8_t *) (void *) &this->dig[ HASH_DIGEST_WORDS ];
    return end - this->hmac_tail( head_words );
  }
  size_t to_base64( char *buf ) const {
    return kv::bin_to_base64( this->digest(), HASH_DIGEST_SIZE, buf, false );
  }
  char *to_base64_str( char *buf ) const {
    size_t sz = this->to_base64( buf );
    buf[ sz ] = '\0';
    return buf;
  }
  void from_base64( const char *buf ) {
    kv::base64_to_bin( buf, HASH_DIGEST_B64_LEN, this->digest() );
  }
  void copy_from( const void *p ) {
    ::memcpy( this->dig, p, HASH_DIGEST_SIZE );
  }
  void copy_to( void *p ) const {
    ::memcpy( p, this->dig, HASH_DIGEST_SIZE );
  }
  /* hash bytes */
  void kdf_bytes( const void *data,  size_t datalen,
                  const void *data2 = NULL,  size_t datalen2 = 0 ) noexcept;
  /* compbine thse into a hash */
  void kdf_user_pwd( const UserBuf &u,  const CryptPass &pwd ) noexcept;
  void kdf_svc_pwd( const ServiceBuf &u,  const CryptPass &pwd ) noexcept;
  /* /dev/urandom key */
  void make_session_rand( void ) noexcept;
  /* combine these into a hash */
  void kdf_challenge_secret( const HmacDigest &secret_hmac,
                             const Nonce &snonce1,  const Nonce &snonce2,
                             const Nonce &cnonce1,  const Nonce &cnonce2,
                             uint64_t seqno,  uint64_t time,
                             uint32_t stage ) noexcept;
  void kdf_peer_nonce( const HashDigest &ha1,  const Nonce &snonce1,
                       const Nonce &snonce2 ) noexcept;
  /* use challenge as the AES key, hash as the plaintext, result -> this->dig */
  void encrypt_hash( const HashDigest &challenge_hash,
                     const HashDigest &hash ) noexcept;
  /* use challenge as the AES key, hash as the ciphertext, result -> this->dig*/
  void decrypt_hash( const HashDigest &challenge_hash,
                     const HashDigest &encrypted_hash ) noexcept;
  /* use key+nonce as the AES key, hash as the plaintext, result -> this->dig */
  void encrypt_key_nonce( const HashDigest &key_hash,  const Nonce &key_nonce,
                          const HashDigest &hash ) noexcept;
  /* use key+nonce as the AES key, hash as the ciphertext, result -> this->dig*/
  void decrypt_key_nonce( const HashDigest &key_hash,  const Nonce &key_nonce,
                          const HashDigest &hash ) noexcept;
  /* use current digest as the key/IV + ctr, hmac/IV,
   * data_out = ciphertext (datalen) + HMAC size (16) */
  void encrypt_hmac( const void *data,  size_t data_len,  void *data_out,
                     uint64_t ctr ) noexcept;
  /* use current digest as the key/IV + ctr, hmac/IV,
   * data_out = ciphertext (datalen) - HMAC size (16)
   * returns false if the HMAC test failes */
  bool decrypt_hmac( const void *data,  size_t data_len,  void *data_out,
                     uint64_t ctr ) noexcept;
  void print( void ) const noexcept;
};
/* Meow HMAC hashes */
struct HmacDigest {
  uint64_t dig[ HMAC_WORDS ];
  void * operator new( size_t, void *ptr ) { return ptr; }

  HmacDigest() {}
  void zero( void ) volatile { /* make the compiler execute */
    for ( size_t i = 0; i < HMAC_WORDS; i++ )
      this->dig[ i ] = 0;
  }
  HmacDigest & operator=( const HmacDigest &x ) {
    ::memcpy( this->dig, x.dig, HMAC_SIZE );
    return *this;
  }
  bool operator==( const HmacDigest &x ) const { return this->cmp( x ) == 0; }
  bool operator!=( const HmacDigest &x ) const { return this->cmp( x ) != 0; }
  bool operator>( const HmacDigest &x )  const { return this->cmp( x ) > 0; }
  bool operator<( const HmacDigest &x )  const { return this->cmp( x ) < 0; }
  int cmp( const HmacDigest &x ) const {
    return ::memcmp( this->dig, x.dig, HMAC_SIZE );
  }
  bool equals( const void *b ) const {
    return ::memcmp( this->dig, b, HMAC_SIZE ) == 0;
  }
  uint8_t * digest( void ) const {
    return (uint8_t *) (void *) this->dig;
  }
  void copy_from( const void *p ) {
    ::memcpy( this->dig, p, HMAC_SIZE );
  }
  size_t to_base64( char *buf ) const {
    return kv::bin_to_base64( this->digest(), HMAC_SIZE, buf, false );
  }
  char *to_base64_str( char *buf ) const {
    size_t sz = this->to_base64( buf );
    buf[ sz ] = '\0';
    return buf;
  }
  void from_base64( const char *buf ) {
    kv::base64_to_bin( buf, HMAC_B64_LEN, this->digest() );
  }
  void print( void ) const noexcept;
};

#define vec_sz sizeof( vec ) / sizeof( vec[ 0 ] )
struct MeowHmacDigest : public HmacDigest {
  /* HMAC( IV=digest[off..off+2], s1 + digest[off+2..8] ) */
  void calc_off( const HashDigest &ha1,  size_t off_words,
                 const void * s1,  size_t s1_len ) {
    meow_vec_t vec[ 2 ] = {
      { s1, s1_len },
      { ha1.hmac_tail( off_words + HMAC_WORDS ),
        ha1.hmac_tail_sz( off_words + HMAC_WORDS ) }
    };
    ha1.get_hmac( off_words, this->dig );
    kv_hash_meow128_vec( vec, vec_sz, &this->dig[ 0 ], &this->dig[ 1 ] );
  }
  /* HMAC( IV=digest[0..1], s1 + s2 + digest[2..8] ) */
  void calc_2( const HashDigest &ha1,
               const void * s1,  size_t s1_len,
               const void * s2,  size_t s2_len ) {
    meow_vec_t vec[ 3 ] = {
      { s1, s1_len }, { s2, s2_len },
      { ha1.hmac_tail( HMAC_WORDS ), ha1.hmac_tail_sz( HMAC_WORDS ) }
    };
    ha1.get_hmac( 0, this->dig );
    kv_hash_meow128_vec( vec, vec_sz, &this->dig[ 0 ], &this->dig[ 1 ] );
  }
  /* HMAC( IV=digest[0..1], s1 + s2 + s3 + digest[2..8] ) */
  void calc_3( const HashDigest &ha1,
               const void * s1,  size_t s1_len,
               const void * s2,  size_t s2_len,
               const void * s3,  size_t s3_len ) {
    meow_vec_t vec[ 4 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len },
      { ha1.hmac_tail( HMAC_WORDS ), ha1.hmac_tail_sz( HMAC_WORDS ) }
    };
    ha1.get_hmac( 0, this->dig );
    kv_hash_meow128_vec( vec, vec_sz, &this->dig[ 0 ], &this->dig[ 1 ] );
  }
  /* HMAC( IV=digest[0..1], s1 + s2 + s3 + s4 + digest[2..8] ) */
  void calc_4( const HashDigest &ha1,
           const void * s1,  size_t s1_len, const void * s2,  size_t s2_len,
           const void * s3,  size_t s3_len, const void * s4,  size_t s4_len ) {
    meow_vec_t vec[ 5 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len }, { s4, s4_len },
      { ha1.hmac_tail( HMAC_WORDS ), ha1.hmac_tail_sz( HMAC_WORDS ) }
    };
    ha1.get_hmac( 0, this->dig );
    kv_hash_meow128_vec( vec, vec_sz, &this->dig[ 0 ], &this->dig[ 1 ] );
  }
  void calc_5( const HashDigest &ha1,
           const void * s1,  size_t s1_len, const void * s2,  size_t s2_len,
           const void * s3,  size_t s3_len, const void * s4,  size_t s4_len,
           const void * s5,  size_t s5_len ) {
    meow_vec_t vec[ 6 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len }, { s4, s4_len },
      { s5, s5_len },
      { ha1.hmac_tail( HMAC_WORDS ), ha1.hmac_tail_sz( HMAC_WORDS ) }
    };
    ha1.get_hmac( 0, this->dig );
    kv_hash_meow128_vec( vec, vec_sz, &this->dig[ 0 ], &this->dig[ 1 ] );
  }
  void calc_8( const HashDigest &ha1,
           const void * s1,  size_t s1_len, const void * s2,  size_t s2_len,
           const void * s3,  size_t s3_len, const void * s4,  size_t s4_len,
           const void * s5,  size_t s5_len, const void * s6,  size_t s6_len,
           const void * s7,  size_t s7_len, const void * s8,  size_t s8_len ) {
    meow_vec_t vec[ 9 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len }, { s4, s4_len },
      { s5, s5_len }, { s6, s6_len }, { s7, s7_len }, { s8, s8_len },
      { ha1.hmac_tail( HMAC_WORDS ), ha1.hmac_tail_sz( HMAC_WORDS ) }
    };
    ha1.get_hmac( 0, this->dig );
    kv_hash_meow128_vec( vec, vec_sz, &this->dig[ 0 ], &this->dig[ 1 ] );
  }
};

struct PolyHmacDigest : public HmacDigest {
  /* HMAC( IV=digest[off..off+2], s1 + digest[off+2..8] ) */
  void calc_off( const HashDigest &ha1,  size_t off_words,
                 const void * s1,  size_t s1_len ) {
    poly1305_vec_t vec[ 2 ] = {
      { s1, s1_len },
      { ha1.hmac_tail( off_words + POLY1305_W64KEY ),
        ha1.hmac_tail_sz( off_words + POLY1305_W64KEY ) }
    };
    poly1305_auth_v( this->dig, vec, vec_sz, ha1.dig );
  }
  /* HMAC( IV=digest[0..1], s1 + s2 + digest[2..8] ) */
  void calc_2( const HashDigest &ha1,
               const void * s1,  size_t s1_len,
               const void * s2,  size_t s2_len ) {
    poly1305_vec_t vec[ 3 ] = {
      { s1, s1_len }, { s2, s2_len },
      { ha1.hmac_tail( POLY1305_W64KEY ), ha1.hmac_tail_sz( POLY1305_W64KEY ) }
    };
    poly1305_auth_v( this->dig, vec, vec_sz, ha1.dig );
  }
  /* HMAC( IV=digest[0..1], s1 + s2 + s3 + digest[2..8] ) */
  void calc_3( const HashDigest &ha1,
               const void * s1,  size_t s1_len,
               const void * s2,  size_t s2_len,
               const void * s3,  size_t s3_len ) {
    poly1305_vec_t vec[ 4 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len },
      { ha1.hmac_tail( POLY1305_W64KEY ), ha1.hmac_tail_sz( POLY1305_W64KEY ) }
    };
    poly1305_auth_v( this->dig, vec, vec_sz, ha1.dig );
  }
  /* HMAC( IV=digest[0..1], s1 + s2 + s3 + s4 + digest[2..8] ) */
  void calc_4( const HashDigest &ha1,
           const void * s1,  size_t s1_len, const void * s2,  size_t s2_len,
           const void * s3,  size_t s3_len, const void * s4,  size_t s4_len ) {
    poly1305_vec_t vec[ 5 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len }, { s4, s4_len },
      { ha1.hmac_tail( POLY1305_W64KEY ), ha1.hmac_tail_sz( POLY1305_W64KEY ) }
    };
    poly1305_auth_v( this->dig, vec, vec_sz, ha1.dig );
  }
  void calc_5( const HashDigest &ha1,
           const void * s1,  size_t s1_len, const void * s2,  size_t s2_len,
           const void * s3,  size_t s3_len, const void * s4,  size_t s4_len,
           const void * s5,  size_t s5_len ) {
    poly1305_vec_t vec[ 6 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len }, { s4, s4_len },
      { s5, s5_len },
      { ha1.hmac_tail( POLY1305_W64KEY ), ha1.hmac_tail_sz( POLY1305_W64KEY ) }
    };
    poly1305_auth_v( this->dig, vec, vec_sz, ha1.dig );
  }
  void calc_8( const HashDigest &ha1,
           const void * s1,  size_t s1_len, const void * s2,  size_t s2_len,
           const void * s3,  size_t s3_len, const void * s4,  size_t s4_len,
           const void * s5,  size_t s5_len, const void * s6,  size_t s6_len,
           const void * s7,  size_t s7_len, const void * s8,  size_t s8_len ) {
    poly1305_vec_t vec[ 9 ] = {
      { s1, s1_len }, { s2, s2_len }, { s3, s3_len }, { s4, s4_len },
      { s5, s5_len }, { s6, s6_len }, { s7, s7_len }, { s8, s8_len },
      { ha1.hmac_tail( POLY1305_W64KEY ), ha1.hmac_tail_sz( POLY1305_W64KEY ) }
    };
    poly1305_auth_v( this->dig, vec, vec_sz, ha1.dig );
  }
};
#undef vec_sz

struct CnonceRandom {
  static const size_t CNONCE_WORDS = 128;
  uint64_t buf[ CNONCE_WORDS ]; /* random buffer, 8192 bits */
  Nonce    val;                 /* the next nonce calculated */
  uint64_t ctr;                 /* index into buf[] */
  void * operator new( size_t, void *ptr ) { return ptr; }

  CnonceRandom() : ctr( 0 ) {}

  void refill_random( void ) noexcept;

  void swap( uint64_t &h ) {
    uint64_t x = h;
    h = this->buf[ this->ctr % CNONCE_WORDS ];
    this->buf[ this->ctr % CNONCE_WORDS ] = x;
    this->ctr++;
  }
  /* get next nonce value */
  const Nonce &calc( void ) noexcept {
    if ( this->ctr % CNONCE_WORDS == 0 )
      this->refill_random();
    for ( size_t i = 0; i < NONCE_WORDS; i++ )
      this->swap( this->val.nonce[ i ] );
    return this->val;
  }
};

struct Hash128Elem {
  uint32_t hash[ 4 ];
  Hash128Elem() {}
  Hash128Elem( const Hash128Elem &h1 ) {
    for ( size_t i = 0; i < 4; i++ )
      this->hash[ i ] = h1.hash[ i ];
  }
  Hash128Elem( const HmacDigest &hmac ) {
    ::memcpy( this->hash, hmac.digest(), sizeof( this->hash ) );
  }
  Hash128Elem( const Nonce &nonce ) {
    ::memcpy( this->hash, nonce.digest(), sizeof( this->hash ) );
  }
  bool operator==( const Hash128Elem &h1 ) const {
    for ( size_t i = 0; i < 4; i++ )
      if ( this->hash[ i ] != h1.hash[ i ] )
        return false;
    return true;
  }
  Hash128Elem &operator=( const Hash128Elem &h1 ) {
    for ( size_t i = 0; i < 4; i++ )
      this->hash[ i ] = h1.hash[ i ];
    return *this;
  }
  size_t operator&( size_t mod ) const {
    size_t h = (uint64_t) this->hash[ 0 ] | ((uint64_t) this->hash[ 1 ] << 32 );
    return h & mod;
  }
};

}
}

#endif
