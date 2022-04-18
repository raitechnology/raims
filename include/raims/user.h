#ifndef __rai__raims__user_h__
#define __rai__raims__user_h__

#include <raikv/util.h>
#include <raims/ec25519.h>
#include <raims/ed25519.h>
#include <raims/crypt.h>
#include <raims/config_tree.h>
#include <raimd/md_msg.h>

namespace rai {
namespace ms {
static const size_t MAX_USER_LEN    = 128, /* strlen( user ) */
                    MAX_SERVICE_LEN = 128, /* strlen( service ) */
                    MAX_TIME_LEN    = 32;  /* strlen( create ) */

typedef EC25519 ECDH; /* elliptic curve diffie-hellman */
typedef ED25519 DSA;  /* digital signature algo */

static const size_t
       ECDH_KEY_LEN            = EC25519_KEY_LEN,
       ECDH_CIPHER_KEY_LEN     = EC25519_KEY_LEN + HMAC_SIZE,
       ECDH_CIPHER_B64_LEN     = KV_BASE64_SIZE( ECDH_CIPHER_KEY_LEN ),
       DSA_KEY_LEN             = ED25519_KEY_LEN,
       DSA_SIGN_LEN            = ED25519_SIG_LEN,
       DSA_CIPHER_KEY_LEN      = DSA_KEY_LEN + HMAC_SIZE,
       DSA_CIPHER_B64_LEN      = KV_BASE64_SIZE( DSA_CIPHER_KEY_LEN ),
       DSA_CIPHER_SIGN_LEN     = DSA_SIGN_LEN + HMAC_SIZE,
       DSA_CIPHER_SIGN_B64_LEN = KV_BASE64_SIZE( DSA_CIPHER_SIGN_LEN );
#if 0
static const size_t 
       MAX_RSA_CIPHER_PRI_LEN      = MAX_RSA_DER_PRI_LEN + HMAC_SIZE,
       MAX_RSA_CIPHER_PUB_LEN      = MAX_RSA_DER_PUB_LEN + HMAC_SIZE,
       MAX_RSA_CIPHER_SIGN_LEN     = MAX_RSA_SIGN_LEN + HMAC_SIZE,
       MAX_RSA_CIPHER_PRI_B64_LEN  = KV_BASE64_SIZE( MAX_RSA_CIPHER_PRI_LEN ),
       MAX_RSA_CIPHER_PUB_B64_LEN  = KV_BASE64_SIZE( MAX_RSA_CIPHER_PUB_LEN ),
       MAX_RSA_CIPHER_SIGN_B64_LEN = KV_BASE64_SIZE( MAX_RSA_CIPHER_SIGN_LEN );
#endif

static inline void copy_max( char *out,  size_t &out_len,   size_t max_len,
                             const void *in,  size_t in_len ) {
  if ( in_len > max_len ) in_len = max_len;
  ::memcpy( out, in, in_len );
  out_len = in_len;
}

static inline int cmp_bytes( const void *s, size_t s_len, const void *t,
                             size_t t_len )
{
  int n = ::memcmp( s, t, kv::min_int<size_t>( s_len, t_len ) );
  if ( n < 0 )
    return -1;
  if ( n == 0 && s_len <= t_len )
    return ( s_len < t_len ) ? -1 : 0;
  return 1;
}

bool make_path( char *path,  size_t path_len, const char *fmt, ... )
  noexcept __attribute__((format(printf,3,4)));

bool init_pass( ConfigTree *tree,  CryptPass &pass,
                const char *dir_namne ) noexcept;

enum WhichPubPri {
  DO_PUB  = 1,
  DO_PRI  = 2,
  DO_BOTH = 3
};

struct UserBuf {
  char   user[ MAX_USER_LEN ],
         service[ MAX_SERVICE_LEN ],
         create[ MAX_TIME_LEN ],
         expires[ MAX_TIME_LEN ],
         revoke[ MAX_TIME_LEN ],
         pri[ KV_ALIGN( ECDH_CIPHER_B64_LEN, 4 ) ],
         pub[ KV_ALIGN( ECDH_CIPHER_B64_LEN, 4 ) ];
  size_t user_len,
         service_len,
         create_len,
         expires_len,
         revoke_len,
         pri_len,
         pub_len;

 void * operator new( size_t, void *ptr ) { return ptr; }
 void operator delete( void *ptr ) { ::free( ptr ); }

  UserBuf() : user_len( 0 ), service_len( 0 ), create_len( 0 ),
              expires_len( 0 ), revoke_len( 0 ), pri_len( 0 ), pub_len( 0 ) {}
  UserBuf( const UserBuf &b )          { this->copy( b ); }
  UserBuf( const ConfigTree::User &u ) { this->copy( u ); }
  ~UserBuf() {
    this->zero();
  }
  void copy( const ConfigTree::User &u ) noexcept;
  void copy( const UserBuf &b ) { ::memcpy( this, &b, sizeof( *this ) ); }
  void zero( void ) volatile {
    ::memset( (void *) this, 0, sizeof( *this ) );
  }
  /* compare x and y, user name */
  static int cmp_user( const UserBuf &x,  const UserBuf &y ) noexcept;
  /* compare x and y, user name with create time */
  static int cmp_user_create( const UserBuf &x,  const UserBuf &y ) noexcept;
  /* convert create, expires into timestamps and return expire time */
  uint64_t get_expires( void ) const noexcept;
  /* convert create, revoke into timestamps and return revoke time */
  uint64_t get_revoke( void ) const noexcept;
  /* generate a key pair, pri[] pub[] are encrypted with pass + times */
  bool gen_key( const char *user,  size_t ulen,  const char *svc,  size_t slen,
              const char *expire,  size_t elen, const CryptPass &pwd ) noexcept;
  /* encrypt the keys, pub or pri */
  bool put_ecdh( const CryptPass &pwd,  ECDH &ec,
                 WhichPubPri put_op ) noexcept;
  /* decrypt the keys, pub or pri */
  bool get_ecdh( const CryptPass &pwd,  ECDH &ec,
                 WhichPubPri get_op,  void *pub_key_out = NULL,
                 size_t *pub_key_len = NULL ) const noexcept;
  /* print for config */
  bool print_yaml( int indent,  const char *fn = NULL,
                   bool include_pri = false ) noexcept;
  /* print for config */
  bool print_json( int indent,  char sep = 0,  const char *fn = NULL,
                   bool include_pri = false ) noexcept;
  /* test if user can decrypt keys */
  static bool test_user( const CryptPass &pwd,
                         const ConfigTree::User &u ) noexcept;
  /* read old pass and convert to new pass */
  bool change_pass( const CryptPass &old_pwd,
                    const CryptPass &new_pwd ) noexcept;
};

struct RevokeElem;
struct UserElem {
  UserElem   * next;
  RevokeElem * revoke;
  UserBuf      user;
  size_t       sig_len;
  char         sig[ DSA_CIPHER_SIGN_B64_LEN ];

 void * operator new( size_t, void *ptr ) { return ptr; }
 void operator delete( void *ptr ) { ::free( ptr ); }

  UserElem( const UserBuf &b ) : next( 0 ), revoke( 0 ), user( b ) {
    this->sig_len = 0;
    this->sig[ 0 ] = '\0';
  }
  UserElem( const ConfigTree::User &b ) : next( 0 ), revoke( 0 ), user( b ) {
    this->sig_len = 0;
    this->sig[ 0 ] = '\0';
  }
  UserElem( const UserElem &b ) : next( 0 ), revoke( 0 ), user( b.user ) {
    this->sig_len = b.sig_len;
    ::memcpy( this->sig, b.sig, DSA_CIPHER_SIGN_B64_LEN );
  }
  ~UserElem() {
    this->sig_len = 0;
    ::memset( this->sig, 0, sizeof( this->sig ) );
  }
  bool print_yaml( const char *fn,  bool include_pri ) noexcept;

  bool print_yaml_count( const char *fn,  bool include_pri,
                         size_t count ) noexcept;
  bool print_json( const char *fn,  bool include_pri ) noexcept;

  bool print_json_count( const char *fn,  bool include_pri,
                         size_t count ) noexcept;
};

struct RevokeElem {
  RevokeElem * next;
  UserElem   * user;
  size_t       sig_len;
  char         sig[ DSA_CIPHER_SIGN_B64_LEN ];

 void * operator new( size_t, void *ptr ) { return ptr; }
 void operator delete( void *ptr ) { ::free( ptr ); }

  RevokeElem( UserElem *u,  RevokeElem *r = NULL ) : next( 0 ), user( u ) {
    if ( r != NULL ) {
      this->sig_len = r->sig_len;
      ::memcpy( this->sig, r->sig, r->sig_len );
    }
    else {
      this->sig_len = 0;
      this->sig[ 0 ] = '\0';
    }
    u->revoke = this;
  }
};

struct UserHmacData {
  ECDH           ec;
  UserBuf      & user;
  HashDigest     kdf_hash;
  PolyHmacDigest user_hmac,
                 revoke_hmac;

  UserHmacData( UserBuf &u ) : user( u ) {}
  ~UserHmacData() {
    this->zero();
  }
  void zero( void ) volatile {
    this->kdf_hash.zero();
    this->user_hmac.zero();
    this->revoke_hmac.zero();
  }
  bool decrypt( const CryptPass &pwd,  WhichPubPri get_op ) noexcept;
  bool calc_secret_hmac( UserHmacData &data2,
                         PolyHmacDigest &secret_hmac ) noexcept;
  void calc_hello_key( ServiceBuf &svc,  HashDigest &ha ) noexcept;
};

typedef kv::SLinkList<UserElem> UserList;
typedef kv::SLinkList<RevokeElem> RevokeList;

struct ServiceBuf {
  char       service[ MAX_SERVICE_LEN ],
             create[ MAX_TIME_LEN ],
             pri[ KV_ALIGN( DSA_CIPHER_B64_LEN, 4 ) ],
             pub[ KV_ALIGN( DSA_CIPHER_B64_LEN, 4 ) ],
             pub_key[ KV_ALIGN( DSA_KEY_LEN, 4 ) ];
  size_t     service_len,
             create_len,
             pri_len,
             pub_len,
             pub_key_len;
  UserList   users;
  RevokeList revoke;

  ServiceBuf() : service_len( 0 ), create_len( 0 ), pri_len( 0 ), pub_len( 0 ),
                 pub_key_len( 0 ) {}
  ~ServiceBuf() {
    this->release();
  }
  void release( void ) {
    this->release_users();
    size_t hdr_size = ( ( (uint8_t *) (void *) &this->users ) -
                        ( (uint8_t *) (void *) this ) );
    ::memset( (void *) this, 0, hdr_size );
  }
  void release_users( void ) {
    while ( ! this->users.is_empty() )
      delete this->users.pop_hd();
    while ( ! this->revoke.is_empty() )
      delete this->revoke.pop_hd();
  }
  /* merge user config with signatures in svc */
  void load_service( const ConfigTree &tree,
                     const ConfigTree::Service &svc ) noexcept;
  /* decrypt sigs and check with the pub key */
  bool check_signatures( const CryptPass &pass ) noexcept;
  /* duplicate svc, used to construct a new password enc */
  void copy( const ServiceBuf &svc ) noexcept;
  /* copy the config tree service to this */
  void copy( const ConfigTree::Service &svc ) noexcept;
  /* generate a key pair, pri[] pub[] are encrypted with pass + times */
  bool gen_key( const char *svc,  size_t slen,  const CryptPass &pwd ) noexcept;
  /* sign the users in list users with pri key */
  bool sign_users( DSA *dsa,  const CryptPass &pwd ) noexcept;
  /* encrypt the keys, pub or pri */
  bool put_dsa( const CryptPass &pwd,  DSA &dsa,
                WhichPubPri put_op ) noexcept;
  /* decrypt the keys, pub or pri */
  bool get_dsa( const CryptPass &pwd,  DSA &dsa,
                WhichPubPri get_op ) noexcept;
  /* append user to users list and revoke, if revoked */
  void add_user( const UserBuf &u ) noexcept;
  void add_user( const UserElem &u ) noexcept;
  void add_user( const ConfigTree::User &u ) noexcept;
  /* remove all instances of user */
  bool remove_user( const char *user,  size_t user_len ) noexcept;
  /* revoke all instances of user */
  bool revoke_user( const char *user,  size_t user_len ) noexcept;
  /* print json config format */
  bool print_yaml( int indent,  const char *fn = NULL,
                   bool include_pri = false ) noexcept;
  /* print json config format */
  bool print_json( int indent,  char sep = 0,  const char *fn = NULL,
                   bool include_pri = false ) noexcept;
  /* read old pass and convert to new pass */
  bool change_pass( const CryptPass &old_pwd,
                    const CryptPass &new_pwd ) noexcept;
};

struct HmacKdf {
  HashDigest kdf_pwd; /* the AES key, a key derived passwd */
  uint64_t & ctr;     /* ctr mode AES offset */

  HmacKdf( uint64_t & c ) : ctr( c ) {}
  ~HmacKdf() { this->zero(); }
  void zero( void ) volatile { this->kdf_pwd.zero(); } /* avoid leaking pass */
  /* svc + create + pass = kdf_pwd */
  void init_kdf( const UserBuf &b,  const CryptPass &pwd ) {
    this->kdf_pwd.kdf_user_pwd( b, pwd );
  }
  /* user + svc + create + pass = kdf_pwd */
  void init_kdf( const ServiceBuf &b,  const CryptPass &pwd ) {
    this->kdf_pwd.kdf_svc_pwd( b, pwd );
  }
};
/* plain + pass -> hmac( kdf, aes( kdf, plain ) ) + aes( kdf, plain )  */
template< size_t MAX_CIPHER_LEN, size_t MAX_PLAIN_LEN >
struct HmacDecrypt : public HmacKdf {
  uint8_t cipher[ MAX_CIPHER_LEN ], /* base64 -> encrypted binary */
          plain[ MAX_PLAIN_LEN ];   /* ecrypted binary -> plain */
  size_t  cipher_len,
          plain_len;

  HmacDecrypt( uint64_t & c ) : HmacKdf( c ), cipher_len( 0 ), plain_len( 0 ) {
    this->zero();
  }
  ~HmacDecrypt() { this->zero(); }
  void zero( void ) volatile {
    ::memset( (void *) this->cipher, 0, sizeof( this->cipher ) );
    ::memset( (void *) this->plain, 0, sizeof( this->plain ) );
    this->HmacKdf::zero();
  }

  bool decrypt( const UserBuf &b,  const char *b64,  size_t b64_len ) {
    return this->decrypt( b.user, (int) b.user_len, b64, b64_len );
  }
  bool decrypt( const ServiceBuf &b,  const char *b64,  size_t b64_len ) {
    return this->decrypt( b.service, (int) b.service_len, b64, b64_len );
  }
  bool decrypt( const char *n,  int l,  const char *b64,  size_t b64_len ) {
    if ( KV_BASE64_BIN_SIZE( b64_len ) > MAX_CIPHER_LEN ) {
      fprintf( stderr, "Bad base64 cipher size \"%.*s\"\n", l, n );
      return false;
    }
    this->cipher_len = kv::base64_to_bin( b64, b64_len, this->cipher );
    if ( this->cipher_len < HMAC_SIZE || this->cipher_len > MAX_CIPHER_LEN ) {
      fprintf( stderr, "Bad cipher encoding for \"%.*s\"\n", l, n );
      return false;
    }
    if ( ! this->kdf_pwd.decrypt_hmac( this->cipher, this->cipher_len,
                                       this->plain, this->ctr ) ) {
      fprintf( stderr, "Bad hmac check for \"%.*s\", pass may be wrong\n", l,n);
      return false;
    }
    this->plain_len = this->cipher_len - HMAC_SIZE;
    return true;
  }
};
/* hmac( kdf, aes( kdf, plain ) ) + aes( kdf, plain ) -> plain */
template< size_t MAX_CIPHER_LEN, size_t MAX_PLAIN_LEN >
struct HmacEncrypt : public HmacKdf {
  uint8_t    cipher[ MAX_CIPHER_LEN ], /* encrypted binary -> base64 */
             plain[ MAX_PLAIN_LEN ];   /* plain -> encrypted binary */
  size_t     cipher_len,
             plain_len;

  HmacEncrypt( uint64_t & c ) : HmacKdf( c ), cipher_len( 0 ), plain_len( 0 ) {
    this->zero();
  }
  ~HmacEncrypt() { this->zero(); }
  void zero( void ) volatile {
    ::memset( (void *) this->cipher, 0, sizeof( this->cipher ) );
    ::memset( (void *) this->plain, 0, sizeof( this->plain ) );
    this->HmacKdf::zero();
  }
  bool encrypt( void *out,  size_t &out_size ) {
    this->kdf_pwd.encrypt_hmac( this->plain, this->plain_len, this->cipher,
                                this->ctr );
    this->cipher_len = this->plain_len + HMAC_SIZE;
    if ( KV_BASE64_SIZE( this->cipher_len ) > out_size ) {
      fprintf( stderr, "base64 sz %u > %u\n",
               (uint32_t) this->cipher_len, (uint32_t) out_size );
      out_size = 0;
      return false;
    }
    out_size = kv::bin_to_base64( this->cipher, this->cipher_len, out, false );
    return true;
  }
};

}
}
#endif
