#ifndef __rai__raims__ecdh_h__
#define __rai__raims__ecdh_h__

extern "C" {
/* in openssl/ossl_typ.h */
struct evp_pkey_ctx_st;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;
}

#include <raikv/util.h>

namespace rai {
namespace ms {

/*
 * $ openssl ecparam -list_curves
 * secp224r1 : NIST/SECG curve over a 224 bit prime field
 * secp256k1 : SECG curve over a 256 bit prime field
 * secp384r1 : NIST/SECG curve over a 384 bit prime field
 * secp521r1 : NIST/SECG curve over a 521 bit prime field
 * prime256v1: X9.62/SECG curve over a 256 bit prime field
 */
/* DER ASN.1 format is in RFC5208 (https://tools.ietf.org/html/rfc5208)
 * DER -- "Distinguished Encoding Rules"
 *   https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/ */
/* if the curve changes, must adjust the length constants */
#if 1
#define ECDH_NID_CURVE NID_X9_62_prime256v1
static const size_t MAX_ECDH_DER_PRI_LEN     = 128, /* i2d private DER encoded */
                    MAX_ECDH_DER_PRI_B64_LEN = KV_BASE64_SIZE( 128 ), /* no = */
                    MAX_ECDH_DER_PUB_LEN     =  80, /* i2d public DER encoded */
                    MAX_ECDH_DER_PUB_B64_LEN = KV_BASE64_SIZE( 80 ), /* no = */
                    MAX_ECDH_SECRET_LEN      =  48, /* shared secret len */
                    MAX_ECDH_SECRET_B64_LEN  = KV_BASE64_SIZE( 48 ); /* no = */
//static const size_t ECDH_DER_PRI_LEN     = 121, /* i2d private DER encoded */
//                    ECDH_DER_PRI_B64_LEN = KV_BASE64_SIZE( 121 ), /* no = */
//                    ECDH_DER_PUB_LEN     =  65, /* i2d public DER encoded */
//                    ECDH_DER_PUB_B64_LEN = KV_BASE64_SIZE( 65 ), /* no = */
//                    ECDH_SECRET_LEN      =  32, /* shared secret len */
//                    ECDH_SECRET_B64_LEN  = KV_BASE64_SIZE( 32 ); /* no = */
#endif
#if 0
#define ECDH_NID_CURVE NID_secp521r1
static const size_t ECDH_DER_PRI_LEN     = 223, /* i2d private */
                    ECDH_DER_PRI_B64_LEN = KV_BASE64_SIZE( 223 ),
                    ECDH_DER_PUB_LEN     = 133, /* i2d public */
                    ECDH_DER_PUB_B64_LEN = KV_BASE64_SIZE( 133 ),
                    ECDH_SECRET_LEN      =  66, /* shared secret len */
                    ECDH_SECRET_B64_LEN  = KV_BASE64_SIZE( 66 );
#endif

struct OpenSsl_ECDH {
  EVP_PKEY_CTX * pctx,    /* key parameters for EC, NID_X9_62_prime256v1 */
               * kctx,    /* key generator */
               * ssctx;   /* shared secret generator */
  EVP_PKEY     * keypair, /* generate key pair */
               * pub,     /* load public key */
               * pri,     /* load private key */
               * params;  /* params for EC, NID_X9_62_prime256v1 */

  OpenSsl_ECDH()
    : pctx( 0 ), kctx( 0 ), ssctx( 0 ),
      keypair( 0 ), pub( 0 ), pri( 0 ), params( 0 ) {}

  ~OpenSsl_ECDH() {
    release( this->pctx );
    release( this->kctx );
    release( this->ssctx );
    release( this->keypair );
    release( this->pub );
    release( this->pri );
    release( this->params );
  }
  /* free key mem */
  static void release( EVP_PKEY *&evp ) noexcept;
  /* free ctx mem */
  static void release( EVP_PKEY_CTX *&ctx ) noexcept;
  /* initialize the PKEY_CTX for generating keys */
  bool init_ctx( void ) noexcept;
  /* create a PKEY by using the parameters above in init_ctx() */
  bool paramgen( EVP_PKEY *&k ) noexcept;
  /* set buf to PEM text if success && buflen >= PEM len */
  bool private_to_pem( char *buf, size_t &buflen ) noexcept;
  /* set buf to PEM text if success && buflen >= PEM len */
  bool public_to_pem( char *buf,  size_t &buflen ) noexcept;
  /* -----BEGIN PRIVATE KEY----- */
  bool pem_to_private( const char *data,  size_t len ) noexcept;
  /* -----BEGIN PUBLIC KEY----- */
  bool pem_to_public( const char *data,  size_t len ) noexcept;
  /* PKCS#8 unencrypted PrivateKeyInfo decoder (DER ASN.1 fmt) */
  bool d2i_private( const void *data,  size_t len ) noexcept;
  /* decoder for the DER binary format */
  bool d2i_public( const void *data,  size_t len ) noexcept;
  /* encode to public unencrypted DER binary format */
  bool i2d_public( void *data,  size_t &len ) noexcept;
  /* encode private to unencrypted DER binary format */
  bool i2d_private( void *data,  size_t &len ) noexcept;
  /* generate a new keypair, public and private parts */
  bool gen_key( void ) noexcept;
  /* compute shared secret using private + public (peer) keys,
   * ecdh.shared_secret( alice.pri, bob.pub, secret, secretlen ) */
  bool shared_secret( EVP_PKEY *pri_key,  EVP_PKEY *pub_key,
                      void *secret,  size_t &secretlen ) noexcept;
};

}
}
#endif
