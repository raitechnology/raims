#ifndef __rai__raims__rsa_h__
#define __rai__raims__rsa_h__

extern "C" {
/* in openssl/ossl_typ.h */
struct evp_pkey_ctx_st;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;
struct evp_md_ctx_st;
typedef struct evp_md_ctx_st EVP_MD_CTX;
}

#include <raikv/util.h>

namespace rai {
namespace ms {

/* DER ASN.1 format is in RFC5208 (https://tools.ietf.org/html/rfc5208)
 * DER -- "Distinguished Encoding Rules"
 *   https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/ */
/* if the bits changes, must adjust the length constants */
#if 1
#define RSA_BITS 1024
static const size_t MAX_RSA_DER_PRI_LEN     = 624, /* i2d private DER encoded */
                    MAX_RSA_DER_PRI_B64_LEN = KV_BASE64_SIZE( 624 ), /* no = */
                    MAX_RSA_DER_PUB_LEN     = 160, /* i2d public DER encoded */
                    MAX_RSA_DER_PUB_B64_LEN = KV_BASE64_SIZE( 160 ), /* no = */
                    MAX_RSA_SIGN_LEN        = 144, /* signature len */
                    MAX_RSA_SIGN_B64_LEN    = KV_BASE64_SIZE( 144 ); /* no = */
//static const size_t RSA_DER_PRI_LEN     = 608, /* i2d private DER encoded */
//                    RSA_DER_PRI_B64_LEN = KV_BASE64_SIZE( 608 ), /* no = */
//                    RSA_DER_PUB_LEN     = 140, /* i2d public DER encoded */
//                    RSA_DER_PUB_B64_LEN = KV_BASE64_SIZE( 140 ), /* no = */
//                    RSA_SIGN_LEN        = 128, /* signature len */
//                    RSA_SIGN_B64_LEN    = KV_BASE64_SIZE( 128 ); /* no = */
#endif
#if 0
#define RSA_BITS 2048
static const size_t RSA_DER_PRI_LEN     = 1193,/* i2d private */
                    RSA_DER_PRI_B64_LEN = KV_BASE64_SIZE( 1193 ),
                    RSA_DER_PUB_LEN     = 270, /* i2d public */
                    RSA_DER_PUB_B64_LEN = KV_BASE64_SIZE( 270 ),
                    RSA_SIGN_LEN        = 256, /* signature len */
                    RSA_SIGN_B64_LEN    = KV_BASE64_SIZE( 256 );
#endif

struct OpenSsl_RSA {
  EVP_PKEY_CTX * kctx;    /* key generator */
  EVP_PKEY     * keypair, /* generate key pair */
               * pub,     /* load public key */
               * pri;     /* load private key */
  EVP_MD_CTX   * md;

  OpenSsl_RSA()
    : kctx( 0 ), keypair( 0 ), pub( 0 ), pri( 0 ), md( 0 ) {}

  ~OpenSsl_RSA() {
    release( this->kctx );
    release( this->keypair );
    release( this->pub );
    release( this->pri );
    release( this->md );
  }
  /* free key mem */
  static void release( EVP_PKEY *&evp ) noexcept;
  /* free ctx mem */
  static void release( EVP_PKEY_CTX *&ctx ) noexcept;
  /* free md mem */
  static void release( EVP_MD_CTX *&md ) noexcept;
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
  /* sign msg with pri key */
  bool sign_msg( const void *data,  size_t len,  void *sig,
                 size_t &siglen ) noexcept;
  /* verify msg with pub key */
  bool verify_msg( const void *data,  size_t len,  const void *sig,
                   size_t siglen ) noexcept;
};

}
}
#endif
