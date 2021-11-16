#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <raims/rsa.h>

using namespace rai;
using namespace ms;

void
OpenSsl_RSA::release( EVP_PKEY *&evp ) noexcept
{
  if ( evp != NULL ) {
    EVP_PKEY_free( evp );
    evp = NULL;
  }
}
void
OpenSsl_RSA::release( EVP_PKEY_CTX *&ctx ) noexcept
{
  if ( ctx != NULL ) {
    EVP_PKEY_CTX_free( ctx );
    ctx = NULL;
  }
}
void
OpenSsl_RSA::release( EVP_MD_CTX *&md ) noexcept
{
  if ( md != NULL ) {
    EVP_MD_CTX_free( md );
    md = NULL;
  }
}
/* set buf to PEM text if success && buflen >= PEM len */
bool
OpenSsl_RSA::private_to_pem( char *buf,  size_t &buflen ) noexcept
{
  BIO      * bio  = BIO_new( BIO_s_mem() );
  char     * text = NULL;
  EVP_PKEY * k    = ( this->keypair ? this->keypair : this->pri );
  bool       res  = ( PEM_write_bio_PrivateKey( bio, k, NULL, NULL, 0,
                                                NULL, NULL ) > 0 );
  if ( res ) {
    BIO_flush( bio );
    int len = BIO_get_mem_data( bio, &text );
    if ( (size_t) len <= buflen ) {
      ::memcpy( buf, text, len );
      buflen = len;
    }
    else {
      buflen = len;
      res = false;
    }
  }
  else {
    buflen = 0;
  }
  BIO_free_all( bio );
  return res;
}
/* set buf to PEM text if success && buflen >= PEM len */
bool
OpenSsl_RSA::public_to_pem( char *buf,  size_t &buflen ) noexcept
{
  BIO      * bio  = BIO_new( BIO_s_mem() );
  char     * text = NULL;
  EVP_PKEY * k    = ( this->keypair ? this->keypair : this->pub );
  bool       res  = ( PEM_write_bio_PUBKEY( bio, k ) > 0 );
  if ( res ) {
    BIO_flush( bio );
    int len = BIO_get_mem_data( bio, &text );
    if ( (size_t) len <= buflen ) {
      ::memcpy( buf, text, len );
      buflen = len;
    }
    else {
      buflen = len;
      res = false;
    }
  }
  else {
    buflen = 0;
  }
  BIO_free_all( bio );
  return res;
}
/* -----BEGIN PRIVATE KEY----- */
bool
OpenSsl_RSA::pem_to_private( const char *data,  size_t len ) noexcept
{
  BIO * bio = BIO_new_mem_buf( data, len );
  release( this->pri );
  this->pri = PEM_read_bio_PrivateKey( bio, NULL, NULL, NULL );
  BIO_free_all( bio );
  return this->pri != NULL;
}
/* -----BEGIN PUBLIC KEY----- */
bool
OpenSsl_RSA::pem_to_public( const char *data,  size_t len ) noexcept
{
  BIO * bio = BIO_new_mem_buf( data, len );
  release( this->pub );
  this->pub = PEM_read_bio_PUBKEY( bio, NULL, NULL, NULL );
  BIO_free_all( bio );
  return this->pub != NULL;
}
/* PKCS#8 unencrypted PrivateKeyInfo decoder (DER ASN.1 fmt) */
bool
OpenSsl_RSA::d2i_private( const void *data,  size_t len ) noexcept
{
  const uint8_t *cbuf = (const uint8_t *) data;
  if ( d2i_PrivateKey( EVP_PKEY_RSA, &this->pri, &cbuf, len ) == NULL )
    return false;
  return true;
}
/* decoder for the DER binary format */
bool
OpenSsl_RSA::d2i_public( const void *data,  size_t len ) noexcept
{
  const uint8_t *cbuf = (const uint8_t *) data;
  if ( d2i_PublicKey( EVP_PKEY_RSA, &this->pub, &cbuf, len ) == NULL )
    return false;
  return true;
}
/* encode to public unencrypted DER binary format */
bool
OpenSsl_RSA::i2d_public( void *data,  size_t &len ) noexcept
{
  uint8_t  * buf = (uint8_t *) data;
  EVP_PKEY * k   = ( this->keypair ? this->keypair : this->pub );
  int res = i2d_PublicKey( k, ( buf == NULL ? NULL : &buf ) );
  len = (size_t) ( res < 0 ? 0 : res );
  return res > 0;
}
/* encode private to unencrypted DER binary format */
bool
OpenSsl_RSA::i2d_private( void *data,  size_t &len ) noexcept
{
  uint8_t  * buf = (uint8_t *) data;
  EVP_PKEY * k   = ( this->keypair ? this->keypair : this->pri );
  int res = i2d_PrivateKey( k, ( buf == NULL ? NULL : &buf ) );
  len = (size_t) ( res < 0 ? 0 : res );
  return res > 0;
}
/* generate a new keypair, public and private parts */
bool
OpenSsl_RSA::gen_key( void ) noexcept
{
  if ( this->kctx == NULL )
    if ( (this->kctx = EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL )) == NULL )
      return false;
  if ( EVP_PKEY_keygen_init( this->kctx ) <= 0 )
    return false;
  release( this->keypair );
  EVP_PKEY_CTX_set_rsa_keygen_bits( this->kctx, 1024 );
  if ( EVP_PKEY_keygen( this->kctx, &this->keypair ) <= 0 )
    return false;
  return true;
}
/* sign msg with pri key */
bool
OpenSsl_RSA::sign_msg( const void *data,  size_t len,  void *sig,  
                       size_t &siglen ) noexcept
{
  EVP_PKEY * k   = ( this->keypair ? this->keypair : this->pri );
  bool       res = true;
  if ( this->md == NULL )
    this->md = EVP_MD_CTX_create();
  if ( k == NULL || this->md == NULL )
    res = false;
  else {
    if ( EVP_DigestSignInit( this->md, NULL, EVP_sha512(), NULL, k ) <= 0 ||
         EVP_DigestSignUpdate( this->md, data, len ) <= 0 ||
         EVP_DigestSignFinal( this->md, (uint8_t *) sig, &siglen ) <= 0 )
    res = false;
  }
  if ( this->md != NULL )
    EVP_MD_CTX_reset( this->md );
  return res;
}
/* verify msg with pub key */
bool
OpenSsl_RSA::verify_msg( const void *data,  size_t len,  const void *sig,
                         size_t siglen ) noexcept
{
  EVP_PKEY * k   = ( this->keypair ? this->keypair : this->pub );
  bool       res = true;
  if ( this->md == NULL )
    this->md = EVP_MD_CTX_create();
  if ( k == NULL || this->md == NULL )
    res = false;
  else {
    if ( EVP_DigestVerifyInit( this->md, NULL, EVP_sha512(), NULL, k ) <= 0 ||
         EVP_DigestVerifyUpdate( this->md, data, len ) <= 0 ||
         EVP_DigestVerifyFinal( this->md, (const uint8_t *) sig, siglen ) <= 0 )
    res = false;
  }
  if ( this->md != NULL )
    EVP_MD_CTX_reset( this->md );
  return res;
}
