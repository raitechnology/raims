#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <raims/ecdh.h>

using namespace rai;
using namespace ms;

void
OpenSsl_ECDH::release( EVP_PKEY *&evp ) noexcept
{
  if ( evp != NULL ) {
    EVP_PKEY_free( evp );
    evp = NULL;
  }
}
void
OpenSsl_ECDH::release( EVP_PKEY_CTX *&ctx ) noexcept
{
  if ( ctx != NULL ) {
    EVP_PKEY_CTX_free( ctx );
    ctx = NULL;
  }
}
/* initialize the PKEY_CTX for generating keys */
bool
OpenSsl_ECDH::init_ctx( void ) noexcept
{
  this->pctx = EVP_PKEY_CTX_new_id( EVP_PKEY_EC, NULL );
  if ( this->pctx == NULL )
    return false;
  if ( EVP_PKEY_paramgen_init( this->pctx ) <= 0 ||
       EVP_PKEY_CTX_set_ec_paramgen_curve_nid( this->pctx,
                                               /* NID_X9_62_prime256v1 */
                                               ECDH_NID_CURVE ) <= 0 )
    return false;
  return true;
}
/* create a PKEY by using the parameters above in init_ctx() */
bool
OpenSsl_ECDH::paramgen( EVP_PKEY *&k ) noexcept
{
  if ( this->pctx == NULL ) {
    if ( ! this->init_ctx() )
      return false;
  }
  return EVP_PKEY_paramgen( this->pctx, &k ) > 0;
}
/* set buf to PEM text if success && buflen >= PEM len */
bool
OpenSsl_ECDH::private_to_pem( char *buf,  size_t &buflen ) noexcept
{
  BIO      * bio  = BIO_new( BIO_s_mem() );
  char     * text = NULL;
  EVP_PKEY * k    = ( this->keypair ? this->keypair : this->pri );
  bool       res  = ( PEM_write_bio_PrivateKey( bio, k, NULL, NULL, 0,
                                                NULL, NULL ) > 0 );
  if ( res ) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
    BIO_flush( bio );
#pragma GCC diagnostic pop
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
OpenSsl_ECDH::public_to_pem( char *buf,  size_t &buflen ) noexcept
{
  BIO      * bio  = BIO_new( BIO_s_mem() );
  char     * text = NULL;
  EVP_PKEY * k    = ( this->keypair ? this->keypair : this->pub );
  bool       res  = ( PEM_write_bio_PUBKEY( bio, k ) > 0 );
  if ( res ) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
    BIO_flush( bio );
#pragma GCC diagnostic pop
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
OpenSsl_ECDH::pem_to_private( const char *data,  size_t len ) noexcept
{
  BIO * bio = BIO_new_mem_buf( data, len );
  release( this->pri );
  this->pri = PEM_read_bio_PrivateKey( bio, NULL, NULL, NULL );
  BIO_free_all( bio );
  return this->pri != NULL;
}
/* -----BEGIN PUBLIC KEY----- */
bool
OpenSsl_ECDH::pem_to_public( const char *data,  size_t len ) noexcept
{
  BIO * bio = BIO_new_mem_buf( data, len );
  release( this->pub );
  this->pub = PEM_read_bio_PUBKEY( bio, NULL, NULL, NULL );
  BIO_free_all( bio );
  return this->pub != NULL;
}
/* PKCS#8 unencrypted PrivateKeyInfo decoder (DER ASN.1 fmt) */
bool
OpenSsl_ECDH::d2i_private( const void *data,  size_t len ) noexcept
{
  const uint8_t *cbuf = (const uint8_t *) data;
  if ( this->pri == NULL )
    if ( ! this->paramgen( this->pri ) )
      return false;
  if ( d2i_PrivateKey( EVP_PKEY_EC, &this->pri, &cbuf, len ) == NULL )
    return false;
  return true;
}
/* decoder for the DER binary format */
bool
OpenSsl_ECDH::d2i_public( const void *data,  size_t len ) noexcept
{
  const uint8_t *cbuf = (const uint8_t *) data;
  if ( this->pub == NULL )
    if ( ! this->paramgen( this->pub ) )
      return false;
  if ( d2i_PublicKey( EVP_PKEY_EC, &this->pub, &cbuf, len ) == NULL )
    return false;
  return true;
}
/* encode to public unencrypted DER binary format */
bool
OpenSsl_ECDH::i2d_public( void *data,  size_t &len ) noexcept
{
  uint8_t  * buf = (uint8_t *) data;
  EVP_PKEY * k   = ( this->keypair ? this->keypair : this->pub );
  if ( k == NULL ) k = ( this->keypair ? this->keypair : this->pub );
  int res = i2d_PublicKey( k, ( buf == NULL ? NULL : &buf ) );
  len = (size_t) ( res < 0 ? 0 : res );
  return res > 0;
}
/* encode private to unencrypted DER binary format */
bool
OpenSsl_ECDH::i2d_private( void *data,  size_t &len ) noexcept
{
  uint8_t  * buf = (uint8_t *) data;
  EVP_PKEY * k   = ( this->keypair ? this->keypair : this->pri );
  if ( k == NULL ) k = ( this->keypair ? this->keypair : this->pri );
  int res = i2d_PrivateKey( k, ( buf == NULL ? NULL : &buf ) );
  len = (size_t) ( res < 0 ? 0 : res );
  return res > 0;
}
/* generate a new keypair, public and private parts */
bool
OpenSsl_ECDH::gen_key( void ) noexcept
{
  if ( this->params == NULL )
    if ( ! this->paramgen( this->params ) )
      return false;
  if ( this->kctx == NULL )
    if ( (this->kctx = EVP_PKEY_CTX_new( this->params, NULL )) == NULL )
      return false;
  if ( EVP_PKEY_keygen_init( this->kctx ) <= 0 )
    return false;
  release( this->keypair );
  if ( EVP_PKEY_keygen( this->kctx, &this->keypair ) <= 0 )
    return false;
  return true;
}
/* compute shared secret using private + public (peer) keys */
bool
OpenSsl_ECDH::shared_secret( EVP_PKEY *pri_key,  EVP_PKEY *pub_key,
                             void *secret,  size_t &secretlen ) noexcept
{
  release( this->ssctx );
  this->ssctx = EVP_PKEY_CTX_new( pri_key, NULL );
  if ( EVP_PKEY_derive_init( this->ssctx ) <= 0 )
    return false;
  if ( EVP_PKEY_derive_set_peer( this->ssctx, pub_key ) <= 0 )
    return false;
  uint8_t *sec = (uint8_t *) secret;
  if ( EVP_PKEY_derive( this->ssctx, sec, &secretlen ) <= 0 )
    return false;
  return true;
}
