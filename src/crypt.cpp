#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <raikv/os_file.h>
#include <raikv/atom.h>
#include <raims/sha512.h>
#include <raims/aes.h>
#include <raims/crypt.h>
#include <raims/user.h>
#include <raikv/key_hash.h>
#include <raims/kdf.h>

using namespace rai;
using namespace kv;
using namespace ms;

/* block used for RC4 permutations */
static uint8_t T_init[ 256 ] = {
0xa8,0x3d,0x2c,0xba,0x46,0x3a,0x9b,0xd1,0x05,0xff,0xcf,0x06,0x7e,0x6a,0x0b,0x34,
0xd6,0x9d,0x8c,0x95,0x25,0x4c,0x8f,0xe4,0xdb,0x1b,0xcb,0xc3,0x5d,0x04,0x3c,0xc4,
0x46,0xaf,0xb4,0x33,0x61,0xa7,0x86,0xe4,0x82,0x56,0x15,0x73,0xe8,0x23,0x38,0xc0,
0x2b,0x65,0xe3,0x2c,0xdd,0x3e,0x34,0x99,0x19,0xb8,0x4c,0x2e,0x40,0x5c,0x42,0x1f,

0xb5,0xa9,0x2a,0x4d,0x98,0x90,0x92,0x97,0xd8,0xfc,0x7d,0x44,0x56,0x23,0x4d,0xda,
0x9d,0x97,0xc6,0xf0,0x62,0xcf,0xb4,0x7f,0x94,0x73,0x46,0x80,0x9b,0x1e,0x77,0xd5,
0x80,0xcb,0x51,0x37,0x7e,0xae,0x4b,0xf7,0x26,0xd2,0xe5,0x77,0x64,0x00,0x1f,0x4a,
0xe4,0x9b,0xe7,0x87,0xf6,0x10,0x77,0x3b,0xfb,0x1d,0xd3,0xe6,0x02,0xfe,0x4f,0xc9,

0xf6,0x8a,0xee,0xbb,0x60,0xd8,0xb2,0x20,0x2b,0x06,0xe8,0xac,0xc6,0x98,0x2b,0xe0,
0xd7,0x99,0x17,0xc0,0x84,0xe4,0x5f,0xfa,0x6a,0x45,0x39,0xb4,0xcb,0xf9,0xb5,0xe8,
0x97,0x7f,0x81,0xee,0xa7,0xf9,0xe6,0xfc,0xc2,0x27,0x53,0xdc,0xf5,0x5b,0x02,0x86,
0x5d,0xb5,0xeb,0x95,0x75,0xc2,0x83,0x24,0x6e,0x64,0xf9,0x08,0x2e,0xcf,0xcf,0xbe,

0x86,0x55,0x5d,0x93,0xed,0x3b,0x35,0xfa,0xea,0x3a,0xe2,0x04,0x32,0x40,0x73,0x02,
0x64,0x3a,0xb7,0x45,0xe5,0xab,0x9c,0x1c,0x84,0x2d,0x82,0x19,0xdd,0x64,0x8e,0x8f,
0x94,0xf2,0xec,0xf7,0xed,0x3f,0x79,0x19,0xb7,0x05,0x6f,0x37,0xbd,0x06,0xd5,0xeb,
0xbc,0x17,0xbf,0xf2,0x6d,0x9d,0x59,0xda,0xa0,0x94,0xbd,0x5f,0xbc,0xb9,0xb8,0xce,
};
/* block used for AES crypto */
static uint8_t U_init[ 256 ] = {
0x13,0xa1,0xde,0xff,0x5b,0x6d,0x9c,0x31,0x6c,0x67,0x62,0xda,0xd6,0x85,0x46,0x52,
0xa4,0xd0,0xa3,0xf5,0xc8,0xe0,0xc0,0xdb,0xaa,0x0d,0x05,0x7d,0x7c,0x86,0xbf,0xe4,
0xba,0xa4,0xfd,0x5c,0x04,0xb5,0xe1,0x2b,0x1d,0xed,0xf0,0x97,0x3b,0x0a,0x8f,0x45,
0xec,0xb7,0x32,0x1d,0xb6,0xa8,0xa4,0x00,0x57,0xe5,0x12,0xf7,0x78,0xe4,0xf9,0x25,

0xd5,0x0c,0x91,0x98,0x3d,0x2a,0x43,0xdb,0x26,0xa3,0x9b,0xdc,0xb3,0x2a,0x36,0xf1,
0xdf,0xe9,0x7e,0x9a,0x9a,0x10,0x20,0xad,0x8b,0xaf,0x24,0x1a,0xe2,0xb5,0x16,0x5a,
0x52,0x09,0x49,0xf0,0x12,0xec,0xb1,0x41,0x63,0x4d,0x39,0x56,0x08,0x87,0x60,0xbc,
0xfd,0xc8,0x33,0x5b,0xac,0xa0,0x18,0x9a,0xa1,0x8e,0xae,0xec,0x09,0x6d,0x66,0xac,

0xbd,0x4b,0xb1,0x3d,0x54,0x61,0x69,0x77,0x61,0x6e,0xbb,0xaf,0xc0,0x08,0x8e,0x0d,
0x2d,0x69,0x53,0x69,0x59,0xbf,0xf2,0xe6,0xb9,0x5d,0xa0,0x7b,0x0d,0xfe,0xe7,0x73,
0xe6,0x85,0x4e,0x5b,0xac,0x4c,0x97,0x20,0x9c,0x21,0x4f,0xd2,0xd2,0x07,0xcf,0xf7,
0xe0,0xfc,0x65,0xf6,0xc8,0xf7,0x92,0xba,0xb0,0x33,0x37,0xe0,0xac,0xc4,0x2f,0xd1,

0xf6,0x93,0x28,0x64,0xc4,0xcd,0x85,0x96,0x4b,0x19,0xdb,0xc1,0x1b,0xcf,0xef,0x88,
0xa2,0x77,0xc2,0x92,0x04,0x22,0xb7,0x53,0x26,0x24,0x17,0x4c,0xfa,0x59,0x4f,0x37,
0x2e,0xe7,0x49,0x6e,0x64,0x65,0x70,0x65,0x6e,0x64,0x65,0x6e,0x63,0x65,0xa5,0x25,
0x6d,0xa3,0x4a,0x0f,0x16,0x81,0x5c,0x9a,0x7c,0xe7,0xc4,0x3a,0x4b,0x69,0xae,0x85
};
/* it's possible to hexedit the compiled binary to change these 640 chars */
static char kdf_hash_data[ 640 ] =
"_SALT_Oo.  Sherpa Pink Himalayan, Hickory Smoked, Applewood Smoked, Cherrywood "
"Black Truffle, Fleur de Sel, Organic Bacon, Organic Chili Lime, Alderwood Pine " 
"Organic Himalayan Garlic Extra Fine Grain. Organic Lemon Rosemary; Organic Srir" 
"acha Sea Brine Himalayan Onion: Lemon Rosemary; Bacon Herb Garlic Turkey Offlin"
"_PEPPER_Oo. reasonable hardware performance constant-distance rotation operatio"
"Northwich and Droitwich, Cheshire; Salzburg, Austria, was named the city of sal"
"exhaustion of the mined rock salt supplies resulted in a change to wild brine  "
"Salt is extracted from underground beds either by mining or by solution mining ";

kv_atom_uint32_t rai::ms::kdf_hash_init;
kv_atom_uint32_t rai::ms::kdf_hash_ready;
uint8_t * rai::ms::T;
uint8_t * rai::ms::U;

/* use mmap() with madvice() MADV_DONTDUMP to omit from core dumps
 *
 * Openssl allocates pages around arena with mprotect( mem, pg, PROT_NONE )
 * to add guard boundaries.  It also locks pages in memory with
 * mlock2( mem, pgs, MLOCK_ONFAULT ) to prevent being swapped */
void *
rai::ms::alloc_secure_mem( size_t len ) noexcept
{
  MapFile map( NULL, len );
  if ( ! map.open( MAP_FILE_RDWR | MAP_FILE_PRIVATE | MAP_FILE_LOCK |
                   MAP_FILE_SECURE | MAP_FILE_NOUNMAP ) ) {
    perror( "secure mem" );
    if ( map.map == NULL )
      assert( 0 );
  }
  return map.map;
}

void
rai::ms::free_secure_mem( void *p,  size_t len ) noexcept
{
  MapFile::unmap( p, len );
}

bool
rai::ms::load_secure_env( const char *env,  const char *unlnk_env,
                            const char *data,  void *&mem,
                            size_t &mem_sz ) noexcept
{
  const char *env_data = data;
  mem    = NULL;
  mem_sz = 0;
  if ( env_data == NULL ) {
    if ( env != NULL )
      env_data = ::getenv( env );
  }
  if ( env_data == NULL )
    return true;

  /* if not a file, just copy data */
  size_t len = ::strlen( env_data );
  if ( len <= sizeof( "file:" ) || ::memcmp( env_data, "file:", 5 ) != 0 ) {
    mem = alloc_secure_mem( len );
    ::memcpy( mem, env_data, len );
    mem_sz = len;
    return true;
  }
  if ( load_secure_file( &env_data[ 5 ], mem, mem_sz ) ) {
    /* if burn after reading */
    if ( unlnk_env != NULL ) {
      if ( ::getenv( unlnk_env ) != NULL ) {
        if ( os_unlink( &env_data[ 5 ] ) < 0 )
          ::perror( env_data );
      }
    }
    return true;
  }
  return false;
}

bool
rai::ms::load_secure_file( const char *fn,  void *&mem,  size_t &sz ) noexcept
{
  MapFile map( fn );
  if ( ! map.open() ) {
    ::perror( fn );
    return false;
  }
  sz = map.map_size;
  /* strip one cr/nl */
  if ( ((char *) map.map)[ sz - 1 ] == '\n' ) {
    sz--;
    if ( ((char *) map.map)[ sz - 1 ] == '\r' )
      sz--;
  }
  /* copy to secure mem */
  mem = alloc_secure_mem( sz );
  ::memcpy( mem, map.map, sz );

  return true;
}

bool
CryptPass::init_pass_file( const char *path ) noexcept
{
  void * mem;
  size_t mem_sz;
  if ( ! load_secure_file( path, mem, mem_sz ) ) {
    fprintf( stderr, "Unable to load passwd: \"%s\"\n", path );
    return false;
  }
  this->pass     = (char *) mem;
  this->pass_len = mem_sz;
  return true;
}

bool
CryptPass::init_salt_file( const char *path ) noexcept
{
  void * mem;
  size_t mem_sz;
  if ( ! load_secure_file( path, mem, mem_sz ) ) {
    fprintf( stderr, "Unable to load salt: \"%s\"\n", path );
    return false;
  }
  init_kdf( mem, mem_sz );
  free_secure_mem( mem, mem_sz );
  return true;
}

bool
CryptPass::init_pass( const char *pass ) noexcept
{
  /* this passwd is unique for this process, it is necessary to decrypt
   * the keypairs configured for each user */
  void * mem;
  size_t mem_sz;
  if ( ! load_secure_env( "RAI_PASS", "RAI_PASS_UNLINK", pass, mem, mem_sz ) )
    return false;
  this->pass     = (char *) mem;
  this->pass_len = mem_sz;
  return true;
}

void
CryptPass::clear_pass( void ) noexcept
{
  if ( this->pass_len > 0 ) {
    ::memset( this->pass, 0, this->pass_len );
    free_secure_mem( this->pass, this->pass_len );
    this->pass     = NULL;
    this->pass_len = 0;
  }
}

bool
CryptPass::gen_pass( void ) noexcept
{
  char bytes[ 32 ];
  rand::fill_urandom_bytes( bytes, sizeof( bytes ) );
  this->pass     = (char *) alloc_secure_mem( KV_BASE64_SIZE( sizeof( bytes )));
  if ( this->pass != NULL )
    this->pass_len = bin_to_base64( bytes, sizeof( bytes ), this->pass, false );
  ::memset( bytes, 0, sizeof( bytes ) );
  return this->pass != NULL;
}

void *
CryptPass::gen_salt( size_t &salt_len ) noexcept
{
  char bytes[ 640 ];
  rand::fill_urandom_bytes( bytes, sizeof( bytes ) );
  void * salt = alloc_secure_mem( KV_BASE64_SIZE( sizeof( bytes ) ) );
  if ( salt != NULL )
    salt_len = bin_to_base64( bytes, sizeof( bytes ), salt, false );
  ::memset( bytes, 0, sizeof( bytes ) );
  return salt;
}

bool
rai::ms::init_kdf( const void *mem,  size_t mem_sz ) noexcept
{
  bool success = true;
  /* this hash is used for any hash calculation, crossing process boundaries
   * it needs to be globally set for any two endpoints to authenticate */
  if ( ! kv_sync_xchg32( &kdf_hash_init, 1 ) ) {
    kv_acquire_fence();

    void       * data       = NULL;
    size_t       data_sz    = 0;
    const char * hash_iters = ::getenv( "RAI_KDF_ITERS" ),
               * hash_seed;
    size_t       iters      = ( hash_iters == NULL ? 0 : atoi( hash_iters ) ),
                 len;

    if ( mem != NULL ) {
      hash_seed = (char *) mem;
      len       = mem_sz;
    }
    else {
      success = load_secure_env( "RAI_KDF", "RAI_KDF_UNLINK", NULL,
                                 data, data_sz );
      if ( data == NULL ) {
        hash_seed = kdf_hash_data;
        len       = sizeof( kdf_hash_data );
      }
      else {
        hash_seed = (char *) data;
        len       = data_sz;
      }
    }
    T = (uint8_t *) alloc_secure_mem( sizeof( T_init ) + sizeof( U_init ) );
    U = (uint8_t *) &T[ sizeof( T_init ) ];
    ::memcpy( T, T_init, sizeof( T_init ) );
    ::memcpy( U, U_init, sizeof( U_init ) );
    ::memset( T_init, 0, sizeof( T_init ) );
    ::memset( U_init, 0, sizeof( U_init ) );

    size_t cnt   = sizeof( T_init ) / SHA512_HASH_SIZE,
           chunk = len / cnt,
           off   = 0;
    if ( chunk == 0 )
      chunk = 1;
    Sha512Context ctx, ctx2;
    /* merge crypt_hash into T[], U[] */
    for ( size_t i = 0; ; i += SHA512_HASH_SIZE ) {
      ctx.initialize();
      ctx2.initialize();
      size_t size = len - off;
      if ( size > chunk )
        size = chunk;
      ctx.update( &hash_seed[ off ], size );
      ctx2.update(  &hash_seed[ off ], size );
      ctx.update( &T[ i % sizeof( T_init ) ], SHA512_HASH_SIZE );
      ctx2.update( &U[ i % sizeof( U_init ) ], SHA512_HASH_SIZE );
      ctx.finalize( &T[ i % sizeof( T_init ) ] );
      ctx2.finalize( &U[ i % sizeof( U_init ) ] );
      off += size;
      if ( off == len ) {
        if ( iters == 0 || --iters == 0 )
          break;
        off = 0;
      }
    }
    ::memset( kdf_hash_data, 0, sizeof( kdf_hash_data ) );
    if ( data != NULL )
      free_secure_mem( data, data_sz );
    kv_release_fence();
    kv_sync_xchg32( &kdf_hash_ready, 1 );
  }
  else {
    kv_acquire_fence();
    while ( ! kv_sync_load32( &kdf_hash_ready ) )
      kv_sync_pause();
    kv_release_fence();
  }
  return success;
}
/* construct password based key */
void
HashDigest::kdf_user_pwd( const UserBuf &u,  const CryptPass &pwd ) noexcept
{
  static const char user_sep[]    = "user:",
                    svc_sep[]     = ";svc:",
                    create_sep[]  = ";create:",
                    expires_sep[] = ";expires:",
                    pass_sep[]    = ";pass:",
                    version_tl[]  = ";1616195974";
  KeyDeriveFun kdf;
  kdf.update( user_sep, sizeof( user_sep ) - 1 );
  kdf.update( u.user, u.user_len );
  kdf.update( svc_sep, sizeof( svc_sep ) - 1 );
  kdf.update( u.service, u.service_len );
  kdf.update( create_sep, sizeof( create_sep ) - 1 );
  kdf.update( u.create, u.create_len );
  if ( u.expires_len != 0 ) {
    kdf.update( expires_sep, sizeof( expires_sep ) - 1 );
    kdf.update( u.expires, u.expires_len );
  }
  if ( pwd.pass_len != 0 ) {
    kdf.update( pass_sep, sizeof( pass_sep ) - 1 );
    kdf.update( pwd.pass, pwd.pass_len );
  }
  kdf.update( version_tl, sizeof( version_tl ) - 1 );
  kdf.complete( this->dig );
  kdf.mix( this->dig, sizeof( this->dig ), 13 );
}
/* construct password based key */
void
HashDigest::kdf_svc_pwd( const ServiceBuf &u,  const CryptPass &pwd ) noexcept
{
  static const char svc_sep[]     = "svc:",
                    create_sep[]  = ";create:",
                    pass_sep[]    = ";pass:",
                    version_tl[]  = ";1621598065";
  KeyDeriveFun kdf;
  kdf.update( svc_sep, sizeof( svc_sep ) - 1 );
  kdf.update( u.service, u.service_len );
  kdf.update( create_sep, sizeof( create_sep ) - 1 );
  kdf.update( u.create, u.create_len );
  if ( pwd.pass_len != 0 ) {
    kdf.update( pass_sep, sizeof( pass_sep ) - 1 );
    kdf.update( pwd.pass, pwd.pass_len );
  }
  kdf.update( version_tl, sizeof( version_tl ) - 1 );
  kdf.complete( this->dig );
  kdf.mix( this->dig, sizeof( this->dig ), 13 );
}
/* use AES ctr mode and prefix with a HMAC of the encrypted data */
void
HashDigest::encrypt_hmac( const void *data,  size_t data_len,  void *data_out,
                          uint64_t ctr ) noexcept
{
  AES128          aes;
  uint8_t       * hmac_out   = (uint8_t *) data_out;
  uint8_t       * cipher_out = &hmac_out[ HMAC_SIZE ];
  const uint8_t * plain_in   = (const uint8_t *) data;
  uint8_t         tmp[ 16 ]; /* next encrypted block */
  uint64_t        iv[ 2 ];   /* the current ctr mode IV */
  size_t          i, k;

  /* first 16 bytes is AES key */
  aes.expand_key( this->digest() );
  /* second 16 bytes is AES ctr mode IV */
  ::memcpy( iv, this->digest() + 16, 16 );

  iv[ 1 ] += ctr++;
  aes.encrypt( iv, tmp );
  for ( i = 0; ; i += 16 ) {
    if ( i + 16 >= data_len )
      break;
    /* xor the encrypted IV */
    for ( k = 0; k < 16; k++ )
      cipher_out[ i + k ] = plain_in[ i + k ] ^ tmp[ k ];
    /* next block, incr ctr */
    iv[ 1 ] += ctr++;
    aes.encrypt( iv, tmp );
  }
  /* trail block */
  for ( k = 0; k < data_len - i; k++ )
    cipher_out[ i + k ] = plain_in[ i + k ] ^ tmp[ k ];

  PolyHmacDigest hmac;
  hmac.calc_off( *this, 4, cipher_out, data_len );
  ::memcpy( hmac_out, hmac.digest(), HMAC_SIZE );
}
/* check that HMAC is correct, then decrypt using AES ctr mode */
bool
HashDigest::decrypt_hmac( const void *data,  size_t data_len,  void *data_out,
                          uint64_t ctr ) noexcept
{
  AES128          aes;
  uint8_t       * plain_out  = (uint8_t *) data_out;
  const uint8_t * hmac_in    = (const uint8_t *) data;
  const uint8_t * cipher_in  = &hmac_in[ HMAC_SIZE ];
  size_t          cipher_len = data_len - HMAC_SIZE;
  uint8_t         tmp[ 16 ]; /* next encrypted block */
  uint64_t        iv[ 2 ];   /* the current ctr mode IV */
  size_t          i, k;

  PolyHmacDigest hmac;
  hmac.calc_off( *this, 4, cipher_in, cipher_len );
  if ( ::memcmp( hmac_in, hmac.digest(), HMAC_SIZE ) != 0 )
    return false;

  /* first 16 bytes is AES key */
  aes.expand_key( this->digest() );
  /* second 16 bytes is AES ctr mode IV */
  ::memcpy( iv, this->digest() + 16, 16 );

  iv[ 1 ] += ctr++;
  aes.encrypt( iv, tmp );
  for ( i = 0; ; i += 16 ) {
    if ( i + 16 >= cipher_len )
      break;
    /* xor the encrypted IV */
    for ( k = 0; k < 16; k++ )
      plain_out[ i + k ] = cipher_in[ i + k ] ^ tmp[ k ];
    /* next block, incr ctr */
    iv[ 1 ] += ctr++;
    aes.encrypt( iv, tmp );
  }
  /* trail block */
  for ( k = 0; k < cipher_len - i; k++ )
    plain_out[ i + k ] = cipher_in[ i + k ] ^ tmp[ k ];

  return true;
}
/* session random key */
void
HashDigest::make_session_rand( void ) noexcept
{
  rand::fill_urandom_bytes( this->dig, sizeof( this->dig ) );
}
/* hash secret with 2 the cnonce sides, peer side, and local side + seq, time */
void
HashDigest::kdf_challenge_secret( const HmacDigest &secret_hmac,
                                  const Nonce &snonce1,  const Nonce &snonce2,
                                  const Nonce &cnonce1,  const Nonce &cnonce2,
                                  uint64_t seqno,  uint64_t time,
                                  uint32_t stage ) noexcept
{
  KeyDeriveFun kdf;
  kdf.update( secret_hmac.dig, HMAC_SIZE );
  kdf.update( snonce1.nonce, NONCE_SIZE );
  kdf.update( snonce2.nonce, NONCE_SIZE );
  kdf.update( cnonce1.nonce, NONCE_SIZE );
  kdf.update( cnonce2.nonce, NONCE_SIZE );
  kdf.update( &seqno, sizeof( seqno ) );
  kdf.update( &time, sizeof( time ) );
  kdf.update( &stage, sizeof( stage ) );
  kdf.complete( this->digest() );
}
void
HashDigest::kdf_peer_nonce( const HashDigest &ha1,  const Nonce &snonce1,
                            const Nonce &snonce2 ) noexcept
{
  KeyDeriveFun kdf;
  kdf.update( ha1.dig, HASH_DIGEST_SIZE );
  kdf.update( snonce1.nonce, NONCE_SIZE );
  kdf.update( snonce2.nonce, NONCE_SIZE );
  kdf.complete( this->digest() );
}
/* compute the hash of data */
void
HashDigest::kdf_bytes( const void *data,  size_t datalen,
                       const void *data2,  size_t datalen2 ) noexcept
{
  KeyDeriveFun kdf;
  kdf.update( data, datalen );
  if ( datalen2 != 0 )
    kdf.update( data2, datalen2 );
  kdf.complete( this->digest() );
}
/* AES_encrypt[ challenge, hash ] -> encrypted_hash */
void
HashDigest::encrypt_hash( const HashDigest &challenge_hash,
                          const HashDigest &hash ) noexcept
{
  AES128 aes;
  for ( size_t i = 0; i < HASH_DIGEST_SIZE; i += 16 ) {
    aes.expand_key( challenge_hash.digest() + i );
    aes.encrypt( hash.digest() + i, this->digest() + i );
  }
}
/* AES_decrypt[ challenge, encrypted_hash ] -> hash */
void
HashDigest::decrypt_hash( const HashDigest &challenge_hash,
                          const HashDigest &encrypted_hash ) noexcept
{
  AES128 aes;
  for ( size_t i = 0; i < HASH_DIGEST_SIZE; i += 16 ) {
    aes.expand_key( challenge_hash.digest() + i );
    aes.decrypt( encrypted_hash.digest() + i, this->digest() + i );
  }
}
/* AES_encrypt[ key, nonce, hash ] -> encrypted_hash */
void
HashDigest::encrypt_key_nonce( const HashDigest &key_hash,
                               const Nonce &key_nonce,
                               const HashDigest &hash ) noexcept
{
  AES128 aes;
  Nonce  nonce;
  const uint64_t * dig = key_hash.dig;
  for ( size_t i = 0; i < HASH_DIGEST_SIZE; i += 16 ) {
    nonce = key_nonce ^ dig;  dig += 2;
    aes.expand_key( nonce.digest() );
    aes.encrypt( hash.digest() + i, this->digest() + i );
  }
}
/* AES_decrypt[ key, nonce, encrypted_hash ] -> hash */
void
HashDigest::decrypt_key_nonce( const HashDigest &key_hash,
                               const Nonce &key_nonce,
                               const HashDigest &encrypted_hash ) noexcept
{
  AES128 aes;
  Nonce  nonce;
  const uint64_t * dig = key_hash.dig;
  for ( size_t i = 0; i < HASH_DIGEST_SIZE; i += 16 ) {
    nonce = key_nonce ^ dig; dig += 2;
    aes.expand_key( nonce.digest() );
    aes.decrypt( encrypted_hash.digest() + i, this->digest() + i );
  }
}

void
Nonce::seed_random( void ) noexcept
{
  rand::fill_urandom_bytes( this->nonce, sizeof( this->nonce ) );
}
/* use urandom every 200 times, about 30 minutes with usage at 10 secs */
void
CnonceRandom::refill_random( void ) noexcept
{
  if ( this->ctr % ( CNONCE_WORDS * 200 ) == 0 ) {
    rand::fill_urandom_bytes( this->buf, sizeof( this->buf ) );
    this->val.seed_random();
  }
  else {
    KeyDeriveFun kdf;
    static const size_t CNONCE_WORDS = sizeof( this->buf ) / 8;
    size_t off = 0;
    for ( uint64_t i = this->ctr; ; i++ ) {
      kdf.update( &i, sizeof( i ) );
      kdf.update( &this->buf[ off % CNONCE_WORDS ], HASH_DIGEST_SIZE );
      kdf.complete( &this->buf[ off % CNONCE_WORDS ] );
      off += HASH_DIGEST_WORDS;
      if ( off == CNONCE_WORDS * 2 )
        break;
    }
  }
}

void
Nonce::print( void ) const noexcept
{
  char buf[ NONCE_B64_LEN ];

  this->to_base64( buf );
  printf( "nonce:%.*s", (int) NONCE_B64_LEN, buf );
}

void
HashDigest::print( void ) const noexcept
{
  char buf[ HASH_DIGEST_B64_LEN ];

  this->to_base64( buf );
  printf( "hash:%.*s", (int) HASH_DIGEST_B64_LEN, buf );
}

void
HmacDigest::print( void ) const noexcept
{
  char buf[ HMAC_B64_LEN ];

  this->to_base64( buf );
  printf( "hmac:%.*s", (int) HMAC_B64_LEN, buf );
}

