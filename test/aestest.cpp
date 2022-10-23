#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <raims/aes.h>
#include <raikv/util.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/ssl.h>
#include <openssl/aes.h>

using namespace rai;
using namespace ms;

void
print_128( uint8_t *buf )
{
  for ( int i = 0; i < 128 / 8; i++ )
    printf( "%02x ", buf[ i ] );
  printf( "\n" );
}

int
main( int argc, char *argv[] )
{
  uint8_t plain1[]  = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                       0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  uint8_t cipher1[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                       0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
  uint8_t key1[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t plain2[]  = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                       0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
  uint8_t cipher2[] = {0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
                       0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf};
  uint8_t key2[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t plain3[]  = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                       0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef};
  uint8_t cipher3[] = {0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
                       0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88};
  uint8_t key3[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t plain[ AES128::BLOCK_SIZE ], cipher[ AES128::BLOCK_SIZE ];
  uint8_t plain_ssl[ AES128::BLOCK_SIZE ], cipher_ssl[ AES128::BLOCK_SIZE ];
  AES128 aes;
  AES_KEY ssl_aes_enc, ssl_aes_dec;
  
  aes.expand_key( key1 );
  aes.encrypt( plain1, cipher );
  aes.decrypt( cipher, plain );
  printf( "test1 : %s\n", ::memcmp( cipher, cipher1, sizeof( cipher ) ) == 0 &&
           ::memcmp( plain, plain1, sizeof( plain ) ) == 0 ? "pass" : "fail" );

  AES_set_encrypt_key( key1, sizeof( key1 ) * 8, &ssl_aes_enc );
  AES_set_decrypt_key( key1, sizeof( key1 ) * 8, &ssl_aes_dec );
  AES_encrypt( plain1, cipher_ssl, &ssl_aes_enc );
  AES_decrypt( cipher_ssl, plain_ssl, &ssl_aes_dec );
  printf( "test1b : %s\n", ::memcmp( cipher, cipher1, sizeof( cipher ) ) == 0 &&
           ::memcmp( plain, plain1, sizeof( plain ) ) == 0 ? "pass" : "fail" );

  aes.expand_key( key2 );
  aes.encrypt( plain2, cipher );
  aes.decrypt( cipher, plain );
  printf( "test2 : %s\n", ::memcmp( cipher, cipher2, sizeof( cipher ) ) == 0 &&
           ::memcmp( plain, plain2, sizeof( plain ) ) == 0 ? "pass" : "fail" );
  aes.expand_key( key3 );
  aes.encrypt( plain3, cipher );
  aes.decrypt( cipher, plain );
  printf( "test3 : %s\n", ::memcmp( cipher, cipher3, sizeof( cipher ) ) == 0 &&
           ::memcmp( plain, plain3, sizeof( plain ) ) == 0 ? "pass" : "fail" );


  uint64_t ctr[ 2 ], ctr2[ 2 ];
  uint8_t  buf[ AES128::BLOCK_SIZE * 16 ], buf2[ AES128::BLOCK_SIZE * 16 ];
  size_t   i, k;

  ctr[ 0 ] = ctr2[ 0 ] = kv_bswap64( 1 );
  ctr[ 1 ] = ctr2[ 1 ] = kv_bswap64( (uint64_t) -8 );
  ::memset( buf, 0, sizeof( buf ) );
  ::memset( buf2, 0, sizeof( buf2 ) );

  aes.encrypt_ctr( ctr, buf, sizeof( buf ) / AES128::BLOCK_SIZE );

  for ( i = 0; i < sizeof( buf ); i += AES128::BLOCK_SIZE ) {
    aes.encrypt_ctr( ctr2, &buf2[ i ], 1 );
  }
  printf( "test4 : %s\n",
          ::memcmp( buf, buf2, sizeof( buf ) ) == 0 &&
          ctr[ 0 ] == ctr2[ 0 ] && ctr[ 1 ] == ctr2[ 1 ] ? "pass" : "fail" );

  uint8_t * ptr  = (uint8_t *) kv::aligned_malloc( 1024 * 1024 ),
          * ptr2 = (uint8_t *) kv::aligned_malloc( 1024 * 1024 );
  double t1, t2;
  bool runaes = false, runssl = false;

  if ( argc == 1 || ::strstr( argv[ 1 ], "aes" ) != NULL ) {
    runaes = true;
    ::memset( ptr, 0, 1024 * 1024 );
    ctr[ 0 ] = kv_bswap64( 1 );
    ctr[ 1 ] = kv_bswap64( (uint64_t) -8 );
    t1 = kv_current_monotonic_time_s();
    for ( k = 0; k < 16 * 1024; k++ ) {
      for ( i = 0; i < 1024 * 1024; i += sizeof( buf ) ) {
        aes.encrypt_ctr( ctr, buf, sizeof( buf ) / AES128::BLOCK_SIZE );
        aes.byte_xor( buf, &ptr[ i ], sizeof( buf ) );
      }
    }
    t2 = kv_current_monotonic_time_s();
    printf( "aes 16GB %f sec, %f MB/sec\n", t2 - t1, ( 16 * 1024.0 ) / ( t2 - t1 ) );
  }
  if ( argc > 1 && ::strstr( argv[ 1 ], "ssl" ) != NULL ) {
    runssl = true;
    ::memset( ptr2, 0, 1024 * 1024 );
    ctr[ 0 ] = kv_bswap64( 1 );
    ctr[ 1 ] = kv_bswap64( (uint64_t) -8 );
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex( ctx, EVP_aes_128_ctr(), NULL, key2,
                        (uint8_t *) (void *) ctr );
    t1 = kv_current_monotonic_time_s();
    for ( k = 0; k < 16 * 1024; k++ ) {
      for ( i = 0; i < 1024 * 1024; i += sizeof( buf ) ) {
        int len = sizeof( buf );
        EVP_EncryptUpdate( ctx, &ptr2[ i ], &len, &ptr2[ i ], sizeof( buf ) );
      }
    }
    t2 = kv_current_monotonic_time_s();
    printf( "ssl 16GB %f sec, %f MB/sec\n", t2 - t1, ( 16 * 1024.0 ) / ( t2 - t1 ) );
  }
  if ( runaes && runssl ) {
    printf( "test5 : %s\n",
            ::memcmp( ptr, ptr2, 1024 * 1024 ) == 0 ? "pass" : "fail" );
  }
  return 0;
}

