#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raims/ed25519.h>
#include <raims/crypt.h>
#include <raims/user.h>

using namespace rai;
using namespace ms;
using namespace kv;

int
main( void )
{
  static const char *str = "test data";
  DSA dsa;
  PolyHmacDigest hmac;
  HashDigest ha;
  uint8_t plain[ ED25519_SIG_LEN ];
  char buf[ 256 ];

  ha.kdf_bytes( "password", 8 );
  dsa.gen_key();
  hmac.calc_off( ha, 0, str, strlen( str ) );

  dsa.sign( hmac.digest(), HMAC_SIZE );
  dsa.sig.copy_to( plain );
  size_t sz = bin_to_base64( plain, ED25519_SIG_LEN, buf, false );
  buf[ sz ] = '\0';
  printf( "sig: %s\n", buf );

  for ( size_t j = 0; j < 10; j++ ) {
    uint8_t test_sig[ 100 ][ ED25519_SIG_LEN ];
    uint64_t t = current_monotonic_time_ns();
    for ( size_t i = 0; i < 100; i++ ) {
      hmac.calc_off( ha, 0, &i, sizeof( i ) );
      dsa.sign( hmac.digest(), HMAC_SIZE );
      dsa.sig.copy_to( test_sig[ i ] );
    }
    uint64_t t2 = current_monotonic_time_ns();
    printf( "%lu ns per sig\n", ( t2 - t ) / 100 );

    t = current_monotonic_time_ns();
    for ( size_t i = 0; i < 100; i++ ) {
      dsa.sig = test_sig[ i ];
      hmac.calc_off( ha, 0, &i, sizeof( i ) );
      if ( ! dsa.verify( hmac.digest(), HMAC_SIZE ) )
        printf( "verify failed\n" );
    }
    t2 = current_monotonic_time_ns();
    printf( "%lu ns per verify\n", ( t2 - t ) / 100 );
  }
  return 0;
}

