#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <raims/ec25519.h>

using namespace rai;
using namespace kv;
using namespace ms;

static void
curveassert_die( const uint8_t *a, const uint8_t *b, size_t len,
                 int round, const char *failreason )
{
  size_t i;
  if ( round > 0 )
    printf( "round %d, %s\n", round, failreason );
  else
    printf( "%s\n", failreason );
  printf( "want: " );
  for ( i = 0; i < len; i++ )
    printf( "%02x,", a[ i ] );
  printf( "\n" );
  printf( "got : " );
  for ( i = 0; i < len; i++ )
    printf( "%02x,", b[ i ] );
  printf( "\n" );
  printf( "diff: " );
  for ( i = 0; i < len; i++ )
    if ( a[ i ] ^ b[ i ] )
      printf( "%02x,", a[ i ] ^ b[ i ] );
    else
      printf( "  ," );
  printf( "\n\n" );
  exit( 1 );
}

static void
curveassert_equal( const uint8_t *a, const uint8_t *b, size_t len,
                   const char *failreason )
{
  if ( memcmp( a, b, len ) == 0 )
    return;
  curveassert_die( a, b, len, -1, failreason );
}

/* result of the curve25519 scalarmult |((|max| * |max|) * |max|)... 1024 times|
 * basepoint */

/*
static const curve25519_key curve25519_expected = {
  0x8e,0x74,0xac,0x44,0x38,0xa6,0x87,0x54,
  0xc8,0xc6,0x1b,0xa0,0x8b,0xd2,0xf7,0x7b,
  0xbb,0xc6,0x26,0xd5,0x24,0xb3,0xbe,0xa0,
  0x38,0x30,0x1d,0xec,0x2d,0x92,0xe7,0x51
};
*/

/* this is the result if the 256th bit of a point is ignored:*/
static const uint8_t curve25519_expected[] = {
  0x1e, 0x61, 0x8e, 0xc0, 0x2f, 0x25, 0x1b, 0x8d,
  0x62, 0xed, 0x0e, 0x57, 0x3c, 0x83, 0x11, 0x49,
  0x7b, 0xa5, 0x85, 0x40, 0x1a, 0xcf, 0xd4, 0x3e,
  0x5b, 0xeb, 0xa8, 0xb5, 0xae, 0x75, 0x96, 0x2d
};

/* shared key resulting from the private keys |max| and |mid| */
static const uint8_t curve25519_shared[] = {
  0x78, 0x0e, 0x63, 0xa6, 0x58, 0x5c, 0x6d, 0x56,
  0xf1, 0xa0, 0x18, 0x2d, 0xec, 0xe6, 0x96, 0x3b,
  0x5b, 0x4d, 0x63, 0x08, 0x7b, 0xf9, 0x19, 0x0e,
  0x3a, 0x77, 0xf5, 0x27, 0x9c, 0xd7, 0x8b, 0x44
};

static void
test_main( void )
{
  static const uint8_t max[] = { 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255 };
  static const uint8_t mid[] = { 127, 127, 127, 127, 127, 127, 127, 127,
                                 127, 127, 127, 127, 127, 127, 127, 127,
                                 127, 127, 127, 127, 127, 127, 127, 127,
                                 127, 127, 127, 127, 127, 127, 127, 127 };
  ec25519_key max_key( max ), mid_key( mid );
  ec25519_key pk[ 2 ];
  ec25519_key shared[ 2 ];
  int i;

  EC25519::donna( pk[ 0 ], max_key, max_key );
  for ( i = 0; i < 1023; i++ )
    EC25519::donna( pk[ ( i & 1 ) ^ 1 ], pk[ i & 1 ], max_key );
  EC25519::donna_basepoint( pk[ 0 ], pk[ 1 ] );
  curveassert_equal(
    curve25519_expected, pk[ 0 ], sizeof( ec25519_key ),
    "curve25519 sanity test failed to generate correct value" );

  EC25519::donna_basepoint( pk[ 0 ], max_key );
  EC25519::donna_basepoint( pk[ 1 ], mid_key );
  EC25519::donna( shared[ 0 ], max_key, pk[ 1 ] );
  EC25519::donna( shared[ 1 ], mid_key, pk[ 0 ] );
  curveassert_equal( curve25519_shared, shared[ 0 ], sizeof( curve25519_shared ),
                     "curve25519 failed to generate the same shared key (1)" );
  curveassert_equal( curve25519_shared, shared[ 1 ], sizeof( curve25519_shared ),
                     "curve25519 failed to generate the same shared key (2)" );

  uint64_t t = current_monotonic_time_ns();
  for ( i = 0; i < 2048; i++ ) {
    EC25519::donna( pk[ 1 ], pk[ 0 ], max_key );
  }
  t = current_monotonic_time_ns() - t;
  printf( "%" PRIu64 " ticks/curve25519 scalarmult\n", t / 2048 );

  EC25519 bob, alice, shared1, shared2;
  bob.gen_key();
  alice.gen_key();
  shared1.pri = bob.pri; shared1.pub = alice.pub;
  shared2.pri = alice.pri; shared2.pub = bob.pub;

  shared1.shared_secret();
  shared2.shared_secret();

  curveassert_equal( shared1.secret, shared2.secret, EC25519_KEY_LEN,
                     "curve25519 failed, bob alice exchange" );
}

int
main( void )
{
  test_main();
  return 0;
}
