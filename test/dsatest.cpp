#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raims/ed25519.h>

using namespace rai;
using namespace kv;
using namespace ms;

static void
edassert( int check, int round, const char *failreason )
{
  if ( check )
    return;
  printf( "round %d, %s\n", round, failreason );
  exit( 1 );
}

static void
edassert_die( const uint8_t *a, const uint8_t *b, size_t len,
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
edassert_equal( const uint8_t *a, const uint8_t *b, size_t len,
                const char *failreason )
{
  if ( memcmp( a, b, len ) == 0 )
    return;
  edassert_die( a, b, len, -1, failreason );
}

static void
edassert_equal_round( const uint8_t *a, const uint8_t *b,
                      size_t len, int round, const char *failreason )
{
  if ( memcmp( a, b, len ) == 0 )
    return;
  edassert_die( a, b, len, round, failreason );
}
/* test data */
typedef struct test_data_t {
  uint8_t sk[ 32 ], pk[ 32 ], sig[ 64 ];
  const char *  m;
} test_data;


/* result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)... 1024 times */
const uint8_t curved25519_expected[] = {
  0xac, 0xce, 0x24, 0xb1, 0xd4, 0xa2, 0x36, 0x21, 0x15, 0xe2, 0x3e,
  0x84, 0x3c, 0x23, 0x2b, 0x5f, 0x95, 0x6c, 0xc0, 0x7b, 0x95, 0x82,
  0xd7, 0x93, 0xd5, 0x19, 0xb6, 0xf1, 0xfb, 0x96, 0xd6, 0x04
};

test_data dataset[] = {
#include "dsa_regression.h"
};

static void
test_main( void )
{
  ED25519 dsa;
  int     i/*, res*/;
  uint8_t forge[ 1024 ] = { 'x' };

  for ( i = 0; i < 1024; i++ ) {
    dsa.sk = dataset[ i ].sk;
    dsa.publickey();
    edassert_equal_round( dataset[ i ].pk, dsa.pk, ED25519_KEY_LEN, i,
                          "public key didn't match" );
    dsa.sign( dataset[ i ].m, i );
    edassert_equal_round( dataset[ i ].sig, dsa.sig, ED25519_SIG_LEN, i,
                          "signature didn't match" );
    edassert( ! dsa.sign_open( dataset[ i ].m, i ), i,
              "failed to open message" );

    memcpy( forge, dataset[ i ].m, i );
    if ( i )
      forge[ i - 1 ] += 1;

    edassert( dsa.sign_open( forge, ( i ) ? i : 1 ), i,
              "opened forged message" );
  }
  ec25519_key csk[ 2 ];
  csk[ 0 ].zero(); csk[ 1 ].zero();
  csk[ 0 ].key[ 0 ] = 255;
  for ( i = 0; i < 1024; i++ )
    ED25519::scalarmult_basepoint( csk[ ( i & 1 ) ^ 1 ], csk[ i & 1 ] );
  edassert_equal( curved25519_expected, csk[ 0 ], EC25519_KEY_LEN,
                  "curve25519 failed to generate correct value" );

#if 0
  for ( i = 0; i < 2048; i++ ) {
    timeit( ed25519_publickey( dataset[ 0 ].sk, pk ), pkticks )
      edassert_equal_round( dataset[ 0 ].pk, pk, sizeof( pk ), i,
                            "public key didn't match" );
    timeit( ed25519_sign( (uint8_t *) dataset[ 0 ].m, 0, dataset[ 0 ].sk,
                          pk, sig ),
            signticks )
      edassert_equal_round( dataset[ 0 ].sig, sig, sizeof( sig ), i,
                            "signature didn't match" );
    timeit( res =
              ed25519_sign_open( (uint8_t *) dataset[ 0 ].m, 0, pk, sig ),
            openticks ) edassert( !res, 0, "failed to open message" );
    timeit( curved25519_scalarmult_basepoint( csk[ 1 ], csk[ 0 ] ),
            curvedticks );
  }

  printf( "%.0f ticks/public key generation\n", (double) pkticks );
  printf( "%.0f ticks/signature\n", (double) signticks );
  printf( "%.0f ticks/signature verification\n", (double) openticks );
  printf( "%.0f ticks/curve25519 basepoint scalarmult\n",
          (double) curvedticks );
#endif
}

#if 0
/* from ed25519-donna-batchverify.h */
extern uint8_t batch_point_buffer[3][32];

/* y coordinate of the final point from 'amd64-51-30k' with the same random generator */
static const uint8_t batch_verify_y[ 32 ] = {
  0x51, 0xe7, 0x68, 0xe0, 0xf7, 0xa1, 0x88, 0x45, 0xde, 0xa1, 0xcb,
  0xd9, 0x37, 0xd4, 0x78, 0x53, 0x1b, 0x95, 0xdb, 0xbe, 0x66, 0x59,
  0x29, 0x3b, 0x94, 0x51, 0x2f, 0xbc, 0x0d, 0x66, 0xba, 0x3f
};

/*
static const uint8_t batch_verify_y[32] = {
	0x5c,0x63,0x96,0x26,0xca,0xfe,0xfd,0xc4,
	0x2d,0x11,0xa8,0xe4,0xc4,0x46,0x42,0x97,
	0x97,0x92,0xbe,0xe0,0x3c,0xef,0x96,0x01,
	0x50,0xa1,0xcc,0x8f,0x50,0x85,0x76,0x7d
};

Introducing the 128 bit r scalars to the heap _before_ the largest scalar
fits in to 128 bits alters the heap shape and produces a different,
yet still neutral/valid y/z value.

This was the value of introducing the r scalars when the largest scalar fit
in to 135-256 bits. You can produce it with amd64-64-24k / amd64-51-32k
with the random sequence used in the first pass by changing

    unsigned long long hlen=((npoints+1)/2)|1;

to

    unsigned long long hlen=npoints;

in ge25519_multi_scalarmult.c

ed25519-donna-batchverify.h has been modified to match the 
default amd64-64-24k / amd64-51-32k behaviour
*/



/* batch test */
#define test_batch_count 64
#define test_batch_rounds 96
typedef enum batch_test_t {
  batch_no_errors     = 0,
  batch_wrong_message = 1,
  batch_wrong_pk      = 2,
  batch_wrong_sig     = 3
} batch_test;

static int
test_batch_instance( batch_test type, uint64_t *ticks )
{
  ed25519_secret_key   sks[ test_batch_count ];
  ed25519_public_key   pks[ test_batch_count ];
  ed25519_signature    sigs[ test_batch_count ];
  uint8_t              messages[ test_batch_count ][ 128 ];
  size_t               message_lengths[ test_batch_count ];
  const uint8_t       *message_pointers[ test_batch_count ];
  const uint8_t       *pk_pointers[ test_batch_count ];
  const uint8_t       *sig_pointers[ test_batch_count ];
  int                  valid[ test_batch_count ], ret, validret;
  size_t               i;
  uint64_t             t;

  /* generate keys */
  for ( i = 0; i < test_batch_count; i++ ) {
    ed25519_randombytes_unsafe( sks[ i ], sizeof( sks[ i ] ) );
    ed25519_publickey( sks[ i ], pks[ i ] );
    pk_pointers[ i ] = pks[ i ];
  }

  /* generate messages */
  ed25519_randombytes_unsafe( messages, sizeof( messages ) );
  for ( i = 0; i < test_batch_count; i++ ) {
    message_pointers[ i ] = messages[ i ];
    message_lengths[ i ]  = ( i & 127 ) + 1;
  }

  /* sign messages */
  for ( i = 0; i < test_batch_count; i++ ) {
    ed25519_sign( message_pointers[ i ], message_lengths[ i ], sks[ i ],
                  pks[ i ], sigs[ i ] );
    sig_pointers[ i ] = sigs[ i ];
  }

  validret = 0;
  if ( type == batch_wrong_message ) {
    message_pointers[ 0 ] = message_pointers[ 1 ];
    validret              = 1 | 2;
  }
  else if ( type == batch_wrong_pk ) {
    pk_pointers[ 0 ] = pk_pointers[ 1 ];
    validret         = 1 | 2;
  }
  else if ( type == batch_wrong_sig ) {
    sig_pointers[ 0 ] = sig_pointers[ 1 ];
    validret          = 1 | 2;
  }

  /* batch verify */
  t   = get_ticks();
  ret = ed25519_sign_open_batch( message_pointers, message_lengths, pk_pointers,
                                 sig_pointers, test_batch_count, valid );
  *ticks = get_ticks() - t;
  edassert_equal( (uint8_t *) &validret, (uint8_t *) &ret,
                  sizeof( int ), "batch return code" );
  for ( i = 0; i < test_batch_count; i++ ) {
    validret = ( ( type == batch_no_errors ) || ( i != 0 ) ) ? 1 : 0;
    edassert_equal( (uint8_t *) &validret, (uint8_t *) &valid[ i ],
                    sizeof( int ), "individual batch return code" );
  }
  return ret;
}

static void
test_batch( void )
{
  uint64_t dummy_ticks, ticks[ test_batch_rounds ], best = maxticks, sum;
  size_t   i, count;

  /* check the first pass for the expected result */
  test_batch_instance( batch_no_errors, &dummy_ticks );
  edassert_equal( batch_verify_y, batch_point_buffer[ 1 ], 32,
                  "failed to generate expected result" );

  /* make sure ge25519_multi_scalarmult_vartime throws an error on the entire
   * batch with wrong data */
  for ( i = 0; i < 4; i++ ) {
    test_batch_instance( batch_wrong_message, &dummy_ticks );
    test_batch_instance( batch_wrong_pk, &dummy_ticks );
    test_batch_instance( batch_wrong_sig, &dummy_ticks );
  }

  /* speed test */
  for ( i = 0; i < test_batch_rounds; i++ ) {
    test_batch_instance( batch_no_errors, &ticks[ i ] );
    if ( ticks[ i ] < best )
      best = ticks[ i ];
  }

  /* take anything within 1% of the best time */
  for ( i = 0, sum = 0, count = 0; i < test_batch_rounds; i++ ) {
    if ( ticks[ i ] < ( best * 1.01 ) ) {
      sum += ticks[ i ];
      count++;
    }
  }
  printf( "%.0f ticks/verification\n",
          (double) sum / ( count * test_batch_count ) );
}
#endif

int
main( void )
{
  test_main();
  /*test_batch();*/
  return 0;
}
