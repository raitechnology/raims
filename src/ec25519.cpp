/*
 * From Andrew Moon, https://github.com/floodyberry/ec25519-donna
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raims/ec25519.h>

using namespace rai;
using namespace ms;
using namespace kv;

typedef uint64_t bignum25519[5];
typedef __uint128_t uint128_t;
#define shr128(out,in,shift) out = (uint64_t)(in >> (shift));
#define add128(a,b) a += b;
#define add128_64(a,b) a += (uint64_t)b;
#define lo128(a) ((uint64_t)a)

static void ec25519_scalarmult_donna( ec25519_key &mypublic,
                                      const ec25519_key &n,
                                      const ec25519_key &basepoint ) noexcept;
static void ec25519_square_times( bignum25519 out, const bignum25519 in,
                                  uint64_t count ) noexcept;
static void ec25519_mul( bignum25519 out, const bignum25519 a,
                         const bignum25519 b ) noexcept;
static void ec25519_square( bignum25519 out, const bignum25519 in ) noexcept;

void
EC25519::shared_secret( void ) noexcept
{
  this->donna( this->secret, this->pri, this->pub );
}

void
EC25519::gen_key( void ) noexcept
{
  rand::fill_urandom_bytes( this->pri, 32 );
  this->donna_basepoint( this->pub, this->pri );
}

void
EC25519::donna( ec25519_key &mypublic, const ec25519_key &secret,
                const ec25519_key &basepoint ) noexcept
{
  ec25519_key e = secret;
  e.key[ 0 ]  &= 0xf8;
  e.key[ 31 ] &= 0x7f;
  e.key[ 31 ] |= 0x40;
  ec25519_scalarmult_donna( mypublic, e, basepoint );
}

void
EC25519::donna_basepoint( ec25519_key &mypublic,
                          const ec25519_key &secret ) noexcept
{
  ec25519_key basepoint;
  basepoint.zero();
  basepoint.key[ 0 ] = 9;
  EC25519::donna( mypublic, secret, basepoint );
}

/*
 * In:  b =   2^5 - 2^0
 * Out: b = 2^250 - 2^0
 */
static void
ec25519_pow_two5mtwo0_two250mtwo0( bignum25519 b ) noexcept
{
  bignum25519 t0, c;

  /* 2^5  - 2^0 */ /* b */
  /* 2^10 - 2^5 */ ec25519_square_times( t0, b, 5 );
  /* 2^10 - 2^0 */ ec25519_mul( b, t0, b );
  /* 2^20 - 2^10 */ ec25519_square_times( t0, b, 10 );
  /* 2^20 - 2^0 */ ec25519_mul( c, t0, b );
  /* 2^40 - 2^20 */ ec25519_square_times( t0, c, 20 );
  /* 2^40 - 2^0 */ ec25519_mul( t0, t0, c );
  /* 2^50 - 2^10 */ ec25519_square_times( t0, t0, 10 );
  /* 2^50 - 2^0 */ ec25519_mul( b, t0, b );
  /* 2^100 - 2^50 */ ec25519_square_times( t0, b, 50 );
  /* 2^100 - 2^0 */ ec25519_mul( c, t0, b );
  /* 2^200 - 2^100 */ ec25519_square_times( t0, c, 100 );
  /* 2^200 - 2^0 */ ec25519_mul( t0, t0, c );
  /* 2^250 - 2^50 */ ec25519_square_times( t0, t0, 50 );
  /* 2^250 - 2^0 */ ec25519_mul( b, t0, b );
}
/*
 * z^(p - 2) = z(2^255 - 21)
 */
static void
ec25519_recip( bignum25519 out, const bignum25519 z ) noexcept
{
  bignum25519 a, t0, b;

  /* 2 */ ec25519_square( a, z ); /* a = 2 */
  /* 8 */ ec25519_square_times( t0, a, 2 );
  /* 9 */ ec25519_mul( b, t0, z ); /* b = 9 */
  /* 11 */ ec25519_mul( a, b, a ); /* a = 11 */
  /* 22 */ ec25519_square( t0, a );
  /* 2^5 - 2^0 = 31 */ ec25519_mul( b, t0, b );
  /* 2^250 - 2^0 */ ec25519_pow_two5mtwo0_two250mtwo0( b );
  /* 2^255 - 2^5 */ ec25519_square_times( b, b, 5 );
  /* 2^255 - 21 */ ec25519_mul( out, b, a );
}

static const uint64_t reduce_mask_51 = ((uint64_t)1 << 51) - 1;
static const uint64_t reduce_mask_52 = ((uint64_t)1 << 52) - 1;

/* out = in */
static void
ec25519_copy( bignum25519 out, const bignum25519 in ) noexcept
{
  out[ 0 ] = in[ 0 ];
  out[ 1 ] = in[ 1 ];
  out[ 2 ] = in[ 2 ];
  out[ 3 ] = in[ 3 ];
  out[ 4 ] = in[ 4 ];
}

/* out = a + b */
static void
ec25519_add( bignum25519 out, const bignum25519 a,
             const bignum25519 b ) noexcept
{
  out[ 0 ] = a[ 0 ] + b[ 0 ];
  out[ 1 ] = a[ 1 ] + b[ 1 ];
  out[ 2 ] = a[ 2 ] + b[ 2 ];
  out[ 3 ] = a[ 3 ] + b[ 3 ];
  out[ 4 ] = a[ 4 ] + b[ 4 ];
}

static const uint64_t two54m152 = ( ( (uint64_t) 1 ) << 54 ) - 152;
static const uint64_t two54m8   = ( ( (uint64_t) 1 ) << 54 ) - 8;

/* out = a - b */
static void
ec25519_sub( bignum25519 out, const bignum25519 a,
             const bignum25519 b ) noexcept
{
  out[ 0 ] = a[ 0 ] + two54m152 - b[ 0 ];
  out[ 1 ] = a[ 1 ] + two54m8 - b[ 1 ];
  out[ 2 ] = a[ 2 ] + two54m8 - b[ 2 ];
  out[ 3 ] = a[ 3 ] + two54m8 - b[ 3 ];
  out[ 4 ] = a[ 4 ] + two54m8 - b[ 4 ];
}

/* out = (in * scalar) */
static void
ec25519_scalar_product( bignum25519 out, const bignum25519 in,
                        const uint64_t scalar ) noexcept
{
  uint128_t a;
  uint64_t  c;

  a        = ( (uint128_t) in[ 0 ] ) * scalar;
  out[ 0 ] = (uint64_t) a & reduce_mask_51;
  c        = ( uint64_t )( a >> 51 );
  a        = ( (uint128_t) in[ 1 ] ) * scalar + c;
  out[ 1 ] = (uint64_t) a & reduce_mask_51;
  c        = ( uint64_t )( a >> 51 );
  a        = ( (uint128_t) in[ 2 ] ) * scalar + c;
  out[ 2 ] = (uint64_t) a & reduce_mask_51;
  c        = ( uint64_t )( a >> 51 );
  a        = ( (uint128_t) in[ 3 ] ) * scalar + c;
  out[ 3 ] = (uint64_t) a & reduce_mask_51;
  c        = ( uint64_t )( a >> 51 );
  a        = ( (uint128_t) in[ 4 ] ) * scalar + c;
  out[ 4 ] = (uint64_t) a & reduce_mask_51;
  c        = ( uint64_t )( a >> 51 );
  out[ 0 ] += c * 19;
}

/* out = a * b */
static void
ec25519_mul( bignum25519 out, const bignum25519 a,
             const bignum25519 b ) noexcept
{
  uint128_t t[ 5 ];
  uint64_t  r0, r1, r2, r3, r4, s0, s1, s2, s3, s4, c;

  r0 = b[ 0 ];
  r1 = b[ 1 ];
  r2 = b[ 2 ];
  r3 = b[ 3 ];
  r4 = b[ 4 ];

  s0 = a[ 0 ];
  s1 = a[ 1 ];
  s2 = a[ 2 ];
  s3 = a[ 3 ];
  s4 = a[ 4 ];

  t[ 0 ] = ( (uint128_t) r0 ) * s0;
  t[ 1 ] = ( (uint128_t) r0 ) * s1 + ( (uint128_t) r1 ) * s0;
  t[ 2 ] =
    ( (uint128_t) r0 ) * s2 + ( (uint128_t) r2 ) * s0 + ( (uint128_t) r1 ) * s1;
  t[ 3 ] = ( (uint128_t) r0 ) * s3 + ( (uint128_t) r3 ) * s0 +
           ( (uint128_t) r1 ) * s2 + ( (uint128_t) r2 ) * s1;
  t[ 4 ] = ( (uint128_t) r0 ) * s4 + ( (uint128_t) r4 ) * s0 +
           ( (uint128_t) r3 ) * s1 + ( (uint128_t) r1 ) * s3 +
           ( (uint128_t) r2 ) * s2;

  r1 *= 19;
  r2 *= 19;
  r3 *= 19;
  r4 *= 19;

  t[ 0 ] += ( (uint128_t) r4 ) * s1 + ( (uint128_t) r1 ) * s4 +
            ( (uint128_t) r2 ) * s3 + ( (uint128_t) r3 ) * s2;
  t[ 1 ] +=
    ( (uint128_t) r4 ) * s2 + ( (uint128_t) r2 ) * s4 + ( (uint128_t) r3 ) * s3;
  t[ 2 ] += ( (uint128_t) r4 ) * s3 + ( (uint128_t) r3 ) * s4;
  t[ 3 ] += ( (uint128_t) r4 ) * s4;

  r0 = lo128( t[ 0 ] ) & reduce_mask_51;
  shr128( c, t[ 0 ], 51 );
  add128_64( t[ 1 ], c ) r1 = lo128( t[ 1 ] ) & reduce_mask_51;
  shr128( c, t[ 1 ], 51 );
  add128_64( t[ 2 ], c ) r2 = lo128( t[ 2 ] ) & reduce_mask_51;
  shr128( c, t[ 2 ], 51 );
  add128_64( t[ 3 ], c ) r3 = lo128( t[ 3 ] ) & reduce_mask_51;
  shr128( c, t[ 3 ], 51 );
  add128_64( t[ 4 ], c ) r4 = lo128( t[ 4 ] ) & reduce_mask_51;
  shr128( c, t[ 4 ], 51 );
  r0 += c * 19;
  c  = r0 >> 51;
  r0 = r0 & reduce_mask_51;
  r1 += c;

  out[ 0 ] = r0;
  out[ 1 ] = r1;
  out[ 2 ] = r2;
  out[ 3 ] = r3;
  out[ 4 ] = r4;
}

/* out = in^(2 * count) */
static void
ec25519_square_times( bignum25519 out, const bignum25519 in,
                      uint64_t count ) noexcept
{
  uint128_t t[ 5 ];
  uint64_t  r0, r1, r2, r3, r4, c;
  uint64_t  d0, d1, d2, d4, d419;

  r0 = in[ 0 ];
  r1 = in[ 1 ];
  r2 = in[ 2 ];
  r3 = in[ 3 ];
  r4 = in[ 4 ];

  do {
    d0   = r0 * 2;
    d1   = r1 * 2;
    d2   = r2 * 2 * 19;
    d419 = r4 * 19;
    d4   = d419 * 2;

    t[ 0 ] = ( (uint128_t) r0 ) * r0 + ( (uint128_t) d4 ) * r1 +
             ( ( (uint128_t) d2 ) * ( r3 ) );
    t[ 1 ] = ( (uint128_t) d0 ) * r1 + ( (uint128_t) d4 ) * r2 +
             ( ( (uint128_t) r3 ) * ( r3 * 19 ) );
    t[ 2 ] = ( (uint128_t) d0 ) * r2 + ( (uint128_t) r1 ) * r1 +
             ( ( (uint128_t) d4 ) * ( r3 ) );
    t[ 3 ] = ( (uint128_t) d0 ) * r3 + ( (uint128_t) d1 ) * r2 +
             ( ( (uint128_t) r4 ) * ( d419 ) );
    t[ 4 ] = ( (uint128_t) d0 ) * r4 + ( (uint128_t) d1 ) * r3 +
             ( ( (uint128_t) r2 ) * ( r2 ) );

    r0 = lo128( t[ 0 ] ) & reduce_mask_51;
    shr128( c, t[ 0 ], 51 );
    add128_64( t[ 1 ], c ) r1 = lo128( t[ 1 ] ) & reduce_mask_51;
    shr128( c, t[ 1 ], 51 );
    add128_64( t[ 2 ], c ) r2 = lo128( t[ 2 ] ) & reduce_mask_51;
    shr128( c, t[ 2 ], 51 );
    add128_64( t[ 3 ], c ) r3 = lo128( t[ 3 ] ) & reduce_mask_51;
    shr128( c, t[ 3 ], 51 );
    add128_64( t[ 4 ], c ) r4 = lo128( t[ 4 ] ) & reduce_mask_51;
    shr128( c, t[ 4 ], 51 );
    r0 += c * 19;
    c  = r0 >> 51;
    r0 = r0 & reduce_mask_51;
    r1 += c;
  } while ( --count );

  out[ 0 ] = r0;
  out[ 1 ] = r1;
  out[ 2 ] = r2;
  out[ 3 ] = r3;
  out[ 4 ] = r4;
}

static void
ec25519_square( bignum25519 out, const bignum25519 in ) noexcept
{
  uint128_t t[ 5 ];
  uint64_t  r0, r1, r2, r3, r4, c;
  uint64_t  d0, d1, d2, d4, d419;

  r0 = in[ 0 ];
  r1 = in[ 1 ];
  r2 = in[ 2 ];
  r3 = in[ 3 ];
  r4 = in[ 4 ];

  d0   = r0 * 2;
  d1   = r1 * 2;
  d2   = r2 * 2 * 19;
  d419 = r4 * 19;
  d4   = d419 * 2;

  t[ 0 ] = ( (uint128_t) r0 ) * r0 + ( (uint128_t) d4 ) * r1 +
           ( ( (uint128_t) d2 ) * ( r3 ) );
  t[ 1 ] = ( (uint128_t) d0 ) * r1 + ( (uint128_t) d4 ) * r2 +
           ( ( (uint128_t) r3 ) * ( r3 * 19 ) );
  t[ 2 ] = ( (uint128_t) d0 ) * r2 + ( (uint128_t) r1 ) * r1 +
           ( ( (uint128_t) d4 ) * ( r3 ) );
  t[ 3 ] = ( (uint128_t) d0 ) * r3 + ( (uint128_t) d1 ) * r2 +
           ( ( (uint128_t) r4 ) * ( d419 ) );
  t[ 4 ] = ( (uint128_t) d0 ) * r4 + ( (uint128_t) d1 ) * r3 +
           ( ( (uint128_t) r2 ) * ( r2 ) );

  r0 = lo128( t[ 0 ] ) & reduce_mask_51;
  shr128( c, t[ 0 ], 51 );
  add128_64( t[ 1 ], c ) r1 = lo128( t[ 1 ] ) & reduce_mask_51;
  shr128( c, t[ 1 ], 51 );
  add128_64( t[ 2 ], c ) r2 = lo128( t[ 2 ] ) & reduce_mask_51;
  shr128( c, t[ 2 ], 51 );
  add128_64( t[ 3 ], c ) r3 = lo128( t[ 3 ] ) & reduce_mask_51;
  shr128( c, t[ 3 ], 51 );
  add128_64( t[ 4 ], c ) r4 = lo128( t[ 4 ] ) & reduce_mask_51;
  shr128( c, t[ 4 ], 51 );
  r0 += c * 19;
  c  = r0 >> 51;
  r0 = r0 & reduce_mask_51;
  r1 += c;

  out[ 0 ] = r0;
  out[ 1 ] = r1;
  out[ 2 ] = r2;
  out[ 3 ] = r3;
  out[ 4 ] = r4;
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void
ec25519_expand( bignum25519 out, const uint8_t *in ) noexcept
{
  static const union {
    uint8_t  b[ 2 ];
    uint16_t s;
  } endian_check = { { 1, 0 } };
  uint64_t x0, x1, x2, x3;

  if ( endian_check.s == 1 ) {
    x0 = *(uint64_t *) ( in + 0 );
    x1 = *(uint64_t *) ( in + 8 );
    x2 = *(uint64_t *) ( in + 16 );
    x3 = *(uint64_t *) ( in + 24 );
  }
  else {
#define F( s )                                                                 \
  ( ( ( (uint64_t) in[ s + 0 ] ) ) | ( ( (uint64_t) in[ s + 1 ] ) << 8 ) |     \
    ( ( (uint64_t) in[ s + 2 ] ) << 16 ) |                                     \
    ( ( (uint64_t) in[ s + 3 ] ) << 24 ) |                                     \
    ( ( (uint64_t) in[ s + 4 ] ) << 32 ) |                                     \
    ( ( (uint64_t) in[ s + 5 ] ) << 40 ) |                                     \
    ( ( (uint64_t) in[ s + 6 ] ) << 48 ) |                                     \
    ( ( (uint64_t) in[ s + 7 ] ) << 56 ) )

    x0 = F( 0 );
    x1 = F( 8 );
    x2 = F( 16 );
    x3 = F( 24 );
  }

  out[ 0 ] = x0 & reduce_mask_51;
  x0       = ( x0 >> 51 ) | ( x1 << 13 );
  out[ 1 ] = x0 & reduce_mask_51;
  x1       = ( x1 >> 38 ) | ( x2 << 26 );
  out[ 2 ] = x1 & reduce_mask_51;
  x2       = ( x2 >> 25 ) | ( x3 << 39 );
  out[ 3 ] = x2 & reduce_mask_51;
  x3       = ( x3 >> 12 );
  out[ 4 ] = x3 & reduce_mask_51; /* ignore the top bit */
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void
ec25519_contract( uint8_t *out, const bignum25519 input ) noexcept
{
  uint64_t t[ 5 ];
  uint64_t f, i;

  t[ 0 ] = input[ 0 ];
  t[ 1 ] = input[ 1 ];
  t[ 2 ] = input[ 2 ];
  t[ 3 ] = input[ 3 ];
  t[ 4 ] = input[ 4 ];

#define ec25519_contract_carry()                                            \
  t[ 1 ] += t[ 0 ] >> 51;                                                      \
  t[ 0 ] &= reduce_mask_51;                                                    \
  t[ 2 ] += t[ 1 ] >> 51;                                                      \
  t[ 1 ] &= reduce_mask_51;                                                    \
  t[ 3 ] += t[ 2 ] >> 51;                                                      \
  t[ 2 ] &= reduce_mask_51;                                                    \
  t[ 4 ] += t[ 3 ] >> 51;                                                      \
  t[ 3 ] &= reduce_mask_51;

#define ec25519_contract_carry_full()                                       \
  ec25519_contract_carry() t[ 0 ] += 19 * ( t[ 4 ] >> 51 );                 \
  t[ 4 ] &= reduce_mask_51;

#define ec25519_contract_carry_final()                                      \
  ec25519_contract_carry() t[ 4 ] &= reduce_mask_51;

ec25519_contract_carry_full() ec25519_contract_carry_full()

/* now t is between 0 and 2^255-1, properly carried. */
/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
t[ 0 ] += 19;
ec25519_contract_carry_full()

/* now between 19 and 2^255-1 in both cases, and offset by 19. */
t[ 0 ] += 0x8000000000000 - 19;
t[ 1 ] += 0x8000000000000 - 1;
t[ 2 ] += 0x8000000000000 - 1;
t[ 3 ] += 0x8000000000000 - 1;
t[ 4 ] += 0x8000000000000 - 1;

/* now between 2^255 and 2^256-20, and offset by 2^255. */
ec25519_contract_carry_final()

#define write51full( n, shift )                                                \
  f = ( ( t[ n ] >> shift ) | ( t[ n + 1 ] << ( 51 - shift ) ) );              \
  for ( i = 0; i < 8; i++, f >>= 8 )                                           \
    *out++ = (uint8_t) f;
#define write51( n ) write51full( n, 13 * n )

write51( 0 ) write51( 1 ) write51( 2 ) write51( 3 )

#undef ec25519_contract_carry
#undef ec25519_contract_carry_full
#undef ec25519_contract_carry_final
#undef write51full
#undef write51
}

/*
 * Swap the contents of [qx] and [qpx] iff @swap is non-zero
 */
static void
ec25519_swap_conditional( bignum25519 x, bignum25519 qpx,
                          uint64_t iswap ) noexcept
{
  const uint64_t swap = ( uint64_t )( -(int64_t) iswap );
  uint64_t       x0, x1, x2, x3, x4;

  x0 = swap & ( x[ 0 ] ^ qpx[ 0 ] );
  x[ 0 ] ^= x0;
  qpx[ 0 ] ^= x0;
  x1 = swap & ( x[ 1 ] ^ qpx[ 1 ] );
  x[ 1 ] ^= x1;
  qpx[ 1 ] ^= x1;
  x2 = swap & ( x[ 2 ] ^ qpx[ 2 ] );
  x[ 2 ] ^= x2;
  qpx[ 2 ] ^= x2;
  x3 = swap & ( x[ 3 ] ^ qpx[ 3 ] );
  x[ 3 ] ^= x3;
  qpx[ 3 ] ^= x3;
  x4 = swap & ( x[ 4 ] ^ qpx[ 4 ] );
  x[ 4 ] ^= x4;
  qpx[ 4 ] ^= x4;
}

static void
ec25519_scalarmult_donna( ec25519_key &mypublic, const ec25519_key &n,
                          const ec25519_key &basepoint ) noexcept
{
  bignum25519 nqpqx = { 1 }, nqpqz = { 0 }, nqz = { 1 }, nqx;
  bignum25519 q, qx, qpqx, qqx, zzz, zmone;
  size_t      bit, lastbit;
  int32_t     i;

  ec25519_expand( q, basepoint );
  ec25519_copy( nqx, q );

  /* bit 255 is always 0, and bit 254 is always 1, so skip bit 255 and
     start pre-swapped on bit 254 */
  lastbit = 1;

  /* we are doing bits 254..3 in the loop, but are swapping in bits 253..2 */
  for ( i = 253; i >= 2; i-- ) {
    ec25519_add( qx, nqx, nqz );
    ec25519_sub( nqz, nqx, nqz );
    ec25519_add( qpqx, nqpqx, nqpqz );
    ec25519_sub( nqpqz, nqpqx, nqpqz );
    ec25519_mul( nqpqx, qpqx, nqz );
    ec25519_mul( nqpqz, qx, nqpqz );
    ec25519_add( qqx, nqpqx, nqpqz );
    ec25519_sub( nqpqz, nqpqx, nqpqz );
    ec25519_square( nqpqz, nqpqz );
    ec25519_square( nqpqx, qqx );
    ec25519_mul( nqpqz, nqpqz, q );
    ec25519_square( qx, qx );
    ec25519_square( nqz, nqz );
    ec25519_mul( nqx, qx, nqz );
    ec25519_sub( nqz, qx, nqz );
    ec25519_scalar_product( zzz, nqz, 121665 );
    ec25519_add( zzz, zzz, qx );
    ec25519_mul( nqz, nqz, zzz );

    bit = ( n[ i / 8 ] >> ( i & 7 ) ) & 1;
    ec25519_swap_conditional( nqx, nqpqx, bit ^ lastbit );
    ec25519_swap_conditional( nqz, nqpqz, bit ^ lastbit );
    lastbit = bit;
  }

  /* the final 3 bits are always zero, so we only need to double */
  for ( i = 0; i < 3; i++ ) {
    ec25519_add( qx, nqx, nqz );
    ec25519_sub( nqz, nqx, nqz );
    ec25519_square( qx, qx );
    ec25519_square( nqz, nqz );
    ec25519_mul( nqx, qx, nqz );
    ec25519_sub( nqz, qx, nqz );
    ec25519_scalar_product( zzz, nqz, 121665 );
    ec25519_add( zzz, zzz, qx );
    ec25519_mul( nqz, nqz, zzz );
  }

  ec25519_recip( zmone, nqz );
  ec25519_mul( nqz, nqx, zmone );
  ec25519_contract( mypublic, nqz );
}
