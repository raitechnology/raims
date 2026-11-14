#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <raims/aes.h>
#include <raikv/util.h>

using namespace rai;
using namespace ms;

#if defined( __x86_64__ ) || defined( __i386__ )
#include <wmmintrin.h>

static __m128i
key_expansion_128( __m128i key, __m128i gen )
{
  __m128i tmp;

  gen = _mm_shuffle_epi32( gen, _MM_SHUFFLE( 3, 3, 3, 3 ) );
  tmp = _mm_slli_si128( key, 4 );
  key = _mm_xor_si128( key, tmp );
  tmp = _mm_slli_si128( tmp, 4 );
  key = _mm_xor_si128( key, tmp );
  tmp = _mm_slli_si128( tmp, 4 );
  key = _mm_xor_si128( key, tmp );
  key = _mm_xor_si128( key, gen );

  return key;
}

/* key_sched is accessed with unaligned load/store so the buffer carries no
 * alignment contract (see aes.h): AES-NI operands need no alignment, and
 * vmovdqu == vmovdqa on aligned data under -mavx.  This lets the enclosing
 * socket object be allocated by plain malloc without a codegen trap. */
void
AES128::expand_key( const void *key ) noexcept
{
  __m128i * sched = (__m128i *) this->key_sched,
            genass, k;
  int i, j;

  k = _mm_loadu_si128( (const __m128i *) key );
  _mm_storeu_si128( &sched[ 0 ], k );

  genass = _mm_aeskeygenassist_si128( k, 0x1 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 1 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x2 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 2 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x4 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 3 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x8 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 4 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x10 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 5 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x20 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 6 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x40 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 7 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x80 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 8 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x1b );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 9 ], k );
  genass = _mm_aeskeygenassist_si128( k, 0x36 );
  k = key_expansion_128( k, genass );
  _mm_storeu_si128( &sched[ 10 ], k );
  j = 10;
  for ( i = 11; i < 20; i++ )
    _mm_storeu_si128( &sched[ i ],
                      _mm_aesimc_si128( _mm_loadu_si128( &sched[ --j ] ) ) );
}

void
AES128::encrypt( const void *plain,  void *cipher ) noexcept
{
  __m128i * sched = (__m128i *) this->key_sched,
            mix   = _mm_loadu_si128( (__m128i *) plain );

  mix = _mm_xor_si128( mix, _mm_loadu_si128( &sched[ 0 ] ) );
  for ( size_t i = 1; i < 10; i++ )
    mix = _mm_aesenc_si128( mix, _mm_loadu_si128( &sched[ i ] ) );
  mix = _mm_aesenclast_si128( mix, _mm_loadu_si128( &sched[ 10 ] ) );

  _mm_storeu_si128( (__m128i *) cipher, mix );
}

void
AES128::decrypt( const void *cipher,  void *plain ) noexcept
{
  __m128i * sched = (__m128i *) this->key_sched,
            mix   = _mm_loadu_si128( (__m128i *) cipher );

  mix = _mm_xor_si128( mix, _mm_loadu_si128( &sched[ 10 ] ) );
  for ( size_t i = 11; i < 20; i++ )
    mix = _mm_aesdec_si128( mix, _mm_loadu_si128( &sched[ i ] ) );
  mix = _mm_aesdeclast_si128( mix, _mm_loadu_si128( &sched[ 0 ] ) );

  _mm_storeu_si128( (__m128i *) plain, mix );
}

static inline uint64_t bswap( uint64_t x ) { return kv_bswap64( x ); }

void
AES128::encrypt_ctr( uint64_t ctr[ 2 ], void *out, size_t out_blocks ) noexcept
{
  uint8_t * ptr = (uint8_t *) out;
  uint64_t  i   = bswap( ctr[ 1 ] ),
            j   = ctr[ 0 ];

  if ( ~i >= out_blocks - 1 && out_blocks >= 8 ) {
    do {
      __m128i * sched = (__m128i *) this->key_sched, sk,
                mix0, mix1, mix2, mix3, mix4, mix5, mix6, mix7;

      mix0 = _mm_set_epi64x( bswap( i     ), j );
      mix1 = _mm_set_epi64x( bswap( i + 1 ), j );
      mix2 = _mm_set_epi64x( bswap( i + 2 ), j );
      mix3 = _mm_set_epi64x( bswap( i + 3 ), j );
      mix4 = _mm_set_epi64x( bswap( i + 4 ), j );
      mix5 = _mm_set_epi64x( bswap( i + 5 ), j );
      mix6 = _mm_set_epi64x( bswap( i + 6 ), j );
      mix7 = _mm_set_epi64x( bswap( i + 7 ), j );

      sk = _mm_loadu_si128( &sched[ 0 ] );
      mix0 = _mm_xor_si128( mix0, sk );
      mix1 = _mm_xor_si128( mix1, sk );
      mix2 = _mm_xor_si128( mix2, sk );
      mix3 = _mm_xor_si128( mix3, sk );
      mix4 = _mm_xor_si128( mix4, sk );
      mix5 = _mm_xor_si128( mix5, sk );
      mix6 = _mm_xor_si128( mix6, sk );
      mix7 = _mm_xor_si128( mix7, sk );

      for ( size_t k = 1; k < 10; k++ ) {
        sk = _mm_loadu_si128( &sched[ k ] );
        mix0 = _mm_aesenc_si128( mix0, sk );
        mix1 = _mm_aesenc_si128( mix1, sk );
        mix2 = _mm_aesenc_si128( mix2, sk );
        mix3 = _mm_aesenc_si128( mix3, sk );
        mix4 = _mm_aesenc_si128( mix4, sk );
        mix5 = _mm_aesenc_si128( mix5, sk );
        mix6 = _mm_aesenc_si128( mix6, sk );
        mix7 = _mm_aesenc_si128( mix7, sk );
      }
      sk = _mm_loadu_si128( &sched[ 10 ] );
      mix0 = _mm_aesenclast_si128( mix0, sk );
      mix1 = _mm_aesenclast_si128( mix1, sk );
      mix2 = _mm_aesenclast_si128( mix2, sk );
      mix3 = _mm_aesenclast_si128( mix3, sk );
      mix4 = _mm_aesenclast_si128( mix4, sk );
      mix5 = _mm_aesenclast_si128( mix5, sk );
      mix6 = _mm_aesenclast_si128( mix6, sk );
      mix7 = _mm_aesenclast_si128( mix7, sk );

      _mm_storeu_si128( (__m128i *) ptr,          mix0 );
      _mm_storeu_si128( (__m128i *) &ptr[ 16 ],   mix1 );
      _mm_storeu_si128( (__m128i *) &ptr[ 16*2 ], mix2 );
      _mm_storeu_si128( (__m128i *) &ptr[ 16*3 ], mix3 );
      _mm_storeu_si128( (__m128i *) &ptr[ 16*4 ], mix4 );
      _mm_storeu_si128( (__m128i *) &ptr[ 16*5 ], mix5 );
      _mm_storeu_si128( (__m128i *) &ptr[ 16*6 ], mix6 );
      _mm_storeu_si128( (__m128i *) &ptr[ 16*7 ], mix7 );

      ptr = &ptr[ 16*8 ];
      i  += 8;
      out_blocks -= 8;
    } while ( out_blocks >= 8 );
    if ( i == 0 ) {
      j = bswap( bswap( j ) + 1 );
      ctr[ 0 ] = j;
    }
  }
  while ( out_blocks > 0 ) {
    uint64_t in[ 2 ] = { j, bswap( i ) };
    this->encrypt( in, ptr );
    ptr = &ptr[ 16 ];
    if ( ++i == 0 ) {
      j = bswap( bswap( j ) + 1 );
      ctr[ 0 ] = j;
    }
    out_blocks -= 1;
  }
  ctr[ 1 ] = bswap( i );
}

void
AES128::block_xor( const void *in,  void *out,  size_t blocks ) noexcept
{
  const uint8_t * in_ptr = (const uint8_t *) in;
  uint8_t * out_ptr = (uint8_t *) out;

  if ( blocks >= 4 ) {
    do {
      __m128i b0, b1, b2, b3, x0, x1, x2, x3;

      b0 = _mm_loadu_si128( (__m128i *) in_ptr           );
      b1 = _mm_loadu_si128( (__m128i *) &in_ptr[ 16 ]    );
      b2 = _mm_loadu_si128( (__m128i *) &in_ptr[ 16*2 ]  );
      b3 = _mm_loadu_si128( (__m128i *) &in_ptr[ 16*3 ]  );

      x0 = _mm_loadu_si128( (__m128i *) out_ptr          );
      x1 = _mm_loadu_si128( (__m128i *) &out_ptr[ 16 ]   );
      x2 = _mm_loadu_si128( (__m128i *) &out_ptr[ 16*2 ] );
      x3 = _mm_loadu_si128( (__m128i *) &out_ptr[ 16*3 ] );

      b0 = _mm_xor_si128( x0, b0 );
      b1 = _mm_xor_si128( x1, b1 );
      b2 = _mm_xor_si128( x2, b2 );
      b3 = _mm_xor_si128( x3, b3 );

      _mm_storeu_si128( (__m128i *) out_ptr,          b0 );
      _mm_storeu_si128( (__m128i *) &out_ptr[ 16 ],   b1 );
      _mm_storeu_si128( (__m128i *) &out_ptr[ 16*2 ], b2 );
      _mm_storeu_si128( (__m128i *) &out_ptr[ 16*3 ], b3 );

      in_ptr  = &in_ptr[ 16*4 ];
      out_ptr = &out_ptr[ 16*4 ];
      blocks -= 4;
    } while ( blocks >= 4 );
  }
  while ( blocks > 0 ) {
    __m128i b, x;

    b = _mm_loadu_si128( (__m128i *) in_ptr  );
    x = _mm_loadu_si128( (__m128i *) out_ptr );

    b = _mm_xor_si128( x, b );

    _mm_storeu_si128( (__m128i *) out_ptr, b );

    in_ptr  = &in_ptr[ 16 ];
    out_ptr = &out_ptr[ 16 ];
    blocks -= 1;
  }
}

#else
/* ARMv8 Crypto Extension port (arm_neon.h: vaeseq_u8/vaesmcq_u8/vaesdq_u8/
 * vaesimcq_u8). */
#include <arm_neon.h>

static const uint8_t kv_aes_sbox[ 256 ] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t kv_aes_rcon[ 10 ] = {
  0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* FIPS-197 standard AES-128 key schedule: derive round keys sched[1..10]
 * (each 16 bytes) from sched[0] (the raw key), then compute the
 * "equivalent inverse cipher" keys sched[11..20] used by the fused
 * AESD/AESIMC decrypt below */
__attribute__((__target__("+crypto")))
void
AES128::expand_key( const void *key ) noexcept
{
  uint8_t * sched = this->key_sched;
  memcpy( &sched[ 0 ], key, 16 );

  for ( int r = 1; r <= 10; r++ ) {
    const uint8_t * prev = &sched[ ( r - 1 ) * 16 ];
    uint8_t       * cur  = &sched[ r * 16 ];
    uint8_t temp[ 4 ] = { prev[ 13 ], prev[ 14 ], prev[ 15 ], prev[ 12 ] }; /* RotWord */
    temp[ 0 ] = kv_aes_sbox[ temp[ 0 ] ];                                    /* SubWord */
    temp[ 1 ] = kv_aes_sbox[ temp[ 1 ] ];
    temp[ 2 ] = kv_aes_sbox[ temp[ 2 ] ];
    temp[ 3 ] = kv_aes_sbox[ temp[ 3 ] ];
    temp[ 0 ] ^= kv_aes_rcon[ r - 1 ];

    for ( int w = 0; w < 4; w++ ) {
      cur[ w ]      = prev[ w ]      ^ temp[ w ];
      cur[ 4  + w ] = prev[ 4  + w ] ^ cur[ w ];
      cur[ 8  + w ] = prev[ 8  + w ] ^ cur[ 4 + w ];
      cur[ 12 + w ] = prev[ 12 + w ] ^ cur[ 8 + w ];
    }
  }

  int j = 10;
  for ( int i = 11; i < 20; i++ ) {
    uint8x16_t k = vld1q_u8( &sched[ --j * 16 ] );
    vst1q_u8( &sched[ i * 16 ], vaesimcq_u8( k ) );
  }
}

__attribute__((__target__("+crypto")))
void
AES128::encrypt( const void *plain,  void *cipher ) noexcept
{
  const uint8_t * sched = this->key_sched;
  uint8x16_t t = vld1q_u8( (const uint8_t *) plain );

  /* AESE(a,k) = SubBytes(ShiftRows(a XOR k)) -- AddRoundKey happens first,
   * opposite of x86 AESENC -- so each AESE call both completes the
   * previous round's AddRoundKey and performs the current round */
  for ( int i = 0; i < 9; i++ ) {
    t = vaeseq_u8( t, vld1q_u8( &sched[ i * 16 ] ) );
    t = vaesmcq_u8( t );
  }
  t = vaeseq_u8( t, vld1q_u8( &sched[ 9 * 16 ] ) );
  t = veorq_u8( t, vld1q_u8( &sched[ 10 * 16 ] ) );

  vst1q_u8( (uint8_t *) cipher, t );
}

__attribute__((__target__("+crypto")))
void
AES128::decrypt( const void *cipher,  void *plain ) noexcept
{
  const uint8_t * sched = this->key_sched;
  uint8x16_t t = vld1q_u8( (const uint8_t *) cipher );

  /* Mirror image of encrypt(), using the FIPS equivalent-inverse-cipher
   * form (hence the pre-InvMixColumns'd sched[11..19] */
  t = vaesdq_u8( t, vld1q_u8( &sched[ 10 * 16 ] ) );
  for ( int i = 11; i < 19; i++ ) {
    t = vaesimcq_u8( t );
    t = vaesdq_u8( t, vld1q_u8( &sched[ i * 16 ] ) );
  }
  t = vaesimcq_u8( t );
  t = vaesdq_u8( t, vld1q_u8( &sched[ 19 * 16 ] ) );
  t = veorq_u8( t, vld1q_u8( &sched[ 0 ] ) );

  vst1q_u8( (uint8_t *) plain, t );
}

static inline uint64_t bswap( uint64_t x ) { return kv_bswap64( x ); }

/* CTR-mode keystream generation only (no plaintext XOR here -- callers
 * use block_xor()/byte_xor() separately */
void
AES128::encrypt_ctr( uint64_t ctr[ 2 ], void *out, size_t out_blocks ) noexcept
{
  uint8_t * ptr = (uint8_t *) out;
  uint64_t  i   = bswap( ctr[ 1 ] ),
            j   = ctr[ 0 ];

  while ( out_blocks > 0 ) {
    uint64_t in[ 2 ] = { j, bswap( i ) };
    this->encrypt( in, ptr );
    ptr = &ptr[ 16 ];
    if ( ++i == 0 ) {
      j = bswap( bswap( j ) + 1 );
      ctr[ 0 ] = j;
    }
    out_blocks -= 1;
  }
  ctr[ 1 ] = bswap( i );
}

void
AES128::block_xor( const void *in,  void *out,  size_t blocks ) noexcept
{
  const uint8_t * in_ptr = (const uint8_t *) in;
  uint8_t * out_ptr = (uint8_t *) out;

  while ( blocks > 0 ) {
    uint8x16_t b = vld1q_u8( in_ptr );
    uint8x16_t x = vld1q_u8( out_ptr );
    vst1q_u8( out_ptr, veorq_u8( x, b ) );
    in_ptr  = &in_ptr[ 16 ];
    out_ptr = &out_ptr[ 16 ];
    blocks -= 1;
  }
}

#endif /* arch dispatch */

/* byte_xor() is pure data movement (no AES instructions), identical on
 * every architecture -- shared, not duplicated per arch branch. */
void
AES128::byte_xor( const void *in,  void *out,  size_t bytes ) noexcept
{
  size_t blocks = bytes / 16;
  bytes %= 16;
  if ( blocks > 0 ) {
    AES128::block_xor( in, out, blocks );
    in  = &((const uint8_t *) in)[ 16 * blocks ];
    out = &((uint8_t *) out)[ 16 * blocks ];
  }
  if ( bytes >= 8 ) {
    uint64_t in_w, out_w;
    ::memcpy( &in_w, in, sizeof( in_w ) );
    ::memcpy( &out_w, out, sizeof( out_w ) );
    out_w ^= in_w;
    ::memcpy( out, &out_w, sizeof( out_w ) );
    in  = &((const uint8_t *) in)[ 8 ];
    out = &((uint8_t *) out)[ 8 ];
    bytes -= 8;
  }
  for ( size_t i = 0; i < bytes; i++ ) {
    ((uint8_t *) out)[ i ] ^= ((const uint8_t *) in)[ i ];
  }
}
