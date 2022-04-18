#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include <raims/aes.h>

using namespace rai;
using namespace ms;

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

void
AES128::expand_key( const void *key ) noexcept
{
  __m128i * sched = (__m128i *) this->key_sched,
            genass;
  int i, j;

  sched[ 0 ] = _mm_loadu_si128( (const __m128i *) key );

  genass      = _mm_aeskeygenassist_si128( sched[ 0 ], 0x1 );
  sched[ 1 ]  = key_expansion_128( sched[ 0 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 1 ], 0x2 );
  sched[ 2 ]  = key_expansion_128( sched[ 1 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 2 ], 0x4 );
  sched[ 3 ]  = key_expansion_128( sched[ 2 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 3 ], 0x8 );
  sched[ 4 ]  = key_expansion_128( sched[ 3 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 4 ], 0x10 );
  sched[ 5 ]  = key_expansion_128( sched[ 4 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 5 ], 0x20 );
  sched[ 6 ]  = key_expansion_128( sched[ 5 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 6 ], 0x40 );
  sched[ 7 ]  = key_expansion_128( sched[ 6 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 7 ], 0x80 );
  sched[ 8 ]  = key_expansion_128( sched[ 7 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 8 ], 0x1b );
  sched[ 9 ]  = key_expansion_128( sched[ 8 ], genass );
  genass      = _mm_aeskeygenassist_si128( sched[ 9 ], 0x36 );
  sched[ 10 ] = key_expansion_128( sched[ 9 ], genass );
  j = 10;
  for ( i = 11; i < 20; i++ )
    sched[ i ] = _mm_aesimc_si128( sched[ --j ] );
}

void
AES128::encrypt( const void *plain,  void *cipher ) noexcept
{
  __m128i * sched = (__m128i *) this->key_sched,
            mix   = _mm_loadu_si128( (__m128i *) plain );

  mix = _mm_xor_si128( mix, sched[ 0 ] );
  for ( int i = 1; i < 10; i++ )
    mix = _mm_aesenc_si128( mix, sched[ i ] );
  mix = _mm_aesenclast_si128( mix, sched[ 10 ] );

  _mm_storeu_si128( (__m128i *) cipher, mix );
}

void
AES128::decrypt( const void *cipher,  void *plain ) noexcept
{
  __m128i * sched = (__m128i *) this->key_sched,
            mix   = _mm_loadu_si128( (__m128i *) cipher );

  mix = _mm_xor_si128( mix, sched[ 10 ] );
  for ( int i = 11; i < 20; i++ )
    mix = _mm_aesdec_si128( mix, sched[ i ] );
  mix = _mm_aesdeclast_si128( mix, sched[ 0 ] );

  _mm_storeu_si128( (__m128i *) plain, mix );
}

