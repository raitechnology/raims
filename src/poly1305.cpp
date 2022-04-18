/*
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

/* $OpenBSD: poly1305.c,v 1.3 2013/12/19 22:57:13 djm Exp $ */
#include <string.h>
#include <stdint.h>
#include <raims/poly1305.h>

using namespace rai;
using namespace ms;

#ifndef _MSC_VER
typedef __uint128_t uint128_t;

static inline uint64_t SHR( uint128_t in, int shift ) {
  return (uint64_t)( in >> shift );
}
static inline void ADD( uint128_t &a, uint128_t b ) {
  a += b;
}
static inline void ADDLO( uint128_t &a, uint64_t b ) {
  a += b;
}
static inline uint64_t LO( uint128_t a ) {
  return (uint64_t) a;
}
static inline void MUL( uint128_t &out, uint64_t a, uint64_t b ) {
  out = (uint128_t) a * b;
}
#else
#include <intrin.h>

typedef struct uint128_s {
  uint64_t lo, hi;

  uint128_s() {}
  uint128_s( uint64_t l,  uint64_t h = 0 ) : lo( l ), hi( h ) {}
  uint128_s( const uint128_s &b ) : lo( b.lo ), hi( b.hi ) {}

  uint64_t operator >>( int shift ) const {
    return __shiftright128( this->lo, this->hi, shift );
  }
  uint128_s operator *( uint64_t m ) const {
    uint128_s x;
    x.lo = _umul128( this->lo, m, &x.hi );
    return x;
  }
  uint128_s operator +( const uint128_s &b ) const {
    uint128_s a = *this;;
    return a += b;
  }
  uint128_s &operator +=( const uint128_s &b ) {
    uint64_t p = this->lo;
    this->lo += b.lo;
    this->hi += b.hi + ( this->lo < p );
    return *this;
  }
  explicit operator uint64_t() const {
    return this->lo;
  }
} uint128_t;

static inline uint64_t SHR( uint128_t in, int shift ) {
  return in >> shift;
}
static inline void ADD( uint128_t &a, uint128_t b ) {
  a += b;
}
static inline void ADDLO( uint128_t &a, uint64_t b ) {
  a += b;
}
static inline uint64_t LO( uint128_t a ) {
  return (uint64_t) a;
}
static inline void MUL( uint128_t &out, uint64_t a, uint64_t b ) {
  out = (uint128_t) a * b;
}
#endif

void
rai::ms::poly1305_auth( uint8_t out[ POLY1305_W64TAG ],
                        const unsigned char *m,
                        size_t inlen,
                        const uint8_t key[ POLY1305_W64KEY ] ) noexcept
{
  poly1305_vec_t vec = { m, inlen };
  if ( ( (uintptr_t) (void *) out & 7 ) == 0 &&
       ( (uintptr_t) (void *) key & 7 ) == 0 ) {
    poly1305_auth_v( (uint64_t *) (void *) out, &vec, 1,
                     (const uint64_t *) (void *) key );
  }
  else {
    uint64_t outw[ POLY1305_W64TAG ], keyw[ POLY1305_W64KEY ];
    memcpy( keyw, key, sizeof( keyw ) );
    poly1305_auth_v( outw, &vec, 1, keyw );
    memcpy( out, outw, sizeof( outw ) );
  }
}

void
rai::ms::poly1305_auth_v( uint64_t out[ POLY1305_W64TAG ],
                          const poly1305_vec_t *vec,
                          size_t veclen,
                          const uint64_t key[ POLY1305_W64KEY ] ) noexcept
{
  uint64_t t0, t1;
  uint64_t h0, h1, h2, h_add;
  uint64_t r0, r1, r2;
  uint64_t g0, g1, g2;
  uint64_t s1, s2;
  uint64_t c;
  uint128_t d0, d1, d2, d;
  size_t i, j, k, inlen, inoff;
  uint8_t mp[16];
  const uint8_t *m;

  /* clamp key */
  t0 = key[ 0 ];
  t1 = key[ 1 ];

  /* precompute multipliers */
  r0 = ( t0                    ) & 0xffc0fffffff;
  r1 = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
  r2 = ((t1 >> 24)             ) & 0x00ffffffc0f;

  s1 = r1 * (5 << 2);
  s2 = r2 * (5 << 2);

  /* init state */
  h0 = 0;
  h1 = 0;
  h2 = 0;
  h_add = (uint64_t) 1 << 40;

  inlen = 0;
  for ( i = 0; i < veclen; i++ )
    inlen += vec[ i ].buflen;
  i = 0; j = 0;
  /* process blocks */
  for ( inoff = 0; inoff < inlen; inoff += 16 ) {
    m = &((const uint8_t *) vec[ i ].buf)[ j ];
    if ( j + 16 <= vec[ i ].buflen ) {
      j += 16;
    }
    else {
      k = vec[ i ].buflen - j;
      for ( j = 0; j < k; j++ )
        mp[ j ] = ((const uint8_t *) m)[ j ];
      for (;;) {
        if ( ++i == veclen ) {
          mp[ k++ ] = 1;
          for ( ; k < 16; k++ )
            mp[ k ] = 0;
          h_add = 0;
          goto break_loop;
        }
        j = 0;
        m = (const uint8_t *) vec[ i ].buf;
        while ( j < vec[ i ].buflen ) {
          mp[ k++ ] = ((const uint8_t *) m)[ j++ ];
          if ( k == 16 )
            goto break_loop;
        }
      }
    break_loop:;
      m = mp;
    }
    memcpy( &t0, m, 8 );
    memcpy( &t1, &m[ 8 ], 8 );

    h0 += (( t0                    ) & 0xfffffffffff);
    h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
    h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | h_add;

    /* h *= r */
    MUL(d0, h0, r0); MUL(d, h1, s2); ADD(d0, d); MUL(d, h2, s1); ADD(d0, d);
    MUL(d1, h0, r1); MUL(d, h1, r0); ADD(d1, d); MUL(d, h2, s2); ADD(d1, d);
    MUL(d2, h0, r2); MUL(d, h1, r1); ADD(d2, d); MUL(d, h2, r0); ADD(d2, d);

    /* (partial) h %= p */
                  c = SHR(d0, 44); h0 = LO(d0) & 0xfffffffffff;
    ADDLO(d1, c); c = SHR(d1, 44); h1 = LO(d1) & 0xfffffffffff;
    ADDLO(d2, c); c = SHR(d2, 42); h2 = LO(d2) & 0x3ffffffffff;
    h0  += c * 5; c = (h0 >> 44);  h0 =    h0  & 0xfffffffffff;
    h1  += c;
  }

               c = (h1 >> 44); h1 &= 0xfffffffffff;
  h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
  h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
  h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
  h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
  h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
  h1 += c;

  /* compute h + -p */
  g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
  g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
  g2 = h2 + c - ((uint64_t) 1 << 42);

  /* select h if h < p, or h + -p if h >= p */
  c = (g2 >> ((sizeof(uint64_t) * 8) - 1)) - 1;
  g0 &= c;
  g1 &= c;
  g2 &= c;
  c = ~c;
  h0 = (h0 & c) | g0;
  h1 = (h1 & c) | g1;
  h2 = (h2 & c) | g2;

  /* h = (h + pad) */
  t0 = key[ 2 ];
  t1 = key[ 3 ];

  h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
  h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
  h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;

  /* mac = h % (2^128) */
  h0 = ((h0      ) | (h1 << 44));
  h1 = ((h1 >> 20) | (h2 << 24));

  out[ 0 ] = h0;
  out[ 1 ] = h1;
}

#if 0
static void
poly1305_block64( const uint32_t r[ 4 ],
                  uint32_t h[ 5 ],
                  const void *m )
{
  static const uint32_t end = 1;
  uint32_t s[ 16 ], i;
  memcpy( s, m, sizeof( s ) );

  uint64_t u0 = h[0];
  uint64_t u1 = h[1];
  uint64_t u2 = h[2];
  uint64_t u3 = h[3];
  uint32_t u4 = h[4];
  const uint32_t r0 = r[0];       // r0  <= 0fffffff
  const uint32_t r1 = r[1];       // r1  <= 0ffffffc
  const uint32_t r2 = r[2];       // r2  <= 0ffffffc
  const uint32_t r3 = r[3];       // r3  <= 0ffffffc

  for ( i = 0; i < 16; i += 4 ) {
    // s = h + c, without carry propagation
    const uint64_t s0 = u0 + (uint64_t) s[i+0]; // s0 <= 1_fffffffe
    const uint64_t s1 = u1 + (uint64_t) s[i+1]; // s1 <= 1_fffffffe
    const uint64_t s2 = u2 + (uint64_t) s[i+2]; // s2 <= 1_fffffffe
    const uint64_t s3 = u3 + (uint64_t) s[i+3]; // s3 <= 1_fffffffe
    const uint32_t s4 = u4 + end;       // s4 <=          5

    // Local all the things!
    const uint32_t rr0 = (r0 >> 2) * 5;  // rr0 <= 13fffffb // lose 2 bits...
    const uint32_t rr1 = (r1 >> 2) + r1; // rr1 <= 13fffffb // rr1 == (r1 >> 2) * 5
    const uint32_t rr2 = (r2 >> 2) + r2; // rr2 <= 13fffffb // rr1 == (r2 >> 2) * 5
    const uint32_t rr3 = (r3 >> 2) + r3; // rr3 <= 13fffffb // rr1 == (r3 >> 2) * 5

    // (h + c) * r, without carry propagation
    const uint64_t x0 = s0*r0+ s1*rr3+ s2*rr2+ s3*rr1+ s4*rr0; // <= 97ffffe007fffff8
    const uint64_t x1 = s0*r1+ s1*r0 + s2*rr3+ s3*rr2+ s4*rr1; // <= 8fffffe20ffffff6
    const uint64_t x2 = s0*r2+ s1*r1 + s2*r0 + s3*rr3+ s4*rr2; // <= 87ffffe417fffff4
    const uint64_t x3 = s0*r3+ s1*r2 + s2*r1 + s3*r0 + s4*rr3; // <= 7fffffe61ffffff2
    const uint32_t x4 = s4 * (r0 & 3); // ...recover 2 bits    // <=                f

    // partial reduction modulo 2^130 - 5
    const uint32_t u5 = x4 + (x3 >> 32); // u5 <= 7ffffff5
    u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
    u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
    u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
    u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
    u4 = (u3 >> 32)     + (u5 & 3);
  }

  // Update the hash
  h[0] = (uint32_t) u0; // u0 <= 1_9ffffff0
  h[1] = (uint32_t) u1; // u1 <= 1_97ffffe0
  h[2] = (uint32_t) u2; // u2 <= 1_8fffffe2
  h[3] = (uint32_t) u3; // u3 <= 1_87ffffe4
  h[4] = (uint32_t) u4; // u4 <=          4
}
             
static void
poly1305_block( const uint32_t r[ 4 ],
                uint32_t h[ 5 ],
                const void *m,
                uint32_t end )
{
  uint32_t s[ 4 ];
  memcpy( s, m, sizeof( s ) );

  // s = h + c, without carry propagation
  const uint64_t s0 = h[0] + (uint64_t) s[0]; // s0 <= 1_fffffffe
  const uint64_t s1 = h[1] + (uint64_t) s[1]; // s1 <= 1_fffffffe
  const uint64_t s2 = h[2] + (uint64_t) s[2]; // s2 <= 1_fffffffe
  const uint64_t s3 = h[3] + (uint64_t) s[3]; // s3 <= 1_fffffffe
  const uint32_t s4 = h[4] + end;       // s4 <=          5

  // Local all the things!
  const uint32_t r0 = r[0];       // r0  <= 0fffffff
  const uint32_t r1 = r[1];       // r1  <= 0ffffffc
  const uint32_t r2 = r[2];       // r2  <= 0ffffffc
  const uint32_t r3 = r[3];       // r3  <= 0ffffffc
  const uint32_t rr0 = (r0 >> 2) * 5;  // rr0 <= 13fffffb // lose 2 bits...
  const uint32_t rr1 = (r1 >> 2) + r1; // rr1 <= 13fffffb // rr1 == (r1 >> 2) * 5
  const uint32_t rr2 = (r2 >> 2) + r2; // rr2 <= 13fffffb // rr1 == (r2 >> 2) * 5
  const uint32_t rr3 = (r3 >> 2) + r3; // rr3 <= 13fffffb // rr1 == (r3 >> 2) * 5

  // (h + c) * r, without carry propagation
  const uint64_t x0 = s0*r0+ s1*rr3+ s2*rr2+ s3*rr1+ s4*rr0; // <= 97ffffe007fffff8
  const uint64_t x1 = s0*r1+ s1*r0 + s2*rr3+ s3*rr2+ s4*rr1; // <= 8fffffe20ffffff6
  const uint64_t x2 = s0*r2+ s1*r1 + s2*r0 + s3*rr3+ s4*rr2; // <= 87ffffe417fffff4
  const uint64_t x3 = s0*r3+ s1*r2 + s2*r1 + s3*r0 + s4*rr3; // <= 7fffffe61ffffff2
  const uint32_t x4 = s4 * (r0 & 3); // ...recover 2 bits    // <=                f

  // partial reduction modulo 2^130 - 5
  const uint32_t u5 = x4 + (x3 >> 32); // u5 <= 7ffffff5
  const uint64_t u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
  const uint64_t u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
  const uint64_t u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
  const uint64_t u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
  const uint64_t u4 = (u3 >> 32)     + (u5 & 3);

  // Update the hash
  h[0] = (uint32_t) u0; // u0 <= 1_9ffffff0
  h[1] = (uint32_t) u1; // u1 <= 1_97ffffe0
  h[2] = (uint32_t) u2; // u2 <= 1_8fffffe2
  h[3] = (uint32_t) u3; // u3 <= 1_87ffffe4
  h[4] = (uint32_t) u4; // u4 <=          4
}
             
static void
poly1305_final( uint32_t h[ 5 ],  const uint32_t pad[ 4 ],
                uint32_t out[ 4 ] )
{
  uint64_t c = 5;
  uint32_t i;
  for ( i = 0; i < 4; i++ ) {
    c  += h[ i ];
    c >>= 32;
  }
  c += h[ 4 ];
  c  = (c >> 2) * 5; // shift the carry back to the beginning
  // c now indicates how many times we should subtract 2^130-5 (0 or 1)
  for ( i = 0; i < 4; i++ ) {
    c += (uint64_t) h[ i ] + pad[ i ];
    out[ i ] = (uint32_t) c;
    c = c >> 32;
  }
}

void
poly1305_auth_v2( uint64_t out[ POLY1305_W64TAG ],
                 const poly1305_vec_t *vec,
                 size_t veclen,
                 const uint64_t key[ POLY1305_W64KEY ] )
{
  uint32_t r[ 4 ]   = { (uint32_t)  key[ 0 ]         & 0x0fffffff,
                        (uint32_t)( key[ 0 ] >> 32 ) & 0x0ffffffc,
                        (uint32_t)  key[ 1 ]         & 0x0ffffffc,
                        (uint32_t)( key[ 1 ] >> 32 ) & 0x0ffffffc },
           pad[ 4 ] = { (uint32_t) key[ 2 ],
                        (uint32_t) ( key[ 2 ] >> 32 ),
                        (uint32_t) key[ 3 ],
                        (uint32_t) ( key[ 3 ] >> 32 ) },
           h[ 5 ]   = { 0, 0, 0, 0, 0 },
           end      = 1;
  size_t   inlen    = 0,
           inoff, i, j, k;
  uint8_t  mp[ 16 ];
  const void * m;

  for ( i = 0; i < veclen; i++ )
    inlen += vec[ i ].buflen;
  i = 0; j = 0;
  /* process blocks */
  for ( inoff = 0; inoff < inlen; ) {
    if ( j + 64 <= vec[ i ].buflen ) {
      m = &((const uint8_t *) vec[ i ].buf)[ j ];
      j += 64;
      poly1305_block64( r, h, m );
      inoff += 64;
    }
    else {
      m = &((const uint8_t *) vec[ i ].buf)[ j ];
      if ( j + 16 <= vec[ i ].buflen ) {
        j += 16;
      }
      else {
        k = vec[ i ].buflen - j;
        for ( j = 0; j < k; j++ )
          mp[ j ] = ((const uint8_t *) m)[ j ];
        for (;;) {
          if ( ++i == veclen ) {
            mp[ k++ ] = 1;
            for ( ; k < 16; k++ )
              mp[ k ] = 0;
            end = 0;
            goto break_loop;
          }
          j = 0;
          m = vec[ i ].buf;
          while ( j < vec[ i ].buflen ) {
            mp[ k++ ] = ((const uint8_t *) m)[ j++ ];
            if ( k == 16 )
              goto break_loop;
          }
        }
      break_loop:;
        m = mp;
      }
      poly1305_block( r, h, m, end );
      inoff += 16;
    }
  }
  poly1305_final( h, pad, (uint32_t *) out );
}

static void
poly1305_block2( const uint64_t r[ 3 ],  const uint64_t s[ 2 ],
                 uint64_t h[ 3 ],  const void *m,  uint64_t h_add )
{
  uint128_t d0, d1, d2, d;
  uint64_t t[ 2 ];
  uint64_t c;

  memcpy( t, m, sizeof( t ) );
  h[ 0 ] += (( t[ 0 ]                        ) & 0xfffffffffff);
  h[ 1 ] += (((t[ 0 ] >> 44) | (t[ 1 ] << 20)) & 0xfffffffffff);
  h[ 2 ] += (((t[ 1 ] >> 24)                 ) & 0x3ffffffffff) | h_add;

  /* h *= r */
  MUL(d0, h[ 0 ], r[ 0 ]); MUL(d, h[ 1 ], s[ 1 ]); ADD(d0, d); MUL(d, h[ 2 ], s[ 0 ]); ADD(d0, d);
  MUL(d1, h[ 0 ], r[ 1 ]); MUL(d, h[ 1 ], r[ 0 ]); ADD(d1, d); MUL(d, h[ 2 ], s[ 1 ]); ADD(d1, d);
  MUL(d2, h[ 0 ], r[ 2 ]); MUL(d, h[ 1 ], r[ 1 ]); ADD(d2, d); MUL(d, h[ 2 ], r[ 0 ]); ADD(d2, d);

  /* (partial) h %= p */
                c = SHR(d0, 44); h[ 0 ] = LO(d0) & 0xfffffffffff;
  ADDLO(d1, c); c = SHR(d1, 44); h[ 1 ] = LO(d1) & 0xfffffffffff;
  ADDLO(d2, c); c = SHR(d2, 42); h[ 2 ] = LO(d2) & 0x3ffffffffff;

  h[ 0 ] += c * 5;
  c       = (h[ 0 ] >> 44);
  h[ 0 ]  = h[ 0 ] & 0xfffffffffff;
  h[ 1 ] += c;
}

static void
poly1305_block642( const uint64_t r[ 3 ],  const uint64_t s[ 2 ],
                   uint64_t h[ 3 ],  const void *m )
{
  static const uint64_t h_add = (uint64_t) 1 << 40;
  uint128_t d0, d1, d2, d;
  uint64_t t[ 8 ];
  uint64_t c;
  uint32_t i;

  memcpy( t, m, sizeof( t ) );

  for ( i = 0; i < 8; i += 2 ) {
    h[ 0 ] += (( t[ i ]                        ) & 0xfffffffffff);
    h[ 1 ] += (((t[ i ] >> 44) | (t[i+1] << 20)) & 0xfffffffffff);
    h[ 2 ] += (((t[i+1] >> 24)                 ) & 0x3ffffffffff) | h_add;

    /* h *= r */
    MUL(d0, h[ 0 ], r[ 0 ]); MUL(d, h[ 1 ], s[ 1 ]); ADD(d0, d); MUL(d, h[ 2 ], s[ 0 ]); ADD(d0, d);
    MUL(d1, h[ 0 ], r[ 1 ]); MUL(d, h[ 1 ], r[ 0 ]); ADD(d1, d); MUL(d, h[ 2 ], s[ 1 ]); ADD(d1, d);
    MUL(d2, h[ 0 ], r[ 2 ]); MUL(d, h[ 1 ], r[ 1 ]); ADD(d2, d); MUL(d, h[ 2 ], r[ 0 ]); ADD(d2, d);

    /* (partial) h %= p */
                  c = SHR(d0, 44); h[ 0 ] = LO(d0) & 0xfffffffffff;
    ADDLO(d1, c); c = SHR(d1, 44); h[ 1 ] = LO(d1) & 0xfffffffffff;
    ADDLO(d2, c); c = SHR(d2, 42); h[ 2 ] = LO(d2) & 0x3ffffffffff;

    h[ 0 ] += c * 5;
    c       = (h[ 0 ] >> 44);
    h[ 0 ]  = h[ 0 ] & 0xfffffffffff;
    h[ 1 ] += c;
  }
}

static void
poly1305_final2( uint64_t h[ 3 ],  const uint64_t key[ POLY1305_W64KEY ],
                 uint64_t out[ POLY1305_W64TAG ] )
{
  uint64_t c, g0, g1, g2, t0, t1;

                   c = (h[ 1 ] >> 44); h[ 1 ] &= 0xfffffffffff;
  h[ 2 ] += c;     c = (h[ 2 ] >> 42); h[ 2 ] &= 0x3ffffffffff;
  h[ 0 ] += c * 5; c = (h[ 0 ] >> 44); h[ 0 ] &= 0xfffffffffff;
  h[ 1 ] += c;     c = (h[ 1 ] >> 44); h[ 1 ] &= 0xfffffffffff;
  h[ 2 ] += c;     c = (h[ 2 ] >> 42); h[ 2 ] &= 0x3ffffffffff;
  h[ 0 ] += c * 5; c = (h[ 0 ] >> 44); h[ 0 ] &= 0xfffffffffff;
  h[ 1 ] += c;

  /* compute h + -p */
  g0 = h[ 0 ] + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
  g1 = h[ 1 ] + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
  g2 = h[ 2 ] + c - ((uint64_t) 1 << 42);

  /* select h if h < p, or h + -p if h >= p */
  c = (g2 >> ((sizeof(uint64_t) * 8) - 1)) - 1;
  g0 &= c;
  g1 &= c;
  g2 &= c;
  c = ~c;
  h[ 0 ] = (h[ 0 ] & c) | g0;
  h[ 1 ] = (h[ 1 ] & c) | g1;
  h[ 2 ] = (h[ 2 ] & c) | g2;

  /* h = (h + pad) */
  t0 = key[ 2 ];
  t1 = key[ 3 ];

  h[ 0 ] += (( t0                    ) & 0xfffffffffff)    ; c = (h[ 0 ] >> 44); h[ 0 ] &= 0xfffffffffff;
  h[ 1 ] += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h[ 1 ] >> 44); h[ 1 ] &= 0xfffffffffff;
  h[ 2 ] += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                     h[ 2 ] &= 0x3ffffffffff;

  /* mac = h % (2^128) */
  h[ 0 ] = ((h[ 0 ]      ) | (h[ 1 ] << 44));
  h[ 1 ] = ((h[ 1 ] >> 20) | (h[ 2 ] << 24));

  out[ 0 ] = h[ 0 ];
  out[ 1 ] = h[ 1 ];
}

void
poly1305_auth_v4( uint64_t out[ POLY1305_W64TAG ],
                 const poly1305_vec_t *vec,
                 size_t veclen,
                 const uint64_t key[ POLY1305_W64KEY ] )
{
  uint64_t r[ 3 ] = {   key[ 0 ] & 0xffc0fffffff,
                    ( ( key[ 0 ] >> 44 ) | ( key[ 1 ] << 20 ) ) & 0xfffffc0ffff,
                      ( key[ 1 ] >> 24 ) & 0x00ffffffc0f };
  uint64_t h[ 3 ] = { 0, 0, 0 },
           h_add  = (uint64_t) 1 << 40,
           s[ 2 ] = { r[ 1 ] * (5 << 2), r[ 2 ] * (5 << 2) };
  size_t   inlen  = 0, inoff,
           i, j, k;
  uint8_t  mp[16];
  const void *m;

  for ( i = 0; i < veclen; i++ )
    inlen += vec[ i ].buflen;
  i = 0; j = 0;
  /* process blocks */
  for ( inoff = 0; inoff < inlen; ) {
    if ( j + 64 <= vec[ i ].buflen ) {
      m = &((const uint8_t *) vec[ i ].buf)[ j ];
      j += 64;
      poly1305_block642( r, s, h, m );
      inoff += 64;
    }
    else {
      m = &((const uint8_t *) vec[ i ].buf)[ j ];
      if ( j + 16 <= vec[ i ].buflen ) {
        j += 16;
      }
      else {
        k = vec[ i ].buflen - j;
        for ( j = 0; j < k; j++ )
          mp[ j ] = ((const uint8_t *) m)[ j ];
        for (;;) {
          if ( ++i == veclen ) {
            mp[ k++ ] = 1;
            for ( ; k < 16; k++ )
              mp[ k ] = 0;
            h_add = 0;
            goto break_loop;
          }
          j = 0;
          m = vec[ i ].buf;
          while ( j < vec[ i ].buflen ) {
            mp[ k++ ] = ((const uint8_t *) m)[ j++ ];
            if ( k == 16 )
              goto break_loop;
          }
        }
      break_loop:;
        m = mp;
      }
      poly1305_block2( r, s, h, m, h_add );
      inoff += 16;
    }
  }
  poly1305_final2( h, key, out );
}
#endif
