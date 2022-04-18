#ifndef __rai__raims__poly1305_h__
#define __rai__raims__poly1305_h__
/*
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

namespace rai {
namespace ms {

#define POLY1305_KEYLEN 32
#define POLY1305_W64KEY POLY1305_KEYLEN / 8
#define POLY1305_TAGLEN 16
#define POLY1305_W64TAG POLY1305_TAGLEN / 8

typedef struct {
  const void *buf;
  size_t buflen;
} poly1305_vec_t;

void poly1305_auth(uint8_t out[POLY1305_TAGLEN],
                   const uint8_t *m, size_t inlen,
                   const uint8_t key[POLY1305_KEYLEN]) noexcept;

void poly1305_auth_v(uint64_t out[POLY1305_W64TAG],
                     const poly1305_vec_t *vec,  size_t veclen,
                     const uint64_t key[POLY1305_W64KEY]) noexcept;

}
}

#endif /* POLY1305_H */
