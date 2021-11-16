#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <raims/ecdh.h>

using namespace rai;
using namespace ms;

int
main( void )
{
  char   buf[ 1024 ], bob_private[ 1024 ], bob_public[ 1024 ];
  size_t buflen;
  OpenSsl_ECDH ec, ec_pri, ec_pub, alice, bob;

  if ( ec.gen_key() ) {
    buflen = sizeof( buf );
    if ( ec.private_to_pem( buf, buflen ) ) {
      printf( "alice:\n%.*s", (int) buflen, buf );
      alice.pem_to_private( buf, buflen );
    }
    buflen = sizeof( buf );
    if ( ec.public_to_pem( buf, buflen ) ) {
      printf( "alice:\n%.*s", (int) buflen, buf );
      alice.pem_to_public( buf, buflen );
    }
  }
  if ( ec.gen_key() ) {
    buflen = sizeof( bob_private );
    if ( ec.private_to_pem( bob_private, buflen ) ) {
      printf( "bob:\n%.*s", (int) buflen, bob_private );
      bob.pem_to_private( bob_private, buflen );
    }
    buflen = sizeof( bob_public );
    if ( ec.public_to_pem( bob_public, buflen ) ) {
      printf( "bob:\n%.*s", (int) buflen, bob_public );
      bob.pem_to_public( bob_public, buflen );
    }
  }
  char    out[ 1024 ];
  uint8_t skey[ 1024 ], data[ 1024 ];
  size_t  skeylen, outlen, datalen;

  if ( ec.i2d_private( data, datalen ) ) {
    outlen = kv::bin_to_base64( data, datalen, out, false );
    printf( "\nbob pri DER(%lu,%lu):\n%.*s\n", datalen, outlen,
            (int) outlen, out );
    if ( ec_pri.d2i_private( data, datalen ) ) {
      buflen = sizeof( buf );
      if ( ec_pri.private_to_pem( buf, buflen ) )
        printf( "bob_private cmp %d\n", memcmp( bob_private, buf, buflen ) );
    }
  }

  if ( ec.i2d_public( data, datalen ) ) {
    outlen = kv::bin_to_base64( data, datalen, out, false );
    printf( "\nbob pub DER(%lu,%lu):\n%.*s\n", datalen, outlen,
            (int) outlen, out );
    if ( ec_pub.d2i_public( data, datalen ) ) {
      buflen = sizeof( buf );
      if ( ec_pub.public_to_pem( buf, buflen ) )
        printf( "bob_public cmp %d\n", memcmp( bob_public, buf, buflen ) );
    }
  }

  skeylen = sizeof( skey );
  if ( alice.shared_secret( alice.pri, bob.pub, skey, skeylen ) ) {
    outlen = kv::bin_to_base64( skey, skeylen, out, false );
    printf( "\nalice+bob shared:(%lu,%lu)\n%.*s\n", skeylen, outlen,
            (int) outlen, out );
  }

  skeylen = sizeof( skey );
  if ( alice.shared_secret( bob.pri, alice.pub, skey, skeylen ) ) {
    outlen = kv::bin_to_base64( skey, skeylen, out, false );
    printf( "\nbob+alice shared:(%lu,%lu)\n%.*s\n", skeylen, outlen,
            (int) outlen, out );
  }
  return 0;
}
