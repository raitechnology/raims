#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <raims/rsa.h>

using namespace rai;
using namespace ms;

int
main( void )
{
  char   buf[ 1024 ], bob_private[ 1024 ], bob_public[ 1024 ];
  size_t buflen;
  OpenSsl_RSA rsa, rsa_pri, rsa_pub, alice, bob;

  if ( rsa.gen_key() ) {
    buflen = sizeof( buf );
    if ( rsa.private_to_pem( buf, buflen ) ) {
      printf( "alice:\n%.*s", (int) buflen, buf );
      alice.pem_to_private( buf, buflen );
    }
    buflen = sizeof( buf );
    if ( rsa.public_to_pem( buf, buflen ) ) {
      printf( "alice:\n%.*s", (int) buflen, buf );
      alice.pem_to_public( buf, buflen );
    }
  }
  if ( rsa.gen_key() ) {
    buflen = sizeof( bob_private );
    if ( rsa.private_to_pem( bob_private, buflen ) ) {
      printf( "bob:\n%.*s", (int) buflen, bob_private );
      bob.pem_to_private( bob_private, buflen );
    }
    buflen = sizeof( bob_public );
    if ( rsa.public_to_pem( bob_public, buflen ) ) {
      printf( "bob:\n%.*s", (int) buflen, bob_public );
      bob.pem_to_public( bob_public, buflen );
    }
  }

  char    out[ 1024 ];
  uint8_t data[ 1024 ];
  size_t  outlen, datalen;

  if ( rsa.i2d_private( data, datalen ) ) {
    outlen = kv::bin_to_base64( data, datalen, out, false );
    printf( "\nbob pri DER(%lu,%lu):\n%.*s\n", datalen, outlen,
            (int) outlen, out );
    if ( rsa_pri.d2i_private( data, datalen ) ) {
      buflen = sizeof( buf );
      if ( rsa_pri.private_to_pem( buf, buflen ) )
        printf( "bob_private cmp %d\n", memcmp( bob_private, buf, buflen ) );
    }
  }
  if ( rsa.i2d_public( data, datalen ) ) {
    outlen = kv::bin_to_base64( data, datalen, out, false );
    printf( "\nbob pub DER(%lu,%lu):\n%.*s\n", datalen, outlen,
            (int) outlen, out );
    if ( rsa_pub.d2i_public( data, datalen ) ) {
      buflen = sizeof( buf );
      if ( rsa_pub.public_to_pem( buf, buflen ) )
        printf( "bob_public cmp %d\n", memcmp( bob_public, buf, buflen ) );
    }
  }
  if ( alice.i2d_public( data, datalen ) ) {
    if ( rsa_pub.d2i_public( data, datalen ) ) {
      printf( "\nalice pub imported\n" );
    }
  }
  if ( alice.i2d_private( data, datalen ) ) {
    if ( rsa_pri.d2i_private( data, datalen ) ) {
      printf( "\nalice pri imported\n" );
    }
  }

  char sig[ MAX_RSA_SIGN_LEN ];
  size_t siglen = sizeof( sig );
  if ( rsa_pri.sign_msg( "hello world", 11, sig, siglen ) ) {
    outlen = kv::bin_to_base64( sig, siglen, out, false );
    printf( "\nsign: %.*s\n", (int) outlen, out );
  }

  if ( rsa_pub.verify_msg( "hello world", 11, sig, siglen ) )
    printf( "\nverify: true\n" );
  else
    printf( "\nverify: false\n" );

  if ( rsa_pub.verify_msg( "hhllo world", 11, sig, siglen ) )
    printf( "\nnot verified: false\n" );
  else
    printf( "\nnot verified: true\n" );
  return 0;
}

