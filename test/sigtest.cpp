#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raims/ed25519.h>
#include <raims/crypt.h>
#include <raims/user.h>
#include <raims/msg.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

void
msg_test( void )
{
  DSA dsa;
  Nonce nonce;
  HashDigest key, key2;
  nonce.seed_random();
  key.kdf_bytes( "xxx", 3 );
  key2.kdf_bytes( "yyy", 3 );
  dsa.gen_key();
  MsgEst e( 4 );
  e.seqno()
   .tport( 5 )
   .tportid()
   .cost()
   .cost2()
   .cost3()
   .cost4()
   .pk_sig();
  MsgCat m;
  m.reserve( e.sz );
  m.open( nonce, 4 )
   .seqno( 1 )
   .tport( "tport", 5 )
   .tportid( 1 )
   .cost( 1000 )
   .cost2( 1000 )
   .cost3( 1000 )
   .cost4( 1000 )
   .pk_sig();
  m.close( e.sz, 0x1234, CABA_INBOX );
  m.sign_dsa( "test", 4, key, key2, dsa );

  MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );
  MDMsgMem mem;
  MDMsg  * msg;

  msg = CabaMsg::unpack( m.msg, 0, m.len(), 0, MsgFrameDecoder::msg_dict,
                         &mem );
  if ( msg != NULL ) {
    msg->print( &mout );

    printf( "verify: %s\n",
      ((CabaMsg *) msg)->verify_sig( key2, dsa ) ? "true" : "false" );
  }
}

int
main( void )
{
  static const char *str = "test data";
  DSA dsa;
  PolyHmacDigest hmac;
  HashDigest ha;
  uint8_t plain[ ED25519_SIG_LEN ];
  char buf[ 256 ];

  CabaMsg::init_auto_unpack();
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
  msg_test();
  return 0;
}

