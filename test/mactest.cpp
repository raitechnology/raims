#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raikv/util.h>
#include <raims/msg.h>
#include <raimd/md_types.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

int
main( int argc, char *argv[] )
{
  const char * sub     = argc > 1 ? argv[ 1 ] : "subject",
             * data    = argc > 2 ? argv[ 2 ] :
               "datadatadatadatadataas3asddatatatadateaeraedsfaefaad0123456789012345";
  uint32_t     sublen  = ::strlen( sub ),
               datalen = ::strlen( data );
  uint64_t     tm,
               tok;
  Nonce        nonce;
  HashDigest   ha1;

  MsgEst e( sublen );
  e.seqno ()
   .ret   ()
   .time  ()
   .token ()
   .fmt   ()
   .data  ( datalen );

  tok = 0;
  nonce.seed_random();
  ha1.make_session_rand();
  tm  = current_realtime_ns();

  uint32_t i = 0;
  for (;;) {
    MsgCat m;
    tok++;
    m.reserve( e.sz );
    m.open   ( nonce, sublen )
     .seqno  ( i )
     .ret    ( 1 )
     .time   ( tm )
     .token  ( tok )
     .fmt    ( 1 )
     .data   ( data, datalen );
    uint32_t h = kv_crc_c( sub, sublen, 0 );
    m.close( e.sz, h, CABA_MCAST );
    m.sign( sub, sublen, ha1 );

    if ( ++i == 1000000 ) {
      printf( "sz %lu, ns = %.2f\n", m.len(),
              ( current_realtime_ns() - tm ) / 1000000.0 );

      MDOutput mout;
      mout.print_hex( m.msg, m.len() );
      break;
    }
  }
  return 0;
}

