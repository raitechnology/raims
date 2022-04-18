#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raims/crypt.h>
#include <raimd/md_types.h>
#include <raikv/util.h>
#include <raikv/key_hash.h>
#define KDF_DEBUG
#include <raims/kdf.h>

using namespace rai;
using namespace kv;
using namespace ms;

int
main( void )
{
  KeyDeriveFunDebug df_dbg;
  uint8_t digest[ 512 / 8 ];
  char aa[ 64 ];

  ::memset( aa, '#', 64 );
  df_dbg.update( aa, sizeof( aa ) );
  df_dbg.complete( digest );

  uint64_t t = current_monotonic_time_ns();
  for ( int i = 0; i < 100000; i++ ) {
    HashDigest d;
    d.kdf_bytes( aa, sizeof( aa ) );
    ::memcpy( aa, d.dig, sizeof( d.dig ) );
  }
  printf( "%" PRIu64 " ns / kdf\n",
          ( current_monotonic_time_ns() - t ) / 100000 );
  /*df.mix( digest, sizeof( digest ), 1 );*/
  return 0;
}

