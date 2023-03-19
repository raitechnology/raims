#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/parse_config.h>
#include <raikv/os_file.h>

using namespace rai;
using namespace ms;
using namespace md;
using namespace kv;

static const char *
get_arg( int argc, char *argv[], int b, const char *f, const char *def )
{
  for ( int i = 1; i < argc - b; i++ )
    if ( ::strcmp( f, argv[ i ] ) == 0 ) /* -p port */
      return argv[ i + b ];
  return def; /* default value */
}

int
main( int argc, char *argv[] )
{
  const char * fn = get_arg( argc, argv, 1, "-d", "config" ),
             * j  = get_arg( argc, argv, 0, "-j", 0 ),
             * he = get_arg( argc, argv, 0, "-h", 0 );
  if ( he != NULL ) {
    printf( "%s -d dir [-j]\n"
            "   -d dir : config file or directory\n"
            "   -j     : print json\n"
            "Parse config\n",
            argv[ 0 ] );
    return 0;
  }

  MDMsgMem         mem;
  StringTab        st( mem );
  ConfigErrPrinter err;
  ConfigTree     * tree;
  MDOutput         p;
  os_stat          stbuf;

  if ( fn == NULL || ::strcmp( fn, "-" ) == 0 )
    tree = ConfigDB::parse_fd( 0, st, err );
  else if ( os_fstat( fn, &stbuf ) < 0 || ( stbuf.st_mode & S_IFDIR ) == 0 )
    tree = ConfigDB::parse_jsfile( fn, st, err );
  else
    tree = ConfigDB::parse_dir( fn, st, err );

  if ( tree != NULL ) {
    ConfigJson json;
    JsonValue *cfg = json.copy( tree, PRINT_NORMAL );
    if ( j == NULL ) {
      cfg->print_yaml( &p );
    }
    else {
      cfg->print_json( &p );
    }
  }
  return 0;
}

