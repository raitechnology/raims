#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raims/user.h>
#include <raims/parse_config.h>

using namespace rai;
using namespace ms;
using namespace md;

static const char *
get_arg( int argc, char *argv[], int b, const char *f,
         const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ )
    if ( ::strcmp( f, argv[ i ] ) == 0 ) /* -p port */
      return argv[ i + b ]; 
  return def; /* default value */
} 

int
main( int argc, char *argv[] )
{
  const char * us = get_arg( argc, argv, 1, "-u", NULL ),
             * sv = get_arg( argc, argv, 1, "-s", "*" ),
             * ex = get_arg( argc, argv, 1, "-e", NULL ),
             * fn = get_arg( argc, argv, 1, "-c", NULL ),
             * pa = get_arg( argc, argv, 1, "-p", NULL ),
             * np = get_arg( argc, argv, 1, "-n", NULL ),
             * he = get_arg( argc, argv, 0, "-h", 0 ); 
  if ( he != NULL || ( us == NULL && fn == NULL ) ) {
    printf( "%s -u user -s svc -e expires -p passwd -c cfg -n newpass\n"
            "   -u user    : user name\n"
            "   -s svc     : service name\n"
            "   -e expires : when user expires\n"
            "   -c cfg     : update config file\n"
            "   -p pass    : encrypt using pass\n"
            "   -n newpass : change encryption to use this password\n"
            "Generate a key pair for user and service encrypted with passwd\n",
            argv[ 0 ] );
    return 0;
  } 
  CryptPass    pass,
               new_pass;
  ConfigTree * tree     = NULL;
  MDMsgMem     mem;

  if ( ! pass.init_pass( pa ) ) { /* loads env if null */
    fprintf( stderr, "failed to load pass\n" );
    return 1;
  }
  if ( np != NULL )
    if ( ! new_pass.init_pass( np ) ) {
      fprintf( stderr, "failed to load new pass\n" );
      return 1;
    }

  if ( fn != NULL ) {
    tree = ConfigDB::parse_jsfile( mem, fn );
    if ( tree == NULL )
      return 1;
    if ( np != NULL ) {
      for ( uint32_t k = 0; k < tree->user_cnt; k++ ) {
        ConfigTree::User *u;
        u = UserBuf::change_pass( *tree->user[ k ], pass, new_pass, mem );
        if ( u == NULL )
          return 1;
        tree->user[ k ] = u;
      }
    }
  }
  CryptPass & the_pass = ( np != NULL ? new_pass : pass );
  printf( "{\n  users : [\n" );
  if ( tree != NULL ) {
    for ( uint32_t k = 0; k < tree->user_cnt; k++ ) {
      UserBuf buf( *tree->user[ k ] );
      char comma = ( k < tree->user_cnt - 1 ) ? ',' : 0;
      if ( us != NULL )
        comma = ',';
      buf.print_json( 4, comma );
    }
  }
  if ( us != NULL ) {
    for ( int i = 2; ; i++ ) {
      UserBuf buf;
      buf.gen_key( us, ::strlen( us ), sv, ::strlen( sv ), ex,
                   ( ex ? ::strlen( ex ) : 0 ), the_pass );
      OpenSsl_ECDH ec;
      if ( ! buf.get_ecdh( the_pass, ec, true, true ) ) {
        fprintf( stderr, "failed to decode keys\n" );
      }
      us = get_arg( argc, argv, i, "-u", NULL );
      if ( us == NULL || us[ 0 ] == '-' ) {
        buf.print_json( 4 );
        break;
      }
      buf.print_json( 4, ',' );
    }
  }
  printf( "  ]\n}\n" );

  return 0;
} 

