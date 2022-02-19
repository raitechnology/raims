#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/parse_config.h>

using namespace rai;
using namespace ms;
using namespace md;

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
  const char * fn = get_arg( argc, argv, 1, "-c", NULL ),
             * y  = get_arg( argc, argv, 0, "-y", 0 ),
             * he = get_arg( argc, argv, 0, "-h", 0 );
  if ( he != NULL || fn == NULL ) {
    printf( "%s -c cfg\n"
            "   -c cfg  : config file\n"
            "Parse config\n",
            argv[ 0 ] );
    return 0;
  }

  MDMsgMem         mem;
  StringTab        st( mem );
  ConfigErrPrinter err;
  ConfigTree     * tree = ConfigDB::parse_jsfile( fn, st, err )/*,
                 * tree2 = ConfigDB::parse_tport_examples( st )*/;
  ConfigPrinter    p;

  if ( tree != NULL ) {
    if ( y != NULL ) {
      int did_which;
      tree->print_y( p, did_which );
    }
    else
      tree->print_js( p );
  }
  /*if ( tree2 != NULL ) {
    if ( y != NULL )
      tree2->print_y( p );
    else
      tree2->print_js( p );
  }*/
  /*if ( tree != NULL )
    tree->print_index();*/
#if 0
    size_t i, j;
    printf( "ok\n" );
    for ( i = 0; i < tree->service_cnt; i++ ) {
      ConfigTree::Service *s = tree->service[ i ];
      printf( "service " ); s->svc.print(); printf( "\n" );
      for ( j = 0; j < s->user_cnt; j++ ) {
        printf( "  user " ); s->user[ j ]->user.print(); printf( "\n" );
      }
      for ( j = 0; j < s->entitle_cnt; j++ ) {
        printf( "  entitle " ); s->entitle[ j ]->group_name.print(); printf( "\n" );
      }
    }
    for ( i = 0; i < tree->user_cnt; i++ ) {
      ConfigTree::User *u = tree->user[ i ];
      printf( "user " ); u->user.print(); printf( "\n" );
      if ( u->service != NULL ) {
        printf( "  service " ); u->service->svc.print(); printf( "\n" );
      }
      for ( j = 0; j < u->entitle_cnt; j++ ) {
        printf( "  entitle " ); u->entitle[ j ]->group_name.print(); printf( "\n" );
      }
    }
#endif
  return 0;
}

