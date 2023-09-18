#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/adj_graph.h>
#include <raims/string_tab.h>
#include <raikv/os_file.h>

using namespace rai;
using namespace kv;
using namespace md;
using namespace ms;

static const char *
get_arg( int &x, int argc, const char *argv[], int b, const char *f,
         const char *g, const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ ) {
    if ( ::strcmp( f, argv[ i ] ) == 0 || ::strcmp( g, argv[ i ] ) == 0 ) {
      if ( x < i + b + 1 )
        x = i + b + 1;
      return argv[ i + b ];
    }
  }
  return def; /* default value */
}

int
main( int argc, const char *argv[] ) noexcept
{
  int x = 1;
  const char * do_debug  = get_arg( x, argc, argv, 0, "-d", "-debug", NULL ),
             * do_fwd    = get_arg( x, argc, argv, 0, "-f", "-forward", NULL ),
             * do_tree   = get_arg( x, argc, argv, 0, "-t", "-tree", NULL ),
             * do_graph  = get_arg( x, argc, argv, 0, "-g", "-graph", NULL ),
             * do_web    = get_arg( x, argc, argv, 0, "-w", "-web", NULL ),
             * do_loop   = get_arg( x, argc, argv, 0, "-l", "-loopback", NULL ),
             * show_path = get_arg( x, argc, argv, 1, "-p", "-path", "0" ),
             * help      = get_arg( x, argc, argv, 0, "-h", "-help", NULL );
  bool show_forward_path     = ( do_fwd != NULL || do_debug != NULL ),
       show_multicast_tree   = ( do_tree != NULL || do_debug != NULL ),
       show_graph            = ( do_graph != NULL || do_debug != NULL ),
       show_web_json         = ( do_web != NULL || do_debug != NULL ),
       use_loop              = ( do_loop != NULL ),
       generate_config       = ! ( show_forward_path ||
                                   show_multicast_tree ||
                                   show_graph ||
                                   show_web_json );
  uint8_t path = atoi( show_path ) & 3;

  const char *fn = NULL;
  if ( x < argc )
    fn = argv[ x ];
  if ( help != NULL || fn == NULL ) {
    fprintf( stderr,
             "%s [-g] [-f] [-t] [-g] [-w] [-l] file\n"
             "  -d   = same as -c,-f,-t,-g,-w\n"
             "  -f   = show forward cache\n"
             "  -t   = show multicast tree\n"
             "  -g   = show text network description\n"
             "  -w   = show web json network\n"
             "  -l   = use device in config file\n"
             "  -p   = print path for fwd or graph\n"
             "  file = network text description\n"
             "if no option, then generate yaml config file\n"
             "if no input file, then use included test\n",
             argv[ 0 ] );
    return 1;
  }

  MapFile map( fn );
  if ( ! map.open() ) {
    perror( fn );
    return 1;
  }
  MDMsgMem   tmp_mem;
  AdjGraph   graph( tmp_mem );
  StringTab  str_tab( tmp_mem );
  size_t     len = ( fn != NULL ? ::strlen( fn ) : 0 );
  uint32_t   start_uid;
  int        status = 1;
  bool       is_yaml = false;
  
  if ( kv_strcasecmp( &fn[ len - 5 ], ".yaml" ) == 0 )
    is_yaml = true;
  if ( is_yaml ||
       kv_strcasecmp( &fn[ len - 5 ], ".json" ) == 0 ||
       kv_strcasecmp( &fn[ len - 3 ], ".js" ) == 0 )
    status = graph.load_json( str_tab, map.map, map.map_size, is_yaml );
  else
    status = graph.load_graph( str_tab, (const char *) map.map, map.map_size,
                               start_uid );

  if ( status != 0 )
    return 1;
  /*graph.print();*/
  for ( uint8_t p = 0; p < 4; p++ )
    graph.compute_forward_set( p );
  ArrayOutput out;
  AdjGraphOut put( graph, out );
  put.use_loopback = use_loop;
  int multi_args = show_forward_path + show_multicast_tree +
                   show_graph + show_web_json;
  if ( show_multicast_tree ) {
    if ( multi_args ) out.printf( "--- multicast tree (%u):\n", path );
    put.print_tree( path, false );
  }
  if ( show_forward_path ) {
    if ( multi_args ) out.printf( "--- forward path (%u):\n", path );
    put.print_fwd( path );
  }
  if ( show_graph ) {
    if ( multi_args ) out.printf( "--- graph description:\n" );
    put.print_graph();
  }
  if ( show_web_json ) {
    if ( multi_args ) out.printf( "--- web json:\n" );
    put.print_web_paths( 0 );
  }
  if ( generate_config )
    put.print_config( fn );
  if ( out.count > 0 ) {
    fwrite( out.ptr, 1, out.count, stdout );
    fflush( stdout );
  }
  graph.reset();
  return 0;
}


