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
             * verify    = get_arg( x, argc, argv, 0, "-v", "-verify", NULL ),
             * no_cfg    = get_arg( x, argc, argv, 0, "-x", "-nocfg", NULL ),
             * path_lim  = get_arg( x, argc, argv, 1, "-m", "-limit", "8" ),
             * help      = get_arg( x, argc, argv, 0, "-h", "-help", NULL );
  bool show_forward_path     = ( do_fwd != NULL || do_debug != NULL ),
       show_multicast_tree   = ( do_tree != NULL || do_debug != NULL ),
       show_graph            = ( do_graph != NULL || do_debug != NULL ),
       show_web_json         = ( do_web != NULL || do_debug != NULL ),
       do_verify             = ( verify != NULL || do_debug != NULL ),
       use_loop              = ( do_loop != NULL ),
       generate_config       = ! ( show_forward_path ||
                                   show_multicast_tree || show_graph ||
                                   show_web_json || do_verify ) &&
                                   ( no_cfg == NULL );
  uint32_t path = atoi( show_path ),
           limit = atoi( path_lim );

  const char *fn = NULL;
  if ( x < argc )
    fn = argv[ x ];
  if ( help != NULL || fn == NULL ) {
    fprintf( stderr,
             "%s [-g] [-f] [-t] [-g] [-w] [-l] [-p n] [-m n] file\n"
             "  -d   = same as -c,-f,-t,-g,-w\n"
             "  -f   = show forward cache\n"
             "  -t   = show multicast tree\n"
             "  -g   = show text network description\n"
             "  -w   = show web json network\n"
             "  -l   = use device in config file\n"
             "  -p   = print path for fwd or graph\n"
             "  -m   = max path limit\n"
             "  file = network text description\n"
             "if no option, then generate yaml config file\n"
             "if no input file, then use included test\n",
             argv[ 0 ] );
    return 1;
  }

  char * input_buf = NULL;
  size_t input_buf_size = 0, input_off = 0;
  size_t len = ( fn != NULL ? ::strlen( fn ) : 0 );
  MapFile map( fn );
  if ( fn[ 0 ] == '-' && fn[ 1 ] == '\0' ) {
    for (;;) {
      if ( input_off == input_buf_size ) {
        size_t sz = ( input_buf_size == 0 ? 4096 : input_buf_size * 2 );
        input_buf = (char *) ::realloc( input_buf, sz );
        input_buf_size = sz;
      }
      size_t n = fread( &input_buf[ input_off ], 1,
                        input_buf_size - input_off, stdin );
      if ( n == 0 )
        break;
      input_off += n;
    }
  }
  else {
    if ( ! map.open() ) {
      perror( fn );
      return 1;
    }
    input_buf = (char *) map.map;
    input_off = map.map_size;
  }
  MDMsgMem   tmp_mem;
  AdjGraph   graph( tmp_mem, limit );
  StringTab  str_tab( tmp_mem );
  uint32_t   start_uid;
  int        status = 1;
  bool       is_yaml = false;
  
  if ( len > 5 && kv_strcasecmp( &fn[ len - 5 ], ".yaml" ) == 0 )
    is_yaml = true;
  if ( is_yaml ||
       ( len > 5 && kv_strcasecmp( &fn[ len - 5 ], ".json" ) == 0 ) ||
       ( len > 3 && kv_strcasecmp( &fn[ len - 3 ], ".js" ) == 0 ) )
    status = graph.load_json( str_tab, input_buf, input_off, is_yaml );
  else
    status = graph.load_graph( str_tab, input_buf, input_off, start_uid );
  if ( status != 0 )
    return 1;
  /*graph.print();*/
  ArrayOutput out;
  AdjGraphOut put( graph, out );
  graph.compute_forward_set( 0 );
  for ( uint16_t p = 1; p < graph.path_count; p++ )
    graph.compute_forward_set( p );
  put.use_loopback = use_loop;
  if ( show_multicast_tree ) {
    out.printf( "--- multicast tree (%u/%u):\n", path, graph.path_count );
    put.print_tree( path, false );
  }
  if ( show_forward_path ) {
    out.printf( "--- forward path (%u/%u):\n", path, graph.path_count );
    put.print_fwd( path );
  }
  if ( show_graph ) {
    out.printf( "--- graph description:\n" );
    put.print_graph( 0 );
  }
  if ( show_web_json ) {
    out.printf( "--- web json:\n" );
    put.print_web_paths( 0 );
  }
  if ( do_verify ) {
    out.printf( "--- verify:\n" );
    AdjInconsistent inc;
    for ( uint32_t i = 0; i < graph.user_tab.count; i++ ) {
      graph.init_inconsistent( i, inc );
      graph.find_inconsistent( inc );
      if ( inc.missing.count > 0 ) {
        printf( "src %s:", graph.user_tab.ptr[ i ]->user.val );
        for ( uint32_t j = 0; j < inc.missing.count; j++ ) {
          AdjUser *u = graph.user_tab.ptr[ inc.missing.ptr[ j ] ];
          printf( " %s", u->user.val );
        }
        for ( uint32_t k = 0; k < inc.missing_links.count; k++ ) {
          AdjLink *l = inc.missing_links.ptr[ k ];
          printf( " %s->%s", l->a.user.val, l->b.user.val );
        }
        printf( "\n" );
      }
    }
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


