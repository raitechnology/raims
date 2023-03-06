#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raikv/bit_set.h>
#include <raikv/os_file.h>
#include <raims/string_tab.h>

#define MS_NAMESPACE test_ms
#define NO_MS_HEADERS
#define INCLUDE_DUMMY_DEFS
#include "raims/adjacency.h"

using namespace rai;
using namespace test_ms;

static const char test[] =
"mesh_sydney sydney syd_ap1 syd_ap2 syd_ap3 syd_ap4 : 100\n"
"mesh_perth perth per_ap1 per_ap2 per_ap3 per_ap4 : 100\n"
"mesh_brisbane brisbane bri_ap1 bri_ap2 bri_ap3 bri_ap4 : 100\n"
"mesh_melbourne melbourne mel_ap1 mel_ap2 mel_ap3 mel_ap4 : 100\n"
"mesh_auckland auckland auc_ap1 auc_ap2 auc_ap3 auc_ap4 : 100\n"

"mesh_singapore singapore sin_ap1 sin_ap2 sin_ap3 sin_ap4 : 100\n"
"mesh_taipei taipei tai_ap1 tai_ap2 tai_ap3 tai_ap4 : 100\n"
"mesh_shanghai shanghai sha_ap1 sha_ap2 sha_ap3 sha_ap4 : 100\n"
"mesh_seoul seoul seo_ap1 seo_ap2 seo_ap3 seo_ap4 : 100\n"
"mesh_osaka osaka osa_ap1 osa_ap2 osa_ap3 osa_ap4 : 100\n"

"mesh_karachi karachi kar_ap1 kar_ap2 kar_ap3 kar_ap4 : 100\n"
"mesh_mumbia mumbia mum_ap1 mum_ap2 mum_ap3 mum_ap4 : 100\n"
"mesh_bangalore bangalore ban_ap1 ban_ap2 ban_ap3 ban_ap4 : 100\n"
"mesh_colombo colombo col_ap1 col_ap2 col_ap3 col_ap4 : 100\n"
"mesh_dhaka dhaka dha_ap1 dha_ap2 dha_ap3 dha_ap4 : 100\n"

"mesh_chicago chicago chi_ap1 chi_ap2 chi_ap3 chi_ap4 : 100\n"
"mesh_houston houston hou_ap1 hou_ap2 hou_ap3 hou_ap4 : 100\n"
"mesh_seattle seattle sea_ap1 sea_ap2 sea_ap3 sea_ap4 : 100\n"
"mesh_montreal montreal mon_ap1 mon_ap2 mon_ap3 mon_ap4 : 100\n"
"mesh_mexicocity mexicocity mex_ap1 mex_ap2 mex_ap3 mex_ap4 : 100\n"

"mesh_washdc washdc was_ap1 was_ap2 was_ap3 was_ap4 : 100\n"
"mesh_atlanta atlanta atl_ap1 atl_ap2 atl_ap3 atl_ap4 : 100\n"
"mesh_nyc nyc nyc_ap1 nyc_ap2 nyc_ap3 nyc_ap4 : 100\n"
"mesh_boston boston bos_ap1 bos_ap2 bos_ap3 bos_ap4 : 100\n"
"mesh_toronto toronto tor_ap1 tor_ap2 tor_ap3 tor_ap4 : 100\n"

"mesh_caracas caracas car_ap1 car_ap2 car_ap3 car_ap4 : 100\n"
"mesh_bogota bogota bog_ap1 bog_ap2 bog_ap3 bog_ap4 : 100\n"
"mesh_rio rio rio_ap1 rio_ap2 rio_ap3 rio_ap4 : 100\n"
"mesh_buenosaires buenosaires bue_ap1 bue_ap2 bue_ap3 bue_ap4 : 100\n"
"mesh_santiago santiago san_ap1 san_ap2 san_ap3 san_ap4 : 100\n"

"mesh_madrid madrid mad_ap1 mad_ap2 mad_ap3 mad_ap4 : 100\n"
"mesh_dublin dublin dub_ap1 dub_ap2 dub_ap3 dub_ap4 : 100\n"
"mesh_brussels brussels bru_ap1 bru_ap2 bru_ap3 bru_ap4 : 100\n"
"mesh_milan milan mil_ap1 mil_ap2 mil_ap3 mil_ap4 : 100\n"
"mesh_berlin berlin ber_ap1 ber_ap2 ber_ap3 ber_ap4 : 100\n"

"mesh_cairo cairo cai_ap1 cai_ap2 cai_ap3 cai_ap4 : 100\n"
"mesh_lagos lagos lag_ap1 lag_ap2 lag_ap3 lag_ap4 : 100\n"
"mesh_nairobi nairobi nai_ap1 nai_ap2 nai_ap3 nai_ap4 : 100\n"
"mesh_capetown capetown cap_ap1 cap_ap2 cap_ap3 cap_ap4 : 100\n"
"mesh_tripoli tripoli tri_ap1 tri_ap2 tri_ap3 tri_ap4 : 100\n"

"mesh_qatar qatar qat_ap1 qat_ap2 qat_ap3 qat_ap4 : 100\n"
"mesh_baghdad baghdad bag_ap1 bag_ap2 bag_ap3 bag_ap4 : 100\n"
"mesh_ankara ankara ank_ap1 ank_ap2 ank_ap3 ank_ap4 : 100\n"
"mesh_beirut beirut bei_ap1 bei_ap2 bei_ap3 bei_ap4 : 100\n"
"mesh_tehran tehran teh_ap1 teh_ap2 teh_ap3 teh_ap4 : 100\n"

"mesh_AU sydney perth brisbane melbourne auckland : 500\n"
"mesh_AP singapore taipei shanghai seoul osaka : 500\n"
"mesh_SP karachi mumbia bangalore colombo dhaka : 500\n"

"mesh_NA chicago houston seattle montreal mexicocity : 500\n"
"mesh_DC washdc atlanta nyc boston toronto : 500\n"
"mesh_SA caracas bogota rio buenosaires santiago : 500\n"

"mesh_EU madrid dublin brussels milan berlin : 500\n"
"mesh_AF cairo lagos nairobi capetown tripoli : 500\n"
"mesh_ME qatar baghdad ankara beirut tehran : 500\n"

"mesh_pacific osaka seattle santiago auckland singapore : 5000\n"
"mesh_atlantic nyc dublin madrid lagos rio : 5000\n"
"mesh_indian colombo karachi qatar nairobi dhaka : 5000\n"
"mesh_usa chicago washdc houston atlanta seattle : 5000\n"

"mesh_W1 sydney singapore chicago washdc caracas madrid cairo qatar karachi : 10000 20000 30000 40000\n"
"mesh_W2 perth taipei houston atlanta bogota dublin lagos baghdad mumbia : 40000 10000 20000 30000\n"
"mesh_W3 brisbane shanghai seattle nyc rio brussels nairobi ankara bangalore : 30000 40000 10000 20000\n"
"mesh_W4 melbourne seoul montreal boston buenosaires milan capetown beirut colombo : 20000 30000 40000 10000\n"
"mesh_W5 auckland osaka mexicocity toronto santiago berlin tripoli tehran dhaka : 20000 30000 40000 50000\n";

#if 0
"start A\n"
"node A B C D E F G\n"
"tcp A E\n"
"tcp A F\n"
"tcp A B : 5000 1000 5000 5000\n"
"tcp B C : 1000 5000 5000 5000\n"
"tcp B F : 5000 5000 1000 5000\n"
"tcp B D : 5000 5000 5000 1000\n"
"tcp C D\n"
"tcp C G\n"
"tcp D E\n"
"tcp F G\n";
#endif
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
main( int argc, const char *argv[] )
{
  int x = 1;
  const char * do_debug = get_arg( x, argc, argv, 0, "-d", "-debug", NULL ),
             * do_cost  = get_arg( x, argc, argv, 0, "-c", "-cost", NULL ),
             * do_fwd   = get_arg( x, argc, argv, 0, "-f", "-forward", NULL ),
             * do_tree  = get_arg( x, argc, argv, 0, "-t", "-tree", NULL ),
             * do_graph = get_arg( x, argc, argv, 0, "-g", "-graph", NULL ),
             * do_web   = get_arg( x, argc, argv, 0, "-w", "-web", NULL ),
             * do_loop  = get_arg( x, argc, argv, 0, "-l", "-loopback", NULL ),
             * help     = get_arg( x, argc, argv, 0, "-h", "-help", NULL );
  bool show_path_cost        = ( do_cost != NULL || do_debug != NULL ),
       show_forward_cache    = ( do_fwd != NULL || do_debug != NULL ),
       show_multicast_tree   = ( do_tree != NULL || do_debug != NULL ),
       show_text_description = ( do_graph != NULL || do_debug != NULL ),
       show_web_graph        = ( do_web != NULL || do_debug != NULL ),
       use_loop              = ( do_loop != NULL ),
       generate_config       = ! ( show_path_cost ||
                                   show_forward_cache ||
                                   show_multicast_tree ||
                                   show_text_description ||
                                   show_web_graph );

  if ( help != NULL ) {
    fprintf( stderr,
             "%s [-d] [-g] [-f] [-t] [-g] [-w] [-l] file\n"
             "  -d   = same as -c,-f,-t,-g,-w\n"
             "  -c   = show path cost\n"
             "  -f   = show forward cache\n"
             "  -t   = show multicast tree\n"
             "  -g   = show text network description\n"
             "  -w   = show web json network\n"
             "  -l   = use device in config file\n"
             "  file = network text description\n"
             "if no option, then generate yaml config file\n"
             "if no input file, then use included test\n",
             argv[ 0 ] );
    return 1;
  }
  const char * input_file = NULL;
  if ( x < argc )
    input_file = argv[ x ];

  UserDB user_db;
  md::MDMsgMem mem;
  ms::StringTab st( mem );
  uint32_t start_uid;

  user_db.start_time = kv::current_realtime_ns();
  if ( input_file != NULL )
    user_db.load_users( input_file, st, start_uid );
  else
    user_db.load_users( test, sizeof( test ) - 1, st, start_uid );
  if ( user_db.next_uid == 1 ) {
    fprintf( stderr, "No network found input file\n" );
    return 1;
  }

  AdjDistance & peer_dist = user_db.peer_dist;
  UserBridge *b, *c;
  uint32_t uid, cost, tport_id, tport_count;
  uint8_t path_sel;
  char src_buf[ 32 ];
  kv::ArrayOutput out;

  /* find inconsistent peers */
  for (;;) {
    if ( peer_dist.find_inconsistent( b, c ) ) {
      if ( b != NULL || c != NULL )
        printf( "inconsistent2 %s -> %s\n",
                b != NULL ? b->peer.user.val : "null",
                c != NULL ? c->peer.user.val : "null" );
    }
    if ( ! peer_dist.inc_running )
      break;
  }
  if ( peer_dist.found_inconsistency ) {
    fprintf( stderr, "found inconsistency\n" );
    return 1;
  }
  /*for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ )
    peer_dist.calc_coverage( 0, path_sel );*/

  if ( show_path_cost ) {
    printf( "start %s\n", user_db.user.user.val );
    tport_count = user_db.transport_tab.count;
    for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
      TransportRoute * rte = user_db.transport_tab.ptr[ tport_id ];
      if ( rte->uid_connected.first( uid ) ) {
        printf( "tport %u -> %s\n", tport_id,
                peer_dist.uid_name( uid, src_buf, sizeof( src_buf ) ) );
      }
    }
    printf( "\n--- path-cost:\n" );
    /* calc forward cost */
    for ( uid = 1; uid < user_db.next_uid; uid++ ) {
      uint32_t cost[ COST_PATH_COUNT ];
      for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
        cost[ path_sel ] = peer_dist.calc_cost( 0, uid, path_sel );
        if ( cost[ path_sel ] == COST_MAXIMUM )
          cost[ path_sel ] = 0;
      }
      printf( "%s [%u", peer_dist.uid_name( uid, src_buf, sizeof( src_buf ) ),
              cost[ 0 ] );
      for ( path_sel = 1; path_sel < COST_PATH_COUNT; path_sel++ )
        printf( ", %u", cost[ path_sel ] );
      printf( "]\n" );
    }
    /* transport cost */
    printf( "\n--- tport-cost:\n" );
    tport_count = user_db.transport_tab.count;
    for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
      for ( uid = 1; uid < user_db.next_uid; uid++ ) {
        UserBridge * n = user_db.bridge_tab.ptr[ uid ];
        uint32_t cost[ COST_PATH_COUNT ];
        for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
          cost[ path_sel ] =
            peer_dist.calc_transport_cache( uid, tport_id, path_sel );
          if ( cost[ path_sel ] == COST_MAXIMUM )
            cost[ path_sel ] = 0;
        }
        printf( "tport %u -> %s [%u", tport_id, n->peer.user.val, cost[ 0 ] );
        for ( path_sel = 1; path_sel < COST_PATH_COUNT; path_sel++ )
          printf( ", %u", cost[ path_sel ] );
        printf( "]\n" );
      }
    }
  }
  if ( show_forward_cache ) {
    printf( "\n--- forward-cache:\n" );
    ForwardCache fwd[ COST_PATH_COUNT ];
    /* primary ports */
    for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
      peer_dist.update_path( fwd[ path_sel ], path_sel );
    }
    for ( uid = 0; uid < user_db.next_uid; uid++ ) {
      if ( uid == 0 ) {
        printf( "from %s fwd ",
                peer_dist.uid_name( uid, src_buf, sizeof( src_buf ) ) );
        for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
          ForwardCache &f = fwd[ path_sel ];
          bool first = true;
          for ( bool b = f.first( tport_id ); b; b = f.next( tport_id ) ) {
            if ( first ) { printf( "path %u [", path_sel ); first = false; }
            else printf( ", " );
            printf( "%u", tport_id );
          }
          if ( ! first ) { printf( "] " ); }
        }
        printf( "\n" );
        continue;
      }
      cost = 0;
      for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
        UidSrcPath path = peer_dist.x[ path_sel ].path[ uid ];
        cost += path.cost;
      }
      if ( cost != 0 ) {
        printf( "from %s fwd [",
                peer_dist.uid_name( uid, src_buf, sizeof( src_buf ) ) );
        for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
          if ( path_sel != 0 )
            printf( ", " );
          UidSrcPath path = peer_dist.x[ path_sel ].path[ uid ];
          if ( path.cost == 0 )
            printf( "-" );
          else
            printf( "%u", path.tport );
        }
        printf( "] [" );
        for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
          if ( path_sel != 0 )
            printf( ", " );
          UidSrcPath path = peer_dist.x[ path_sel ].path[ uid ];
          printf( "%u", path.cost );
        }
        printf( "]\n" );
      }
    }
  }
  if ( show_multicast_tree ) {
    printf( "\n--- tree:\n" );
    for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
      for ( uint32_t src_uid = 0; src_uid < user_db.next_uid; src_uid++ ) {
        peer_dist.coverage_init( src_uid );
        cost = 0;
        printf( "[%u] src %s\n", path_sel,
                peer_dist.uid_name( src_uid, src_buf, sizeof( src_buf ) ) );
        while ( (cost = peer_dist.coverage_step( path_sel )) != 0 ) {
          uint32_t max = peer_dist.max_uid;
          kv::UIntBitSet & fwd = peer_dist.fwd;
          char next_buf[ 32 ];
          printf( "  cost %u:", cost );
          for ( bool ok = fwd.first( uid, max ); ok;
                ok = fwd.next( uid, max ) ) {
            AdjacencySpace * set = peer_dist.coverage_link( uid );
            printf( " %s -> %s",
              peer_dist.uid_name( set->uid, src_buf, sizeof( src_buf ) ),
              peer_dist.uid_name( uid, next_buf, sizeof( next_buf ) ) );
          }
          printf( "\n" );
        }
      }
    }
    printf( "\n" );
  }

  if ( show_text_description ) {
    printf( "\n--- text graph:\n" );
    peer_dist.message_graph_description( out );
  }
  else if ( generate_config ) {
    if ( input_file == NULL )
      input_file = "test";
    peer_dist.message_graph_config( out, input_file, use_loop );
  }
  if ( out.count > 0 )
    fwrite( out.ptr, 1, out.count, stdout );

  if ( show_web_graph ) {
    if ( input_file != NULL ) {
      kv::MapFile map( input_file );
      if ( map.open() ) {
        out.clear();
        ms::compute_message_graph( NULL, (const char *) map.map, map.map_size,
                                   out );
        printf( "\n--- web graph:\n" );
        fwrite( out.ptr, 1, out.count, stdout );
      }
    }
  }
  return 0;
}
