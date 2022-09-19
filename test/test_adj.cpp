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

static void
init_test_users( UserDB &user_db,  ms::StringTab &st ) noexcept
{
  static uint32_t default_cost[ 4 ] =
    { COST_DEFAULT, COST_DEFAULT, COST_DEFAULT, COST_DEFAULT };

  user_db.user.set( "A", "test", st );
  UserBridge * b = user_db.add( "B", "test", st );
  UserBridge * c = user_db.add( "C", "test", st );

#if 0
  user_db.make_link( NULL, b, 1000 );
  user_db.make_link( NULL, b, 100 );
  user_db.make_link( NULL, c, 1000 );
  user_db.make_link( b, c, 1000 );
  user_db.make_link( b, c, 1000 );
#endif
  UserBridge * d = user_db.add( "D", "test", st );
  UserBridge * e = user_db.add( "E", "test", st );
  UserBridge * f = user_db.add( "F", "test", st );
  UserBridge * g = user_db.add( "G", "test", st );
  user_db.make_link( NULL, e, default_cost, "tcp", NULL, st );
  user_db.make_link( NULL, f, default_cost, "tcp", NULL, st );
  user_db.make_link( c, d, default_cost, "tcp", NULL, st );
  user_db.make_link( d, e, default_cost, "tcp", NULL, st );
  user_db.make_link( f, g, default_cost, "tcp", NULL, st );
  user_db.make_link( g, c, default_cost, "tcp", NULL, st );

  uint32_t x = COST_DEFAULT * 5;
  uint32_t bc[ 4 ]={ COST_DEFAULT, x, x, x };
  user_db.make_link( b, c, bc, "tcp", NULL, st );
  uint32_t ab[ 4 ]={ x, COST_DEFAULT, x, x };
  user_db.make_link( NULL, b, ab, "tcp", NULL, st );
  uint32_t bf[ 4 ]={ x, x, COST_DEFAULT, x };
  user_db.make_link( b, f, bf, "tcp", NULL, st );
  uint32_t bd[ 4 ]={ x, x, x, COST_DEFAULT };
  user_db.make_link( b, d, bd, "tcp", NULL, st );

#if 0
  user_db.make_link( NULL, b, 1 );
  user_db.make_link( b, c, 1 );
  user_db.make_link( c, d, 1 );
  user_db.make_link( d, e, 1 );
  user_db.make_link( NULL, e, 1 );
#endif
}

int
main( int argc, char *argv[] )
{
  UserDB user_db;
  md::MDMsgMem mem;
  ms::StringTab st( mem );
  uint32_t start_uid;
  bool quiet = ( argc > 1 );

  user_db.start_time = kv::current_realtime_ns();
  if ( argc > 1 )
    user_db.load_users( argv[ 1 ], st, start_uid );
  else
    init_test_users( user_db, st );

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
    printf( "found inconsistency %s\n",
      peer_dist.found_inconsistency ? "true" : "false" );
    if ( ! quiet )
      exit( 1 );
  }

  if ( ! quiet ) {
    /* calc forward cost */
    for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
      for ( uid = 1; uid < user_db.next_uid; uid++ ) {
        UserBridge * n = user_db.bridge_tab.ptr[ uid ];
        cost = peer_dist.calc_cost( 0, uid, path_sel );
        if ( cost == COST_MAXIMUM )
          printf( "%u. cost %s = none\n", path_sel, n->peer.user.val );
        else
          printf( "%u. cost %s = %u\n", path_sel, n->peer.user.val, cost );
      }
    }
    /* transport cost */
    for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
      tport_count = user_db.transport_tab.count;
      for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
        for ( uid = 1; uid < user_db.next_uid; uid++ ) {
          UserBridge * n = user_db.bridge_tab.ptr[ uid ];
          cost = peer_dist.calc_transport_cache( uid, tport_id, path_sel );
          if ( cost == COST_MAXIMUM )
            printf( "%u. dist tport %u %s = none\n",
                    path_sel, tport_id, n->peer.user.val );
          else
            printf( "%u. dist tport %u %s = %u\n",
                    path_sel, tport_id, n->peer.user.val, cost );
        }
      }
    }
    ForwardCache fwd[ COST_PATH_COUNT ];
    /* primary ports */
    for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
      peer_dist.update_path( fwd[ path_sel ], path_sel );
      for ( uid = 1; uid < user_db.next_uid; uid++ ) {
        UidSrcPath path    = peer_dist.x[ path_sel ].path[ uid ];
        uint32_t tport_id  = path.tport,
                 cost      = path.cost,
                 path_cost = peer_dist.calc_transport_cache( uid, tport_id,
                                                             path_sel );
        printf( "user %s = path[ %u ] = %u, cost %u path_cost %u\n",
                peer_dist.uid_name( uid, src_buf, sizeof( src_buf ) ),
                path_sel, tport_id, cost, path_cost );
      }
    }
    /* route forwarding */
    for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
      for ( uid = 0; uid < user_db.next_uid; uid++ ) {
        uint32_t c = peer_dist.calc_coverage( uid, path_sel );
        printf( "rev[ %u ] src %s\n", path_sel,
                peer_dist.uid_name( uid, src_buf, sizeof( src_buf ) ) );
        for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
          TransportRoute * rte = user_db.transport_tab.ptr[ tport_id ];
          if ( rte->uid_connected.clock == c ) {
            printf( "  fwd tport %u\n", tport_id );
          }
        }
      }
    }

    for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
      for ( uint32_t src_uid = 0; src_uid < user_db.next_uid; src_uid++ ) {
        peer_dist.coverage_init( src_uid, path_sel );
        cost = 0;
        printf( "[%u] src %s\n", path_sel,
                peer_dist.uid_name( src_uid, src_buf, sizeof( src_buf ) ) );
        while ( (cost = peer_dist.coverage_step()) != 0 ) {
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
  }
  peer_dist.message_graph_description( out );
  fwrite( out.ptr, 1, out.count, stdout );
  if ( argc > 1 ) {
    kv::MapFile map( argv[ 1 ] );
    if ( map.open() ) {
      out.clear();
      ms::compute_message_graph( NULL, (const char *) map.map, map.map_size, out );
      fwrite( out.ptr, 1, out.count, stdout );
    }
  }
  return 0;
}
