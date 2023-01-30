#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raikv/bit_set.h>
#include <raikv/os_file.h>
#include <raikv/prio_queue.h>
#include <raims/string_tab.h>

#define MS_NAMESPACE test_ms
#define NO_MS_HEADERS
#define INCLUDE_DUMMY_DEFS
#include "raims/adjacency.h"

namespace rai {
namespace test_ms {
#include "adjacency.cpp"
}
}
using namespace rai;
using namespace test_ms;

static int
split_args( char *buf, const char *args[ 500 ] ) noexcept
{
  int i = 0, argc = 0;
  for (;;) {
    while ( buf[ i ] <= ' ' && buf[ i ] != '\0' )
      buf[ i++ ] = '\0';
    if ( buf[ i ] == '\0' || argc == 100 )
      return argc;
    args[ argc++ ] = &buf[ i ];
    while ( buf[ i ] > ' ' )
      i++;
  }
}

static void
parse_cost( const char **args,  int argc,  uint32_t *cost ) noexcept
{
  int i = 0;
  for ( ; i < 4 && i < argc; i++ ) {
    int n = atoi( args[ i ] );
    cost[ i ] = ( n == 0 ? COST_DEFAULT : n );
  }
  if ( i <= 1 ) {
    if ( i == 0 ) cost[ 0 ] = COST_DEFAULT;
    cost[ 1 ] = cost[ 2 ] = cost[ 3 ] = cost[ 0 ];
  }
  if ( i == 2 ) {
    cost[ 2 ] = cost[ 0 ];
    cost[ 3 ] = cost[ 1 ];
  }
  if ( i == 3 )
    cost[ 3 ] = cost[ 0 ];
}

bool
UserDB::load_users( const char *fn,  ms::StringTab &st,
                    uint32_t &start_uid ) noexcept
{
  kv::MapFile map( fn );

  if ( ! map.open() ) {
    perror( fn );
    return false;
  }
  return this->load_users( (const char *) map.map, map.map_size, st, start_uid);
}

bool
UserDB::load_users( const char *p,  size_t size,  ms::StringTab &st,
                    uint32_t &start_uid ) noexcept
{
  static uint32_t default_cost[ 4 ] =
    { COST_DEFAULT, COST_DEFAULT, COST_DEFAULT, COST_DEFAULT };

  const char * args[ 500 ];
  int          argc, ln = 0;
  char         buf[ 8 * 1024 ],
               start[ 80 ];
  uint32_t     cost_val[ 4 ],
             * cost;
  const char * end = &p[ size ];
  size_t       start_len;

  start[ 0 ] = '\0';
  start_len  = 0;
  start_uid  = 0;
  while ( p < end ) {
    size_t       linelen = end - p;
    const char * eol     = (const char *) ::memchr( p, '\n', linelen );

    if ( eol == NULL )
      eol = end;

    linelen = eol - p;
    if ( linelen > sizeof( buf ) - 1 )
      linelen = sizeof( buf ) - 1;
    ::memcpy( buf, p, linelen );
    buf[ linelen ] = '\0';
    p = &eol[ 1 ];

    ln++;
    argc = split_args( buf, args );
    if ( argc == 0 )
      continue;
    if ( ::strcmp( args[ 0 ], "start" ) == 0 ) {
      if ( argc > 1 ) {
        start_len = ::strlen( args[ 1 ] );
        if ( start_len > sizeof( start ) - 1 )
          start_len = sizeof( start ) - 1;
        ::memcpy( start, args[ 1 ], start_len );
        start[ start_len ] = '\0';
      }
      continue;
    }
    if ( ::strcmp( args[ 0 ], "node" ) == 0 ) {
      for ( int i = 1; i < argc; i++ )
        this->find( args[ i ], "test", st );
      continue;
    }

    cost = default_cost;
    for ( int k = 1; k < argc; k++ ) {
      if ( args[ k ][ 0 ] == ':' ) {
        parse_cost( &args[ k + 1 ], argc - ( k + 1 ), cost_val );
        cost = cost_val;
        argc = k;
        break;
      }
    }
    char type[ 5 ];
    int32_t i = 0;
    const char * s = args[ 0 ], * name;
    for ( ; *s != '\0' && *s != ' ' && *s != '_'; s++ ) {
      if ( i < 4 )
        type[ i++ ] = *s;
    }
    type[ i < 4 ? i : 4 ] = '\0';
    if ( *s == '_' )
      name = s + 1;
    else
      name = type;

    if ( ::strcmp( type, "link" ) == 0 || ::strcmp( type, "tcp" ) == 0 ) {
      if ( argc < 3 )
        continue;
      ::strcpy( type, "tcp" );

      UserBridge *one = this->find( args[ 1 ], "test", st ),
                 *two = this->find( args[ 2 ], "test", st );
      this->make_link( one, two, cost, type, name, st );
      for ( int i = 3; i < argc; i++ ) {
        two = this->find( args[ i ], "test", st );
        this->make_link( one, two, cost, type, name, st );
      }
    }
    else if ( ::strcmp( type, "mesh" ) == 0 ) {
      for ( int i = 1; i < argc; i++ ) {
        UserBridge *one = this->find( args[ i ], "test", st );
        for ( int j = i + 1; j < argc; j++ ) {
          UserBridge *two = this->find( args[ j ], "test", st );
          this->make_link( one, two, cost, type, name, st );
        }
      }
    }
    else if ( ::strcmp( type, "pgm" ) == 0 ) {
      for ( int i = 1; i < argc; i++ ) {
        UserBridge     * one  = this->find( args[ i ], "test", st );
        AdjacencySpace * link = one->add_link( cost, type, name, st );
        for ( int j = 1; j < argc; j++ ) {
          if ( i == j )
            continue;
          UserBridge * two = this->find( args[ j ], "test", st );
          link->add( two->uid );
        }
      }
      this->peer_dist.update_seqno++;
    }
  }
  if ( start_len > 0 ) {
    if ( ! this->user.user.equals( start, start_len ) ) {
      for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
        if ( this->bridge_tab.ptr[ uid ]->
               peer.user.equals( start, start_len ) ) {
          start_uid = uid;
          break;
        }
      }
    }
  }
  return true;
}

namespace {
struct SourceTargetStep {
  uint32_t src_uid, target_uid;
  int step;

  SourceTargetStep( uint32_t x,  uint32_t y,  int s )
    : src_uid( x ), target_uid( y ), step( s ) {}
};
}

void
UserDB::print_elements( kv::ArrayOutput &out ) noexcept
{
  kv::ArrayCount<SourceTargetStep, 256> links;
  kv::BitSpace used;

  uint32_t i, uid, uid2, tport_id, max_uid = this->peer_dist.max_uid;
  int step;
  out.puts( "{\n\"nodes\": [\n" );
  if ( this->user.user.len > 0 )
    out.printf(
      "{ \"user\": \"%.*s\", \"uid\": 0, \"step\": %d, \"cost\": %u }",
      this->user.user.len, this->user.user.val, this->step, this->cost );

  for ( uid = 1; uid < max_uid; uid++ ) {
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    out.printf(
      ",\n{ \"user\": \"%.*s\", \"uid\": %u, \"step\": %u, \"cost\": %u }",
      n.peer.user.len, n.peer.user.val, uid, n.step, n.cost );
  }
  out.puts( " ],\n\"links\": [\n" );

  for ( tport_id = 0; tport_id < this->transport_tab.count; tport_id++ ) {
    TransportRoute & rte = *this->transport_tab.ptr[ tport_id ];
    for ( bool ok = rte.uid_connected.first( uid ); ok;
               ok = rte.uid_connected.next( uid ) ) {
      if ( this->fwd.is_member( uid ) )
        step = this->step;
      else
        step = -1;
      links.push( SourceTargetStep( 0, uid, step ) );
    }
  }
  for ( uid = 1; uid < max_uid; uid++ ) {
    UserBridge &n = *this->bridge_tab.ptr[ uid ];
    for ( tport_id = 0; tport_id < n.adjacency.count; tport_id++ ) {
      AdjacencySpace &adj = *n.adjacency.ptr[ tport_id ];
      for ( bool ok = adj.first( uid2 ); ok; ok = adj.next( uid2 ) ) {
        if ( n.fwd.is_member( uid2 ) )
          step = n.step;
        else
          step = -1;
        links.push( SourceTargetStep( uid, uid2, step ) );
      }
    }
  }
  const char *s = "";
  for ( i = 0; i < links.count; i++ ) {
    SourceTargetStep &link = links.ptr[ i ];
    if ( link.step >= 0 ) {
      uid = link.src_uid; uid2 = link.target_uid;
      out.printf( "%s{ \"source\": %u, \"target\": %u, \"step\": %d }",
                  s, uid, uid2, link.step );
      s = ",\n";
      if ( uid > uid2 ) { uint32_t tmp = uid; uid = uid2; uid2 = tmp; }
      used.add( uid * max_uid + uid2 );
    }
  }
  for ( i = 0; i < links.count; i++ ) {
    SourceTargetStep &link = links.ptr[ i ];
    if ( link.step < 0 ) {
      uid = link.src_uid; uid2 = link.target_uid;
      if ( uid > uid2 ) { uint32_t tmp = uid; uid = uid2; uid2 = tmp; }
      if ( ! used.test_set( uid * max_uid + uid2 ) ) {
        out.printf( "%s{ \"source\": %u, \"target\": %u, \"step\": %d }",
                    s, uid, uid2, link.step );
        s = ",\n";
      }
    }
  }
  out.puts( " ]\n}\n" );
}

void
UserDB::print_paths( kv::ArrayOutput &out,  uint32_t start_uid ) noexcept
{
  AdjDistance & peer_dist = this->peer_dist;
  uint32_t uid, max_uid = peer_dist.max_uid;

  out.puts( "[\n" );
  for ( uint8_t path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
    this->fwd.zero();
    this->step = 0;
    this->cost = 0;
    for ( uid = 1; uid < max_uid; uid++ ) {
      UserBridge * n = this->bridge_tab.ptr[ uid ];
      n->fwd.zero();
      n->step = 0;
      n->cost = 0;
    }
    peer_dist.coverage_init( start_uid );
    uint32_t step = 1, cost;
    while ( (cost = peer_dist.coverage_step( path_sel )) != 0 ) {
      kv::UIntBitSet & fwd = peer_dist.fwd;
      for ( bool ok = fwd.first( uid, max_uid ); ok;
            ok = fwd.next( uid, max_uid ) ) {
        AdjacencySpace * set = peer_dist.coverage_link( uid );
        UserBridge     * n   = this->bridge_tab.ptr[ uid ],
                       * src = this->bridge_tab.ptr[ set->uid ];
        if ( n == NULL ) {
          this->step = step;
          this->cost = cost;
        }
        else {
          n->step = step;
          n->cost = cost;
        }
        if ( src == NULL )
          this->fwd.add( uid );
        else
          src->fwd.add( uid );
      }
      step++;
    }
    this->print_elements( out );
    if ( path_sel + 1 < COST_PATH_COUNT )
      out.puts( ",\n" );
  }
  out.puts( "]\n" );
}

UserBridge::~UserBridge()
{
  for ( size_t i = 0; i < this->adjacency.count; i++ ) {
    if ( this->adjacency.ptr[ i ] != NULL ) {
      delete this->adjacency.ptr[ i ];
      this->adjacency.ptr[ i ] = NULL;
    }
  }
}

UserDB::~UserDB()
{
  size_t i;
  for ( i = 0; i < this->bridge_tab.count; i++ ) {
    if ( this->bridge_tab.ptr[ i ] != NULL ) {
      delete this->bridge_tab.ptr[ i ];
      this->bridge_tab.ptr[ i ] = NULL;
    }
  }
  for ( i = 0; i < this->transport_tab.count; i++ ) {
    if ( this->transport_tab.ptr[ i ] != NULL ) {
      delete this->transport_tab.ptr[ i ];
      this->transport_tab.ptr[ i ] = NULL;
    }
  }
}

bool
rai::ms::compute_message_graph( const char *start,  const char *network,
                                size_t network_len,
                                kv::ArrayOutput &out ) noexcept
{
  UserDB user_db;
  md::MDMsgMem mem;
  ms::StringTab st( mem );
  uint32_t start_uid;

  user_db.start_time = kv::current_realtime_ns();
  if ( ! user_db.load_users( network, network_len, st, start_uid ) )
    return false;
  if ( start != NULL ) {
    if ( user_db.user.user.equals( start ) )
      start_uid = 0;
    else {
      for ( uint32_t uid = 1; uid < user_db.next_uid; uid++ ) {
        if ( user_db.bridge_tab[ uid ]->peer.user.equals( start ) ) {
          start_uid = uid;
          break;
        }
      }
    }
  }
  user_db.peer_dist.clear_cache_if_dirty();
  user_db.print_paths( out, start_uid );
  return true;
}
