#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raikv/bit_set.h>
#include <raims/string_tab.h>

using namespace rai;

#define TEST_ADJ
#include "raims/adjacency.h"

struct PeerEntry {
  ms::StringVal user, svc;
  PeerEntry() {
    ::memset( (void *) this, 0, sizeof( *this ) );
  }
  void set( const char *u,  const char *s,  ms::StringTab &st ) {
    st.ref_string( u, ::strlen( u ), this->user );
    st.ref_string( s, ::strlen( s ), this->svc );
  }
};

struct TransportRoute {
  UserDB       & user_db;
  uint32_t       tport_id;
  AdjacencySpace uid_connected;

  void * operator new( size_t, void *ptr ) { return ptr; }
  TransportRoute( UserDB &u,  uint32_t id ) : user_db( u ), tport_id( id ) {}
};

enum { AUTHENTICATED_STATE };
struct UserBridge {
  AdjacencyTab adjacency;
  uint64_t     start_time;
  uint32_t     uid;
  PeerEntry    peer;
  bool is_set( int ) { return true; }

  void * operator new( size_t, void *ptr ) { return ptr; }
  UserBridge( uint32_t id ) : start_time( 0 ), uid( id ) {}
  void add_link( uint32_t target_uid,  uint32_t cost[ COST_PATH_COUNT ] ) {
    AdjacencySpace *adj = this->adjacency.get( this->adjacency.count,
                                               this->uid, cost );
    adj->add( target_uid );
  }
  void add_link( UserBridge *n,  uint32_t cost[ COST_PATH_COUNT ] ) {
    this->add_link( n->uid, cost );
  }
};

struct TransportTab : public kv::ArrayCount< TransportRoute *, 4 > {};
struct UserBridgeTab : public kv::ArrayCount< UserBridge *, 128 > {};

struct UserDB {
  PeerEntry     user;
  uint32_t      next_uid;
  uint64_t      start_time;
  UserBridgeTab bridge_tab;
  TransportTab  transport_tab;
  kv::BitSpace  uid_authenticated;
  AdjDistance   peer_dist;

  UserDB() : next_uid( 1 ), peer_dist( *this ) {}

  UserBridge *add( const char *u,  const char *s,  ms::StringTab &st ) noexcept;
  TransportRoute *add_link( UserBridge *n,
                            uint32_t cost[ COST_PATH_COUNT ] ) noexcept;
  void make_link( UserBridge *x,  UserBridge *y,
                  uint32_t cost[ COST_PATH_COUNT ] ) noexcept;
  void init_users( ms::StringTab &st ) noexcept;
};

#include "../src/adjacency.cpp"

UserBridge *
UserDB::add( const char *u,  const char *s,  ms::StringTab &st ) noexcept
{
  uint32_t uid = this->next_uid++;
  void * p = ::malloc( sizeof( UserBridge ) );
  UserBridge *n = new ( p ) UserBridge( uid );
  this->bridge_tab[ uid ] = n;
  n->peer.set( u, s, st );
  n->start_time = kv::current_realtime_ns();
  this->uid_authenticated.add( uid );
  return n;
}

TransportRoute *
UserDB::add_link( UserBridge *n,  uint32_t cost[ COST_PATH_COUNT ] ) noexcept
{
  uint32_t tport_id = this->transport_tab.count;
  void * p = ::malloc( sizeof( TransportRoute ) );
  TransportRoute *t = new ( p ) TransportRoute( *this, tport_id );
  this->transport_tab[ tport_id ] = t;
  t->uid_connected.add( n->uid );
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    t->uid_connected.cost[ i ] = cost[ i ];
  t->uid_connected.tport_id = tport_id;
  n->add_link( (uint32_t) 0, cost );
  return t;
}

void
UserDB::make_link( UserBridge *x,  UserBridge *y,
                   uint32_t cost[ COST_PATH_COUNT ] ) noexcept
{
  TransportRoute *t;
  if ( x == NULL ) {
    t = this->add_link( y, cost );
    printf( "tport %u -> %s\n", t->tport_id, y->peer.user.val );
  }
  else if ( y == NULL ) {
    t = this->add_link( x, cost );
    printf( "tport %u -> %s\n", t->tport_id, x->peer.user.val );
  }
  else {
    printf( "%s -> %s\n", x->peer.user.val, y->peer.user.val );
    x->add_link( y, cost );
    y->add_link( x, cost );
  }
}

void
UserDB::init_users( ms::StringTab &st ) noexcept
{
  this->start_time = kv::current_realtime_ns();
  this->user.set( "A", "test", st );
  UserBridge * b = this->add( "B", "test", st );
  UserBridge * c = this->add( "C", "test", st );

#if 0
  this->make_link( NULL, b, 1000 );
  this->make_link( NULL, b, 100 );
  this->make_link( NULL, c, 1000 );
  this->make_link( b, c, 1000 );
  this->make_link( b, c, 1000 );
#endif
  UserBridge * d = this->add( "D", "test", st );
  UserBridge * e = this->add( "E", "test", st );
  UserBridge * f = this->add( "F", "test", st );
  UserBridge * g = this->add( "G", "test", st );
  uint32_t def[ 4 ]={ COST_DEFAULT, COST_DEFAULT, COST_DEFAULT, COST_DEFAULT };
  this->make_link( NULL, e, def );
  this->make_link( NULL, f, def );
  this->make_link( c, d, def );
  this->make_link( d, e, def );
  this->make_link( f, g, def );
  this->make_link( g, c, def );

  uint32_t x = COST_DEFAULT * 5;
  uint32_t bc[ 4 ]={ COST_DEFAULT, x, x, x };
  this->make_link( b, c, bc );
  uint32_t ab[ 4 ]={ x, COST_DEFAULT, x, x };
  this->make_link( NULL, b, ab );
  uint32_t bf[ 4 ]={ x, x, COST_DEFAULT, x };
  this->make_link( b, f, bf );
  uint32_t bd[ 4 ]={ x, x, x, COST_DEFAULT };
  this->make_link( b, d, bd );
#if 0
  this->make_link( NULL, b, 1 );
  this->make_link( b, c, 1 );
  this->make_link( c, d, 1 );
  this->make_link( d, e, 1 );
  this->make_link( NULL, e, 1 );
#endif
}

int
main( void )
{
  UserDB user_db;
  md::MDMsgMem mem;
  ms::StringTab st( mem );
  user_db.init_users( st );
  AdjDistance & peer_dist = user_db.peer_dist;
  peer_dist.update_seqno++;
  UserBridge *b, *c;
  uint32_t uid, cost, tport_id, tport_count;
  uint8_t path_sel;
  char src_buf[ 32 ];

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
  printf( "found inconsistency %s\n",
    peer_dist.found_inconsistency ? "true" : "false" );

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
  /* primary ports */
  for ( path_sel = 0; path_sel < COST_PATH_COUNT; path_sel++ ) {
    peer_dist.update_path( path_sel );
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
        for ( bool ok = fwd.first( uid, max ); ok; ok = fwd.next( uid, max ) ) {
          AdjacencySpace * set = peer_dist.coverage_link( uid );
          printf( " %s -> %s",
            peer_dist.uid_name( set->uid, src_buf, sizeof( src_buf ) ),
            peer_dist.uid_name( uid, next_buf, sizeof( next_buf ) ) );
        }
        printf( "\n" );
      }
    }
  }
  return 0;
}
