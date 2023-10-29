#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raims/user_db.h>
#include <raims/user.h>
#include <raims/debug.h>
#include <raims/adj_graph.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

const char *
AdjDistance::uid_name( uint32_t uid,  char *buf,  size_t buflen ) noexcept
{
  size_t off = 0;
  return this->uid_name( uid, buf, off, buflen );
}

const char *
AdjDistance::uid_name( uint32_t uid,  char *buf,  size_t &off,
                       size_t buflen ) noexcept
{
  if ( off < buflen ) {
    if ( this->user_db.bridge_tab.ptr[ uid ] == NULL ) {
      if ( uid == 0 )
        off += ::snprintf( &buf[ off ], buflen - off, "%s.*",
                           this->user_db.user.user.val );
      else
        off += ::snprintf( &buf[ off ], buflen - off, "???.%u",  uid );
    }
    else {
      const UserBridge &n = *this->user_db.bridge_tab.ptr[ uid ];
      off += ::snprintf( &buf[ off ], buflen - off, "%s.%u",
                         n.peer.user.val, uid );
    }
  }
  return buf;
}

const char *
AdjDistance::uid_user( uint32_t uid ) noexcept
{
  if ( uid == 0 )
    return this->user_db.user.user.val;
  if ( this->user_db.bridge_tab.ptr[ uid ] != NULL )
    return this->user_db.bridge_tab.ptr[ uid ]->peer.user.val;
  return "???";
}

const char *
AdjDistance::uid_set_names( kv::UIntBitSet &set,  char *buf,
                            size_t buflen ) noexcept
{
  uint32_t uid;
  size_t   off = 0;
  buf[ 0 ] = '\0';
  for ( bool ok = set.first( uid, this->max_uid ); ok;
        ok = set.next( uid, this->max_uid ) ) {
    this->uid_name( uid, buf, off, buflen );
    if ( off < buflen )
      buf[ off++ ] = ' ';
  }
  if ( off > 0 ) {
    if ( off > buflen )
      off = buflen;
    buf[ off - 1 ] = '\0';
  }
  return buf;
}

void
AdjDistance::update_graph( bool all_paths ) noexcept
{
  UserBridgeList   list;
  UserBridgeElem * el;

  this->graph = new ( this->make( sizeof( AdjGraph ) ) ) AdjGraph( *this );

  list.add_users( this->user_db, *this );
  list.sort<UserBridgeList::cmp_start>();

  this->graph_idx_order = this->mkar<uint32_t>( this->max_uid );
  uint32_t * idx = this->graph_idx_order;
  AdjGraph & g   = *this->graph;

  for ( el = list.hd; el != NULL; el = el->next ) {
    StringVal & name = ( el->uid == 0 ? this->user_db.user.user :
                         this->user_db.bridge_tab.ptr[ el->uid ]->peer.user );
    AdjUser *u     = g.add_user( name, el->uid );
    idx[ el->uid ] = u->idx;
  }

  for ( uint32_t i = 0; i < g.user_tab.count; i++ ) {
    AdjUser * u1    = g.user_tab.ptr[ i ];
    uint32_t  count = this->user_db.peer_dist.adjacency_count( u1->uid );

    for ( uint32_t t = 0; t < count; t++ ) {
      AdjacencySpace *set = this->user_db.peer_dist.adjacency_set( u1->uid, t );
      if ( set == NULL )
        continue;

      uint32_t b;
      for ( bool ok = set->first( b ); ok; ok = set->next( b ) ) {
        AdjUser *u2 = g.user_tab.ptr[ idx[ b ] ];
        if ( debug_adj )
          printf( "add %s link %s.%u -> %s.%u tid=%u\n",
                  set->tport.val, u1->user.val, u1->uid, u2->user.val, u2->uid, t );
        g.add_link( u1, u2, set->tport, set->tport_type, set->cost, t );
      }
    }
  }
  this->compute_path( 0 );
  if ( all_paths ) {
    for ( uint16_t p = 1; p < g.path_count; p++ )
      this->compute_path( p );
  }
}

void
AdjDistance::compute_path( uint16_t p ) noexcept
{
  uint64_t stamp = 0;
  if ( p == 0 ) {
    stamp = kv::current_monotonic_time_ns();
    this->graph->compute_forward_set( 0 );
    this->path_count = this->graph->path_count;
    this->path_computed.ptr =
      this->mkar<uint64_t>( UIntBitSet::size( this->path_count ) );

    this->adjacency_run_count++;
    this->adjacency_this_time  = 0;
    this->adjacency_this_count = 0;
    this->last_run_mono        = stamp;
  }
  else if ( ! this->path_computed.is_member( p ) ) {
    stamp = kv::current_monotonic_time_ns();
    this->graph->compute_forward_set( p );
  }
  if ( stamp != 0 ) {
    this->path_computed.add( p );
    stamp = kv::current_monotonic_time_ns() - stamp;

    this->adjacency_this_count++;
    this->adjacency_this_time += stamp;
    this->adjacency_run_time  += stamp;
  }
}

void
AdjDistance::clear_cache( void ) noexcept
{
  if ( this->graph != NULL ) {
    this->graph->reset();
    this->graph = NULL;
  }
  if ( this->cache_ht != NULL ) {
    delete this->cache_ht;
    this->cache_ht = NULL;
  }
  uint32_t uid_cnt  = this->user_db.next_uid,
           rte_cnt  = (uint32_t) this->user_db.transport_tab.count;
  this->cache_seqno = this->update_seqno;
  this->max_tport   = rte_cnt;
  this->max_uid     = uid_cnt;
  this->reuse();
  this->update_graph( false );

  this->stack         = this->mkar<UidDist>( uid_cnt );
  this->visit         = this->mkar<uint32_t>( uid_cnt );
  this->inc_list      = this->mkar<uint32_t>( uid_cnt );
  this->inc_visit.ptr = this->mkar<uint64_t>( UIntBitSet::size( uid_cnt ) );

  this->miss_tos            = 0;
  this->inc_hd              = 0;
  this->inc_tl              = 0;
  this->inc_run_count       = 0;
  this->inc_running         = false;
  this->found_inconsistency = false;
}

uint32_t
AdjDistance::adjacency_count( uint32_t uid ) const noexcept
{
  if ( uid == 0 )
    return (uint32_t) this->user_db.transport_tab.count;
  if ( ! this->user_db.uid_authenticated.is_member( uid ) )
    return 0;
  return (uint32_t) this->user_db.bridge_tab.ptr[ uid ]->adjacency.count;
}

AdjacencySpace *
AdjDistance::adjacency_set( uint32_t uid,  uint32_t i ) const noexcept
{
  if ( uid == 0 )
    return &this->user_db.transport_tab.ptr[ i ]->uid_connected;
  if ( ! this->user_db.uid_authenticated.is_member( uid ) )
    return NULL;
  return this->user_db.bridge_tab.ptr[ uid ]->adjacency.ptr[ i ];
}

void
AdjDistance::push_inc_list( uint32_t uid ) noexcept
{
  if ( this->inc_hd == 0 ) { /* clear space */
    this->inc_hd += this->max_uid - this->inc_tl;
    this->inc_tl  = this->max_uid;
    ::memmove( &this->inc_list[ this->inc_hd ], this->inc_list,
               ( this->inc_tl - this->inc_hd ) * sizeof( uint32_t ) );
  }
  this->inc_list[ --this->inc_hd ] = uid;
}

int
AdjDistance::find_inconsistent2( UserBridge *&from,
                                 UserBridge *&to ) noexcept

{
  uint32_t uid;
  this->clear_cache_if_dirty();
  if ( ! this->inc_running ) {
    this->inc_tl = this->max_uid;
    this->inc_hd = this->max_uid;
    this->miss_tos = 0;
    this->inc_visit.zero( this->max_uid );
    this->inc_visit.add( 0 );
    this->inc_running = true;
    this->found_inconsistency = false;
    this->push_inc_list( 0 );
  }
  while ( this->miss_tos == 0 && this->inc_hd != this->inc_tl ) {
    uint32_t source_uid = this->inc_list[ --this->inc_tl ];
    uint32_t count      = this->adjacency_count( source_uid );
    for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
      AdjacencySpace *set = this->adjacency_set( source_uid, tport_id );
      uint32_t target_uid;
      bool b;
      if ( set == NULL )
        continue;
      for ( b = set->first( target_uid ); b; b = set->next( target_uid ) ) {
        if ( ! this->inc_visit.test_set( target_uid ) )
          this->push_inc_list( target_uid );
        if ( ! this->match_target_set( source_uid, target_uid, *set ) ) {
          UidMissing & m = this->missing[ this->miss_tos++ ];
          m.uid  = source_uid;
          m.uid2 = target_uid;
        }
      }
    }
  }
  if ( this->miss_tos > 0 ) { /* missing links */
    UidMissing & m = this->missing[ --this->miss_tos ];
    from = this->user_db.bridge_tab.ptr[ m.uid ];
    to   = this->user_db.bridge_tab.ptr[ m.uid2 ];
    this->found_inconsistency = true;
    return LINK_MISSING;
  }
  while ( this->inc_visit.set_first( uid, this->max_uid ) ) {
    UserBridge * n = this->user_db.bridge_tab.ptr[ uid ];
    if ( n == NULL )
      continue;
    if ( n->is_set( AUTHENTICATED_STATE ) ) {
      from = n;
      to   = NULL;
      this->found_inconsistency = true;
      return UID_ORPHANED;
    }
  }
  from = NULL;
  to   = NULL;
  this->inc_running = false;
  this->inc_run_count++;
  this->last_run_mono = kv::current_monotonic_time_ns();
  return CONSISTENT;
}

bool
AdjDistance::match_target_set( uint32_t source_uid,  uint32_t target_uid,
                               AdjacencySpace &set ) noexcept
{
  AdjacencySpace *set2;
  uint32_t count2 = this->adjacency_count( target_uid );
  if ( target_uid == set.rem_uid ) {
    if ( set.rem_tport_id < count2 ) {
      set2 = this->adjacency_set( target_uid, set.rem_tport_id );
      if ( set2 != NULL && set2->is_member( source_uid ) &&
           set.cost.equals( set2->cost ) )
        return true;
    }
  }
  else {
    for ( uint32_t tport_id = 0; tport_id < count2; tport_id++ ) {
      set2 = this->adjacency_set( target_uid, tport_id );
      if ( set2 != NULL && set2->is_member( source_uid ) &&
           set.cost.equals( set2->cost ) )
        return true;
    }
  }
  return false;
}

uint32_t
AdjDistance::uid_refs( uint32_t from,  uint32_t to ) noexcept
{
  size_t count  = this->adjacency_count( from );
  uint32_t refs = 0;
  for ( size_t i = 0; i < count; i++ ) {
    AdjacencySpace * set = this->adjacency_set( from, (uint32_t) i );
    if ( set == NULL )
      continue;
    if ( set->is_member( to ) )
      refs++;
  }
  return refs;
}

uint32_t
AdjDistance::inbound_refs( uint32_t to ) noexcept
{
  uint32_t uid, found = 0;

  for ( uid = 0; uid < this->max_uid; uid++ ) {
    if ( uid != to )
      found += this->uid_refs( uid, to );
  }
  return found;
}

uint32_t
AdjDistance::outbound_refs( uint32_t from ) noexcept
{
  uint32_t uid, found = 0;

  for ( uid = 0; uid < this->max_uid; uid++ ) {
    if ( uid != from )
      found += this->uid_refs( from, uid );
  }
  return found;
}
/* find dest through src */
uint32_t
AdjDistance::calc_cost( uint32_t src_uid,  uint32_t dest_uid,
                        uint16_t path_select ) noexcept
{
  uint32_t i, uid, tos = 0;

  for ( i = 0; i < this->max_uid; i++ )
    this->visit[ i ] = COST_MAXIMUM; /* set other nodes as not reachable */

  this->visit[ src_uid ] = 0; /* start here */
  if ( src_uid == dest_uid )
    return 0;

  uint32_t count = this->adjacency_count( src_uid );
  for ( i = 0; i < count; i++ ) {
    AdjacencySpace * set = this->adjacency_set( src_uid, i );
    if ( set == NULL )
      continue;
    for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
      if ( this->visit[ uid ] > set->cost[ path_select ] ) {
        this->visit[ uid ] = set->cost[ path_select ];
        this->stack[ tos ].uid  = uid;  /* search through uid */
        this->stack[ tos ].dist = set->cost[ path_select ];
        tos++;
      }
    }
  }
  return this->search_cost( dest_uid, tos, path_select );
}

uint32_t
AdjDistance::search_cost( uint32_t dest_uid,  uint32_t tos,
                          uint16_t path_select ) noexcept
{
  uint32_t min_cost = COST_MAXIMUM;

  while ( tos > 0 ) {
    uint32_t src_uid = this->stack[ --tos ].uid,
             d       = this->stack[ tos ].dist;
    if ( src_uid == dest_uid ) {
      if ( d < min_cost ) {
        this->visit[ src_uid ] = d;
        min_cost = d;
        continue;
      }
    }
    if ( d + 1 >= min_cost )
      continue;

    uint32_t count = this->adjacency_count( src_uid );
    for ( uint32_t i = 0; i < count; i++ ) {
      AdjacencySpace * set = this->adjacency_set( src_uid, i );
      uint32_t uid;
      bool     ok;
      if ( set == NULL )
        continue;
      if ( set->is_member( dest_uid ) ) {
        if ( this->visit[ dest_uid ] > d + set->cost[ path_select ] )
          this->visit[ dest_uid ] = d + set->cost[ path_select ];
        if ( d + set->cost[ path_select ] < min_cost )
          min_cost = d + set->cost[ path_select ];
      }
      else {
        for ( ok = set->first( uid ); ok; ok = set->next( uid ) ) {
          if ( this->visit[ uid ] > d + set->cost[ path_select ] ) {
            this->visit[ uid ] = d + set->cost[ path_select ];
            this->stack[ tos ].uid  = uid;
            this->stack[ tos ].dist = d + set->cost[ path_select ];
            tos++;
          }
        }
      }
    }
  }
  return min_cost;
}

uint32_t
AdjDistance::calc_transport_cache( uint32_t dest_uid,  uint32_t tport_id,
                                   uint16_t path_select ) noexcept
{
  this->clear_cache_if_dirty();

  size_t   pos;
  uint64_t max_u = (uint64_t) this->max_uid,
           max_t = (uint64_t) this->max_tport,
           path  = (uint64_t) path_select * max_u * max_t,
           idx   = path + (uint64_t) tport_id * max_u + (uint64_t) dest_uid;
  uint32_t h = 0, val;

  if ( idx <= (uint64_t) 0xffffffffU ) { /* only cache 32 bits */
    h = kv_hash_uint( (uint32_t) idx );
    if ( this->cache_ht == NULL )
      this->cache_ht = kv::UIntHashTab::resize( NULL );
    if ( this->cache_ht->find( h, pos, val ) )
      return val;
  }
  val = this->calc_transport_cost( dest_uid, tport_id, path_select );
  if ( h != 0 )
    this->cache_ht->set_rsz( this->cache_ht, h, pos, val );
  return val;
}

/* find dest through transport */
uint32_t
AdjDistance::calc_transport_cost( uint32_t dest_uid,  uint32_t tport_id,
                                  uint16_t path_select ) noexcept
{
  AdjacencySpace * set = this->adjacency_set( 0, tport_id );
  if ( set == NULL )
    return 0;
  uint32_t cost = set->cost[ path_select ];
  if ( set->is_member( dest_uid ) )
    return cost; /* directly connected */

  uint32_t i, uid, tos = 0;
  this->visit[ 0 ] = 0; /* exclude self from routing */
  for ( i = 1; i < this->max_uid; i++ )
    this->visit[ i ] = COST_MAXIMUM; /* set other nodes as not reachable */
  /* push transport connected uids */
  for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
    this->visit[ uid ] = cost; /* mark visited */
    this->stack[ tos ].uid = uid;
    this->stack[ tos ].dist = cost;
    tos++;
  }
  cost = this->search_cost( dest_uid, tos, path_select );
  return cost;
}

void
AdjDistance::calc_path( ForwardCache &fc,  uint16_t p ) noexcept
{
  if ( p > 0 )
    this->compute_path( p );
  uint32_t   count = this->adjacency_count( 0 );
  uint64_t * m     = this->mkar<uint64_t>( fc.size( count ) );
  fc.init( count, this->cache_seqno, m );
  fc.path = this->mkar<UidSrcPath>( this->max_uid );

  uint32_t * idx = this->graph_idx_order;
  AdjUser  * me  = this->graph->user_tab.ptr[ idx[ 0 ] ];
  AdjLink  * link;
  uint32_t   src, cost, uid;

  for ( src = 0; src < me->links.count; src++ ) {
    link = me->links.ptr[ src ];
    if ( link->dest[ p ].count() != 0 ) {
      fc.add( link->tid );
    }
  }
  AdjFwdTab & fwd = me->fwd[ p ];
  for ( uint32_t j = 0; j < fwd.links.count; j++ ) {
    src  = fwd.src.ptr[ j ];
    link = fwd.links.ptr[ j ];
    cost = fwd.cost.ptr[ j ];
    uid  = link->b.uid;
    fc.path[ uid ].tport   = me->links.ptr[ src ]->tid;
    fc.path[ uid ].src_uid = link->a.uid;
    fc.path[ uid ].cost    = cost;
  }
}

void
AdjDistance::calc_source_path( ForwardCache &fc,  uint32_t src_uid,
                               uint16_t p ) noexcept
{
  if ( src_uid == 0 )
    return this->calc_path( fc, p );
  if ( p > 0 )
    this->compute_path( p );
  uint32_t   count = this->adjacency_count( 0 );
  uint64_t * m     = this->mkar<uint64_t>( fc.size( count ) );
  fc.init( count, this->cache_seqno, m );

  uint32_t * idx = this->graph_idx_order;
  AdjUser  * u   = this->graph->user_tab.ptr[ idx[ src_uid ] ];
  AdjLink  * link;

  AdjFwdTab & fwd = u->fwd[ p ];
  for ( uint32_t j = 0; j < fwd.links.count; j++ ) {
    link = fwd.links.ptr[ j ];
    if ( link->a.uid == 0 )
      fc.add( link->tid );
  }
}

void
AdjDistance::message_graph_description( kv::ArrayOutput &out ) noexcept
{
  if ( this->graph == NULL )
    this->update_graph( true );

  AdjGraphOut put( *this->graph, out );
  put.print_graph();
  out.s( "\n" );
}

