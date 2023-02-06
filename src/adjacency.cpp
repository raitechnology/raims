#ifndef NO_MS_HEADERS
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

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;
#else
#define d_adj( ... )
#define debug_adj 0
#endif

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
AdjDistance::clear_cache( void ) noexcept
{
  uint32_t max       = this->user_db.next_uid,
           rte_cnt   = (uint32_t) this->user_db.transport_tab.count;
  this->cache_seqno  = this->update_seqno;
  this->max_tport    = rte_cnt;
  this->tport_select = rte_cnt;
  this->max_uid      = max;
  this->reuse();
  if ( ( rte_cnt & 1 ) != 0 )
    rte_cnt++;
  size_t isz  = kv::UIntBitSet::size( max ),
         wsz  = max * this->max_tport,
         size = max * sizeof( UidDist ) +    /* stack */
                max * sizeof( uint32_t ) +   /* visit */
                max * sizeof( uint32_t ) +   /* inc_list */
                max * sizeof( UidSrcPath ) * COST_PATH_COUNT + /* x */
                isz * sizeof( uint64_t ) +   /* inc_visit */
                isz * sizeof( uint64_t ) +   /* adj */
                isz * sizeof( uint64_t ) +   /* path */
                isz * sizeof( uint64_t ) +   /* fwd */
                isz * sizeof( uint64_t ) +   /* reachable */
                wsz * sizeof( uint32_t ) * COST_PATH_COUNT;/* cache */

  void     *p = this->make( size );
  uint64_t *m = (uint64_t *) p;
  ::memset( p, 0, size );
  this->inc_visit.ptr = m; m += isz;
  this->adj.ptr       = m; m += isz;
  this->path.ptr      = m; m += isz;
  this->fwd.ptr       = m; m += isz;
  this->reachable.ptr = m; m += isz;
  this->stack         = (UidDist *) m; m = &m[ max ];

  uint32_t *n = (uint32_t *) (void *) m;
  this->cache         = n; n += wsz * COST_PATH_COUNT;
  this->visit         = n; n += max;
  this->inc_list      = n; n += max;

  UidSrcPath *x = (UidSrcPath *) (void *) n;
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ ) {
    this->x[ i ].path = x; x = &x[ max ];
  }

  if ( (char *) (void *) x != (char *) p + size ) {
    fprintf( stderr, "cache allocation is wrong\n" );
  }
  this->miss_tos            = 0;
  this->inc_hd              = 0;
  this->inc_tl              = 0;
  this->inc_run_count       = 0;
  this->last_run_mono       = kv::current_monotonic_time_ns();
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
  if ( uid == 0 ) {
    if ( this->tport_select == this->max_tport || this->tport_select == i )
      return &this->user_db.transport_tab.ptr[ i ]->uid_connected;
    return NULL;
  }
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

bool
AdjDistance::find_inconsistent( UserBridge *&from,
                                UserBridge *&to ) noexcept
{
  uint32_t uid, uid2;
  this->clear_cache_if_dirty();
  /* if not running, initialize by adding directly connected uids to inc_list */
  if ( ! this->inc_running ) {
    this->inc_tl = this->max_uid;
    this->inc_hd = this->max_uid;
    this->miss_tos = 0;
    this->inc_visit.zero( this->max_uid );

    size_t count = this->user_db.transport_tab.count;
    for ( size_t i = 0; i < count; i++ ) {
      AdjacencySpace &set = this->user_db.transport_tab.ptr[ i ]->uid_connected;
      for ( bool ok = set.first( uid ); ok; ok = set.next( uid ) ) {
        if ( ! this->inc_visit.test_set( uid ) )
          this->push_inc_list( uid );
      }
    }
    this->inc_running = true;
    this->found_inconsistency = false;
  }
  /* if more uids in the inc_list[] to check */
  if ( this->miss_tos == 0 && this->inc_hd != this->inc_tl ) {
    uid = this->inc_list[ --this->inc_tl ];
    UserBridge * n = this->user_db.bridge_tab.ptr[ uid ];

    /* check that uid links have a corresponding link back --
     * this does not account for multiple links through different transports
     * to the same uid where one is broken and the other is fine */
    for ( size_t j = 0; j < n->adjacency.count; j++ ) {
      AdjacencySpace * set = n->adjacency.ptr[ j ];
      if ( set == NULL )
        continue;
      for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
        if ( uid2 == 0 )
          continue;
        /* check uid2 if not visisted */
        if ( ! this->inc_visit.test_set( uid2 ) ) {
          this->push_inc_list( uid2 );
        }
        UserBridge *m = this->user_db.bridge_tab.ptr[ uid2 ];
        bool found = false;
        /* check if uids connected to my connected peer are connected back */
        for ( size_t k = 0; k < m->adjacency.count; k++ ) {
          AdjacencySpace * set3 = m->adjacency.ptr[ k ];
          if ( set3 == NULL )
            continue;
          if ( set3->is_member( uid ) ) {
            found = true;
            break;
          }
        }
        if ( ! found ) {
          UidMissing & m = this->missing[ this->miss_tos++ ];
          m.uid = uid;
          m.uid2 = uid;
        }
      }
    }
  }
  if ( this->miss_tos > 0 ) { /* missing links */
    UidMissing & m = this->missing[ --this->miss_tos ];
    uid  = m.uid;
    uid2 = m.uid2;
    from = this->user_db.bridge_tab.ptr[ uid ];
    to   = this->user_db.bridge_tab.ptr[ uid2 ];
    this->found_inconsistency = true;
    return true;
  }
  if ( this->inc_tl > this->inc_hd ) { /* if not empty */
    from = NULL;
    to   = NULL;
    return true; /* check other uids before orphan check */
  }
  if ( this->inc_running ) {
    while ( this->inc_visit.set_first( uid, this->max_uid ) ) {
      UserBridge * n = this->user_db.bridge_tab.ptr[ uid ];
      if ( n == NULL )
        continue;
      if ( n->is_set( AUTHENTICATED_STATE ) ) {
        from = n;
        to   = NULL;
        this->found_inconsistency = true;
        return true;
      }
    }
    this->inc_running = false;
    this->inc_run_count++;
    this->last_run_mono = kv::current_monotonic_time_ns();
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
#if 0
void
AdjDistance::calc_reachable( TransportRoute &rte ) noexcept
{
  uint32_t i, uid, uid2, tos = 0;
  this->clear_cache_if_dirty();
  this->reachable.zero( this->max_uid );
  this->visit[ 0 ] = 0; /* exclude self from routing */
  for ( i = 1; i < this->max_uid; i++ )
    this->visit[ i ] = 1; /* set other nodes as not reachable */
  /* push transport connected uids */
  for ( bool ok = rte.uid_connected.first( uid ); ok;
        ok = rte.uid_connected.next( uid ) ) {
    if ( this->visit[ uid ] != 0 ) {
      this->visit[ uid ] = 0; /* mark visited */
      this->stack[ tos++ ].uid = uid;
    }
  }
  while ( tos > 0 ) {
    uid = this->stack[ --tos ].uid;
    if ( this->user_db.bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->user_db.bridge_tab.ptr[ uid ];
    this->reachable.add( uid );
    for ( i = 0; i < n.adjacency.count; i++ ) {
      AdjacencySpace * set = n.adjacency.ptr[ i ];
      if ( set == NULL )
        continue;
      for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
        if ( this->visit[ uid2 ] != 0 ) {
          this->visit[ uid2 ] = 0;
          this->stack[ tos++ ].uid = uid2;
        }
      }
    }
  }
}
#endif
/* find dest through src */
uint32_t
AdjDistance::calc_cost( uint32_t src_uid,  uint32_t dest_uid,
                        uint8_t path_select ) noexcept
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
                          uint8_t path_select ) noexcept
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
/* find dest through transport */
uint32_t
AdjDistance::calc_transport_cost( uint32_t dest_uid,  uint32_t tport_id,
                                  uint8_t path_select ) noexcept
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
/* the clock var is used to identify which tports are used by a
 * coverage_step() loop */
void
AdjDistance::zero_clocks( void ) noexcept
{
  uint32_t tport_id, uid,
           tport_count = this->user_db.transport_tab.count;
  for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
    TransportRoute * rte = this->user_db.transport_tab.ptr[ tport_id ];
    rte->uid_connected.clock = 0;
  }
  for ( uid = 1; uid < this->max_uid; uid++ ) {
    UserBridge &n = *this->user_db.bridge_tab.ptr[ uid ];
    for ( tport_id = 0; tport_id < n.adjacency.count; tport_id++ ) {
      AdjacencySpace * set = n.adjacency.ptr[ tport_id ];
      if ( set == NULL )
        continue;
      set->clock = 0;
    }
  }
}
/* start a coverage_step() loop */
void
AdjDistance::coverage_init( uint32_t src_uid ) noexcept
{
  this->path.zero( this->max_uid );
  this->fwd.zero( this->max_uid );
  if ( ++this->adjacency_clock == 0 ) {
    this->zero_clocks();
    ++this->adjacency_clock;
  }
  this->path.add( src_uid );
  this->visit[ src_uid ] = 0;
  this->tport_select = this->max_tport;
}

uint64_t
AdjDistance::get_start_time( uint32_t uid ) noexcept
{
  if ( uid == 0 )
    return this->user_db.start_time;
  return this->user_db.bridge_tab.ptr[ uid ]->start_time;
}
/* add a path to the links taken by a coverage step, if a path is equal to
 * an existing one, choose between a redundant list by ordering them by:
 * peer start time, tport type name, tport name, tport id
 * the tport name compare orders by strcmp: { mesh, pgm, tcp } */
void
AdjDistance::push_link( AdjacencySpace *set ) noexcept
{
  uint32_t i, count      = this->links.count,
           replace_count = 0;
  AdjacencySpace *set2;

  set->next_link = NULL;
  for ( i = 0; i < count; i++ ) {
  link_replaced:;
    set2 = this->links.ptr[ i ];

    if ( set->intersects( *set2 ) ) { /* if set and set2 has a common dest */
      if ( set->equals( *set2 ) ) { /* track sets by start time */
        AdjacencySpace **ptr = &this->links.ptr[ i ];
        /* order by start time */
        do {
          set2 = *ptr;
          if ( set->uid == set2->uid ) {
            if ( set->tport_type.cmp( set2->tport_type ) < 0 )
              break;
            if ( set->tport_type.equals( set2->tport_type ) ) {
              if ( set->tport.cmp( set2->tport ) > 0 )
                break;
              if ( set->tport.equals( set2->tport ) )
                if ( set->tport_id < set2->tport_id )
                  break;
            }
          }
          else if ( this->get_start_time( set->uid ) <
                    this->get_start_time( set2->uid ) )
            break;
          ptr = &set2->next_link;
        } while ( set2->next_link != NULL );
        set->next_link = *ptr;
        *ptr = set;
        return;
      }
      else if ( set->superset( *set2 ) ) {  /* set > set2, replace set2 */
        /* if replace multiple sets */
        if ( ++replace_count != 1 ) {
          for ( uint32_t j = i + 1; j < count; j++ )
            this->links.ptr[ j - 1 ] = this->links.ptr[ j ];
          this->links.count = --count;
          if ( i < count )
            goto link_replaced; /* more links to check */
          return;
        }
        this->links.ptr[ i ] = set; /* first replacement */
      }
      else if ( set2->superset( *set ) ) /* set2 > set, discard set */
        return;
      /* set and set2 overlap, both are destinations */
    }
  }
  if ( replace_count == 0 )
    this->links.push( set );
}
/* select an index into the ordering of redundant paths that have equal cost
 * and equal reachability, keeps all paths for printing when debug is on */
AdjacencySpace *
AdjDistance::order_path_select( AdjacencySpace *set,
                                uint8_t path_select ) noexcept
{
  TmpAdjList list;
  AdjacencySpace * next, * path_set[ COST_PATH_COUNT ];
  uint8_t j, k, n = 0;

  ::memset( path_set, 0, sizeof( path_set ) );
  for ( j = 0; set != NULL; j++ ) {
    next = set->next_link;
    if ( j < COST_PATH_COUNT ) {
      path_set[ j ] = set;
      n++;
    }
    else {
      list.push_tl( set );
    }
    set = next;
  }
  j = path_select % n;
  k = ( j > 0 ? j - 1 : n - 1 );
  /* push to hd: j-1, j-2, j-3, j */
  for (;;) {
    list.push_hd( path_set[ k ] );
    if ( j == k )
      break;
    k = ( k > 0 ? k - 1 : n - 1 );
  }
  return list.hd;
}
/* cover the network with the next cost increment, returns cost=0 when done
 * the path are 1<<uid bits that have been visited
 * the fwd are 1<<uid bits that are computed as the next peers reached
 * when this returns */
uint32_t
AdjDistance::coverage_step( uint8_t path_select ) noexcept
{
  AdjacencySpace * set;
  uint32_t min_cost = COST_MAXIMUM, count, i, uid;
  bool ok, new_edge = false;

  this->path.or_bits( this->path, this->max_uid, this->fwd, this->max_uid );
  this->fwd.zero( this->max_uid );
  this->links.count = 0;

  for ( ok = this->path.first( uid, this->max_uid ); ok;
        ok = this->path.next( uid, this->max_uid ) ) {
    count = this->adjacency_count( uid );

    for ( i = 0; i < count; i++ ) {
      if ( (set = this->adjacency_set( uid, i )) == NULL ||
           set->clock == this->adjacency_clock )
        continue;

      uint32_t cost = this->visit[ uid ] + set->cost[ path_select ];
      if ( cost <= min_cost ) {
        this->adj.zero( this->max_uid );
        this->adj.mask_bits( this->path, this->max_uid, *set );
        if ( this->adj.is_empty( this->max_uid ) )
          continue;

        if ( cost < min_cost ) {
          this->links.count = 0;
          min_cost = cost;
          new_edge = true;
        }
        this->push_link( set );
      }
    }
  }
  if ( ! new_edge )
    return 0;

  for ( i = 0; i < this->links.count; i++ ) {
    set = this->links.ptr[ i ];
    /* path_select 0 is oldest, 1 is second oldest, 2 ... */
    if ( set->next_link != NULL ) {
      set = order_path_select( set, path_select );
      this->links.ptr[ i ] = set;
    }
    this->fwd.or_bits( this->fwd, this->max_uid, *set );
    set->clock = this->adjacency_clock;
  }
  for ( ok = this->fwd.first( uid, this->max_uid ); ok;
        ok = this->fwd.next( uid, this->max_uid ) ) {
    this->visit[ uid ] = min_cost;
  }
  return min_cost;
}

AdjacencySpace *
AdjDistance::coverage_link( uint32_t target_uid ) noexcept
{
  AdjacencySpace * set;
  uint32_t i;
  for ( i = 0; i < this->links.count; i++ ) {
    if ( (set = this->links.ptr[ i ]) == NULL )
      continue;
    if ( set->is_member( target_uid ) )
      return set;
  }
  return NULL;
}
/* find which tports are used at midpt_uid starting from src_uid
 * src_uid -> midpt_uid {tport, tport, tport} -> the rest of peers */
void
AdjDistance::calc_forward_cache( ForwardCache &fwd,  uint32_t src_uid,
                             uint32_t midpt_uid,  uint8_t path_select ) noexcept
{
  this->coverage_init( src_uid );
  while ( this->coverage_step( path_select ) != 0 )
    ;
  fwd.init( this->adjacency_count( midpt_uid ), this->cache_seqno );

  uint32_t tport_id, clk = this->adjacency_clock;
  d_adj( "calc_forward_cache src_uid %u, mid %u, path %u, clk %u\n",
         src_uid, midpt_uid, path_select, clk );
  for ( tport_id = 0; tport_id < fwd.tport_count; tport_id++ ) {
    AdjacencySpace * set;
    if ( (set = this->adjacency_set( midpt_uid, tport_id )) == NULL )
      continue;
    if ( set->clock == clk ) {
      d_adj( "fwd_cache(%u) mid %u path %u -> tport_id %u\n", src_uid,
              midpt_uid, path_select, tport_id );
      fwd.add( tport_id );
      fwd.fwd_count++;
    }
  }
}
/* find which tports are needed for src_uid to reach the network from this peer:
 * src_uid -> me(uid:0) {tport, tport, tport} -> rest of peers */
void
AdjDistance::calc_forward_cache( ForwardCache &fwd,  uint32_t src_uid,
                                 uint8_t path_select ) noexcept
{
  this->calc_forward_cache( fwd, src_uid, 0, path_select );
}
/* find if there is a route through midpt_uid that ends at target_uid:
 * me(uid:0) -> midpt_uid {tport, tport, tport} -> target_uid */
bool
AdjDistance::test_forward_midpt( uint32_t midpt_uid,  uint32_t target_uid,
                                 uint8_t path_select ) noexcept
{
  ForwardCache fwd;
  this->calc_forward_cache( fwd, 0, midpt_uid, path_select );
  if ( fwd.fwd_count == 0 )
    return false;
  uint32_t tport_id;
  for ( bool b = fwd.first( tport_id ); b; b = fwd.next( tport_id ) ) {
    AdjacencySpace * set;
    if ( (set = this->adjacency_set( midpt_uid, tport_id )) == NULL )
      continue;
    uint32_t src_uid = 0;
    bool ok = set->first( src_uid );
    if ( ! ok )
      continue;
    for ( ; ok; ok = set->next( src_uid ) ) {
      if ( src_uid == target_uid )
        return true;
    }
    for ( ok = set->first( src_uid ); ok; ok = set->next( src_uid ) ) {
      if ( this->test_forward_midpt( src_uid, target_uid, path_select ) )
        return true;
    }
  }
  return false;
}
/* find which one of my tports, if any, is necessary for each peer to reach the
 * network of peers, there is either zero or one possible tports used for each
 * path_select, this is used as the forwarding database for a message received
 * by a peer and routing to other peers */
void
AdjDistance::calc_path( ForwardCache &fwd,  uint8_t path_select ) noexcept
{
  kv::ArrayCount<AltPath, 8> alt_path;
  uint64_t   & seqno = this->x[ path_select ].seqno;
  UidSrcPath * path  = this->x[ path_select ].path;
  uint32_t     uid;

  d_adj( "calc_path %u\n", path_select );
  seqno = this->update_seqno;

  for ( uid = 0; uid < this->max_uid; uid++ )
    path[ uid ].zero();

  this->update_forward_cache( fwd, 0, path_select );

  uint32_t tport_id, cost, src_uid;
  for ( bool b = fwd.first( tport_id ); b; b = fwd.next( tport_id ) ) {
    this->coverage_init( 0 );
    this->tport_select = tport_id;
    AdjacencySpace & set =
      this->user_db.transport_tab.ptr[ tport_id ]->uid_connected;
    src_uid = 0;
    if ( ! set.first( src_uid ) )
      continue;

    while ( (cost = this->coverage_step( path_select )) != 0 ) {
      for ( uid = 1; uid < this->max_uid; uid++ ) {
        if ( this->fwd.is_member( uid ) ) {
          for ( bool b = set.first( src_uid ); b; b = set.next( src_uid ) ) {
            if ( path[ uid ].cost == 0 ||
                 path[ uid ].cost > cost ||
                 ( path[ uid ].cost == cost &&
                   this->get_start_time( src_uid ) >
                   this->get_start_time( path[ uid ].src_uid ) ) ) {
              d_adj(
                "update uid %s.%u path %u tport %u cost %u src_uid %s.%u\n",
                     this->uid_user( uid ), uid, path_select, tport_id, cost,
                     this->uid_user( src_uid ), src_uid );
              if ( path[ uid ].cost != 0 )
                alt_path[ uid ].alternative( path[ uid ] );
              path[ uid ].tport   = tport_id;
              path[ uid ].cost    = cost;
              path[ uid ].src_uid = src_uid;
            }
            else if ( path[ uid ].cost == cost ) {
              d_adj( "alt uid %s.%u path %u tport %u cost %u src_uid %s.%u\n",
                     this->uid_user( uid ), uid, path_select, tport_id, cost,
                     this->uid_user( src_uid ), src_uid );
              UidSrcPath el;
              el.tport   = tport_id;
              el.cost    = cost;
              el.src_uid = src_uid;
              alt_path[ uid ].alternative( el );
            }
          }
        }
      }
    }
  }
  this->tport_select = this->max_tport;

  for ( uid = 1; uid < this->max_uid; uid++ ) {
    cost = path[ uid ].cost;
    if ( cost == 0 )
      continue;

    tport_id = path[ uid ].tport;
    src_uid  = path[ uid ].src_uid;
    d_adj( "final uid %s.%u path %u tport %u cost %u src_uid %s.%u\n",
           this->uid_user( uid ), uid, path_select, tport_id, cost,
           this->uid_user( src_uid ), src_uid );
    if ( alt_path.count > uid ) {
      AltUidSrcPath & asp = alt_path.ptr[ uid ].alt;
      if ( asp.count > 0 && asp.ptr[ 0 ].cost == cost ) {
        if ( debug_adj ) {
          for ( uint32_t i = 0; i < asp.count; i++ ) {
            UidSrcPath & p = asp.ptr[ i ];
            tport_id = p.tport;
            src_uid  = p.src_uid;
            d_adj( "  other uid %s.%u path %u tport %u cost %u src_uid %s.%u\n",
                   this->uid_user( uid ), uid, path_select, tport_id, cost,
                   this->uid_user( src_uid ), src_uid );
          }
        }
        tport_id = path[ uid ].tport;
        src_uid  = path[ uid ].src_uid;
        if ( ! this->test_forward_midpt( src_uid, uid, path_select ) ) {
          d_adj( "  midpoint failed\n" );
          for ( uint32_t i = 0; i < asp.count; i++ ) {
            UidSrcPath & p = asp.ptr[ i ];
            tport_id = p.tport;
            src_uid  = p.src_uid;
            if ( this->test_forward_midpt( src_uid, uid, path_select ) ) {
              d_adj( "  mid uid %s.%u path %u tport %u cost %u src_uid %s.%u\n",
                     this->uid_user( uid ), uid, path_select, tport_id, cost,
                     this->uid_user( src_uid ), src_uid );
              path[ uid ].copy( p );
              break;
            }
          }
        }
      }
    }
  }
  for ( uid = 1; uid < alt_path.count; uid++ )
    alt_path.ptr[ uid ].release();
  alt_path.clear();
}

uint32_t
AdjDistance::calc_coverage( uint32_t src_uid,  uint8_t path_select ) noexcept
{
  this->coverage_init( src_uid );
  uint32_t cost = 0;
  while ( (cost = this->coverage_step( path_select )) != 0 )
    ;
  return this->adjacency_clock;
}

/* the following describe the network as a text description with the "graph"
 * command */
namespace {
struct UidSort {
  UserBridge * n;
  uint64_t start_time;

  UidSort( UserBridge * b,  uint64_t t ) : n( b ), start_time( t ) {}
  static bool is_older( UidSort *x,  UidSort *y ) {
    return x->start_time > y->start_time;
  }
};

#define T_TCP     "tcp"
#define T_TCP_SZ  3
#define T_MESH    "mesh"
#define T_MESH_SZ 4
#define T_PGM     "pgm"
#define T_PGM_SZ  3

static const uint32_t LISTEN = 1, CONNECT = 2;
struct GraphUserArgs : public kv::ArrayCount<uint32_t, 16> {
  void add( uint32_t type,  uint32_t uid,  uint32_t off,  uint32_t len ) {
    this->push( type ); this->push( uid ); this->push( off ); this->push( len );
  }
};

struct GraphDescription {
  kv::ArrayOutput & out;
  AdjDistance     & dist;
  GraphUserArgs     args;
  uint32_t          off, len,
                    tport_counter;
  bool              is_cfg,
                    use_ports;

  GraphDescription( kv::ArrayOutput &o,  AdjDistance & d,  bool cfg,
                    bool ports )
    : out( o ), dist( d ), tport_counter( 0 ), is_cfg( cfg ),
      use_ports( ports ) {}
  void output_tport( AdjacencySpace *set, uint32_t listen_uid ) noexcept;
  void print_cost( AdjacencySpace *set ) noexcept;
  void output_uid( uint32_t action,  uint32_t uid ) noexcept;
  void describe( void ) noexcept;
  /* tcp listen , connect star */
  bool find_peer_star( uint32_t uid,  AdjacencySpace *set,
                       uint32_t &listen_uid ) noexcept;
  /* mesh all to all connect */
  bool find_peer_mesh( uint32_t uid,  AdjacencySpace *set ) noexcept;
  /* pgm all to all sets */
  bool find_peer_set( uint32_t uid,  AdjacencySpace *set,
                      uint32_t peer_uid,  uint32_t &peer_conn_id ) noexcept;
  /* a connect between endpoints */
  bool find_peer_conn( AdjacencySpace &set,  uint32_t uid,  uint32_t peer_uid,
                       uint32_t &peer_conn_id ) noexcept;
};
}

void
AdjDistance::message_graph_config( kv::ArrayOutput &out,
                                   const char *cfg_name,
                                   bool use_loop ) noexcept
{
  char g_name[ 256 ];
  GraphDescription descr( out, *this, true, ! use_loop );

  if ( cfg_name == NULL )
    ::strcpy( g_name, "graph" );
  else {
    const char *start, *end;
    if ( (start = ::strrchr( cfg_name, '/' )) == NULL )
      start = cfg_name;
    else
      start++;
    if ( (end = ::strrchr( cfg_name, '.' )) == NULL )
      end = &cfg_name[ ::strlen( cfg_name ) ];
    size_t len = end - start;
    if ( len > sizeof( g_name ) )
      len = sizeof( g_name ) - 1;
    ::memcpy( g_name, start, len );
    g_name[ len ] = '\0';
  }

  rai::ms::CryptPass  pass;
  rai::ms::ServiceBuf svc;
  void * salt;
  size_t salt_len;
  salt = pass.gen_salt( salt_len );
  rai::ms::init_kdf( salt, salt_len );
  pass.gen_pass();
  svc.gen_key( g_name, ::strlen( g_name ), pass );
  out.s( "services:\n"
         "  - svc: " ).s( g_name ).s( "\n" )
     .s( "    create: " ).s( svc.create ).s( "\n" )
     .s( "    pri: " ).s( svc.pri ).s( "\n" )
     .s( "    pub: " ).s( svc.pub ).s( "\n" )
     .s( "parameters:\n" )
     .s( "  salt_data: " ).s( (char *) salt ).s( "\n" )
     .s( "  pass_data: " ).s( (char *) pass.pass ).s( "\n" )
     .s( "transports:\n" );
  descr.describe();

  for ( uint32_t current_uid = 0; current_uid < this->max_uid; current_uid++ ) {
    for ( uint32_t i = 0; i < descr.args.count; i += 4 ) {
      uint32_t uid  = descr.args.ptr[ i + 1 ];
      if ( uid != current_uid )
        continue;
      uint32_t type = descr.args.ptr[ i ],
               off  = descr.args.ptr[ i + 2 ],
               len  = descr.args.ptr[ i + 3 ];
      char name[ 256 ];
      if ( len >= sizeof( name ) )
        len = sizeof( name ) - 1;
      ::memcpy( name, &out.ptr[ off ], len );
      name[ len ] = '\0';
      const char * user = descr.dist.uid_user( uid );

      out.s( "# ms_server -d " ).s( g_name ).s( ".yaml -u " ).s( user )
         .s( " -t " ).s( name ).s( "." )
         .s( type == CONNECT ? "connect" : "listen" );

      for ( uint32_t j = 0; j < descr.args.count; j += 4 ) {
        if ( i == j )
          continue;
        uint32_t next_uid  = descr.args.ptr[ j + 1 ];
        if ( next_uid != uid )
          continue;
        type = descr.args.ptr[ j ],
        off  = descr.args.ptr[ j + 2 ],
        len  = descr.args.ptr[ j + 3 ];
        if ( len >= sizeof( name ) )
          len = sizeof( name ) - 1;
        ::memcpy( name, &out.ptr[ off ], len );
        name[ len ] = '\0';
        out.s( " " ).s( name ).s( "." )
           .s( type == CONNECT ? "connect" : "listen" );
      }
      out.s( "\n" );
      break;
    }
  }
}

void
AdjDistance::message_graph_description( kv::ArrayOutput &out ) noexcept
{
  kv::ArrayCount<UidSort, 16> uid_start;
  kv::PrioQueue<UidSort *, UidSort::is_older> uid_sort;
  UserBridge * n;

  out.s( "start " ).s( this->user_db.user.user.val ).s( "\n" );

  uid_start.push( UidSort( NULL, this->user_db.start_time ) );
  for ( uint32_t uid = 1; uid < this->max_uid; uid++ ) {
    n = this->user_db.bridge_tab.ptr[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;
    uid_start.push( UidSort( n, n->start_time ) );
  }
  for ( uint32_t i = 0; i < uid_start.count; i++ )
    uid_sort.push( &uid_start.ptr[ i ] );

  this->max_tport_count = this->adjacency_count( 0 );
  bool first = true;
  while ( ! uid_sort.is_empty() ) {
    UserBridge * n = uid_sort.heap[ 0 ]->n;
    uid_sort.pop();

    if ( first ) {
      out.s( "node" );
      first = false;
    }
    out.s( " " );
    if ( n == NULL )
      out.s( this->user_db.user.user.val );
    else
      out.s( n->peer.user.val );
  }
  out.s( "\n" );

  GraphDescription descr( out, *this, false, false );
  descr.describe();
}

void
GraphDescription::output_tport( AdjacencySpace *set,
                                uint32_t listen_uid ) noexcept
{
  const char * kind = set->tport_type.val;
  uint32_t kind_len = set->tport_type.len;
  if ( this->is_cfg ) {
    this->out.s( "  - tport: " );
    this->off = this->out.count;
    if ( set->tport.len != 0 &&
         ( kind_len != set->tport.len ||
           ::memcmp( set->tport.val, kind, kind_len ) != 0 ) ) {
      this->out.s( set->tport.val );
    }
    else {
      this->out.s( kind ).s("_").u( this->tport_counter );
    }
    this->len = this->out.count - this->off;
    this->out.s( "\n    type: " ).s( kind ).s( "\n" ).s(
                   "    route:\n" );
    if ( this->use_ports ) {
      this->out.s( "      port: " ).i( this->tport_counter + 5000 ).s( "\n" );
      if ( set->tport_type.equals( T_TCP, T_TCP_SZ ) ) {
        this->out.s( "      listen: *\n" )
                 .s( "      connect: " )
                 .s( this->dist.uid_user( listen_uid ) ).s( "\n" );
      }
      else if ( set->tport_type.equals( T_MESH, T_MESH_SZ ) ) {
        this->out.s( "      listen: *\n" )
                 .s( "      connect: [ " );
        kv::BitSpace & graph_mesh = this->dist.graph_mesh;
        uint32_t peer_uid;
        bool sep = false;
        for ( bool ok = graph_mesh.first( peer_uid ); ok;
              ok = graph_mesh.next( peer_uid ) ) {
          if ( sep )
            this->out.s( ", " );
          this->out.s( this->dist.uid_user( peer_uid ) );
          sep = true;
        }
        this->out.s( " ]\n" );
      }
    }
    if ( set->tport_type.equals( T_PGM, T_PGM_SZ ) ) {
      uint32_t x = ( 100 + this->tport_counter ) % 256,
               y = ( 200 + this->tport_counter ) % 256,
               z = ( 1   + this->tport_counter ) % 256;
      this->out.s( "      connect: ;238." )
               .i( x ).s( "." ).i( y ).s( "." ).i( z ).s( "\n" );
    }
    else if ( ! this->use_ports ) {
      this->out.s( "      device: 127.0.0.1\n" );
    }
    this->tport_counter++;
  }
  else {
    if ( set->tport.len != 0 )
      out.s( kind ).s( "_" ).s( set->tport.val );
    else
      out.s( kind );
  }
}

void
GraphDescription::print_cost( AdjacencySpace *set ) noexcept
{
  uint8_t i;
  /* output : cost cost cost cost, when graph == true
   * output    cost: [cost, cost, cost, cost], when graph == false */
  for ( i = 0; i < COST_PATH_COUNT; i++ ) {
    if ( set->cost[ i ] != COST_DEFAULT )
      break;
  }
  if ( i == COST_PATH_COUNT ) { /* no cost */
    if ( ! this->is_cfg )
      this->out.s( "\n" );
    return;
  }
  for ( i = 1; i < COST_PATH_COUNT; i++ ) {
    if ( set->cost[ i ] != set->cost[ 0 ] )
      break;
  }
  const char * prefix = "      cost: [ ";
  bool has_one_cost = false;
  if ( i == COST_PATH_COUNT ) {
    prefix = "      cost: ";
    has_one_cost = true;
  }
  this->out.s( this->is_cfg ? prefix : " : " ).i( set->cost[ 0 ] );
  if ( i == COST_PATH_COUNT )
    goto done;
  for ( i = 2; i < COST_PATH_COUNT; i += 2 ) {
    if ( set->cost[ i ] != set->cost[ 0 ] ||
         set->cost[ i+1 ] != set->cost[ 1 ] )
      break;
  }
  this->out.s( this->is_cfg ? ", " : " " ).i( set->cost[ 1 ] );
  if ( i == COST_PATH_COUNT )
    goto done;
  for ( i = 2; i < COST_PATH_COUNT; i++ ) {
    this->out.s( this->is_cfg ? ", " : " " ).i( set->cost[ i ] );
  }
done:;
  if ( this->is_cfg && ! has_one_cost )
    this->out.s( " ]" );
  this->out.s( "\n" );
  return;
}

void
GraphDescription::output_uid( uint32_t action,  uint32_t uid ) noexcept
{
  if ( this->is_cfg )
    this->args.add( action, uid, this->off, this->len );
  else
    this->out.s( " " ).s( this->dist.uid_user( uid ) );
}

void
GraphDescription::describe( void ) noexcept
{
  UserBridge     * n;
  AdjacencySpace * set;
  uint32_t         count,
                   tport_id,
                   conn_id,
                   peer_conn_id,
                   uid,
                   peer_uid,
                   listen_uid,
                   max_uid;
  bool             ok;

  this->dist.clear_cache_if_dirty();
  this->dist.max_tport_count = this->dist.adjacency_count( 0 );
  max_uid = this->dist.max_uid;

  for ( uid = 1; uid < max_uid; uid++ ) {
    n = this->dist.user_db.bridge_tab.ptr[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;
    count = this->dist.adjacency_count( n->uid );
    if ( count > this->dist.max_tport_count )
      this->dist.max_tport_count = count;
  }

  kv::BitSpace & graph_used = this->dist.graph_used;
  kv::BitSpace & graph_mesh = this->dist.graph_mesh;
  graph_used.zero();
  for ( uid = 0; uid < max_uid; uid++ ) {
    count = this->dist.adjacency_count( uid );
    for ( tport_id = 0; tport_id < count; tport_id++ ) {
      set = this->dist.adjacency_set( uid, tport_id );
      if ( set == NULL )
        continue;

      conn_id = uid * this->dist.max_tport_count + tport_id;
      if ( graph_used.test_set( conn_id ) )
        continue;

      if ( set->tport_type.equals( T_TCP, T_TCP_SZ ) ) {
        if ( this->find_peer_star( uid, set, listen_uid ) ) {
          this->output_tport( set, listen_uid );

          this->output_uid( LISTEN, listen_uid );
          for ( ok = graph_mesh.first( peer_uid ); ok;
                ok = graph_mesh.next( peer_uid ) ) {
            if ( peer_uid != listen_uid )
              this->output_uid( CONNECT, peer_uid );
          }
          this->print_cost( set );
        }
        continue;
      }

      if ( set->tport_type.equals( T_MESH, T_MESH_SZ ) ) {
        if ( this->find_peer_mesh( uid, set ) ) {
          this->output_tport( set, 0 );

          for ( ok = graph_mesh.first( peer_uid ); ok;
                ok = graph_mesh.next( peer_uid ) ) {
            this->output_uid( CONNECT, peer_uid );
          }
          this->print_cost( set );
        }
        continue;
      }

      if ( set->tport_type.equals( T_PGM, T_PGM_SZ ) ) {
        this->output_tport( set, 0 );
        this->output_uid( CONNECT, uid );

        for ( ok = set->first( peer_uid ); ok; ok = set->next( peer_uid ) )
          this->output_uid( CONNECT, peer_uid );
        this->print_cost( set );

        for ( ok = set->first( peer_uid ); ok; ok = set->next( peer_uid ) ) {
          if ( this->find_peer_set( uid, set, peer_uid, peer_conn_id ) )
            graph_used.add( peer_conn_id );
        }
      }
      continue;
    }
  }
}

bool
GraphDescription::find_peer_star( uint32_t uid,  AdjacencySpace *set,
                                  uint32_t &listen_uid ) noexcept
{
  kv::BitSpace & graph_mesh = this->dist.graph_mesh;
  kv::BitSpace & graph_used = this->dist.graph_used;
  uint32_t peer_uid, conn_id, star_uid, max_uid;

  if ( ! set->first( peer_uid ) )
    return false;
  if ( ! this->find_peer_conn( *set, uid, peer_uid, conn_id ) )
    return false;

  max_uid = this->dist.max_uid;
  graph_mesh.zero();
  graph_mesh.add( uid );
  graph_mesh.add( peer_uid );
  graph_used.add( conn_id );

  if ( this->dist.get_start_time( uid ) <
       this->dist.get_start_time( peer_uid ) )
    listen_uid = uid;
  else
    listen_uid = peer_uid;

  for ( star_uid = 0; star_uid < max_uid; star_uid++ ) {
    if ( graph_mesh.is_member( star_uid ) )
      continue;
    if ( this->find_peer_conn( *set, uid, star_uid, conn_id ) )
      listen_uid = uid;
    else if ( this->find_peer_conn( *set, peer_uid, star_uid, conn_id ) )
      listen_uid = peer_uid;
    else
      continue;
    graph_mesh.add( star_uid );
    graph_used.add( conn_id );
    break;
  }
  if ( star_uid < max_uid ) {
    for ( star_uid = 0; star_uid < max_uid; star_uid++ ) {
      if ( graph_mesh.is_member( star_uid ) )
        continue;
      if ( this->find_peer_conn( *set, listen_uid, star_uid, conn_id ) ) {
        graph_mesh.add( star_uid );
        graph_used.add( conn_id );
      }
    }
  }
  return true;
}

bool
GraphDescription::find_peer_mesh( uint32_t uid,  AdjacencySpace *set ) noexcept
{
  kv::ArrayCount<uint32_t, 16> peer_conn;
  kv::BitSpace & graph_used = this->dist.graph_used;
  kv::BitSpace & graph_mesh = this->dist.graph_mesh;
  uint32_t peer_uid, conn_id, mesh_uid, max_uid;
  bool ok;

  if ( ! set->first( peer_uid ) )
    return false;
  if ( ! this->find_peer_conn( *set, uid, peer_uid, conn_id ) )
    return false;

  max_uid = this->dist.max_uid;
  graph_mesh.zero();
  graph_mesh.add( uid );
  graph_mesh.add( peer_uid );
  graph_used.add( conn_id );
  for ( peer_uid = 0; peer_uid < max_uid; peer_uid++ ) {
    if ( graph_mesh.is_member( peer_uid ) )
      continue;
    /* all peers should be connected */
    peer_conn.count = 0;
    for ( ok = graph_mesh.first( mesh_uid ); ok;
          ok = graph_mesh.next( mesh_uid ) ) {
      if ( ! this->find_peer_conn( *set, mesh_uid, peer_uid, conn_id ) )
        goto not_mesh_a_member;
      peer_conn.push( conn_id );
    }
    graph_mesh.add( peer_uid );
    graph_used.add( peer_conn.ptr, peer_conn.count );
  not_mesh_a_member:;
  }
  return true;
}

bool
GraphDescription::find_peer_set( uint32_t uid,  AdjacencySpace *set,
                                 uint32_t peer_uid,
                                 uint32_t &peer_conn_id ) noexcept
{
  kv::BitSpace   & graph_used = this->dist.graph_used;
  AdjacencySpace * peer_set;
  kv::BitSpace     set2;
  uint32_t         peer_count, peer_tport_id, peer_base_id;

  peer_count   = this->dist.adjacency_count( peer_uid );
  peer_base_id = peer_uid * this->dist.max_tport_count;
  for ( peer_tport_id = 0; peer_tport_id < peer_count; peer_tport_id++ ) {
    peer_conn_id = peer_base_id + peer_tport_id;
    if ( ! graph_used.is_member( peer_conn_id ) ) {
      peer_set = this->dist.adjacency_set( peer_uid, peer_tport_id );
      if ( peer_set == NULL )
        continue;
      if ( peer_set->tport_type.equals( set->tport_type ) ) {
        set2.zero();
        set2.or_bits( *set, set2 );
        set2.add( uid );
        set2.remove( peer_uid );
        if ( peer_set->equals( set2 ) )
          return true;
      }
    }
  }
  return false;
}

bool
GraphDescription::find_peer_conn( AdjacencySpace &set,  uint32_t uid,
                                  uint32_t peer_uid,
                                  uint32_t &peer_conn_id ) noexcept
{
  kv::BitSpace   & graph_used = this->dist.graph_used;
  AdjacencySpace * peer_set/*,
                 * weak_equals = NULL*/;
  uint32_t         peer_count,
                   peer_tport_id,
                   peer_base_id/*,
                   weak_peer_conn_id = 0*/;

  peer_count   = this->dist.adjacency_count( peer_uid );
  peer_base_id = peer_uid * this->dist.max_tport_count;
  for ( peer_tport_id = 0; peer_tport_id < peer_count; peer_tport_id++ ) {
    peer_conn_id = peer_base_id + peer_tport_id;
    if ( ! graph_used.is_member( peer_conn_id ) ) {
      peer_set = this->dist.adjacency_set( peer_uid, peer_tport_id );
      if ( peer_set == NULL )
        continue;
      if ( peer_set->tport_type.equals( set.tport_type ) &&
           peer_set->is_member( uid ) ) {
        if ( peer_set->tport.equals( set.tport ) )
          return true;
        /* if ports are named differently, use at last resort since we
         * know the two peers are adjacent
        if ( weak_equals == NULL ) {
          weak_equals = peer_set;
          weak_peer_conn_id = peer_conn_id;
        } */
      }
    }
  }
  /*if ( weak_equals != NULL ) {
    peer_conn_id = weak_peer_conn_id;
    return true;
  }*/
  return false;
}

