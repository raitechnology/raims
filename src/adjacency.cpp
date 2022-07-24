#ifndef NO_MS_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raims/user_db.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;
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
  return buf;
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
  if ( off > 0 )
    buf[ off - 1 ] = '\0';
  return buf;
}

void
AdjDistance::clear_cache( void ) noexcept
{
  uint32_t max      = this->user_db.next_uid,
           rte_cnt  = (uint32_t) this->user_db.transport_tab.count;
  this->cache_seqno = this->update_seqno;
  this->max_tport   = rte_cnt;
  this->max_uid     = max;
  this->reuse();
  if ( ( rte_cnt & 1 ) != 0 )
    rte_cnt++;
  size_t isz  = kv::UIntBitSet::size( max ),
         wsz  = max * this->max_tport,
         size = max * sizeof( UidDist ) +    /* stack */
                max * sizeof( uint32_t ) +   /* visit */
                max * sizeof( uint32_t ) +   /* inc_list */
                max * sizeof( UidSrcPath ) * COST_PATH_COUNT + /* x */
                max * sizeof( UidMissing ) + /* missing */
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
  UidMissing *g = (UidMissing *) (void *) x;
  this->missing       = g; g = &g[ max ];

  if ( (char *) (void *) g != (char *) p + size ) {
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
  if ( uid == 0 )
    return &this->user_db.transport_tab.ptr[ i ]->uid_connected;
  if ( ! this->user_db.uid_authenticated.is_member( uid ) )
    return NULL;
  return this->user_db.bridge_tab.ptr[ uid ]->adjacency.ptr[ i ];
}

uint64_t
AdjDistance::adjacency_start( uint32_t uid ) const noexcept
{
  if ( uid == 0 )
    return this->user_db.start_time;
  return this->user_db.bridge_tab.ptr[ uid ]->start_time;
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
          this->missing[ this->miss_tos ].uid  = uid;
          this->missing[ this->miss_tos++ ].uid2 = uid2;
        }
      }
    }
  }
  if ( this->miss_tos > 0 ) { /* missing links */
    uid  = this->missing[ --this->miss_tos ].uid;
    uid2 = this->missing[ this->miss_tos ].uid2;
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

void
AdjDistance::coverage_init( uint32_t src_uid,  uint8_t path_select ) noexcept
{
  this->path.zero( this->max_uid );
  this->fwd.zero( this->max_uid );
  if ( ++this->adjacency_clock == 0 ) {
    this->zero_clocks();
    ++this->adjacency_clock;
  }
  this->path.add( src_uid );
  this->visit[ src_uid ] = 0;
  this->coverage_select = path_select;
}

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
          if ( this->adjacency_start( set->uid ) <
               this->adjacency_start( set2->uid ) )
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

uint32_t
AdjDistance::coverage_step( void ) noexcept
{
  AdjacencySpace * set;
  uint32_t min_cost = COST_MAXIMUM, count, i, uid;
  bool ok, new_edge = false;
  uint8_t path_select = this->coverage_select;

  this->path.or_bits( this->path, this->max_uid, this->fwd, this->max_uid );
  this->fwd.zero( this->max_uid );
  this->links.zero();

  for ( ok = this->path.first( uid, this->max_uid ); ok;
        ok = this->path.next( uid, this->max_uid ) ) {
    count = this->adjacency_count( uid );
    for ( i = 0; i < count; i++ ) {
      if ( (set = this->adjacency_set( uid, i )) == NULL )
        continue;
      this->adj.zero( this->max_uid );
      this->adj.mask_bits( this->path, this->max_uid, *set );
      if ( this->adj.is_empty( this->max_uid ) )
        continue;
      if ( this->visit[ uid ] + set->cost[ path_select ] < min_cost ) {
        min_cost = this->visit[ uid ] + set->cost[ path_select ];
        new_edge = true;
      }
    }
  }
  if ( ! new_edge )
    return 0;

  for ( ok = this->path.first( uid, this->max_uid ); ok;
        ok = this->path.next( uid, this->max_uid ) ) {
    count = this->adjacency_count( uid );
    for ( i = 0; i < count; i++ ) {
      if ( (set = this->adjacency_set( uid, i )) == NULL )
        continue;
      this->adj.zero( this->max_uid );
      this->adj.mask_bits( this->path, this->max_uid, *set );
      if ( this->adj.is_empty( this->max_uid ) )
        continue;
      if ( this->visit[ uid ] + set->cost[ path_select ] == min_cost )
        this->push_link( set );
    }
  }

  for ( i = 0; i < this->links.count; i++ ) {
    set = this->links.ptr[ i ];
    /* path_select 0 is oldest, 1 is second oldest, 2 ... */
    if ( path_select > 0 && set->next_link != NULL ) {
      for ( uint8_t j = 0; j < path_select; j++ ) {
        if ( (set = set->next_link) == NULL )
          set = this->links.ptr[ i ];
      }
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

void
AdjDistance::calc_forward_cache( ForwardCache &fwd,  uint32_t src_uid,
                                 uint8_t path_select ) noexcept
{
  uint32_t tport_id,
           clk = this->calc_coverage( src_uid, path_select );

  fwd.tport_count           = this->user_db.transport_tab.count,
  fwd.adjacency_cache_seqno = this->cache_seqno;
  fwd.fwd_count             = 0;

  uint32_t sz = fwd.size( fwd.tport_count );
  if ( sz > 1 ) {
    if ( fwd.ptr == &fwd.bits )
      fwd.ptr = NULL;
    fwd.ptr = (uint64_t *) ::realloc( fwd.ptr, sz * sizeof( uint64_t ) );
  }
  fwd.zero( fwd.tport_count );

  for ( tport_id = 0; tport_id < fwd.tport_count; tport_id++ ) {
    TransportRoute * rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( rte->uid_connected.clock == clk ) {
      fwd.add( tport_id );
      fwd.fwd_count++;
    }
  }
}

void
AdjDistance::calc_path( uint8_t path_select ) noexcept
{
  uint64_t   & seqno = this->x[ path_select ].seqno;
  UidSrcPath * path  = this->x[ path_select ].path;
  uint32_t     uid;
  bool         found;

  seqno = this->update_seqno;
  path[ 0 ].zero();
  for ( uid = 1; uid < this->max_uid; uid++ ) {
    this->coverage_init( uid, path_select );
    uint32_t cost = 0;
    found = false;
    while ( (cost = this->coverage_step()) != 0 ) {
      if ( this->fwd.is_member( 0 ) ) {
        AdjacencySpace * set = this->coverage_link( 0 );
        path[ uid ].src_uid = set->uid;
        path[ uid ].cost    = cost;
        found = true;
        break;
      }
    }
    if ( ! found )
      path[ uid ].zero();
  }
  for ( uid = 1; uid < this->max_uid; uid++ ) {
    if ( path[ uid ].cost == 0 )
      continue;
    uint32_t tport_id,
             tport_count = this->user_db.transport_tab.count,
             min_cost    = COST_MAXIMUM,
             uid_src     = path[ uid ].src_uid,
             equal_paths = 0;
    found = false;
    for ( tport_id = 0; tport_id < tport_count; tport_id++ ) {
      TransportRoute * rte = this->user_db.transport_tab.ptr[ tport_id ];
      uint32_t cost = rte->uid_connected.cost[ path_select ];
      if ( rte->uid_connected.is_member( uid_src ) ) {
        /*printf( "vec tport %.*s cost %u\n",
                 (int) rte->uid_connected.tport.len,
                 rte->uid_connected.tport.val, cost );*/
        if ( cost <= min_cost ) {
          if ( cost < min_cost ) {
            equal_paths       = 0;
            min_cost          = cost;
            path[ uid ].tport = tport_id;
            path[ uid ].cost  = cost;
            found = true;
          }
          else if ( ++equal_paths < (uint32_t) path_select ) {
            path[ uid ].tport = tport_id;
          }
        }
      }
    }
    if ( ! found ) {
      path[ uid ].zero();
    }
    /*else {
      printf( "path uid %u cost %u tport %u src_uid %u\n",
              uid, vec_cost[ uid ], vec[ uid ], uid_src );
    }*/
  }
}

uint32_t
AdjDistance::calc_coverage( uint32_t src_uid,  uint8_t path_select ) noexcept
{
  this->coverage_init( src_uid, path_select );
  uint32_t cost = 0;
  while ( (cost = this->coverage_step()) != 0 )
    ;
  return this->adjacency_clock;
}
