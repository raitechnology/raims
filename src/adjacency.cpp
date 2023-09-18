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
AdjDistance::clear_cache( void ) noexcept
{
  if ( this->graph != NULL ) {
    this->graph->reset();
    this->graph = NULL;
  }
  uint32_t uid_cnt   = this->user_db.next_uid,
           rte_cnt   = (uint32_t) this->user_db.transport_tab.count;
  this->cache_seqno  = this->update_seqno;
  this->prune_seqno  = 0;
  this->max_tport    = rte_cnt;
  this->max_uid      = uid_cnt;
  this->reuse();

  size_t isz  = kv::UIntBitSet::size( uid_cnt ),
         wsz  = uid_cnt * this->max_tport,
         size = uid_cnt * sizeof( UidDist ) +    /* stack */
                uid_cnt * sizeof( uint32_t ) +   /* visit */
                uid_cnt * sizeof( uint32_t ) +   /* inc_list */
                uid_cnt * sizeof( uint32_t ) +   /* graph_idx_order */
                uid_cnt * sizeof( UidSrcPath ) * COST_PATH_COUNT + /* x */
                isz     * sizeof( uint64_t ) +   /* inc_visit */
                wsz     * sizeof( uint32_t ) * COST_PATH_COUNT;/* cache */

  void     *p = this->make( size );
  uint64_t *m = (uint64_t *) p;
  ::memset( p, 0, size );
  this->inc_visit.ptr = m; m += isz;
  this->stack         = (UidDist *) m; m = &m[ uid_cnt ];

  uint32_t *n = (uint32_t *) (void *) m;
  this->cache           = n; n += wsz * COST_PATH_COUNT;
  this->visit           = n; n += uid_cnt;
  this->inc_list        = n; n += uid_cnt;
  this->graph_idx_order = n; n += uid_cnt;

  UidSrcPath *x = (UidSrcPath *) (void *) n;
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ ) {
    this->x[ i ].path = x; x = &x[ uid_cnt ];
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

bool
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
    this->inc_running = true;
    this->found_inconsistency = false;

    size_t count = this->user_db.transport_tab.count;
    for ( size_t i = 0; i < count; i++ ) {
      AdjacencySpace &set = this->user_db.transport_tab.ptr[ i ]->uid_connected;
      for ( bool ok = set.first( uid ); ok; ok = set.next( uid ) ) {
        if ( ! this->inc_visit.test_set( uid ) )
          this->push_inc_list( uid );
      }
    }
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
        if ( target_uid == 0 )
          continue;
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
    return true;
  }
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
  from = NULL;
  to   = NULL;
  this->inc_running = false;
  this->inc_run_count++;
  this->last_run_mono = kv::current_monotonic_time_ns();
  return false;
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
           ::memcmp( set.cost, set2->cost, sizeof( set.cost ) ) == 0 )
        return true;
    }
  }
  else {
    for ( uint32_t tport_id = 0; tport_id < count2; tport_id++ ) {
      set2 = this->adjacency_set( target_uid, tport_id );
      if ( set2 != NULL && set2->is_member( source_uid ) &&
           ::memcmp( set.cost, set2->cost, sizeof( set.cost ) ) == 0 )
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

uint64_t
AdjDistance::get_start_time( uint32_t uid ) const noexcept
{
  if ( uid == 0 )
    return this->user_db.start_time;
  return this->user_db.bridge_tab.ptr[ uid ]->start_time;
}

bool
AdjDistance::is_older( uint32_t uid,  uint32_t uid2 ) const noexcept
{
  return this->get_start_time( uid ) < this->get_start_time( uid2 );
}

void
AdjDistance::prune_adjacency_sets( void ) noexcept
{
  kv::ArrayCount<AdjacencySpace *, 32> uid_ref;
  this->prune_seqno = this->cache_seqno;
  d_adj( "update prune seqno %" PRIu64 "\n", this->prune_seqno );

  for ( uint32_t uid = 0; uid < this->max_uid; uid++ ) {
    uint32_t count = this->adjacency_count( uid ),
             rem_uid;
    AdjacencySpace * set;
    for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
      if ( (set = this->adjacency_set( uid, tport_id )) == NULL )
        continue;
      set->prune_path = 0;
    }
    d_adj( "%s.%u adj_count %u\n", this->uid_user( uid ), uid, count );
    for ( uint8_t path_select = 0; path_select < COST_PATH_COUNT;
          path_select++ ) {
      uid_ref.zero();
      for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
        if ( (set = this->adjacency_set( uid, tport_id )) == NULL )
          continue;
        rem_uid = set->rem_uid;
        if ( rem_uid != 0 ) {
          if ( ! this->user_db.uid_authenticated.is_member( rem_uid ) ) {
            /* could be a zombie */
            continue;
          }
        }
        if ( ! set->is_member( rem_uid ) ) {
          /* uid needs to update this set, rem_uid is not connected */
          continue;
        }
        set->next_link = NULL;
        AdjacencySpace * set2 = uid_ref[ rem_uid ];
        /* better cost */
        if ( set2 == NULL ||
             set->cost[ path_select ] < set2->cost[ path_select ] ) {
          uid_ref.ptr[ set->rem_uid ] = set;
          continue;
        }
        if ( set->cost[ path_select ] > set2->cost[ path_select ] )
          continue;

        int cmp;
        bool is_old = this->is_older( set->uid, set2->rem_uid );
        if ( is_old )
          cmp = ( set->tport_id < set2->tport_id ? -1 : 1 );
        else
          cmp = ( set->rem_tport_id < set2->rem_tport_id ? -1 : 1 );
        /* order sets by tport_id, lowest id of the oldest peer wins  */
        if ( cmp < 0 ) {
          set->next_link = uid_ref.ptr[ rem_uid ];
          uid_ref.ptr[ set->rem_uid ] = set;
          continue;
        }
        /* insert into list */
        for (;;) {
          AdjacencySpace * next = set2->next_link;
          if ( next == NULL ) {
            set2->next_link = set;
            break;
          }
          if ( is_old )
            cmp = ( set->tport_id < next->tport_id ? -1 : 1 );
          else
            cmp = ( set->rem_tport_id < next->rem_tport_id ? -1 : 1 );
          if ( cmp < 0 ) {
            set->next_link = next;
            set2->next_link = set;
            break;
          }
          set2 = next;
        }
      }
      /* mark links that should be used with the path_select */
      for ( rem_uid = 0; rem_uid < uid_ref.count; rem_uid++ ) {
        set = uid_ref.ptr[ rem_uid ];
        if ( set == NULL )
          continue;
        if ( path_select == 0 || set->next_link == NULL )
          set->prune_path |= 1 << path_select;
        else {
          AdjacencySpace * path_set[ COST_PATH_COUNT ];
          uint8_t n = 0, i;
          for ( i = 0; i < COST_PATH_COUNT; i++ ) {
            path_set[ n++ ] = set;
            if ( (set = set->next_link) == NULL )
              break;
          }
          path_set[ path_select % n ]->prune_path |= 1 << path_select;
        }
      }
    }
    if ( debug_adj ) {
      for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
        if ( (set = this->adjacency_set( uid, tport_id )) == NULL )
          continue;
        printf( "%s.%u %s.%u prune_path %u\n",
                this->uid_user( uid ), uid,
                set->tport.val, tport_id, set->prune_path );
      }
    }
  }
}

void
AdjDistance::update_graph( void ) noexcept
{
  UserBridgeList   list;
  UserBridgeElem * el;

  if ( this->prune_seqno != this->cache_seqno )
    this->prune_adjacency_sets();
  this->graph = new ( this->make( sizeof( AdjGraph ) ) ) AdjGraph( *this );

  list.add_users( this->user_db, *this );
  list.sort<UserBridgeList::cmp_start>();

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
      if ( set == NULL || set->prune_path == 0 )
        continue;

      uint32_t b;
      for ( bool ok = set->first( b ); ok; ok = set->next( b ) ) {
        AdjUser *u2 = g.user_tab.ptr[ idx[ b ] ];
        g.add_link( u1, u2, set->tport, set->tport_type, set->cost,
                    COST_PATH_COUNT, set->prune_path, t );
      }
    }
  }
  for ( uint8_t p = 0; p < COST_PATH_COUNT; p++ )
    g.compute_forward_set( p );
}

void
AdjDistance::calc_path( ForwardCache &fc,  uint8_t p ) noexcept
{
  if ( this->graph == NULL )
    this->update_graph();

  UidSrcPath * path  = this->x[ p ].path;
  this->x[ p ].seqno = this->update_seqno;

  for ( uint32_t uid = 0; uid < this->max_uid; uid++ )
    path[ uid ].zero();
  fc.init( this->adjacency_count( 0 ), this->cache_seqno );

  uint32_t * idx = this->graph_idx_order;
  AdjUser  * me  = this->graph->user_tab.ptr[ idx[ 0 ] ];
  AdjLink  * link;
  uint32_t   src, cost, uid;

  for ( src = 0; src < me->links.count; src++ ) {
    link = me->links.ptr[ src ];
    if ( link->dest[ p ].count() != 0 ) {
      fc.add( link->tid );
      fc.fwd_count++;
    }
  }
  AdjFwdTab & fwd = me->fwd[ p ];
  for ( uint32_t j = 0; j < fwd.links.count; j++ ) {
    src  = fwd.src.ptr[ j ];
    link = fwd.links.ptr[ j ];
    cost = fwd.cost.ptr[ j ];
    uid  = link->b.uid;
    path[ uid ].tport   = me->links.ptr[ src ]->tid;
    path[ uid ].src_uid = link->a.uid;
    path[ uid ].cost    = cost;
  }
}

void
AdjDistance::calc_forward_cache( ForwardCache &fc,  uint32_t src_uid,
                                 uint8_t p ) noexcept
{
  if ( this->graph == NULL )
    this->update_graph();

  fc.init( this->adjacency_count( 0 ), this->cache_seqno );

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
    this->update_graph();

  AdjGraphOut put( *this->graph, out );
  put.print_web_paths( 0 );
  out.s( "\n" );
}

