#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/adj_graph.h>

using namespace rai;
using namespace kv;
using namespace ms;

AdjUser *
AdjGraph::add_user( StringVal &a,  uint32_t uid ) noexcept
{
  AdjUser * u1 = this->user_tab.find( a, uid );
  if ( u1 == NULL ) {
    u1 = this->make<AdjUser>( &a, uid );
    this->user_tab.add( u1 );
  }
  return u1;
}

void
AdjGraph::add_link( AdjUser *u1,  AdjUser *u2,  StringVal &tp,
                    StringVal &ty,  uint32_t *cost,  uint32_t cnt,
                    uint32_t pr,  uint32_t tid ) noexcept
{
  AdjLink * l = this->make<AdjLink>( u1, u2, &tp, &ty, cost, cnt, pr, tid );
  u1->links.push( l );
}

void
AdjGraph::add_conn( AdjUser *u1,  AdjUser *u2,  StringVal &tp,
                    StringVal &ty,  uint32_t *cost,  uint32_t cnt,
                    uint32_t pr ) noexcept
{
  AdjLink * l1 = this->make<AdjLink>( u1, u2, &tp, &ty, cost, cnt, pr, 0 );
  AdjLink * l2 = this->make<AdjLink>( u2, u1, &tp, &ty, cost, cnt, pr, 0 );
  u1->links.push( l1 );
  u2->links.push( l2 );
}

void
AdjUserTab::reset( void ) noexcept
{
  for ( uint32_t idx = 0; idx < this->count; idx++ ) {
    AdjUser * u = this->ptr[ idx ];
    u->links.clear();
    for ( uint8_t p = 0; p < 4; p++ )
      u->fwd[ p ].reset();
  }
  if ( this->ht != NULL ) {
    delete this->ht;
    this->ht = NULL;
  }
  this->clear();
}

void
AdjFwdTab::reset( void ) noexcept
{
  for ( uint32_t i = 0; i < this->links.count; i++ ) {
    this->links.ptr[ i ]->reset();
  }
  this->links.clear();
  this->cost.clear();
  this->src.clear();
}

void
AdjLink::reset( void ) noexcept
{
  for ( uint8_t p = 0; p < 4; p++ )
    this->dest[ p ].reset();
}

AdjUser *
AdjUserTab::find( StringVal &user,  uint32_t uid ) noexcept
{
  size_t pos;
  uint32_t i;
  AdjUser * u = ( this->ht != NULL &&
                  this->ht->find( user.id, pos, i ) ? this->ptr[ i ] : NULL );
  if ( u != NULL ) {
    if ( u->uid == uid )
      return u;
    /* dup user names with different uids */
    for ( i = 0; i < this->count; i++ ) {
      if ( user.equals( this->ptr[ i ]->user ) && this->ptr[ i ]->uid == uid )
        return this->ptr[ i ];
    }
  }
  return NULL;
}

void
AdjUserTab::add( AdjUser *u ) noexcept
{
  uint32_t i = this->count;
  this->push( u );
  u->idx = i;
  if ( this->ht == NULL )
    this->ht = UIntHashTab::resize( NULL );
  this->ht->upsert_rsz( this->ht, u->user.id, i );
}

void
AdjGraph::compute_forward_set( uint8_t p ) noexcept
{
  for ( uint32_t idx = 0; idx < this->user_tab.count; idx++ ) {
    AdjUser * u = this->user_tab.ptr[ idx ];
    AdjVisit  visit;
    uint32_t  cost = 0;

    visit.user.add( idx );
    visit.cost[ idx ] = 0;
    while ( visit.user.count() != this->user_tab.count ) {
      cost = this->get_min_cost( p, visit );
      if ( cost == 0 )
        break;
      this->add_fwd_set( p, idx, visit, cost );
    }

    for ( uint32_t j = 0; j < u->links.count; j++ ) {
      AdjLink   * link = u->links.ptr[ j ];
      AdjFwdTab & fwd  = u->fwd[ p ];
      for ( uint32_t k = 0; k < fwd.links.count; k++ ) {
        if ( j == fwd.src.ptr[ k ] )
          link->dest[ p ].add( fwd.links.ptr[ k ]->b.idx );
      }
    }
  }
}

uint32_t
AdjGraph::get_min_cost( uint8_t p,  AdjVisit &visit ) noexcept
{
  uint32_t idx, min_cost = 0;
  for ( bool b = visit.user.first( idx ); b; b = visit.user.next( idx ) ) {
    AdjUser * u = this->user_tab.ptr[ idx ];
    uint32_t user_cost = visit.cost[ idx ];
    for ( uint32_t i = 0; i < u->links.count; i++ ) {
      AdjLink * link = u->links.ptr[ i ];
      if ( ( link->prune & ( 1 << p ) ) != 0 ) {
        if ( ! visit.user.is_member( link->b.idx ) ) {
          uint32_t cost = link->cost[ p ] + user_cost;
          if ( cost < min_cost || min_cost == 0 )
            min_cost = cost;
        }
      }
    }
  }
  return min_cost;
}

void
AdjGraph::add_fwd_set( uint8_t p,  uint32_t src_idx,  AdjVisit &visit,
                       uint32_t min_cost ) noexcept
{
  AdjFwdTab & fwd = this->user_tab.ptr[ src_idx ]->fwd[ p ];
  BitSpace tmp;
  uint32_t idx;
  tmp.add( visit.user );
  for ( bool b = tmp.first( idx ); b; b = tmp.next( idx ) ) {
    AdjUser * u = this->user_tab.ptr[ idx ];
    uint32_t user_cost = visit.cost[ idx ];
    for ( uint32_t i = 0; i < u->links.count; i++ ) {
      AdjLink * link = u->links.ptr[ i ];
      if ( ( link->prune & ( 1 << p ) ) != 0 ) {
        if ( ! visit.user.is_member( link->b.idx ) ) {
          uint32_t cost     = link->cost[ p ] + user_cost,
                   src_link = ( user_cost == 0 ? i : visit.src[ idx ] );
          if ( min_cost == cost ) {
            uint32_t dest_idx = link->b.idx;
            visit.user.add( dest_idx );
            visit.cost[ dest_idx ] = cost;
            visit.src[ dest_idx ]  = src_link;
            fwd.links.push( link );
            fwd.cost.push( cost );
            fwd.src.push( src_link );
          }
        }
      }
    }
  }
}

void
AdjGraph::init_inconsistent( uint32_t src_idx,  AdjInconsistent &inc ) noexcept
{
  inc.src.clear();
  inc.missing.clear();
  inc.missing_links.clear();
  inc.visit.reset();
  inc.found.reset();

  inc.start_idx = src_idx;
  inc.visit.add( src_idx );
  inc.src.push( src_idx );
}

void
AdjGraph::find_inconsistent( AdjInconsistent &inc ) noexcept
{
  uint32_t src_idx;

  while ( inc.src.count > 0 ) {
    src_idx = inc.src.ptr[ --inc.src.count ];
    AdjUser * u1 = this->user_tab.ptr[ src_idx ];

    for ( uint32_t i = 0; i < u1->links.count; i++ ) {
      AdjLink * link = u1->links.ptr[ i ];
      if ( ! inc.visit.test_set( link->b.idx ) )
        inc.src.push( link->b.idx );

      AdjUser * u2 = this->user_tab.ptr[ link->b.idx ];
      bool found = false;
      for ( uint32_t j = 0; j < u2->links.count; j++ ) {
        AdjLink * link2 = u2->links.ptr[ j ];
        if ( &link->a == &link2->b && &link->b == &link2->a &&
             link->type.equals( link2->type ) &&
             link->cost_equals( link2->cost ) ) {
          found = true;
          break;
        }
      }
      if ( ! found ) {
        if ( ! inc.found.test_set( link->a.idx ) )
          inc.missing.push( link->a.idx );
        if ( ! inc.found.test_set( link->b.idx ) )
          inc.missing.push( link->b.idx );
        inc.missing_links.push( link );
      }
    }
  }
}

