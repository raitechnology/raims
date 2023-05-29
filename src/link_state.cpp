#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <raims/user_db.h>
#include <raims/ev_inbox_transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

void
AdjacencyRec::set_field( uint32_t fid,  MDReference &mref ) noexcept
{
  switch ( fid ) {
    case FID_TPORTID:
      cvt_number<uint32_t>( mref, this->tportid );
      break;
    case FID_COST:
      cvt_number<uint32_t>( mref, this->cost[ 0 ] );
      break;
    case FID_COST2:
      cvt_number<uint32_t>( mref, this->cost[ 1 ] );
      break;
    case FID_COST3:
      cvt_number<uint32_t>( mref, this->cost[ 2 ] );
      break;
    case FID_COST4:
      cvt_number<uint32_t>( mref, this->cost[ 3 ] );
      break;
    case FID_TPORT:
      this->tport_name.val = (const char *) mref.fptr;
      this->tport_name.len = (uint32_t) mref.fsize;
      break;
    case FID_TPORT_TYPE:
      this->tport_type.val = (const char *) mref.fptr;
      this->tport_type.len = (uint32_t) mref.fsize;
      break;
    case FID_USER:
      this->user.val = (const char *) mref.fptr;
      this->user.len = (uint32_t) mref.fsize;
      break;;
    case FID_BRIDGE:
      this->nonce.copy_from( mref.fptr );
      break;
    case FID_LINK_ADD:
      cvt_number<bool>( mref, this->add );
      break;
    case FID_REM_BRIDGE:
      this->rem_bridge.copy_from( mref.fptr );
      break;
    case FID_REM_TPORTID:
      cvt_number<uint32_t>( mref, this->rem_tportid );
      break;
    default:
      break;
  }
}

void
AdjacencyRec::print( void ) const noexcept
{
  char buf[ NONCE_B64_LEN + 1 ], buf2[ NONCE_B64_LEN + 1 ];
  if ( this->test( FID_REM_BRIDGE ) )
    this->rem_bridge.to_base64_str( buf2 );
  else
    buf2[ 0 ] = '\0';
  printf( "  %cnonce[%s] %ctport_name[%.*s.%.*s], %cuser[%.*s], "
          "%ctport[%u] %ccost[%u,%u,%u,%u], "
          "%crem_bridge[%s], %crem_tportid[%u]\n",
    this->tchar( FID_BRIDGE ),     this->nonce.to_base64_str( buf ),
    this->tchar( FID_TPORT ),      this->tport_name.len, this->tport_name.val,
                                   this->tport_type.len, this->tport_type.val,
    this->tchar( FID_USER ),       this->user.len, this->user.val,
    this->tchar( FID_TPORTID ),    this->tportid,
    this->tchar( FID_COST ),       this->cost[ 0 ], this->cost[ 1 ],
                                   this->cost[ 2 ], this->cost[ 3 ],
    this->tchar( FID_REM_BRIDGE ), buf2,
    this->tchar( FID_REM_TPORTID ), this->rem_tportid );
}

void
AdjacencyRec::print_rec_list( const AdjacencyRec *rec_list,
                              const char *where ) noexcept
{
  printf( "%s rec_list:\n", where );
  for ( const AdjacencyRec *r = rec_list; r != NULL; r = r->next ) {
    r->print();
  }
}

void
UserDB::save_unauthorized_adjacency( MsgFramePublish & ) noexcept
{
}

void
UserDB::print_adjacency( const char *s,  UserBridge &n ) noexcept
{
  printf( "%s adjacency.%u %s: ", s, n.uid, n.peer.user.val );
  for ( uint32_t i = 0; i < n.adjacency.count; i++ ) {
    AdjacencySpace *set = n.adjacency[ i ];
    uint32_t b;
    if ( set != NULL ) {
      if ( set->first( b ) ) {
        do {
          if ( b == 0 ) {
            printf( "%u:%s.%u ", b, this->user.user.val, i );
          }
          else {
            UserBridge *n2 = this->bridge_tab[ b ];
            printf( "%u:%s.%u ", b, n2->peer.user.val, i );
          }
        } while ( set->next( b ) );
      }
    }
  }
  printf( "\n" );
}

void
UserDB::save_unknown_adjacency( UserBridge &n,  TransportRoute &rte,
                                uint64_t seqno,  AdjacencyRec *recs,
                                bool is_change ) noexcept
{
  AdjPending * p, * sav = NULL;
  uint32_t rec_count = 0;

  for ( AdjacencyRec * r = recs; r != NULL; r = r->next )
    rec_count++;
  n.unknown_link_seqno = seqno;
  /* append rec list to existing */
  if ( is_change ) {
    for ( sav = this->adjacency_unknown.hd; sav != NULL; sav = sav->next ){
      if ( sav->uid == n.uid ) {
        this->adjacency_unknown.pop( sav );
        for ( AdjacencyRec *r = sav->rec_list; r != NULL; r = r->next ) {
          if ( r->next == NULL ) {
            r->next = recs;
            recs = sav->rec_list;
            rec_count += sav->rec_count;
            break;
          }
        }
        break;
      }
    }
  }
  if ( sav == NULL || sav->rec_count < rec_count ) {
    void * m = ::malloc( sizeof( AdjPending ) +
                         rec_count * sizeof( AdjacencyRec ) );
    p = new ( m ) AdjPending( rte );

    p->link_state_seqno = seqno;
    p->uid              = n.uid;
    p->reason           = ADJ_RESULT_SYNC;
    p->pending_seqno    = ++this->adjacency_unknown.pending_seqno;
    p->rec_list         = (AdjacencyRec *) (void *) &p[ 1 ];
    p->rec_count        = rec_count;
    AdjacencyRec * cpy = p->rec_list;
    for ( uint32_t i = 0; i < rec_count; i++ ) {
      cpy[ i ].copy( *recs );
      cpy[ i ].next = &cpy[ i + 1 ];
      recs = recs->next;
    }
    cpy[ rec_count - 1 ].next = NULL;
  }
  else {
    p   = sav;
    sav = NULL;
    p->link_state_seqno = seqno;
  }
  this->adjacency_unknown.push_tl( p );

  if ( debug_lnk ) {
    n.printf( "save adj p=%" PRIu64 " n=%" PRIu64 ", %s rec_count %u\n", seqno,
              n.link_state_seqno, rte.name, p->rec_count );
    AdjacencyRec::print_rec_list( p->rec_list, "save_unknown" );
  }
  if ( sav != NULL ) {
    this->remove_pending_peer( NULL, sav->pending_seqno );
    delete sav;
  }
}

void
UserDB::add_unknown_adjacency( UserBridge *n,  Nonce *b_nonce ) noexcept
{
  AdjPending   * p_next;
  AdjacencyRec * rec;
  UserBridge   * m;
  uint32_t       applied_cnt = 0;
  bool           changed = false;

  if ( n != NULL )
    b_nonce = &n->bridge_id.nonce;
  /* if n == null, then b_nonce has no user bridge, discard pending */
  for ( AdjPending *p = this->adjacency_unknown.hd; p != NULL; p = p_next ) {
    SLinkList< AdjacencyRec > fini_recs, pend_recs;
    bool discard_pending = false;
    p_next = p->next;

    m = this->bridge_tab.ptr[ p->uid ];
    if ( m == NULL || ! m->is_set( AUTHENTICATED_STATE ) ||
         m->link_state_seqno >= p->link_state_seqno ||
         m->unknown_link_seqno != p->link_state_seqno  ) {
      discard_pending = true;
    }
    else {
      while ( p->rec_list != NULL ) {
        rec = p->rec_list;
        if ( rec->nonce == *b_nonce ||
             ( rec->test( FID_REM_BRIDGE ) && rec->rem_bridge == *b_nonce ) ) {
          if ( n == NULL ) {
            discard_pending = true;
            break;
          }
          if ( (changed |= this->add_adjacency_change( *m, *rec )) ) {
            p->rec_list = rec->next;
            fini_recs.push_tl( rec );
            applied_cnt++;
            if ( --p->rec_count == 0 )
              break;
            rec = NULL;
          }
        }
        if ( rec != NULL ) {
          p->rec_list = rec->next;
          pend_recs.push_tl( rec );
        }
      }
    }
    if ( debug_lnk ) {
      const char *user = ( n == NULL ? "none" : n->peer.user.val );
      if ( p->rec_list != NULL ) {
        m->printf( "left_recs %u (%s)\n", p->rec_count, user );
        AdjacencyRec::print_rec_list( p->rec_list, "left" );
      }
      if ( fini_recs.hd != NULL ) {
        m->printf( "apply_recs %u (%s) %" PRIu64 " < %" PRIu64 "\n", applied_cnt,
                   user, m->link_state_seqno, p->link_state_seqno  );
        AdjacencyRec::print_rec_list( fini_recs.hd, "applied" );
      }
      if ( pend_recs.hd != NULL ) {
        m->printf( "pend_recs %u (%s)\n", p->rec_count, user );
        AdjacencyRec::print_rec_list( pend_recs.hd, "pending" );
      }
    }
    p->rec_list = pend_recs.hd;

    if ( discard_pending || p->rec_count == 0 ) {
      if ( ! discard_pending && n != NULL ) {
        if ( debug_lnk )
          m->printf( "add unknown adj: sync to %" PRIu64 "\n", p->link_state_seqno );
        this->update_link_state_seqno( m->link_state_seqno,
                                       p->link_state_seqno );
      }
      if ( n == NULL ) {
        m->printf( "remove unknown adj refs %u m->ls=%" PRIu64 ","
                   "p->ls=%" PRIu64 ",m->unk_ls=%" PRIu64 "\n", m->unknown_adj_refs,
                   m->link_state_seqno, p->link_state_seqno,
                   m->unknown_link_seqno );
      }
      m->unknown_link_seqno = 0;
      m->unknown_adj_refs   = 0;
      this->adjacency_unknown.pop( p );
      this->remove_pending_peer( NULL, p->pending_seqno );
      delete p;
    }
  }
  if ( this->adjacency_unknown.is_empty() )
    d_lnk( "no more unknown adj\n" );
  if ( changed )
    this->peer_dist.invalidate( ADJACENCY_CHANGE_INV, n != NULL ? n->uid : 0 );
}

void
UserDB::clear_unknown_adjacency( UserBridge &n ) noexcept
{
  AdjPending * next;

  if ( debug_lnk )
    n.printf( "clear_unknown\n" );
  for ( AdjPending *p = this->adjacency_unknown.hd; p != NULL; p = next ) {
    next = p->next;
    if ( n.uid == p->uid ) {
      this->adjacency_unknown.pop( p );
      this->remove_pending_peer( NULL, p->pending_seqno );
      delete p;
    }
  }
  n.unknown_link_seqno = 0;
  n.unknown_adj_refs   = 0;
}

void
UserDB::remove_adjacency( UserBridge &n ) noexcept
{
  this->clear_unknown_adjacency( n );
}

bool
UserDB::is_peer_sock_valid( const PeerId &pid ) noexcept
{
  if ( (uint32_t) pid.fd > this->poll.maxfd )
    return false;
  if ( this->poll.sock[ pid.fd ] == NULL )
    return false;
  return pid.equals( *this->poll.sock[ pid.fd ] );
}

void
UserDB::push_source_route( UserBridge &n ) noexcept
{
  UserRoute * u_ptr;
  uint32_t    count = (uint32_t) this->transport_tab.count;
  for ( uint32_t i = 0; i < count; i++ ) {
    if ( (u_ptr = n.user_route_ptr( *this, i )) == NULL )
      break;
    if ( u_ptr->is_valid() ) {
      if ( this->is_peer_sock_valid( u_ptr->mcast ) )
        this->push_user_route( n, *u_ptr );
      else
        this->pop_user_route( n, *u_ptr );
    }
  }
}

void
UserDB::push_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept
{
  if ( ! u_rte.is_valid() || ! this->is_peer_sock_valid( u_rte.mcast ) ) {
    n.printe( "user route not valid\n" );
    return;
  }
  uint32_t fd = (uint32_t) u_rte.mcast.fd;
  /* if the bcast route is valid */
  if ( ! u_rte.is_set( IN_ROUTE_LIST_STATE ) ) {
    UserRouteList  & list = this->route_list[ fd ];

    if ( debug_lnk )
      n.printf( "push_user_route %s fd %u\n", u_rte.rte.name, fd );

    u_rte.set( IN_ROUTE_LIST_STATE );
    u_rte.list_id = fd;
    list.push_tl( &u_rte );

    if ( u_rte.hops() == 0 )
      this->push_connected_user_route( n, u_rte );
    else if ( debug_lnk )
      n.printf( "hops not zero, not directly connected\n" );
  }
}

void
UserDB::pop_source_route( UserBridge &n ) noexcept
{
  if ( debug_lnk )
    n.printf( "pop_source_route\n" );
  uint32_t count = (uint32_t) this->transport_tab.count;
  for ( uint32_t i = 0; i < count; i++ ) {
    UserRoute * u_ptr = n.user_route_ptr( *this, i );
    if ( u_ptr != NULL && u_ptr->is_valid() )
      this->pop_user_route( n, *u_ptr );
  }
}
#if 0
bool
UserDB::check_bloom_route( TransportRoute &rte,  uint32_t fd ) noexcept
{
  bool found = false, check_ok = true;
  BloomRoute * b;
  for ( b = rte.sub_route.bloom_list.hd( 0 ); b != NULL; b = b->next ) {
    for ( uint32_t n = 0; n < b->nblooms; n++ ) {
      if ( b->bloom[ n ] == &this->peer_bloom ) {
        if ( b->r == fd )
          found = true;
        else {
          rte.printf( "peer_bloom already has a route %u\n", b->r );
          check_ok = false;
        }
      }
    }
  }
  if ( ! found && fd != 0 ) {
    rte.sub_route.create_bloom_route( fd, &this->peer_bloom, 0 );
    rte.printf( "add peer bloom fd %u\n", fd );
  }
  check_ok &= this->check_bloom_route2();
  return check_ok;
}

bool
UserDB::check_bloom_route2( void ) noexcept
{
  uint32_t count = this->transport_tab.count;
  bool check_ok = true;
  for ( uint32_t i = 1; i < count; i++ ) {
    TransportRoute *r = this->transport_tab[ i ];
    BloomRoute * match_b = NULL, * b;
    uint32_t     match_n = 0;
    for ( b = r->sub_route.bloom_list.hd( 0 ); b != NULL; b = b->next ) {
      if ( b->r > this->poll.maxfd || this->poll.sock[ b->r ] == NULL ) {
        r->printf( "invalid peer_bloom fd=%u\n", b->r );
        check_ok = false;
      }
      else {
        uint32_t rid = this->poll.sock[ b->r ]->route_id;
        if ( rid != (uint32_t) -1 && r->tport_id != rid ) {
          r->printf( "invalid peer_bloom route_id rid=%u != fd=%u\n",
                     this->poll.sock[ b->r ]->route_id, b->r );
          check_ok = false;
        }
      }
      for ( uint32_t n = 0; n < b->nblooms; n++ ) {
        if ( b->bloom[ n ] == &this->peer_bloom ) {
          if ( match_b != NULL ) {
            r->printf( "duplicate peer_bloom fd=%u [ %u ] next=%u [ %u ]\n",
                       b->r, n, match_b->r, match_n );
            check_ok = false;
          }
          match_b = b;
          match_n = n;
        }
      }
    }
  }
  return check_ok;
}
#endif
void
UserDB::push_connected_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept
{
  TransportRoute & rte = u_rte.rte;
  uint32_t fd = u_rte.list_id;
  UserRouteList  & list = this->route_list[ fd ];

  if ( rte.mesh_id != NULL ) {
    if ( rte.uid_in_mesh->ref( n.uid ) == 0 ) {
      *rte.mesh_csum ^= n.bridge_id.nonce;
      if ( debug_lnk )
        n.printf( "add to mesh %s fd %u\n", rte.name, fd );
    }
    else if ( debug_lnk ) {
      n.printf( "already in mesh %s fd %u\n", rte.name, fd );
    }
  }
  else if ( rte.dev_id != NULL ) {
    if ( rte.uid_in_device->ref( n.uid ) == 0 ) {
      if ( debug_lnk )
        n.printf( "add to dev %s fd %u\n", rte.name, fd );
    }
  }
  if ( ! rte.uid_connected.test_set( n.uid ) ) {
    this->peer_dist.invalidate( PUSH_ROUTE_INV, n.uid );
    this->adjacency_change.append( n.uid, rte.tport_id,
                                   this->link_state_seqno + 1, true );
  }
  /*this->check_bloom_route( rte, 0 );*/
  if ( list.sys_route_refs++ == 0 ) {
    if ( debug_lnk )
      printf( "push sys_route %u\n", fd );
    rte.connected_auth.add( fd );
    /*this->check_bloom_route( rte, fd );*/
    if ( ! this->peer_bloom.has_link( fd ) )
      rte.sub_route.create_bloom_route( fd, &this->peer_bloom, 0 );
  }
  if ( this->start_time > n.start_time ) {
    if ( n.start_time == 0 )
      n.printe( "bad start time %" PRIu64 "\n", n.start_time );
    else {
      if ( rte.oldest_uid == 0 )
        rte.oldest_uid = n.uid;
      else {
        UserBridge * n2 = this->bridge_tab[ rte.oldest_uid ];
        if ( n2->start_time > n.start_time )
          rte.oldest_uid = n.uid;
      }
    }
  }
}

void
UserDB::set_connected_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept
{
  if ( ! u_rte.is_valid() || ! this->is_peer_sock_valid( u_rte.mcast ) ) {
    n.printe( "user route not valid\n" );
    return;
  }
  if ( u_rte.is_set( IN_ROUTE_LIST_STATE ) ) {
    if ( u_rte.hops() == 0 )
      return;
    if ( u_rte.list_id != (uint32_t) u_rte.mcast.fd ) {
      uint32_t fd = (uint32_t) u_rte.mcast.fd;
      if ( fd > this->poll.maxfd ) {
        n.printe( "fd is invalid, tport %u\n", u_rte.rte.tport_id );
        return;
      }
      this->route_list[ u_rte.list_id ].pop( &u_rte );
      this->route_list[ fd ].push_tl( &u_rte );
      u_rte.list_id = fd;
    }
    u_rte.connected( 0 );
    this->push_connected_user_route( n, u_rte );
    return;
  }
  this->push_user_route( n, u_rte );
}

void
UserDB::pop_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept
{
  if ( u_rte.test_clear( IN_ROUTE_LIST_STATE ) ) {
    uint32_t         fd   = u_rte.list_id;
    UserRouteList  & list = this->route_list[ fd ];
    TransportRoute & rte  = u_rte.rte;

    if ( debug_lnk )
      n.printf( "pop_user_route %s fd %u\n", u_rte.rte.name, fd );
    list.pop( &u_rte );
    if ( u_rte.hops() == 0 ) {
      if ( rte.mesh_id != NULL ) {
        if ( rte.uid_in_mesh->deref( n.uid ) == 0 ) {
          *rte.mesh_csum ^= n.bridge_id.nonce;
          if ( debug_lnk )
            n.printf( "rm from mesh %s\n", rte.name );
        }
      }
      else if ( rte.dev_id != NULL ) {
        if ( rte.uid_in_device->deref( n.uid ) == 0 ) {
          if ( debug_lnk )
            n.printf( "rm from dev %s\n", rte.name );
        }
      }
      if ( rte.is_mcast() && rte.ibx_tport != NULL ) {
        if ( u_rte.is_set( UCAST_URL_STATE ) ) {
          if ( u_rte.is_set( UCAST_URL_SRC_STATE ) == 0 )
            rte.ibx_tport->shutdown_peer( n.uid, u_rte.url_hash );
        }
      }
      if ( rte.uid_connected.test_clear( n.uid ) ) {
        if ( rte.uid_connected.rem_uid == n.uid ) {
          rte.uid_connected.rem_uid = 0;
          rte.uid_connected.rem_tport_id = 0;
        }
        this->peer_dist.invalidate( POP_ROUTE_INV, n.uid );
        this->adjacency_change.append( n.uid, rte.tport_id,
                                       this->link_state_seqno + 1, false );
      }
      if ( --list.sys_route_refs == 0 ) {
        d_lnk( "pop sys_route %u\n", fd );
        rte.connected_auth.remove( fd );
        BloomRoute *b = this->peer_bloom.get_bloom_by_fd( fd, 0 );
        if ( b != NULL ) {
          if ( debug_lnk )
            rte.printf( "remove peer bloom fd %u\n", fd );
          b->del_bloom_ref( &this->peer_bloom );
          b->remove_if_empty();
        }
        else if ( debug_lnk ) {
          rte.printf( "remove peer bloom fd %u not found\n", fd );
        }
      }
      else if ( debug_lnk ) {
        rte.printf( "pop_user_route fd %u sys_refs %u\n", fd,
                    list.sys_route_refs );
      }
      if ( rte.oldest_uid == n.uid ) {
        uint64_t t = this->start_time;
        uint32_t uid;
        rte.oldest_uid = 0;
        for ( bool ok = rte.uid_connected.first( uid ); ok;
              ok = rte.uid_connected.next( uid ) ) {
          UserBridge * n2 = this->bridge_tab[ uid ];
          if ( n2->start_time != 0 && n2->start_time < t ) {
            t = n2->start_time;
            rte.oldest_uid = uid;
          }
        }
      }
    }
    u_rte.invalidate();
  }
}

UserBridge *
UserDB::close_source_route( uint32_t fd ) noexcept
{
  if ( fd >= this->route_list.count )
    return NULL;
  UserRouteList & list = this->route_list[ fd ];
  while ( ! list.is_empty() ) {
    UserRoute  * u_ptr = list.hd;
    UserBridge & n     = u_ptr->n;

    if ( debug_lnk )
      n.printf( "close_source_route fd %u\n", fd );
    if ( u_ptr->is_set( IN_ROUTE_LIST_STATE ) ) {
      this->pop_user_route( n, *u_ptr );
    }
    else {
      n.printe( "not in route list fd %u\n", fd );
      list.pop( u_ptr );
    }
#if 0
    u_ptr->hops = UserRoute::NO_HOPS;
    u_ptr = n.primary( *this );

    if ( ! u_ptr->is_valid() ) {
      this->add_inbox_route( n, NULL ); /* find new primary */
      u_ptr = n.primary( *this );
      if ( ! u_ptr->is_valid() ) /* no other route exists */
        return &n;
    }
#endif
  }
  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge & n = *this->bridge_tab.ptr[ uid ];
    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ ) {
      if ( n.bloom_rt[ i ] != NULL && n.bloom_rt[ i ]->r == fd ) {
        n.bloom_rt[ i ]->del_bloom_ref( &n.bloom );
        n.bloom_rt[ i ]->remove_if_empty();
        n.bloom_rt[ i ] = NULL;
      }
    }
  }
  return NULL;
}

static inline bool
tport_changed( uint32_t &last,  uint32_t val ) {
  if ( last != val ) {
    last = val;
    return true;
  }
  return false;
}

void
UserDB::send_adjacency_change( void ) noexcept
{
  TransportRoute * rte;
  UserBridge     * n, * rem;
  AdjChange      * p = this->adjacency_change.hd;
  
  this->msg_send_counter[ U_ADJACENCY ]++;
  MsgEst adj;
  for ( ; p != NULL; p = p->next ) {
    rte = this->transport_tab.ptr[ p->tportid ];
    n   = this->bridge_tab.ptr[ p->uid ];

    adj.tportid()
       .link_add()
       .cost()
       .cost2()
       .cost3()
       .cost4()
       .tport( rte->transport.tport.len )
       .tport_type( rte->transport.type.len );
    if ( n != NULL )
      adj.user( n->peer.user.len );
    else
      adj.user( this->user.user.len );
    adj.bridge2 ()
       .rem_bridge()
       .rem_tportid();

    d_lnk( "send chg: %s %s cost %u,%u,%u,%u\n", p->add ? "add" : "remove",
      n != NULL ? n->peer.user.val : this->user.user.val,
      rte->uid_connected.cost[ 0 ], rte->uid_connected.cost[ 1 ],
      rte->uid_connected.cost[ 2 ], rte->uid_connected.cost[ 3 ] );
  }

  MsgEst e( Z_ADJ_SZ );
  e.seqno     ()
   .link_state()
   .user      ( this->user.user.len )
   .adjacency ( adj.sz );

  MsgCat m;
  m.reserve( e.sz );

  this->update_link_state_seqno( this->link_state_seqno,
                                 this->link_state_seqno + 1 );
  m.open( this->bridge_id.nonce, Z_ADJ_SZ )
   .seqno     ( ++this->send_peer_seqno  )
   .link_state( this->link_state_seqno )
   .user      ( this->user.user.val, this->user.user.len );

  SubMsgBuf s( m );
  s.open_submsg(); 
  uint32_t last = -1;
  while ( ! this->adjacency_change.is_empty() ) {
    p = this->adjacency_change.pop_hd();
    this->events.send_adjacency_change( p->uid, p->add );
    n   = this->bridge_tab.ptr[ p->uid ];
    rte = this->transport_tab.ptr[ p->tportid ];
    s.tportid( p->tportid )
     .link_add( p->add )
     .cost   ( rte->uid_connected.cost[ 0 ] )
     .cost2  ( rte->uid_connected.cost[ 1 ] )
     .cost3  ( rte->uid_connected.cost[ 2 ] )
     .cost4  ( rte->uid_connected.cost[ 3 ] );
    if ( tport_changed( last, p->tportid ) ) {
      s.tport     ( rte->transport.tport.val, rte->transport.tport.len )
       .tport_type( rte->transport.type.val, rte->transport.type.len );
    }
    if ( n != NULL ) {
      s.user   ( n->peer.user.val, n->peer.user.len )
       .bridge2( n->bridge_id.nonce );
    }
    else {
      s.user   ( this->user.user.val, this->user.user.len )
       .bridge2( this->bridge_id.nonce );
    }
    if ( p->add && rte->uid_connected.rem_tport_id != 0 ) {
      if ( p->uid != rte->uid_connected.rem_uid ) {
        rem = this->bridge_tab.ptr[ rte->uid_connected.rem_uid ];
        if ( rem != NULL )
          s.rem_bridge( rem->bridge_id.nonce );
      }
      s.rem_tportid( rte->uid_connected.rem_tport_id );
    }
    delete p;
  }
  s.close( m, FID_ADJACENCY );
  m.close( e.sz, adj_h, CABA_RTR_ALERT );
  m.sign( Z_ADJ, Z_ADJ_SZ, *this->session_key );

  uint32_t count = (uint32_t) this->transport_tab.count;
  kv::BitSpace unique;
  for ( uint32_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
      if ( ! unique.superset( rte->uid_connected ) ) {
        EvPublish pub( Z_ADJ, Z_ADJ_SZ, NULL, 0, m.msg, m.len(),
                       rte->sub_route, this->my_src, adj_h, CABA_TYPE_ID );
        rte->forward_to_connected( pub );
        unique.add( rte->uid_connected );
      }
    }
  }
}

bool
UserDB::recv_adjacency_change( const MsgFramePublish &pub,  UserBridge &n,
                               MsgHdrDecoder &dec ) noexcept
{
  uint64_t link_state;
  uint32_t adj_change;
  bool     b = true;

  if ( ! dec.get_ival<uint64_t>( FID_LINK_STATE, link_state ) ||
       ! dec.test( FID_ADJACENCY ) )
    return true;
  AdjacencyRec * unknown, * rec_list =
    dec.decode_rec_list<AdjacencyRec>( FID_ADJACENCY );

  if ( link_state != n.link_state_seqno + 1 ) {
    if ( n.link_state_seqno >= link_state ) {
      if ( debug_lnk )
        n.printf( "already have link state %" PRIu64 " >= %" PRIu64 "\n",
                  n.link_state_seqno, link_state );
      adj_change = HAVE_ADJ_CHANGE;
    }
    else {
      if ( link_state == n.unknown_link_seqno + 1 ) {
        unknown = this->apply_adjacency_change( n, rec_list );
        this->save_unknown_adjacency( n, pub.rte, link_state, unknown, true );
      }
      else {
        if ( debug_lnk )
          n.printf( "missing link state %" PRIu64 " + 1 != %" PRIu64 "\n",
                    n.link_state_seqno, link_state );
        b = this->send_adjacency_request( n, ADJ_CHG_SYNC_REQ );
      }
      adj_change = NEED_ADJ_SYNC;
    }
  }
  else {
    this->peer_dist.clear_cache_if_dirty();

    if ( debug_lnk )
      n.printf( "recv change link state %" PRIu64 "\n", link_state );
    adj_change = UPDATE_ADJ_CHANGE;
    if ( debug_lnk )
      AdjacencyRec::print_rec_list( rec_list, "recv_change" );
    /* there may be multiple users per tport, which has the effect
     * of decoding several records without a tport after the record
     * with the tport set */
    unknown = this->apply_adjacency_change( n, rec_list );
    if ( unknown != NULL ) {
      this->save_unknown_adjacency( n, pub.rte, link_state,
                                    unknown, true );
    }
    if ( n.unknown_adj_refs == 0 )
      this->update_link_state_seqno( n.link_state_seqno, link_state );
    else {
      adj_change = NEED_ADJ_SYNC;
      if ( debug_lnk )
        n.printf( "recv adj change: unknown_adj_refs %u to %" PRIu64 "\n",
                  n.unknown_adj_refs, link_state );
    }
    this->peer_dist.invalidate( ADJACENCY_CHANGE_INV, n.uid );
  }
  this->events.recv_adjacency_change( n.uid, pub.rte.tport_id, adj_change );
  b &= this->bcast_pub( pub, n, dec );
  return b;
}

AdjacencyRec *
UserDB::apply_adjacency_change( UserBridge &n,
                                AdjacencyRec *rec_list ) noexcept
{
  SLinkList< AdjacencyRec > unknown_recs;
  while ( rec_list != NULL ) {
    AdjacencyRec * next = rec_list->next;
    if ( ! this->add_adjacency_change( n, *rec_list ) ) {
      unknown_recs.push_tl( rec_list );
      n.unknown_adj_refs++;
    }
    rec_list = next;
  }
  return unknown_recs.hd;
}

bool
UserDB::add_adjacency_change( UserBridge &n,  AdjacencyRec &rec ) noexcept
{
  AdjacencySpace * set        = NULL;
  uint32_t         tport_id   = 0,
                   bridge_uid = 0;
  size_t           pos;

  if ( rec.test( FID_TPORT ) )
    this->string_tab.add_string( rec.tport_name );
  if ( rec.test( FID_TPORT_TYPE ) )
    this->string_tab.add_string( rec.tport_type );
  if ( rec.test( FID_USER ) )
    this->string_tab.add_string( rec.user );

  if ( rec.test( FID_TPORTID ) ) {
    tport_id = rec.tportid;
    set      = n.adjacency.get( tport_id, n.uid, rec.cost );
    if ( rec.tport_name.len > 0 )
      set->tport = rec.tport_name;
    if ( rec.tport_type.len > 0 )
      set->tport_type = rec.tport_type;
  }

  if ( ! rec.test( FID_BRIDGE ) || set == NULL ) {
    n.printf( "no bridge in rec %d\n", set != NULL );
    return true;
  }
  if ( ! this->node_ht->find( rec.nonce, pos, bridge_uid ) &&
       ! this->zombie_ht->find( rec.nonce, pos, bridge_uid ) ) {
    if ( debug_lnk )
      printf( "%.*s not found recv adj %s %.*s.%u\n",
        (int) rec.user.len, rec.user.val,
        rec.add ? "add" : "rem",
        (int) rec.tport_name.len, rec.tport_name.val, rec.tportid );
    return false;
  }
  if ( bridge_uid == n.uid ) { /* shouldn't be */
    n.printf( "cant add to self\n" );
    return true;
  }
  if ( debug_lnk )
    n.printf( "recv adj %s %.*s.%u\n", rec.add ? "add" : "rem",
      (int) set->tport.len, set->tport.val, set->tport_id );

  if ( rec.add ) {
    if ( ! set->test_set( bridge_uid ) )
      n.uid_csum ^= rec.nonce;

    if ( rec.test( FID_REM_TPORTID ) ) {
      if ( rec.rem_tportid == 0 ) {
        set->rem_uid = 0;
        set->rem_tport_id = 0;
      }
      else if ( rec.test( FID_REM_BRIDGE ) ) {
        size_t   pos;
        uint32_t uid = 0;
        if ( this->node_ht->find( rec.rem_bridge, pos, uid ) ||
             this->zombie_ht->find( rec.rem_bridge, pos, uid ) ) {
          set->rem_uid = uid;
          set->rem_tport_id = rec.rem_tportid;
        }
        else {
          if ( debug_lnk )
            n.printf( "rem not found recv adj %.*s.%u rem %u\n",
              (int) rec.tport_name.len, rec.tport_name.val, rec.tportid,
              rec.rem_tportid );
          set->rem_uid = 0;
          set->rem_tport_id = 0;
          return false;
        }
      }
      else {
        set->rem_uid = bridge_uid;
        set->rem_tport_id = rec.rem_tportid;
      }
    }
  }
  else {
    if ( set->test_clear( bridge_uid ) ) {
      n.uid_csum ^= rec.nonce;
      if ( set->is_empty() ) {
        set->rem_uid = 0;
        set->rem_tport_id = 0;
      }
    }
  }
  return true;
}

bool
UserBridge::throttle_request( uint32_t inc,  ThrottleState &throttle,
                              uint64_t cur_mono  ) noexcept
{
  if ( ( throttle.state & throttle.state_bit ) != 0 )
    return true;
  if ( cur_mono == 0 )
    cur_mono = current_monotonic_time_ns();
  if ( throttle.mono_time +
       ( (uint64_t) 10000000 << throttle.req_count ) >= cur_mono )
    return true;
  if ( inc > 0 ) {
    throttle.state |= throttle.state_bit;
    throttle.mono_time = cur_mono;
    if ( throttle.req_count < 9 ) /* 5 seconds */
      throttle.req_count += inc;
  }
  return false;
}

bool
UserDB::send_adjacency_request( UserBridge &n, AdjacencyRequest reas ) noexcept
{
  if ( n.throttle_adjacency( 1 ) )
    return true;
  this->adj_queue.push( &n );

  bool use_primary   = ( reas == DIJKSTRA_SYNC_REQ || 
                         reas == REQUEST_SYNC_REQ || n.user_route == NULL );
  uint32_t tport_id  = ( use_primary ? n.primary_route :
                         n.user_route->rte.tport_id );
  size_t peer_db_len = ( reas == REQUEST_SYNC_REQ ? 0 :
                         this->peer_db_size( n, true ) );
  this->events.send_adjacency_request( n.uid, tport_id, 0, reas );

  InboxBuf ibx( n.bridge_id, _ADJ_REQ );

  MsgEst e( ibx.len() );
  e.seqno       ()
   .link_state  ()
   .sub_seqno   ()
   .adj_info    ()
   .peer_db     ( peer_db_len );

  MsgCat m;
  m.reserve( e.sz );

  uint64_t ls_seqno = n.link_state_seqno;
  if ( reas == DIJKSTRA_SYNC_REQ && n.null_sync_res > 5 ) {
    ls_seqno = 0;
    n.printe( "restarting dijstra adjacency sync, null_sync_res > 5\n" );
  }
  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno       ( n.inbox.next_send( U_INBOX_ADJ_REQ ) )
   .link_state  ( ls_seqno           )
   .sub_seqno   ( n.sub_seqno        )
   .adj_info    ( reas               );
  if ( peer_db_len > 0 )
    this->peer_db_submsg( n, m, true );

  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  if ( debug_lnk )
    n.printf( "*** send_adj_request ls=%" PRIu64 " %s for %s\n", n.link_state_seqno,
              adjacency_request_string( reas ), n.peer.user.val );
  if ( use_primary )
    return this->forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
  return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
}

size_t
UserDB::adjacency_size( UserBridge *sync ) noexcept
{
  UserBridge * n2 = NULL;
  uint32_t     i, uid, count, last,
               sync_uid = ( sync == NULL ? 0 : sync->uid );

  MsgEst e;
  count = this->peer_dist.adjacency_count( sync_uid );
  last  = count;
  for ( i = 0; i < count; i++ ) {
    AdjacencySpace * set = this->peer_dist.adjacency_set( sync_uid, i );
    uint32_t rem_cnt = 0;
    if ( set == NULL )
      continue;
    for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
      if ( uid != MY_UID ) {
        n2 = this->bridge_tab.ptr[ uid ];
        if ( n2 == NULL )
          continue;
      }
      e.tportid()
       .cost()
       .cost2()
       .cost3()
       .cost4();
      if ( tport_changed( last, i ) ) {
        e.tport     ( set->tport.len )
         .tport_type( set->tport_type.len );
      }
      if ( uid == MY_UID ) {
        e.user   ( this->user.user.len )
         .bridge2();
        rem_cnt++;
      }
      else {
        e.user   ( n2->peer.user.len )
         .bridge2();
        rem_cnt++;
      }
    }
    if ( rem_cnt > 0 ) {
      e.rem_bridge()
       .rem_tportid();
    }
  }
  return e.sz;
}

void
UserDB::adjacency_submsg( UserBridge *sync,  MsgCat &m ) noexcept
{
  UserBridge * n2 = NULL;
  uint32_t     i, uid, count, last, last_uid,
               sync_uid = ( sync == NULL ? 0 : sync->uid );

  SubMsgBuf s( m );
  s.open_submsg();
  count = this->peer_dist.adjacency_count( sync_uid );
  last  = count;
  for ( i = 0; i < count; i++ ) {
    AdjacencySpace * set = this->peer_dist.adjacency_set( sync_uid, i );
    uint32_t rem_cnt = 0;
    if ( set == NULL )
      continue;
    last_uid = 0;
    for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
      if ( uid != MY_UID ) {
        n2 = this->bridge_tab.ptr[ uid ];
        if ( n2 == NULL )
          continue;
      }
      s.tportid( i )
       .cost   ( set->cost[ 0 ] )
       .cost2  ( set->cost[ 1 ] )
       .cost3  ( set->cost[ 2 ] )
       .cost4  ( set->cost[ 3 ] );
      if ( tport_changed( last, i ) ) {
        s.tport     ( set->tport.val, set->tport.len )
         .tport_type( set->tport_type.val, set->tport_type.len );
      }
      if ( uid == MY_UID ) {
        s.user   ( this->user.user.val, this->user.user.len )
         .bridge2( this->bridge_id.nonce );
        last_uid = uid;
        rem_cnt++;
      }
      else {
        s.user   ( n2->peer.user.val, n2->peer.user.len )
         .bridge2( n2->bridge_id.nonce );
        last_uid = uid;
        rem_cnt++;
      }
    }
    if ( rem_cnt > 0 ) {
      if ( set->rem_tport_id == 0 )
        s.rem_tportid( 0 );
      else {
        if ( last_uid != set->rem_uid ) {
          if ( set->rem_uid == 0 ) {
            s.rem_bridge( this->bridge_id.nonce );
          }
          else {
            UserBridge * r = this->bridge_tab.ptr[ set->rem_uid ];
            if ( r == NULL )
              continue;
            s.rem_bridge( r->bridge_id.nonce );
          }
        }
        s.rem_tportid( set->rem_tport_id );
      }
    }
  }
  s.close( m, FID_ADJACENCY );
}

enum {
  SYNC_NONE    = 0,
  SYNC_LINK    = 1,
  SYNC_SUB     = 2,
  SYNC_ANY     = 1 + 2,
  RQ_SYNC_LINK = 4,
  RQ_SYNC_SUB  = 8,
  RQ_SYNC_ANY  = 4 + 8
};
bool
UserDB::recv_adjacency_request( const MsgFramePublish &,  UserBridge &n,
                                MsgHdrDecoder &dec ) noexcept
{
  char         ret_buf[ 16 ];
  InboxBuf     ibx( n.bridge_id, dec.get_return( ret_buf, _ADJ_RPY ) );
  UserBridge * sync  = NULL;
  Nonce        nonce;
  uint64_t     link_seqno = 0,
               sub_seqno  = 0,
               time_val,
               rq_link_seqno,
               rq_sub_seqno;
  size_t       pos;
  uint32_t     uid        = 0,
               reas;

  dec.get_ival<uint64_t>( FID_LINK_STATE, rq_link_seqno );
  dec.get_ival<uint64_t>( FID_SUB_SEQNO, rq_sub_seqno );
  dec.get_ival<uint32_t>( FID_ADJ_INFO, reas );
  dec.get_ival<uint64_t>( FID_TIME, time_val );

  if ( dec.get_nonce( FID_SYNC_BRIDGE, nonce ) ) {
    if ( ! this->node_ht->find( nonce, pos, uid ) ) {
      n.printf( "*** adj_request nonce not found\n" );
      return true;
    }
  }

  if ( uid != 0 ) {
    sync       = this->bridge_tab.ptr[ uid ];
    link_seqno = sync->link_state_seqno;
    sub_seqno  = sync->sub_seqno;
  }
  else {
    sync       = NULL;
    link_seqno = this->link_state_seqno;
    sub_seqno  = this->sub_db.sub_seqno;
  }
  int which = SYNC_NONE;
  if ( link_seqno > rq_link_seqno )
    which |= SYNC_LINK;
  else if ( link_seqno < rq_link_seqno )
    which |= RQ_SYNC_LINK;
  if ( sub_seqno > rq_sub_seqno )
    which |= SYNC_SUB;
  else if ( link_seqno < rq_link_seqno )
    which |= RQ_SYNC_SUB;

  this->events.recv_adjacency_request( n.uid, n.user_route->rte.tport_id,
                                       ( sync == NULL ? 0 : sync->uid ), reas );
  bool b = true, sent_one = false;
  if ( ( which & SYNC_ANY ) != 0 ) {
    b &= this->send_adjacency( n, sync, ibx, time_val, reas, which );
    sent_one = true;
  }
  if ( sync != NULL && ( which & RQ_SYNC_ANY ) != 0 ) {
    b &= this->send_adjacency_request( *sync, REQUEST_SYNC_REQ );
  }
  if ( dec.test( FID_PEER_DB ) ) {
    PeerDBRec * rec_list = dec.decode_rec_list<PeerDBRec>( FID_PEER_DB );
    BitSpace pdb;
    if ( reas == UID_CSUM_SYNC_REQ ){
      for ( uid = 1; uid < this->next_uid; uid++ ) {
        UserBridge * x = this->bridge_tab.ptr[ uid ];
        if ( x == NULL || ! x->is_set( AUTHENTICATED_STATE ) )
          continue;
        pdb.add( uid );
      }
    }
    while ( rec_list != NULL ) {
      PeerDBRec  & rec = *rec_list;
      rec_list = rec.next;
      if ( this->node_ht->find( rec.nonce, pos, uid ) ) {
        UserBridge *sync = this->bridge_tab.ptr[ uid ];
        if ( sync != NULL ) {
          int pdb_which = SYNC_NONE;
          if ( sync->link_state_seqno > rec.link_state )
            pdb_which |= SYNC_LINK;
          else if ( sync->link_state_seqno < rec.link_state )
            pdb_which |= RQ_SYNC_LINK;
          if ( sync->sub_seqno > rec.sub_seqno )
            pdb_which |= SYNC_SUB;
          else if ( sync->sub_seqno < rec.sub_seqno )
            pdb_which |= RQ_SYNC_SUB;
          if ( ( pdb_which & SYNC_ANY ) != 0 ) {
            b &= this->send_adjacency( n, sync, ibx, time_val, reas, pdb_which);
            sent_one = true;
          }
          else if ( ( pdb_which & RQ_SYNC_ANY ) != 0 ) {
            b &= this->send_adjacency_request( *sync, REQUEST_SYNC_REQ );
          }
          pdb.remove( uid );
        }
      }
    }
    if ( reas == UID_CSUM_SYNC_REQ ) {
      for ( bool b = pdb.first( uid ); b; b = pdb.next( uid ) ) {
        UserBridge * sync = this->bridge_tab.ptr[ uid ];
        if ( sync != &n )
          b &= this->send_adjacency( n, sync, ibx, time_val, reas,
                                     SYNC_LINK | SYNC_SUB );
      }
    }
  }
  if ( ! sent_one )
    b &= this->send_adjacency( n, sync, ibx, time_val, reas, which );
  return b;
}

bool
UserDB::send_adjacency( UserBridge &n,  UserBridge *sync,  InboxBuf &ibx,
                        uint64_t time_val,  uint32_t reas,  int which ) noexcept
{
  BloomCodec code;
  uint64_t   link_seqno, sub_seqno;
  uint32_t   hops = 1, sync_uid = 0;
  StringVal  sync_user;

  if ( sync != NULL ) {
    if ( n.user_route->rte.uid_connected.is_member( sync->uid ) &&
         n.user_route->rte.uid_connected.is_member( n.uid ) )
      hops = 0;
    link_seqno = sync->link_state_seqno;
    sub_seqno  = sync->sub_seqno;
    sync_uid   = sync->uid;
    sync_user  = sync->peer.user;
  }
  else {
    if ( n.user_route->rte.uid_connected.is_member( n.uid ) )
      hops = 0;
    link_seqno = this->link_state_seqno;
    sub_seqno  = this->sub_db.sub_seqno;
    sync_user  = this->user.user;
  }

  this->events.send_adjacency( n.uid, n.user_route->rte.tport_id,
                               sync_uid, reas );
  MsgEst e( ibx.len() );
  e.seqno      ()
   .link_state ()
   .sub_seqno  ()
   .hops       ()
   .adj_info   ()
   .user       ( sync_user.len )
   .time       ()
   .sync_bridge();

  if ( ( which & SYNC_LINK ) != 0 )
    e.adjacency( this->adjacency_size( sync ) );
  if ( ( which & SYNC_SUB ) != 0 ) {
    if ( sync != NULL )
      sync->bloom.encode( code );
    else
      this->sub_db.bloom.encode( code );
    e.bloom( code.code_sz * 4 );
  }

  MsgCat m;
  m.reserve( e.sz );

  if ( debug_lnk )
    n.printf( "++++ send_adjacency( %s, %" PRIu64 ", %" PRIu64 ", %d )\n",
            sync ? sync->peer.user.val : "self", link_seqno, sub_seqno, which );
  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno   ( n.inbox.next_send( U_INBOX_ADJ_RPY ) )
   .hops    ( hops )
   .adj_info( reas )
   .user    ( sync_user.val, sync_user.len );

  if ( time_val != 0 )
    m.time( time_val );
  if ( sync != NULL )
    m.sync_bridge( sync->bridge_id.nonce );

  if ( ( which & SYNC_SUB ) != 0 ) {
    m.sub_seqno ( sub_seqno );
    m.bloom( code.ptr, code.code_sz * 4 );
  }
  if ( ( which & SYNC_LINK ) != 0 ) {
    m.link_state( link_seqno );
    this->adjacency_submsg( sync, m );
  }

  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
}

bool
UserDB::recv_adjacency_result( const MsgFramePublish &pub,  UserBridge &n,
                               MsgHdrDecoder &dec ) noexcept
{
  if ( n.test_clear( ADJACENCY_REQUEST_STATE ) )
    this->adj_queue.remove( &n );
  Nonce        nonce;
  uint64_t     link_state = 0,
               sub_seqno  = 0;
  uint32_t     reas;
  int          which = SYNC_NONE;
  UserBridge * sync  = NULL;
  StringVal    sync_user;

  if ( dec.test( FID_USER ) ) {
    sync_user.val = (const char *) dec.mref[ FID_USER ].fptr;
    sync_user.len = (uint32_t) dec.mref[ FID_USER ].fsize;
  }
  if ( dec.get_nonce( FID_SYNC_BRIDGE, nonce ) ) {
    size_t   pos;
    uint32_t uid;
    if ( this->node_ht->find( nonce, pos, uid ) ) {
      if ( uid == 0 ) {
        n.printe( "sync myself!\n" );
        return true;
      }
      sync = this->bridge_tab[ uid ];
    }
    if ( sync == NULL ) {
      if ( ! this->zombie_ht->find( nonce, pos, uid ) ) {
        char buf[ NONCE_B64_LEN + 1 ];
        nonce.to_base64_str( buf );
        n.printf( "sync user %.*s, nonce not found [%s]\n",
                  sync_user.len, sync_user.val, buf );
        return true;
      }
      sync = this->bridge_tab[ uid ];
      if ( sync == NULL || sync->last_auth_type == BYE_BYE )
        return true;
      this->add_user_route( *sync, pub.rte, pub.src_route, dec, n.user_route );
      this->add_authenticated( *sync, dec, AUTH_FROM_ADJ_RESULT, &n );
      if ( ! sync->is_set( AUTHENTICATED_STATE ) )
        return true;
    }
  }
  else {
    sync = &n;
  }

  if ( dec.get_ival<uint64_t>( FID_LINK_STATE, link_state ) &&
       dec.test( FID_ADJACENCY ) )
    which |= SYNC_LINK;
  if ( dec.get_ival<uint64_t>( FID_SUB_SEQNO, sub_seqno ) &&
       dec.test( FID_BLOOM ) )
    which |= SYNC_SUB;
  dec.get_ival<uint32_t>( FID_ADJ_INFO, reas );

  if ( debug_lnk )
    n.printf( "recv_adj_result(%s,lnk=%" PRIu64 ",blm=%" PRIu64 ",%u:%s)\n",
              sync->peer.user.val, link_state, sub_seqno, reas,
              adjacency_request_string( (AdjacencyRequest) reas ) );

  if ( reas == UNKNOWN_ADJ_REQ ) /* from a sync_result, sync_req -> sync_rpy */
    reas = PEER_SYNC_REQ;
  this->events.recv_adjacency_result( n.uid, pub.rte.tport_id,
                                      sync == &n ? 0 : sync->uid, reas );

  bool sync_link_anyway = false;
  if ( ( which & SYNC_LINK ) != 0 ) {
    if ( sync->null_sync_res > 5 && link_state == sync->link_state_seqno )
      sync_link_anyway = true;
    if ( link_state > sync->link_state_seqno )
      n.adj_req_throttle.req_count = 0;
    if ( link_state <= sync->link_state_seqno ) {
      if ( debug_lnk )
        n.printf( "sync link result already have seqno %" PRIu64 "\n", link_state );
    }
  }
  if ( ( which & SYNC_SUB ) != 0 ) {
    if ( sub_seqno > sync->sub_seqno )
      n.adj_req_throttle.req_count = 0;
  }
  if ( ( which & SYNC_LINK ) != 0 &&
       ( link_state > sync->link_state_seqno || sync_link_anyway ) ) {
    AdjacencyRec * rec_list =
      dec.decode_rec_list<AdjacencyRec>( FID_ADJACENCY );
    if ( debug_lnk )
      AdjacencyRec::print_rec_list( rec_list, "recv_result" );

    sync->uid_csum.zero();
    this->peer_dist.clear_cache_if_dirty();
    if ( sync->unknown_adj_refs != 0 )
      this->clear_unknown_adjacency( *sync );

    AdjacencySpace * set = NULL;
    for ( uint32_t i = 0; i < sync->adjacency.count; i++ ) {
      set = sync->adjacency.ptr[ i ];
      if ( set != NULL ) {
        set->zero();
        set->rem_uid = 0;
        set->rem_tport_id = 0;
      }
    }
    AdjacencyRec * unknown = this->apply_adjacency_change( *sync, rec_list );
    if ( sync->unknown_adj_refs == 0 )
      this->update_link_state_seqno( sync->link_state_seqno, link_state );
    else {
      this->save_unknown_adjacency( *sync, pub.rte, link_state,
                                    unknown, false );
      if ( debug_lnk )
        sync->printf( "have unknown %u refs to %" PRIu64 "\n", sync->unknown_adj_refs,
                      link_state );
    }
    this->peer_dist.invalidate( ADJACENCY_UPDATE_INV, sync->uid );
    sync->null_sync_res = 0;
  }
  else if ( reas == DIJKSTRA_SYNC_REQ ) {
    if ( this->last_auth_mono + sec_to_ns( 5 ) < this->poll.mono_ns )
      sync->null_sync_res++;
  }
  if ( ( which & SYNC_SUB ) != 0 && sub_seqno > sync->sub_seqno )
    this->sub_db.recv_bloom( pub, *sync, dec );

  return true;
}
