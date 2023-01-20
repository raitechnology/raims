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

struct AdjacencyRec : public MsgFldSet {
  Nonce          nonce;
  const char   * tport_name,
               * tport_type,
               * user;
  uint32_t       tport_len,
                 tport_type_len,
                 user_len,
                 tportid,
                 cost[ COST_PATH_COUNT ];
  bool           add;
  AdjacencyRec * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjacencyRec() : tport_name( 0 ), user( 0 ), tport_len( 0 ), user_len( 0 ),
                   tportid( 0 ), add( false ), next( 0 ) {
    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
      this->cost[ i ] = COST_DEFAULT;
    this->nonce.zero();
  }
  void set_field( uint32_t fid,  MDReference &mref ) {
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
        this->tport_name = (const char *) mref.fptr;
        this->tport_len  = (uint32_t) mref.fsize;
        break;
      case FID_TPORT_TYPE:
        this->tport_type     = (const char *) mref.fptr;
        this->tport_type_len = (uint32_t) mref.fsize;
        break;
      case FID_USER:
        this->user     = (const char *) mref.fptr;
        this->user_len = (uint32_t) mref.fsize;
        break;;
      case FID_BRIDGE:
        this->nonce.copy_from( mref.fptr );
        break;
      case FID_LINK_ADD:
        cvt_number<bool>( mref, this->add );
        break;
      default:
        break;
    }
  }
  void print( void ) const {
    char buf[ NONCE_B64_LEN + 1 ];
    printf(
"  %cnonce[%s] %ctport_name[%.*s.%.*s], %cuser[%.*s], %ctport[%u] %ccost[%u]\n",
            this->test( FID_BRIDGE ) ? '+' : '-',
            this->nonce.to_base64_str( buf ),
            this->test( FID_TPORT ) ? '+' : '-',
            this->tport_len, this->tport_name,
            this->tport_type_len, this->tport_type,
            this->test( FID_USER ) ? '+' : '-',
            this->user_len, this->user,
            this->test( FID_TPORTID ) ? '+' : '-',
            this->tportid,
            this->test( FID_COST ) ? '+' : '-',
            this->cost[ 0 ] );
  }

  static void print_rec_list( const AdjacencyRec *rec_list,
                              const char *where ) noexcept {
    printf( "%s rec_list:\n", where );
    for ( const AdjacencyRec *r = rec_list; r != NULL; r = r->next ) {
      r->print();
    }
  }
};

void
UserDB::save_unauthorized_adjacency( MsgFramePublish &pub ) noexcept
{
  MsgHdrDecoder & dec = pub.dec;
  AdjPending    * p;
  if ( ! dec.test_3( FID_BRIDGE, FID_LINK_STATE, FID_ADJACENCY ) )
    return;

  if ( dec.test( FID_USER ) ) {
    Nonce nonce;
    if ( dec.get_nonce( FID_BRIDGE, nonce ) ) {
      if ( (p = this->adjacency_unknown.find_unauth( nonce )) == NULL )
        p = this->adjacency_unknown.create( pub.rte, nonce );

      this->string_tab.ref_string( (const char *) dec.mref[ FID_USER ].fptr,
                                   dec.mref[ FID_USER ].fsize, p->user_sv );
    }
  }

  AdjacencyRec * rec_list = dec.decode_rec_list<AdjacencyRec>( FID_ADJACENCY );
  if ( debug_lnk )
    AdjacencyRec::print_rec_list( rec_list, "save_unauth" );

  while ( rec_list != NULL ) {
    AdjacencyRec & rec = *rec_list;
    StringVal      user_sv;
    rec_list = rec.next;

    if ( rec.test( FID_BRIDGE ) ) {
      size_t   pos;
      uint32_t uid;
      if ( ! this->node_ht->find( rec.nonce, pos, uid ) ) {
        if ( (p = this->adjacency_unknown.find_unauth( rec.nonce )) == NULL )
          p = this->adjacency_unknown.create( pub.rte, rec.nonce );

        if ( rec.test( FID_TPORTID ) )
          p->tportid = rec.tportid;

        for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
          p->cost[ i ] = rec.cost[ i ];

        if ( rec.test( FID_TPORT ) )
          this->string_tab.ref_string( rec.tport_name, rec.tport_len,
                                       p->tport_sv );
        if ( rec.test( FID_TPORT_TYPE ) )
          this->string_tab.ref_string( rec.tport_type, rec.tport_type_len,
                                       p->tport_type_sv );
        if ( rec.test( FID_USER ) )
          this->string_tab.ref_string( rec.user, rec.user_len, p->user_sv );

        if ( rec.test( FID_LINK_ADD ) )
          p->add = rec.add;
      }
    }
  }
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
UserDB::add_unknown_adjacency( UserBridge &n ) noexcept
{
  AdjPending * next;
  bool         changed = false;

  if ( debug_lnk )
    n.printf( "add_unknown_adjacency\n" );
  for ( AdjPending *p = this->adjacency_unknown.hd; p != NULL; p = next ) {
    next = p->next;
    if ( n.bridge_id.nonce == p->nonce ) {
      if ( p->uid != 0 ) {
        UserBridge *n2 = this->bridge_tab[ p->uid ];
        if ( n2 != NULL ) {
          AdjacencySpace *set;
          set = n2->adjacency.get( p->tportid, p->uid, p->cost );
          char str64[ NONCE_B64_LEN + 1 ];
          if ( p->tport_sv.len > 0 )
            set->tport = p->tport_sv;
          if ( p->tport_type_sv.len > 0 )
            set->tport_type = p->tport_type_sv;

          if ( n2->unknown_refs != 0 ) {
            if ( p->add ) {
              if ( ! set->test_set( n.uid ) ) {
                n2->uid_csum ^= p->nonce;
                if ( debug_lnk )
                  n2->printf( "unk add csum( %s )\n",
                              n2->uid_csum.to_base64_str( str64 ) );
              }
            }
            else {
              if ( set->test_clear( n.uid ) ) {
                n2->uid_csum ^= p->nonce;
                if ( debug_lnk )
                  n2->printf( "unk del csum( %s )\n",
                              n2->uid_csum.to_base64_str( str64 ) );
              }
            }
            changed = true;
            if ( --n2->unknown_refs == 0 )
              n2->link_state_seqno = n2->unknown_link_seqno;
          }
        }
      }
      this->adjacency_unknown.pop( p );
      if ( p->request_time_mono != 0 )
        this->remove_pending_peer( NULL, p->pending_seqno );
      delete p;
    }
  }
  if ( changed )
    this->peer_dist.invalidate( UNKNOWN_ADJACENCY_INV );
  if ( debug_lnk )
    print_adjacency( "Unknown", n );
}

void
UserDB::clear_unknown_adjacency( UserBridge &n ) noexcept
{
  AdjPending  * next;

  if ( debug_lnk )
    n.printf( "clear_unknown\n" );
  for ( AdjPending *p = this->adjacency_unknown.hd; p != NULL; p = next ) {
    next = p->next;
    if ( n.uid == p->uid || n.bridge_id.nonce == p->nonce ) {
      this->adjacency_unknown.pop( p );
      delete p;
    }
  }
  n.unknown_refs = 0;
}

void
UserDB::remove_adjacency( UserBridge & ) noexcept
{
#if 0
  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( uid == n.uid )
      continue;
    UserBridge *n2 = this->bridge_tab[ uid ];
    if ( n2 == NULL )
      continue;
    for ( uint32_t tport_id = 0; tport_id < n2->adjacency.count; tport_id++ ) {
      AdjacencySpace *set = n2->adjacency[ tport_id ];
      char str64[ NONCE_B64_LEN + 1 ];
      if ( set != NULL ) {
        if ( set->test_clear( n.uid ) ) {
          n.uid_removed.add( uid );
          n2->uid_csum ^= n.bridge_id.nonce;
          if ( debug_lnk )
            n2->printf( "rem adj %s csum( %s )\n",
                        n.peer.user.val,
                        n2->uid_csum.to_base64_str( str64 ) );
        }
      }
    }
  }
#endif
}

void
UserDB::push_source_route( UserBridge &n ) noexcept
{
  UserRoute * u_ptr;
  uint32_t    count = (uint32_t) this->transport_tab.count;
  for ( uint32_t i = 0; i < count; i++ ) {
    if ( (u_ptr = n.user_route_ptr( *this, i )) == NULL )
      break;
    this->push_user_route( n, *u_ptr );
  }
}

void
UserDB::push_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept
{
  /* if the bcast route is valid */
  if ( u_rte.is_valid() && ! u_rte.is_set( IN_ROUTE_LIST_STATE ) ) {
    uint32_t         fd   = u_rte.mcast_fd;
    UserRouteList  & list = this->route_list[ fd ];
    TransportRoute & rte  = u_rte.rte;

    if ( u_rte.hops == 0 ) {
      if ( rte.mesh_id != NULL ) {
        if ( ! rte.uid_in_mesh->test_set( n.uid ) ) {
          char buf[ NONCE_B64_LEN + 1 ];
          *rte.mesh_csum ^= n.bridge_id.nonce;
          if ( debug_lnk )
            n.printf( "add to mesh %s [%s]\n", rte.transport.tport.val,
                      rte.mesh_csum->to_base64_str( buf ) );
        }
      }
      else if ( rte.dev_id != NULL ) {
        rte.uid_in_device->add( n.uid );
        if ( debug_lnk )
          n.printf( "add to dev %s\n", rte.transport.tport.val );
      }
      if ( ! rte.uid_connected.test_set( n.uid ) ) {
        this->peer_dist.invalidate( PUSH_ROUTE_INV );
        this->adjacency_change.append( n.bridge_id.nonce, n.uid, rte.tport_id,
                                       this->link_state_seqno + 1, true );
      }
      if ( list.sys_route_refs++ == 0 ) {
        if ( debug_lnk )
          printf( "push sys_route %u\n", fd );
        rte.connected_auth.add( fd );
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
    u_rte.set( IN_ROUTE_LIST_STATE );
    list.push_tl( &u_rte );
    n.set( IN_ROUTE_LIST_STATE );
  }
}

void
UserDB::pop_source_route( UserBridge &n ) noexcept
{
  if ( debug_lnk )
    n.printf( "pop_source_route\n" );
  if ( n.test_clear( IN_ROUTE_LIST_STATE ) ) {
    uint32_t count = (uint32_t) this->transport_tab.count;
    for ( uint32_t i = 0; i < count; i++ ) {
      UserRoute * u_ptr = n.user_route_ptr( *this, i );
      if ( u_ptr == NULL )
        break;
      this->pop_user_route( n, *u_ptr );
    }
  }
}

void
UserDB::pop_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept
{
  if ( u_rte.test_clear( IN_ROUTE_LIST_STATE ) ) {
    uint32_t         fd   = u_rte.mcast_fd;
    UserRouteList  & list = this->route_list[ fd ];
    TransportRoute & rte  = u_rte.rte;

    list.pop( &u_rte );
    if ( u_rte.hops == 0 ) {
      if ( rte.mesh_id != NULL ) {
        if ( rte.uid_in_mesh->test_clear( n.uid ) ) {
          char buf[ NONCE_B64_LEN + 1 ];
          *rte.mesh_csum ^= n.bridge_id.nonce;
          if ( debug_lnk )
            n.printf( "rm from mesh %s [%s]\n", rte.transport.tport.val,
                      rte.mesh_csum->to_base64_str( buf ) );
        }
      }
      else if ( rte.dev_id != NULL ) {
        rte.uid_in_device->remove( n.uid );
        if ( debug_lnk )
          n.printf( "rm from dev %s\n", rte.transport.tport.val );
      }
      if ( rte.is_mcast() && rte.ibx_tport != NULL ) {
        if ( u_rte.is_set( UCAST_URL_STATE ) ) {
          if ( u_rte.is_set( UCAST_URL_SRC_STATE ) == 0 )
            rte.ibx_tport->shutdown_peer( n.uid, u_rte.url_hash );
        }
      }
      if ( rte.uid_connected.test_clear( n.uid ) ) {
        this->peer_dist.invalidate( POP_ROUTE_INV );
        this->adjacency_change.append( n.bridge_id.nonce, n.uid, rte.tport_id,
                                       this->link_state_seqno + 1, false );
      }
      if ( --list.sys_route_refs == 0 ) {
        d_lnk( "pop sys_route %u\n", fd );
        rte.connected_auth.remove( fd );
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
    u_rte.hops = UserRoute::NO_HOPS;
  }
}

UserBridge *
UserDB::close_source_route( uint32_t fd ) noexcept
{
  if ( fd >= this->route_list.count )
    return NULL;
  UserRouteList & list = this->route_list[ fd ];
  while ( ! list.is_empty() ) {
    UserRoute  * u_ptr     = list.pop_hd();
    UserBridge & n         = u_ptr->n;

    this->pop_user_route( n, *u_ptr );
    u_ptr->hops = UserRoute::NO_HOPS;
    u_ptr = n.primary( *this );

    if ( ! u_ptr->is_valid() ) {
      this->add_inbox_route( n, NULL ); /* find new primary */
      u_ptr = n.primary( *this );
      if ( ! u_ptr->is_valid() ) /* no other route exists */
        return &n;
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
  UserBridge     * n;
  AdjChange      * p = this->adjacency_change.hd;
  
  if ( debug_lnk )
    printf( "send_adj_change\n" );
  MsgEst adj;
  for ( ; p != NULL; p = p->next ) {
    rte = this->transport_tab.ptr[ p->tportid ];
    n   = this->bridge_tab.ptr[ p->uid ];

    adj.tportid()
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
       .link_add();

    if ( debug_lnk )
      printf( "  %s %s cost %u,%u,%u,%u\n", p->add ? "add" : "remove",
        n != NULL ? n->peer.user.val : this->user.user.val,
        rte->uid_connected.cost[ 0 ], rte->uid_connected.cost[ 1 ],
        rte->uid_connected.cost[ 2 ], rte->uid_connected.cost[ 3 ] );
    /*this->uid_csum ^= p->nonce;*/
  }

  MsgEst e( Z_ADJ_SZ );
  e.seqno     ()
   .link_state()
   .user      ( this->user.user.len )
   .adjacency ( adj.sz );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, Z_ADJ_SZ )
   .seqno     ( ++this->send_peer_seqno  )
   .link_state( ++this->link_state_seqno )
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
     .cost   ( rte->uid_connected.cost[ 0 ] )
     .cost2  ( rte->uid_connected.cost[ 1 ] )
     .cost3  ( rte->uid_connected.cost[ 2 ] )
     .cost4  ( rte->uid_connected.cost[ 3 ] );
    if ( tport_changed( last, p->tportid ) ) {
      s.tport     ( rte->transport.tport.val, rte->transport.tport.len )
       .tport_type( rte->transport.type.val, rte->transport.type.len );
    }
    if ( n != NULL )
      s.user( n->peer.user.val, n->peer.user.len );
    else
      s.user( this->user.user.val, this->user.user.len );
    s.bridge2 ( p->nonce )
     .link_add( p->add );
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
                       rte->sub_route, this->my_src_fd, adj_h,
                       CABA_TYPE_ID, 'p' );
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

  if ( link_state != n.link_state_seqno + 1 ) {
    if ( n.link_state_seqno >= link_state ) {
      if ( debug_lnk )
        n.printf( "already have link state %" PRIu64 " >= %" PRIu64 "\n",
                  n.link_state_seqno, link_state );
      adj_change = HAVE_ADJ_CHANGE;
    }
    else {
      if ( debug_lnk )
        n.printf( "missing link state %" PRIu64 " + 1 != %" PRIu64 "\n",
                  n.link_state_seqno, link_state );
      b = this->send_adjacency_request( n, ADJ_CHG_SYNC_REQ );
      adj_change = NEED_ADJ_SYNC;
    }
  }
  else {
    this->peer_dist.clear_cache_if_dirty();

    if ( debug_lnk )
      n.printf( "recv change link state %" PRIu64 "\n", link_state );
    adj_change = UPDATE_ADJ_CHANGE;
    AdjacencyRec * rec_list =
      dec.decode_rec_list<AdjacencyRec>( FID_ADJACENCY );
    if ( debug_lnk )
      AdjacencyRec::print_rec_list( rec_list, "recv_change" );
    /* there may be multiple users per tport, which has the effect
     * of decoding several records without a tport after the record
     * with the tport set */
    while ( rec_list != NULL ) {
      AdjacencyRec   & rec = *rec_list;
      AdjacencySpace * set      = NULL;
      uint32_t         tport_id = 0;
      StringVal        tport_sv,
                       tport_type_sv,
                       user_sv;
      rec_list = rec.next;

      if ( rec.test( FID_TPORT ) )
        this->string_tab.ref_string( rec.tport_name, rec.tport_len, tport_sv );
      if ( rec.test( FID_TPORT_TYPE ) )
        this->string_tab.ref_string( rec.tport_type, rec.tport_type_len,
                                     tport_type_sv );

      if ( rec.test( FID_TPORTID ) ) {
        tport_id = rec.tportid;
        set      = n.adjacency.get( tport_id, n.uid, rec.cost );
        if ( tport_sv.len > 0 )
          set->tport = tport_sv;
        if ( tport_type_sv.len > 0 )
          set->tport_type = tport_type_sv;
      }
      if ( rec.test( FID_USER ) )
        this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
      if ( rec.test( FID_BRIDGE ) && set != NULL ) {
        size_t   pos;
        uint32_t uid = 0;
        char     str64[ NONCE_B64_LEN + 1 ];
        if ( this->node_ht->find( rec.nonce, pos, uid ) ||
             this->zombie_ht->find( rec.nonce, pos, uid ) ) {
          if ( uid != n.uid ) {
            if ( rec.add ) {
              if ( ! set->test_set( uid ) ) {
                n.uid_csum ^= rec.nonce;
                if ( debug_lnk )
                  n.printf( "recv adj add %.*s.%u = %lx csum ( %s )\n",
                            (int) set->tport.len, set->tport.val,
                            set->tport_id, set->ptr[ 0 ],
                            n.uid_csum.to_base64_str( str64 ) );
              }
            }
            else {
              if ( set->test_clear( uid ) ) {
                n.uid_csum ^= rec.nonce;
                if ( debug_lnk )
                  n.printf( "recv adj del csum ( %s )\n",
                            n.uid_csum.to_base64_str( str64 ) );
              }
            }
          }
        }
        else {
          n.unknown_refs++;
          n.unknown_link_seqno = link_state;
          AdjPending *p =
            this->adjacency_unknown.find_update( rec.nonce, tport_id, rec.add );
          if ( p == NULL )
            p = this->adjacency_unknown.create( pub.rte, rec.nonce );
          if ( link_state > p->link_state_seqno ) {
            p->link_state_seqno = link_state;
            p->uid              = n.uid;
            p->tportid          = tport_id;
            p->tport_sv         = set->tport;
            p->tport_type_sv    = set->tport_type;
            p->user_sv          = user_sv;
            p->reason           = ADJ_CHANGE_SYNC;
            p->add              = rec.add;
            for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
              p->cost[ i ] = rec.cost[ i ];
          }
          if ( rec.add ) {
            UserBridge * m;
            uint32_t tmp_cost;
            m = this->closest_peer_route( pub.rte, n, tmp_cost );
            if ( m != NULL )
              this->start_pending_adj( *p, *m );
          }
        }
      }
    }
    if ( n.unknown_refs == 0 )
      n.link_state_seqno = link_state;
    this->peer_dist.invalidate( ADJACENCY_CHANGE_INV );
  }
  this->events.recv_adjacency_change( n.uid, pub.rte.tport_id, adj_change );
  b &= this->forward_pub( pub, n, dec );
  return b;
}

bool
UserBridge::throttle_adjacency( uint32_t inc,  uint64_t cur_mono ) noexcept
{
  if ( this->is_set( ADJACENCY_REQUEST_STATE ) )
    return true;
  if ( cur_mono == 0 )
    cur_mono = current_monotonic_time_ns();
  if ( this->adj_mono_time +
       ( (uint64_t) 10000000 << this->adj_req_count ) >= cur_mono )
    return true;
  if ( inc > 0 ) {
    this->adj_mono_time = cur_mono;
    if ( this->adj_req_count < 7 )
      this->adj_req_count += inc;
  }
  return false;
}

bool
UserDB::send_adjacency_request( UserBridge &n, AdjacencyRequest reas ) noexcept
{
  if ( n.throttle_adjacency( 1 ) )
    return true;

  n.set( ADJACENCY_REQUEST_STATE );
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

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno       ( n.inbox.next_send( U_INBOX_ADJ_REQ ) )
   .link_state  ( n.link_state_seqno    )
   .sub_seqno   ( n.sub_seqno           )
   .adj_info    ( reas                  );
  if ( peer_db_len > 0 )
    this->peer_db_submsg( n, m, true );

  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  if ( debug_lnk )
    n.printf( "*** send_adj_request ls=%lu %s for %s\n", n.link_state_seqno,
              adjacency_request_string( reas ), n.peer.user.val );
  if ( use_primary )
    return this->forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
  return this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
}

size_t
UserDB::adjacency_size( UserBridge *sync ) noexcept
{
  UserBridge * n2;
  uint32_t     i, uid, count, last;

  MsgEst e;
  if ( sync != NULL ) { /* sync adjacency */
    UserBridge &n = *sync;
    count = (uint32_t) n.adjacency.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      AdjacencySpace * set = n.adjacency.ptr[ i ];
      if ( set != NULL ) {
        for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
          if ( uid == MY_UID ) {
            e.tportid()
             .cost()
             .cost2()
             .cost3()
             .cost4();
            if ( tport_changed( last, i ) ) {
              e.tport     ( set->tport.len )
               .tport_type( set->tport_type.len );
            }
            e.user   ( this->user.user.len )
             .bridge2();
          }
          else {
            n2 = this->bridge_tab.ptr[ uid ];
            if ( n2 != NULL ) {
              e.tportid()
               .cost()
               .cost2()
               .cost3()
               .cost4();
              if ( tport_changed( last, i ) ) {
                e.tport     ( set->tport.len )
                 .tport_type( set->tport_type.len );
              }
              e.user   ( n2->peer.user.len )
               .bridge2();
            }
          }
        }
      }
    }
  }
  else { /* my adjacency */
    count = (uint32_t) this->transport_tab.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      TransportRoute * rte = this->transport_tab.ptr[ i ];
      if ( rte != NULL ) {
        for ( bool ok = rte->uid_connected.first( uid ); ok;
              ok = rte->uid_connected.next( uid ) ) {
          n2 = this->bridge_tab.ptr[ uid ];
          if ( n2 != NULL ) {
            e.tportid()
             .cost()
             .cost2()
             .cost3()
             .cost4();
            if ( tport_changed( last, i ) ) {
              e.tport     ( rte->transport.tport.len )
               .tport_type( rte->transport.type.len );
            }
            e.user   ( n2->peer.user.len )
             .bridge2();
          }
        }
      }
    }
  }
  return e.sz;
}

void
UserDB::adjacency_submsg( UserBridge *sync,  MsgCat &m ) noexcept
{
  UserBridge * n2;
  uint32_t     i, uid, count, last;

  SubMsgBuf s( m );
  s.open_submsg();

  if ( sync != NULL ) { /* sync adjacacency */
    UserBridge &n = *sync;
    count = (uint32_t) n.adjacency.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      AdjacencySpace * set = n.adjacency.ptr[ i ];
      if ( set != NULL ) {
        for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
          if ( uid == MY_UID ) {
            s.tportid( i )
             .cost   ( set->cost[ 0 ] )
             .cost2  ( set->cost[ 1 ] )
             .cost3  ( set->cost[ 2 ] )
             .cost4  ( set->cost[ 3 ] );
            if ( tport_changed( last, i ) ) {
              s.tport     ( set->tport.val, set->tport.len )
               .tport_type( set->tport_type.val, set->tport_type.len );
            }
            s.user   ( this->user.user.val, this->user.user.len )
             .bridge2( this->bridge_id.nonce );
          }
          else {
            n2 = this->bridge_tab.ptr[ uid ];
            if ( n2 != NULL ) {
              s.tportid( i )
               .cost   ( set->cost[ 0 ] )
               .cost2  ( set->cost[ 1 ] )
               .cost3  ( set->cost[ 2 ] )
               .cost4  ( set->cost[ 3 ] );
              if ( tport_changed( last, i ) ) {
                s.tport     ( set->tport.val, set->tport.len )
                 .tport_type( set->tport_type.val, set->tport_type.len );
              }
              s.user   ( n2->peer.user.val, n2->peer.user.len )
               .bridge2( n2->bridge_id.nonce );
            }
          }
        }
      }
    }
  }
  else { /* my adjacency */
    count = (uint32_t) this->transport_tab.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      TransportRoute * rte = this->transport_tab.ptr[ i ];
      if ( rte != NULL ) {
        for ( bool ok = rte->uid_connected.first( uid ); ok;
              ok = rte->uid_connected.next( uid ) ) {
          n2 = this->bridge_tab.ptr[ uid ];
          if ( n2 != NULL ) {
            s.tportid( i )
             .cost   ( rte->uid_connected.cost[ 0 ] )
             .cost2  ( rte->uid_connected.cost[ 1 ] )
             .cost3  ( rte->uid_connected.cost[ 2 ] )
             .cost4  ( rte->uid_connected.cost[ 3 ] );
            if ( tport_changed( last, i ) ) {
              s.tport     ( rte->transport.tport.val, rte->transport.tport.len )
               .tport_type( rte->transport.type.val, rte->transport.type.len );
            }
            s.user   ( n2->peer.user.val, n2->peer.user.len )
             .bridge2( n2->bridge_id.nonce );
          }
        }
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
  uint32_t   hops = 1;

  if ( sync != NULL ) {
    if ( n.user_route->rte.uid_connected.is_member( sync->uid ) &&
         n.user_route->rte.uid_connected.is_member( n.uid ) )
      hops = 0;
    link_seqno = sync->link_state_seqno;
    sub_seqno  = sync->sub_seqno;
  }
  else {
    if ( n.user_route->rte.uid_connected.is_member( n.uid ) )
      hops = 0;
    link_seqno = this->link_state_seqno;
    sub_seqno  = this->sub_db.sub_seqno;
  }
  this->events.send_adjacency( n.uid, n.user_route->rte.tport_id,
                               ( sync == NULL ? 0 : sync->uid ), reas );
  MsgEst e( ibx.len() );
  e.seqno      ()
   .link_state ()
   .sub_seqno  ()
   .hops       ()
   .adj_info   ()
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
    n.printf( "++++ send_adjacency( %s, %lu, %lu, %d )\n",
            sync ? sync->peer.user.val : "self", link_seqno, sub_seqno, which );
  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno   ( n.inbox.next_send( U_INBOX_ADJ_RPY ) )
   .hops    ( hops )
   .adj_info( reas );

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
        n.printe( "sync nonce not found [%s]\n", buf );
        return true;
      }
      sync = this->bridge_tab[ uid ];
      this->add_user_route( *sync, pub.rte, pub.src_route, dec, n.user_route );
      this->add_authenticated( *sync, dec, AUTH_FROM_ADJ_RESULT, &n );
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
    n.printf( "recv_adj_result(%s,lnk=%" PRIu64 ",blm=%" PRIu64 ",%u)\n",
              sync->peer.user.val, link_state, sub_seqno, reas );

  if ( reas == UNKNOWN_ADJ_REQ ) /* from a sync_result, sync_req -> sync_rpy */
    reas = PEER_SYNC_REQ;
  this->events.recv_adjacency_result( n.uid, pub.rte.tport_id,
                                      sync == &n ? 0 : sync->uid, reas );

  if ( ( which & SYNC_LINK ) != 0 ) {
    if ( link_state > sync->link_state_seqno )
      n.adj_req_count = 0;
  }
  if ( ( which & SYNC_SUB ) != 0 ) {
    if ( sub_seqno > sync->sub_seqno )
      n.adj_req_count = 0;
  }
  if ( ( which & SYNC_LINK ) != 0 && link_state > sync->link_state_seqno ) {
    AdjacencyRec * rec_list =
      dec.decode_rec_list<AdjacencyRec>( FID_ADJACENCY );
    if ( debug_lnk )
      AdjacencyRec::print_rec_list( rec_list, "recv_result" );

    sync->uid_csum.zero();
    if ( debug_lnk )
      sync->printf( "zero uid_csum\n" );
    this->peer_dist.clear_cache_if_dirty();
    if ( sync->unknown_refs != 0 )
      this->clear_unknown_adjacency( *sync );

    AdjacencySpace * set = NULL;
    for ( uint32_t i = 0; i < sync->adjacency.count; i++ ) {
      set = sync->adjacency.ptr[ i ];
      if ( set != NULL )
        set->zero();
    }
    while ( rec_list != NULL ) {
      AdjacencyRec & rec = *rec_list;
      StringVal      user_sv;
      uint32_t       tport_id = 0;
      StringVal      tport_sv,
                     tport_type_sv;
      rec_list = rec.next;

      if ( rec.test( FID_TPORT ) )
        this->string_tab.ref_string( rec.tport_name, rec.tport_len, tport_sv );
      if ( rec.test( FID_TPORT_TYPE ) )
        this->string_tab.ref_string( rec.tport_type, rec.tport_type_len,
                                     tport_type_sv );

      if ( rec.test( FID_TPORTID ) ) {
        tport_id = rec.tportid;
        set      = sync->adjacency.get( tport_id, sync->uid, rec.cost );
        if ( tport_sv.len > 0 )
          set->tport = tport_sv;
        if ( tport_type_sv.len > 0 )
          set->tport_type = tport_type_sv;
      }
      else {
        set = NULL;
      }
      if ( rec.test( FID_USER ) )
        this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
      if ( rec.test( FID_BRIDGE ) && set != NULL ) {
        size_t   pos;
        uint32_t uid = 0;
        char     str64[ NONCE_B64_LEN + 1 ];
        if ( this->node_ht->find( rec.nonce, pos, uid ) ||
             this->zombie_ht->find( rec.nonce, pos, uid ) ) {
          if ( uid != sync->uid && set != NULL ) {
            sync->uid_csum ^= rec.nonce;
            if ( debug_lnk )
              sync->printf( "recv adj update %.*s csum( %s )\n",
                            (int) rec.user_len, rec.user,
                            sync->uid_csum.to_base64_str( str64 ) );
            set->add( uid );
          }
        }
        else {
          sync->unknown_refs++;
          sync->unknown_link_seqno = link_state;
          AdjPending *p =
            this->adjacency_unknown.find_update( rec.nonce, tport_id, rec.add );
          if ( p == NULL )
            p = this->adjacency_unknown.create( pub.rte, rec.nonce );
          if ( link_state > p->link_state_seqno ) {
            p->link_state_seqno = link_state;
            p->uid              = sync->uid;
            p->tportid          = tport_id;
            p->tport_sv         = set->tport;
            p->tport_type_sv    = set->tport_type;
            p->user_sv          = user_sv;
            p->reason           = ADJ_RESULT_SYNC;
            p->add              = true;
            for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
              p->cost[ i ] = rec.cost[ i ];
          }
          UserBridge * m;
          uint32_t dist;
          m = this->closest_peer_route( pub.rte, *sync, dist );
          if ( m != NULL )
            this->start_pending_adj( *p, *m );
        }
      }
    }
    if ( sync->unknown_refs == 0 )
      sync->link_state_seqno = link_state;
    this->peer_dist.invalidate( ADJACENCY_UPDATE_INV );
  }
  if ( ( which & SYNC_SUB ) != 0 && sub_seqno > sync->sub_seqno )
    this->sub_db.recv_bloom( pub, *sync, dec );

  return true;
}
