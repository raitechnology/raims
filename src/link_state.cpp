#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
               * user;
  uint32_t       tport_len,
                 user_len,
                 tport;
  bool           add;
  AdjacencyRec * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjacencyRec() : tport_name( 0 ), user( 0 ), tport_len( 0 ), user_len( 0 ),
                   tport( 0 ), add( false ), next( 0 ) {
    this->nonce.zero();
  }
  void set_field( uint32_t fid,  MDReference &mref ) {
    switch ( fid ) {
      case FID_TPORTID:
        cvt_number<uint32_t>( mref, this->tport );
        break;
      case FID_TPORT:
        this->tport_name = (const char *) mref.fptr;
        this->tport_len  = mref.fsize;
        break;
      case FID_USER:
        this->user     = (const char *) mref.fptr;
        this->user_len = mref.fsize;
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
    printf( "  %cnonce[%s] %ctport_name[%.*s], %cuser[%.*s], %ctport[%u]\n",
            this->test( FID_BRIDGE ) ? '+' : '-',
            this->nonce.to_base64_str( buf ),
            this->test( FID_TPORT ) ? '+' : '-',
            this->tport_len, this->tport_name,
            this->test( FID_USER ) ? '+' : '-',
            this->user_len, this->user,
            this->test( FID_TPORTID ) ? '+' : '-',
            this->tport );
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
  if ( ! dec.test_3( FID_BRIDGE, FID_LINK_STATE, FID_ADJACENCY ) )
    return;

  if ( dec.test( FID_USER ) ) {
    StringVal user_sv;
    Nonce     bridge;
    if ( dec.get_nonce( FID_BRIDGE, bridge ) ) {
      this->string_tab.ref_string( (const char *) dec.mref[ FID_USER ].fptr,
                                   dec.mref[ FID_USER ].fsize, user_sv );
      this->adjacency_unknown.unauth( pub.rte, bridge, user_sv );
    }
  }

  AdjacencyRec * rec_list = dec.decode_rec_list<AdjacencyRec>( FID_ADJACENCY );
  if ( debug_lnk )
    AdjacencyRec::print_rec_list( rec_list, "save_unauth" );

  while ( rec_list != NULL ) {
    AdjacencyRec & rec = *rec_list;
    StringVal      user_sv;
    rec_list = rec.next;

    if ( rec.test( FID_USER ) )
      this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
    if ( rec.test( FID_BRIDGE ) ) {
      size_t   pos;
      uint32_t uid;
      if ( ! this->node_ht->find( rec.nonce, pos, uid ) )
        this->adjacency_unknown.unauth( pub.rte, rec.nonce, user_sv );
                                        /*UNAUTH_ADJ_SYNC );*/
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

AdjPending *
AdjPendingList::update( TransportRoute &r,  const Nonce &n,
                        uint32_t uid,  uint32_t tport,  uint64_t tx,  bool a,
                        const StringVal &tp_sv,  const StringVal &us_sv,
                        PeerSyncReason reas ) noexcept
{
  for ( AdjPending *p = this->hd; p != NULL; p = p->next ) {
    if ( p->reason != UNAUTH_ADJ_SYNC ) {
      if ( p->nonce == n && p->tport == tport && p->add == a ) {
        if ( uid == p->uid ) {
          if ( tx > p->link_state_seqno )
            p->link_state_seqno = tx;
          return p;
        }
      }
    }
  }
  char nbuf[ NONCE_B64_LEN + 1 ];
  d_lnk( "pending([%s], %.*s, %.*s, uid-%u)\n", n.to_base64_str( nbuf ),
         tp_sv.len, tp_sv.val, us_sv.len, us_sv.val, uid );
  return this->append( r, n, uid, tport, tx, a, tp_sv, us_sv, reas );
}

void
AdjPendingList::unauth( TransportRoute &r,  const Nonce &n,
                        StringVal &us_sv ) noexcept
{
  for ( AdjPending *p = this->hd; p != NULL; p = p->next ) {
    if ( p->reason == UNAUTH_ADJ_SYNC ) {
      if ( p->nonce == n )
        return;
    }
  }
  char nbuf[ NONCE_B64_LEN + 1 ];
  d_lnk( "pending([%s], %.*s)\n", n.to_base64_str( nbuf ), us_sv.len, us_sv.val);
  this->append( r, n, us_sv );
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
          AdjacencySpace *set = n2->adjacency.get( p->tport );
          if ( p->tport_sv.len > 0 ) {
            set->tport = p->tport_sv;
          }
          if ( n2->unknown_refs != 0 ) {
            if ( p->add ) {
              if ( ! set->test_set( n.uid ) )
                n2->uid_csum ^= p->nonce;
            }
            else {
              if ( set->test_clear( n.uid ) )
                n2->uid_csum ^= p->nonce;
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
UserDB::remove_adjacency( const UserBridge &n ) noexcept
{
  for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
    if ( uid == n.uid )
      continue;
    UserBridge *n2 = this->bridge_tab[ uid ];
    if ( n2 == NULL )
      continue;
    for ( uint32_t tport_id = 0; tport_id < n2->adjacency.count; tport_id++ ) {
      AdjacencySpace *set = n2->adjacency[ tport_id ];
      if ( set != NULL ) {
        if ( set->test_clear( n.uid ) )
          n2->uid_csum ^= n.bridge_id.nonce;
      }
    }
  }
}

void
UserDB::push_source_route( UserBridge &n ) noexcept
{
  UserRoute * u_ptr;
  uint32_t    count = this->transport_tab.count;
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
      if ( ! rte.uid_connected.test_set( n.uid ) ) {
        this->peer_dist.invalidate( PUSH_ROUTE_INV );
        this->adjacency_change.append( n.bridge_id.nonce, n.uid, rte.tport_id,
                                       this->link_state_seqno + 1, true );
      }
      if ( list.sys_route_refs++ == 0 ) {
        rte.connected_auth.add( fd );
        rte.sub_route.add_sub_route_str( X_HELLO, X_HELLO_SZ, fd );
        rte.sub_route.add_sub_route_str( X_HB   , X_HB_SZ   , fd );
        rte.sub_route.add_sub_route_str( X_BYE  , X_BYE_SZ  , fd );

        rte.sub_route.add_sub_route_str( Z_BLM  , Z_BLM_SZ  , fd );
        rte.sub_route.add_sub_route_str( Z_ADJ  , Z_ADJ_SZ  , fd );

        rte.sub_route.add_pattern_route_str( S_JOIN , S_JOIN_SZ , fd );
        rte.sub_route.add_pattern_route_str( S_LEAVE, S_LEAVE_SZ, fd );

        rte.sub_route.add_pattern_route_str( P_PSUB , P_PSUB_SZ , fd );
        rte.sub_route.add_pattern_route_str( P_PSTOP, P_PSTOP_SZ, fd );
      }
      if ( this->start_time > n.start_time ) {
        if ( n.start_time == 0 )
          n.printe( "bad start time %lu\n", n.start_time );
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
  if ( n.test_clear( IN_ROUTE_LIST_STATE ) ) {
    uint32_t count = this->transport_tab.count;
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
        if ( rte.uid_in_mesh->test_clear( n.uid ) )
          *rte.mesh_csum ^= n.bridge_id.nonce;
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
        rte.connected_auth.remove( fd );
        rte.sub_route.del_sub_route_str( X_HELLO, X_HELLO_SZ, fd );
        rte.sub_route.del_sub_route_str( X_HB,    X_HB_SZ   , fd );
        rte.sub_route.del_sub_route_str( X_BYE,   X_BYE_SZ  , fd );

        rte.sub_route.del_sub_route_str( Z_BLM,   Z_BLM_SZ  , fd );
        rte.sub_route.del_sub_route_str( Z_ADJ,   Z_ADJ_SZ  , fd );

        rte.sub_route.del_pattern_route_str( S_JOIN , S_JOIN_SZ , fd );
        rte.sub_route.del_pattern_route_str( S_LEAVE, S_LEAVE_SZ, fd );

        rte.sub_route.del_pattern_route_str( P_PSUB , P_PSUB_SZ , fd );
        rte.sub_route.del_pattern_route_str( P_PSTOP, P_PSTOP_SZ, fd );
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
    bool         has_route = false;

    this->pop_user_route( n, *u_ptr );
    u_ptr->hops = UserRoute::NO_HOPS;

    uint32_t count = this->transport_tab.count;
    for ( uint32_t i = 0; i < count; i++ ) {
      if ( (u_ptr = n.user_route_ptr( *this, i )) == NULL )
        break;
      if ( u_ptr->is_set( IN_ROUTE_LIST_STATE ) )
        has_route = true;
    }
    if ( ! has_route ) {
      n.clear( IN_ROUTE_LIST_STATE );
      return &n;
    }
    u_ptr = n.primary( *this );
    if ( ! u_ptr->is_valid() )
      this->add_inbox_route( n, NULL );
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
    rte = this->transport_tab.ptr[ p->tport ];
    n   = this->bridge_tab.ptr[ p->uid ];

    adj.tportid()
       .tport( rte->transport.tport.len );
    if ( n != NULL )
      adj.user( n->peer.user.len );
    else
      adj.user( this->user.user.len );
    adj.bridge2 ()
       .link_add();

    if ( debug_lnk )
      printf( "  %s %s\n", p->add ? "add" : "remove",
        n != NULL ? n->peer.user.val : this->user.user.val );

    this->uid_csum ^= p->nonce;
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
    rte = this->transport_tab.ptr[ p->tport ];
    s.tportid( p->tport );
    if ( tport_changed( last, p->tport ) )
      s.tport( rte->transport.tport.val, rte->transport.tport.len );
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

  size_t count = this->transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 ) {
      EvPublish pub( Z_ADJ, Z_ADJ_SZ, NULL, 0, m.msg, m.len(), this->my_src_fd,
                     adj_h, NULL, 0, (uint8_t) MSG_BUF_TYPE_ID, 'p' );
      rte->forward_to_connected( pub );
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
        n.printf( "already have link state %lu >= %lu\n", n.link_state_seqno,
                   link_state );
      adj_change = HAVE_ADJ_CHANGE;
    }
    else {
      if ( debug_lnk )
        n.printf( "missing link state %lu + 1 != %lu\n", n.link_state_seqno,
                   link_state );
      b = this->send_adjacency_request( n, ADJ_CHG_SYNC_REQ );
      adj_change = NEED_ADJ_SYNC;
    }
  }
  else {
    this->peer_dist.clear_cache_if_dirty();

    if ( debug_lnk )
      n.printf( "recv change link state %lu\n", link_state );
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
      AdjacencySpace * set   = NULL;
      uint32_t         tport = 0;
      StringVal        tport_sv,
                       user_sv;
      rec_list = rec.next;

      if ( rec.test( FID_TPORT ) )
        this->string_tab.ref_string( rec.tport_name, rec.tport_len, tport_sv );

      if ( rec.test( FID_TPORTID ) ) {
        tport = rec.tport;
        set   = n.adjacency.get( tport );
        if ( tport_sv.len > 0 )
          set->tport = tport_sv;
      }
      if ( rec.test( FID_USER ) )
        this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
      if ( rec.test( FID_BRIDGE ) && set != NULL ) {
        size_t   pos;
        uint32_t uid = 0;
        if ( this->node_ht->find( rec.nonce, pos, uid ) ||
             this->zombie_ht->find( rec.nonce, pos, uid ) ) {
          if ( uid != n.uid ) {
            if ( rec.add ) {
              if ( ! set->test_set( uid ) )
                n.uid_csum ^= rec.nonce;
            }
            else {
              if ( set->test_clear( uid ) )
                n.uid_csum ^= rec.nonce;
            }
          }
        }
        else {
          n.unknown_refs++;
          n.unknown_link_seqno = link_state;
          AdjPending *p =
            this->adjacency_unknown.update( pub.rte, rec.nonce, n.uid, tport,
                                            link_state, rec.add, set->tport,
                                            user_sv, ADJ_CHANGE_SYNC );
          if ( rec.add ) {
            UserBridge * m;
            uint32_t dist;
            m = this->closest_peer_route( pub.rte, n, dist );
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
UserDB::send_adjacency_request( UserBridge &n,  AdjacencyRequest reas ) noexcept
{
  if ( ! n.test_set( ADJACENCY_REQUEST_STATE ) ) {
    n.adj_mono_time = current_monotonic_time_ns();
    this->adj_queue.push( &n );
    this->events.send_adjacency_request( n.uid, n.user_route->rte.tport_id,
                                         0, reas );

    InboxBuf ibx( n.bridge_id, _ADJ_REQ );

    MsgEst e( ibx.len() );
    e.seqno       ()
     .link_state  ()
     .sub_seqno   ()
     .adj_info    ();

    MsgCat m;
    m.reserve( e.sz );

    m.open( this->bridge_id.nonce, ibx.len() )
     .seqno     ( ++n.send_inbox_seqno  )
     .link_state( n.link_state_seqno    )
     .sub_seqno ( n.sub_seqno           )
     .adj_info  ( reas                  );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->session_key );

    return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
  }
  return true;
}

bool
UserDB::send_adjacency_request2( UserBridge &n,  UserBridge &sync,
                                 AdjacencyRequest reas ) noexcept
{
  if ( ! n.test_set( ADJACENCY_REQUEST_STATE ) ) {
    n.adj_mono_time = current_monotonic_time_ns();
    this->adj_queue.push( &n );
    this->events.send_adjacency_request( n.uid, n.user_route->rte.tport_id,
                                         sync.uid, reas );
    InboxBuf ibx( n.bridge_id, _ADJ_REQ );

    MsgEst e( ibx.len() );
    e.seqno       ()
     .sync_bridge ()
     .link_state  ()
     .sub_seqno   ()
     .adj_info    ();

    MsgCat m;
    m.reserve( e.sz );

    m.open( this->bridge_id.nonce, ibx.len() )
     .seqno       ( ++n.send_inbox_seqno  )
     .sync_bridge ( sync.bridge_id.nonce  )
     .link_state  ( sync.link_state_seqno )
     .sub_seqno   ( sync.sub_seqno        )
     .adj_info    ( reas                  );
    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->session_key );

    return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
  }
  return true;
}

size_t
UserDB::adjacency_size( UserBridge *sync ) noexcept
{
  UserBridge * n2;
  uint32_t     i, uid, count, last;

  MsgEst e;
  if ( sync != NULL ) { /* sync adjacency */
    UserBridge &n = *sync;
    count = n.adjacency.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      AdjacencySpace * set = n.adjacency.ptr[ i ];
      if ( set != NULL ) {
        for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
          if ( uid == MY_UID ) {
            e.tportid();
            if ( tport_changed( last, i ) )
              e.tport( set->tport.len );
            e.user   ( this->user.user.len )
             .bridge2();
          }
          else {
            n2 = this->bridge_tab.ptr[ uid ];
            if ( n2 != NULL ) {
              e.tportid();
              if ( tport_changed( last, i ) )
                e.tport( set->tport.len );
              e.user   ( n2->peer.user.len )
               .bridge2();
            }
          }
        }
      }
    }
  }
  else { /* my adjacency */
    count = this->transport_tab.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      TransportRoute * rte = this->transport_tab.ptr[ i ];
      if ( rte != NULL ) {
        for ( bool ok = rte->uid_connected.first( uid ); ok;
              ok = rte->uid_connected.next( uid ) ) {
          n2 = this->bridge_tab.ptr[ uid ];
          if ( n2 != NULL ) {
            e.tportid();
            if ( tport_changed( last, i ) )
              e.tport( rte->transport.tport.len );
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
    count = n.adjacency.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      AdjacencySpace * set = n.adjacency.ptr[ i ];
      if ( set != NULL ) {
        for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
          if ( uid == MY_UID ) {
            s.tportid( i );
            if ( tport_changed( last, i ) )
              s.tport( set->tport.val, set->tport.len );
            s.user   ( this->user.user.val, this->user.user.len )
             .bridge2( this->bridge_id.nonce );
          }
          else {
            n2 = this->bridge_tab.ptr[ uid ];
            if ( n2 != NULL ) {
              s.tportid( i );
              if ( tport_changed( last, i ) )
                s.tport( set->tport.val, set->tport.len );
              s.user   ( n2->peer.user.val, n2->peer.user.len )
               .bridge2( n2->bridge_id.nonce );
            }
          }
        }
      }
    }
  }
  else { /* my adjacency */
    count = this->transport_tab.count;
    last  = count;
    for ( i = 0; i < count; i++ ) {
      TransportRoute * rte = this->transport_tab.ptr[ i ];
      if ( rte != NULL ) {
        for ( bool ok = rte->uid_connected.first( uid ); ok;
              ok = rte->uid_connected.next( uid ) ) {
          n2 = this->bridge_tab.ptr[ uid ];
          if ( n2 != NULL ) {
            s.tportid( i );
            if ( tport_changed( last, i ) )
              s.tport( rte->transport.tport.val, rte->transport.tport.len );
            s.user   ( n2->peer.user.val, n2->peer.user.len )
             .bridge2( n2->bridge_id.nonce );
          }
        }
      }
    }
  }
  s.close( m, FID_ADJACENCY );
}

bool
UserDB::recv_adjacency_request( const MsgFramePublish &,  UserBridge &n,
                                const MsgHdrDecoder &dec ) noexcept
{
  BloomCodec   code;
  UserBridge * sync  = NULL;
  Nonce        nonce;
  char         ret_buf[ 16 ];
  InboxBuf     ibx( n.bridge_id, dec.get_return( ret_buf, _ADJ_RPY ) );
  uint64_t     link_seqno = 0,
               sub_seqno  = 0,
               time_val,
               rq_link_seqno,
               rq_sub_seqno;
  uint32_t     uid        = 0,
               hops       = 1,
               reas;

  dec.get_ival<uint64_t>( FID_LINK_STATE, rq_link_seqno );
  dec.get_ival<uint64_t>( FID_SUB_SEQNO, rq_sub_seqno );
  dec.get_ival<uint32_t>( FID_ADJ_INFO, reas );
  dec.get_ival<uint64_t>( FID_TIME, time_val );

  if ( dec.get_nonce( FID_SYNC_BRIDGE, nonce ) ) {
    size_t pos;
    if ( ! this->node_ht->find( nonce, pos, uid ) )
      return true;
  }

  MsgEst e( ibx.len() );
  e.seqno      ()
   .link_state ()
   .sub_seqno  ()
   .hops       ()
   .adj_info   ()
   .time       ()
   .sync_bridge();

  if ( uid != 0 ) {
    sync       = this->bridge_tab.ptr[ uid ];
    link_seqno = sync->link_state_seqno;
    sub_seqno  = sync->sub_seqno;
    if ( n.user_route->rte.uid_connected.is_member( sync->uid ) &&
         n.user_route->rte.uid_connected.is_member( n.uid ) )
      hops = 0;
  }
  else {
    sync       = NULL;
    link_seqno = this->link_state_seqno;
    sub_seqno  = this->sub_db.sub_seqno;
    if ( n.user_route->rte.uid_connected.is_member( n.uid ) )
      hops = 0;
  }
  if ( rq_link_seqno != link_seqno ) {
    e.adjacency( this->adjacency_size( sync ) );
  }
  if ( rq_sub_seqno != sub_seqno ) {
    if ( sync != NULL )
      sync->bloom.encode( code );
    else
      this->sub_db.bloom.encode( code );
    e.bloom( code.code_sz * 4 );
  }

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno     ( ++n.send_inbox_seqno )
   .link_state( link_seqno           )
   .sub_seqno ( sub_seqno            )
   .hops      ( hops                 )
   .adj_info  ( reas                 );
  if ( time_val != 0 )
    m.time( time_val );
  if ( dec.test( FID_SYNC_BRIDGE ) )
    m.sync_bridge( nonce );

  d_lnk( "recv_adj_request(%s,%lu,%lu)\n",
       sync == NULL ? "me" : sync->peer.user.val, rq_sub_seqno, rq_link_seqno );

  if ( rq_sub_seqno != sub_seqno ) {
    m.bloom( code.ptr, code.code_sz * 4 );
  }
  if ( rq_link_seqno != link_seqno ) {
    this->adjacency_submsg( sync, m );
  }
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  this->events.recv_adjacency_request( n.uid, n.user_route->rte.tport_id,
                                       ( sync == NULL ? 0 : sync->uid ), reas );
  return this->forward_to_inbox( n, ibx, h, m.msg, m.len(), false );
}

bool
UserDB::recv_adjacency_result( const MsgFramePublish &pub,  UserBridge &n,
                               MsgHdrDecoder &dec ) noexcept
{
  if ( n.test_clear( ADJACENCY_REQUEST_STATE ) )
    this->adj_queue.remove( &n );
  if ( ! dec.test_2( FID_LINK_STATE, FID_SUB_SEQNO ) )
    return true;
  Nonce        nonce;
  uint64_t     link_state,
               sub_seqno;
  uint32_t     reas;
  UserBridge * sync = NULL;

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

  dec.get_ival<uint64_t>( FID_LINK_STATE, link_state );
  dec.get_ival<uint64_t>( FID_SUB_SEQNO, sub_seqno );
  dec.get_ival<uint32_t>( FID_ADJ_INFO, reas );

  if ( debug_lnk )
    n.printf( "recv_adj_result(%s,lnk=%lu,blm=%lu,%u)\n", sync->peer.user.val,
              link_state, sub_seqno, reas );

  if ( reas == UNKNOWN_ADJ_REQ ) /* from a sync_result, sync_req -> sync_rpy */
    reas = PEER_SYNC_REQ;
  this->events.recv_adjacency_result( n.uid, pub.rte.tport_id,
                                      sync == &n ? 0 : sync->uid, reas );

  if ( dec.test( FID_ADJACENCY ) && link_state > sync->link_state_seqno ) {
    AdjacencyRec * rec_list =
      dec.decode_rec_list<AdjacencyRec>( FID_ADJACENCY );
    if ( debug_lnk )
      AdjacencyRec::print_rec_list( rec_list, "recv_result" );

    sync->uid_csum.zero();
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
      uint32_t       tport = 0;
      StringVal      tport_sv;
      rec_list = rec.next;

      if ( rec.test( FID_TPORT ) )
        this->string_tab.ref_string( rec.tport_name, rec.tport_len, tport_sv );

      if ( rec.test( FID_TPORTID ) ) {
        tport = rec.tport;
        set   = sync->adjacency.get( tport );
        if ( tport_sv.len > 0 )
          set->tport = tport_sv;
      }
      else {
        set = NULL;
      }
      if ( rec.test( FID_USER ) )
        this->string_tab.ref_string( rec.user, rec.user_len, user_sv );
      if ( rec.test( FID_BRIDGE ) && set != NULL ) {
        size_t   pos;
        uint32_t uid = 0;
        if ( this->node_ht->find( rec.nonce, pos, uid ) ||
             this->zombie_ht->find( rec.nonce, pos, uid ) ) {
          if ( uid != sync->uid && set != NULL ) {
            sync->uid_csum ^= rec.nonce;
            set->add( uid );
          }
        }
        else {
          sync->unknown_refs++;
          sync->unknown_link_seqno = link_state;
          AdjPending *p =
            this->adjacency_unknown.update( pub.rte, rec.nonce, sync->uid,
                                            tport, link_state, true, set->tport,
                                            user_sv, ADJ_RESULT_SYNC );
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
  if ( dec.test( FID_BLOOM ) && sub_seqno > sync->sub_seqno )
    this->sub_db.recv_bloom( pub, *sync, dec );

  return true;
}

void
AdjDistance::clear_cache( void ) noexcept
{
  uint32_t max      = this->user_db.next_uid,
           rte_cnt  = this->user_db.transport_tab.count;
  this->cache_seqno = this->update_seqno;
  this->max_tport   = rte_cnt;
  this->max_uid     = max;
  this->cache.set_max_value( max + 1 );      /* 0 = invalid */
  this->reuse();
  if ( ( rte_cnt & 1 ) != 0 )
    rte_cnt++;
  size_t isz  = ( max + 63 ) / 64,
         wsz  = this->cache.index_word_size( this->max_tport * max ),
         size = max * sizeof( UidDist ) +    /* stack */
                max * sizeof( uint32_t ) +   /* visit */
                max * sizeof( uint32_t ) +   /* inc_list */
                max * sizeof( UidMissing ) + /* missing */
                isz * sizeof( uint64_t ) +   /* inc_visit */
                wsz * sizeof( uint64_t );    /* cache */
                /*rte_cnt * sizeof( uint32_t ); * tport_dist */

  d_lnk( "ADJacency clear cache %lu wsz=%lu max_tport=%u max_uid=%u\n",
          this->update_seqno, wsz, this->max_tport, max );
  /*this->tport_dist    = (uint32_t *) this->make( size );
  this->cache.ptr     = (uint64_t *) (void *) &this->tport_dist[ rte_cnt ];*/
  this->cache.ptr     = (uint64_t *) this->make( size );
  this->inc_visit.ptr = &this->cache.ptr[ wsz ];
  this->stack         = (UidDist *) (void *) &this->inc_visit.ptr[ isz ];
  this->visit         = (uint32_t *) (void *) &this->stack[ max ];
  this->inc_list      = &this->visit[ max ];
  this->missing       = (UidMissing *) (void *) &this->inc_list[ max ];
  this->miss_tos      = 0;
  this->inc_hd        = 0;
  this->inc_tl        = 0;
  this->inc_run_count = 0;
  this->last_run_mono = current_monotonic_time_ns();
  this->inc_running   = false;
  this->found_inconsistency = false;
  ::memset( this->cache.ptr, 0, wsz * sizeof( uint64_t ) );
  ::memset( this->inc_visit.ptr, 0, isz * sizeof( uint64_t ) );
}

uint32_t
AdjDistance::adjacency_count( uint32_t uid ) const noexcept
{
  if ( uid == 0 )
    return this->user_db.transport_tab.count;
  if ( ! this->user_db.uid_authenticated.is_member( uid ) )
    return 0;
  return this->user_db.bridge_tab.ptr[ uid ]->adjacency.count;
}

BitSpace *
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

uint32_t
AdjDistance::uid_refs( uint32_t from,  uint32_t to ) noexcept
{
  size_t count  = this->adjacency_count( from );
  uint32_t refs = 0;
  for ( size_t i = 0; i < count; i++ ) {
    BitSpace * set = this->adjacency_set( from, i );
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
    if ( uid != to ) {
      uint32_t refs = this->uid_refs( uid, to );
      if ( debug_lnk && refs > 0 ) {
        printf( "ref %s -> %s\n",
              uid == 0 ? "me" : this->user_db.bridge_tab[ uid ]->peer.user.val,
              to == 0 ? "me" : this->user_db.bridge_tab[ to ]->peer.user.val );
      }
      found += refs;
    }
  }
  return found;
}

uint32_t
AdjDistance::outbound_refs( uint32_t from ) noexcept
{
  uint32_t uid, found = 0;

  for ( uid = 0; uid < this->max_uid; uid++ ) {
    if ( uid != from ) {
      uint32_t refs = this->uid_refs( from, uid );
      if ( debug_lnk && refs > 0 ) {
        printf( "ref %s -> %s\n",
            from == 0 ? "me" : this->user_db.bridge_tab[ from ]->peer.user.val,
            uid == 0 ? "me" : this->user_db.bridge_tab[ uid ]->peer.user.val );
      }
      found += refs;
    }
  }
  return found;
}

bool
AdjDistance::find_inconsistent2( UserBridge *&from,
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
      BitSpace &set = this->user_db.transport_tab.ptr[ i ]->uid_connected;
      for ( bool ok = set.first( uid ); ok; ok = set.next( uid ) ) {
        if ( ! this->inc_visit.test_set( uid ) )
          this->inc_list[ --this->inc_hd ] = uid;
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
      BitSpace * set = n->adjacency.ptr[ j ];
      if ( set == NULL )
        continue;
      for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
        if ( uid2 == 0 )
          continue;
        /* check uid2 if not visisted */
        if ( ! this->inc_visit.test_set( uid2 ) ) {
          if ( this->inc_hd == 0 ) { /* clear space */
            this->inc_hd += this->max_uid - this->inc_tl;
            this->inc_tl  = this->max_uid;
            ::memmove( &this->inc_list[ this->inc_hd ], this->inc_list,
                       ( this->inc_tl - this->inc_hd ) * sizeof( uint32_t ) );
          }
          this->inc_list[ --this->inc_hd ] = uid2;
        }
        UserBridge *m = this->user_db.bridge_tab.ptr[ uid2 ];
        bool found = false;
        /* check if uids connected to my connected peer are connected back */
        for ( size_t k = 0; k < m->adjacency.count; k++ ) {
          BitSpace * set3 = m->adjacency.ptr[ k ];
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
  if ( this->inc_tl > this->inc_hd ) {
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
    this->last_run_mono = current_monotonic_time_ns();
  }
  return false;
}

bool
AdjDistance::is_consistent( void ) noexcept
{
  bool res = true;
  uint32_t uid, uid2, found, found2;

  for ( uid = 0; uid < this->max_uid; uid++ ) {
    for ( uid2 = uid + 1; uid2 < this->max_uid; uid2++ ) {
      found  = this->uid_refs( uid, uid2 );
      found2 = this->uid_refs( uid2, uid );

      if ( found != found2 ) {
        printf( "uid=%s(%u) uid2=%s(%u) differ in=%u out=%u\n",
                uid == 0 ? "me" :
                  this->user_db.bridge_tab[ uid ]->peer.user.val, uid,
                uid2 == 0 ? "me" :
                  this->user_db.bridge_tab[ uid2 ]->peer.user.val, uid2,
                found, found2 );
                res = false;
      }
    }
  }
  return res;
}

uint32_t
AdjDistance::calc_distance( uint32_t dest_uid ) noexcept
{
  this->clear_cache_if_dirty();
  uint32_t max = this->max_uid;
  for ( uint32_t i = 0; i < this->max_tport; i++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ i ];
    size_t   off = rte->tport_id * this->max_uid + dest_uid;
    uint32_t d   = this->cache.get( off );
    if ( d != 0 )
      d -= 1;
    else {
      d = this->calc_transport( dest_uid, *rte );
      this->cache.set( off, d + 1 );
    }
    if ( d < max ) {
      max = d;
      if ( max == 0 )
        break;
    }
  }
  return max;
}

uint32_t
AdjDistance::calc_transport_cache3( uint32_t dest_uid,  uint32_t tport_id,
                                    TransportRoute &rte ) noexcept
{
  size_t   off = tport_id * this->max_uid + dest_uid;
  uint32_t d   = this->calc_transport( dest_uid, rte );
  this->cache.set( off, d + 1 );
  return d;
}
/* find dest through transport */
uint32_t
AdjDistance::calc_transport( uint32_t dest_uid,
                             TransportRoute &rte ) noexcept
{
  if ( rte.uid_connected.is_member( dest_uid ) )
    return 0; /* directly connected */

  uint32_t i, uid, tos = 0;
  this->visit[ 0 ] = 0; /* exclude self from routing */
  for ( i = 1; i < this->max_uid; i++ )
    this->visit[ i ] = this->max_uid; /* set other nodes as not reachable */
  /* push transport connected uids */
  for ( bool ok = rte.uid_connected.first( uid ); ok;
        ok = rte.uid_connected.next( uid ) ) {
    this->visit[ uid ] = 0; /* mark visited */
    if ( this->user_db.bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->user_db.bridge_tab.ptr[ uid ];

    for ( i = 0; i < n.adjacency.count; i++ ) {
      BitSpace * set = n.adjacency.ptr[ i ];
      uint32_t   uid2;
      if ( set == NULL )
        continue;
      if ( set->is_member( dest_uid ) )
        return 1; /* dest is directly connected through uid */

      for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
        if ( this->visit[ uid2 ] > 1 ) {
          this->visit[ uid2 ] = 1;
          this->stack[ tos ].uid  = uid2;
          this->stack[ tos ].dist = 1;
          tos++;
        }
      }
    }
  }
  return this->search( dest_uid, tos ); /* search transport to find dest */
}

void
AdjDistance::calc_reachable( TransportRoute &rte ) noexcept
{
  uint32_t i, uid, uid2, tos = 0;
  this->clear_cache_if_dirty();
  rte.reachable.zero();
  rte.reachable_seqno = this->cache_seqno;
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
    rte.reachable.add( uid );
    for ( i = 0; i < n.adjacency.count; i++ ) {
      BitSpace * set = n.adjacency.ptr[ i ];
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

uint32_t
AdjDistance::fill_to_dist( uint32_t tos,  uint32_t maxdist,
                           PeerUidSet &visit,  PeerUidSet &peers ) noexcept
{
  uint32_t peer_count = 0;
  while ( tos > 0 ) {
    uint32_t uid = this->stack[ --tos ].uid,
             d   = this->stack[ tos ].dist;
    if ( d == maxdist ) {
      //printf( "fill.add %u\n", uid );
      peers.add( uid );
      peer_count++;
      continue;
    }
    uint32_t count = this->adjacency_count( uid );
    if ( count == 0 )
      continue;
    for ( uint32_t i = 0; i < count; i++ ) {
      BitSpace * set = this->adjacency_set( uid, i );
      uint32_t   uid2;
      if ( set == NULL )
        continue;
      for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
        if ( ! visit.test_set( uid2 ) ) {
          //printf( "%u.fill (%u,d=%u)\n", uid, uid2, d + 1 );
          this->stack[ tos ].uid  = uid2;
          this->stack[ tos ].dist = d + 1;
          tos++;
        }
      }
    }
  }
  return peer_count;
}

uint32_t
AdjDistance::push_peer( uint32_t peer_uid,  uint32_t dist,
                        PeerUidSet &visit ) noexcept
{
  uint32_t count = this->adjacency_count( peer_uid ), tos = 0;
  visit.src_uid = peer_uid;
  visit.add( peer_uid );
  for ( uint32_t i = 0; i < count; i++ ) {
    BitSpace * set = this->adjacency_set( peer_uid, i );
    uint32_t   uid;
    if ( set == NULL )
      continue;

    for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
      if ( ! visit.test_set( uid ) ) {
        //printf( "%u.push (%u,d=%u)\n", peer_uid, uid, dist + 1 );
        this->stack[ tos ].uid  = uid;
        this->stack[ tos ].dist = dist + 1;
        tos++;
      }
    }
  }
  return tos;
}

uint32_t
AdjDistance::find_best_route( void ) noexcept
{
  PeerUidSet * rec = NULL,
             * tmp = NULL;
  uint32_t     peer_uid,
               rcount = 0;
  /* compare the route destinations for each peer, find which are preferred:
   *  - unique route, no other tport goes there
   *  - redundant route, use the tport with more destinations
   *  - redundant route, use the tport attached to the oldest peer */
  for ( bool ok = this->uid_peers.first( peer_uid ); ok;
        ok = this->uid_peers.next( peer_uid ) ) {
    uint32_t count = this->adjacency_count( peer_uid );
    for ( uint32_t i = 0; i < count; i++ ) {
      BitSpace *set = this->adjacency_set( peer_uid, i );
      if ( set == NULL )
        continue;
      if ( rec == NULL )
        rec = this->uid_free.get( this->max_uid );
      else
        rec->reset( this->max_uid );
      rec->or_bits( this->uid_visit );
      rec->tport_id = i;
      rec->dest_count = 0;
      uint32_t uid;
      /* for this tport, find which nodes are reachable */
      for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
        if ( ! rec->test_set( uid ) ) {
          if ( rec->dest_count++ == 0 )
            rec->first_uid = uid;
          rec->last_uid = uid;
        }
      }
      /* if this tport has a new dest not visited */
      if ( rec->dest_count > 0 ) {
        rec->src_uid = peer_uid;
        rec->not_bits( this->uid_visit ); /* mask out already visited */
        /* compare the new tport with existing routes computed */
        for ( uint32_t j = 0; j < this->uid_next.idx; j++ ) {
          PeerUidSet * test = this->uid_next.ptr[ j ];
          if ( rec->first_uid <= test->last_uid && /* may be better candidate */
               rec->last_uid  >= test->first_uid ) {
            if ( tmp == NULL )
              tmp = this->uid_free.get( this->max_uid );
            else
              tmp->reset( this->max_uid );
            if ( rec->dest_count >= test->dest_count ) { /* if new is >= old */
              tmp->or_bits( *test );
              tmp->not_bits( *rec );
              if ( tmp->count() == 0 ) { /* equivalent route */
                if ( rec->dest_count > test->dest_count || /* more dests */
                     this->adjacency_start( rec->src_uid ) < /* or older */
                     this->adjacency_start( test->src_uid ) ) {
                  this->uid_next.ptr[ j ] = rec; /* replace better route */
                  rec = test;
                  goto break_loop;
                }
                else { /* discard route */
                  goto break_loop; /* existing is better */
                }
              }
            }
            else { /* if ( rec->dest_count < test->dest_count ) */
              tmp->or_bits( *rec );
              tmp->not_bits( *test );
              if ( tmp->count() == 0 ) /* existing is better */
                goto break_loop;
            }
          }
        }
        this->uid_next.append( rec );
        rcount++;
        rec = NULL;
      break_loop:;
      }
    }
  }
  return rcount;
}

bool
AdjDistance::get_primary_tport( uint32_t dest_uid,
                                uint32_t &dest_tport ) noexcept
{
  if ( this->primary_seqno != this->update_seqno )
    this->calc_primary();

  for (;;) {
    PeerUidSet *rec = this->primary_rec.ptr[ dest_uid ];
    if ( rec == NULL )
      return false;
    if ( rec->src_uid == UserDB::MY_UID ) {
      dest_tport = rec->tport_id;
      return true;
    }
    dest_uid = rec->src_uid;
  }
}

void
AdjDistance::calc_primary( void ) noexcept
{
  if ( this->primary_seqno != this->update_seqno ) {
    uint32_t dist, k, count, uid;
    this->primary_seqno = this->update_seqno;
    this->uid_free.requeue( this->uid_primary );
    this->primary_rec.zero();
    this->primary_rec.resize( this->max_uid, true );

    for ( dist = 0; ; dist++ ) {
      if ( this->calc_dist_peers( 0, dist ) == 0 )
        break;
      count = this->uid_next.idx;
      for ( k = 0; k < count; k++ ) {
        PeerUidSet * rec = this->uid_next.ptr[ k ];
        this->uid_primary.append( rec );
        this->uid_free.ptr[ rec->rec_idx ] = NULL;
        for ( bool ok = rec->first( uid ); ok; ok = rec->next( uid ) ) {
          this->primary_rec.ptr[ uid ] = rec;
        }
      }
    }
  }
}

uint32_t
AdjDistance::calc_dist_peers( uint32_t src_uid,  uint32_t dist ) noexcept
{
  uint32_t tos, pcount, rcount = 0;

  this->clear_cache_if_dirty();
  this->uid_peers.reset( this->max_uid );
  this->uid_visit.reset( this->max_uid );
  this->uid_free.reset();
  this->uid_next.reset();

  /* push transport connected uids */
  if ( dist == 0 ) {
    this->uid_peers.add( src_uid );
    pcount = 1;
  }
  else {
    tos    = this->push_peer( src_uid, 0, this->uid_visit );
    pcount = this->fill_to_dist( tos, dist, this->uid_visit, this->uid_peers );
  }
  if ( pcount > 0 )
    rcount = this->find_best_route();

  return rcount;
}

uint32_t
AdjDistance::find_best_route2( void ) noexcept
{
  char src_buf[ 80 ], peer_buf[ 1024 ];
  PeerUidSet *rec = NULL, *tmp = NULL;
  uint32_t peer_uid, rcount = 0;

  for ( bool ok = this->uid_peers.first( peer_uid ); ok;
        ok = this->uid_peers.next( peer_uid ) ) {
    uint32_t count = this->adjacency_count( peer_uid );
    for ( uint32_t i = 0; i < count; i++ ) {
      BitSpace *set = this->adjacency_set( peer_uid, i );
      if ( set == NULL )
        continue;
      if ( rec == NULL )
        rec = this->uid_free.get( this->max_uid );
      else
        rec->reset( this->max_uid );
      rec->or_bits( this->uid_visit );
      rec->tport_id = i;
      rec->dest_count = 0;
      uint32_t uid;
      for ( bool ok = set->first( uid ); ok; ok = set->next( uid ) ) {
        if ( ! rec->test_set( uid ) ) {
          if ( rec->dest_count++ == 0 )
            rec->first_uid = uid;
          rec->last_uid = uid;
        }
      }
      if ( rec->dest_count > 0 ) { /* has a new dest not visited */
        rec->src_uid = peer_uid;
        rec->not_bits( this->uid_visit );
        printf( "test rec %s peers %s\n", 
         this->uid_name( rec->src_uid, src_buf, sizeof( src_buf ) ),
         this->uid_set_names( *rec, peer_buf, sizeof( peer_buf ) ) );
        for ( uint32_t j = 0; j < this->uid_next.idx; j++ ) {
          PeerUidSet * test = this->uid_next.ptr[ j ]; /* find others */
          printf( "%s dest count %u[%u->%u], %s test dest count %u[%u->%u]\n",
            this->uid_name( rec->src_uid, src_buf, sizeof( src_buf ) ),
            rec->dest_count, rec->first_uid, rec->last_uid,
            this->uid_name( test->src_uid, peer_buf, sizeof( peer_buf ) ),
            test->dest_count, test->first_uid, test->last_uid  );
          if ( rec->first_uid <= test->last_uid && /* may be better candidate */
               rec->last_uid  >= test->first_uid ) {
            if ( tmp == NULL )
              tmp = this->uid_free.get( this->max_uid );
            else
              tmp->reset( this->max_uid );
            if ( rec->dest_count >= test->dest_count ) { /* if new is >= old */
              tmp->or_bits( *test );
              tmp->not_bits( *rec );
              if ( tmp->count() == 0 ) { /* equivalent route */
                if ( rec->dest_count > test->dest_count || /* more dests */
                     this->adjacency_start( rec->src_uid ) < /* or older */
                     this->adjacency_start( test->src_uid ) ) {
                  printf( "%s replace with %s\n",
                this->uid_name( test->src_uid, src_buf, sizeof( src_buf ) ),
                this->uid_name( rec->src_uid, peer_buf, sizeof( peer_buf ) ) );
                  this->uid_next.ptr[ j ] = rec; /* replace better route */
                  rec = test;
                  goto break_loop;
                }
                else { /* discard route */
                  goto break_loop; /* existing is better */
                }
              }
            }
            else { /* if ( rec->dest_count < test->dest_count ) */
              tmp->or_bits( *rec );
              tmp->not_bits( *test );
              if ( tmp->count() == 0 ) /* existing is better */
                goto break_loop;
            }
          }
        }
        printf( "append[%u] from %s using peers %s\n", this->uid_next.idx,
         this->uid_name( rec->src_uid, src_buf, sizeof( src_buf ) ),
         this->uid_set_names( *rec, peer_buf, sizeof( peer_buf ) ) );
        this->uid_next.append( rec );
        rcount++;
        rec = NULL;
      break_loop:;
      }
    }
  }
  return rcount;
}

uint32_t
AdjDistance::calc_dist_peers2( uint32_t src_uid,  uint32_t dist ) noexcept
{
  uint32_t tos, pcount, rcount = 0;

  this->clear_cache_if_dirty();
  this->uid_peers.reset( this->max_uid );
  this->uid_visit.reset( this->max_uid );
  this->uid_free.reset();
  this->uid_next.reset();

  /* push transport connected uids */
  if ( dist == 0 ) {
    this->uid_peers.add( src_uid );
    pcount = 1;
  }
  else {
    tos    = this->push_peer( src_uid, 0, this->uid_visit );
    pcount = this->fill_to_dist( tos, dist, this->uid_visit, this->uid_peers );
  }
  if ( pcount > 0 ) {
    char src_buf[ 80 ], peer_buf[ 1024 ];
    printf( "calc_dist from %s using peers %s\n",
        this->uid_name( src_uid, src_buf, sizeof( src_buf ) ),
        this->uid_set_names( this->uid_peers, peer_buf, sizeof( peer_buf ) ) );
    rcount = this->find_best_route2();
  }

  return rcount;
}
/* find dest through src */
uint32_t
AdjDistance::calc_distance_from( UserBridge &src,
                                 uint32_t dest_uid ) noexcept
{
  this->visit[ 0 ] = 0; /* exclude self from routing */
  for ( uint32_t i = 1; i < this->max_uid; i++ )
    this->visit[ i ] = this->max_uid; /* set other nodes as not reachable */

  uint32_t i, tos = 0;
  this->visit[ src.uid ] = 0; /* start here */

  for ( i = 0; i < src.adjacency.count; i++ ) {
    BitSpace * set = src.adjacency.ptr[ i ];
    uint32_t   uid2;
    if ( set == NULL )
      continue;
    if ( set->is_member( dest_uid ) ) /* directly attached to src */
      return 1;
    for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
      if ( this->visit[ uid2 ] > 1 ) {
        /*this->print( "push", uid2, 1 );*/
        this->visit[ uid2 ] = 1;
        this->stack[ tos ].uid  = uid2; /* search through uid2 */
        this->stack[ tos ].dist = 1;
        tos++;
      }
    }
  }
  return this->search( dest_uid, tos ); /* search src adjacency to find dest */
}

uint32_t
AdjDistance::search( uint32_t dest_uid,  uint32_t tos ) noexcept
{
  uint32_t min_dist = this->max_uid;

  while ( tos > 0 ) {
    uint32_t j = this->stack[ --tos ].uid,
             d = this->stack[ tos ].dist;
    if ( d + 1 >= min_dist )
      continue;
    if ( this->user_db.bridge_tab.ptr[ j ] == NULL )
      continue;
    UserBridge &n = *this->user_db.bridge_tab.ptr[ j ];
    for ( size_t i = 0; i < n.adjacency.count; i++ ) {
      BitSpace * set = n.adjacency.ptr[ i ];
      uint32_t   uid;
      bool       ok;
      if ( set == NULL )
        continue;
      if ( set->is_member( dest_uid ) ) {
        if ( this->visit[ dest_uid ] > d + 1 )
          this->visit[ dest_uid ] = d + 1;
        if ( d + 1 < min_dist )
          min_dist = d + 1;
      }
      else {
        for ( ok = set->first( uid ); ok; ok = set->next( uid ) ) {
          if ( this->visit[ uid ] > d + 1 ) {
            this->visit[ uid ] = d + 1;
            this->stack[ tos ].uid  = uid;
            this->stack[ tos ].dist = d + 1;
            tos++;
          }
        }
      }
    }
  }
  return min_dist;
}

const char *
AdjDistance::uid_name( uint32_t uid,  char *buf,  size_t buflen ) noexcept
{
  size_t off = 0;
  buf[ 0 ] = '\0';
  this->uid_name( uid, buf, off, buflen );
  if ( off == buflen )
    off--;
  buf[ off ] = '\0';
  return buf;
}

const char *
AdjDistance::uid_name( uint32_t uid,  char *buf,  size_t &off,
                       size_t buflen ) noexcept
{
  if ( this->user_db.bridge_tab.ptr[ uid ] == NULL ) {
    if ( uid == UserDB::MY_UID )
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
AdjDistance::uid_set_names( const PeerUidSet &rec,  char *buf,
                            size_t buflen ) noexcept
{
  uint32_t uid;
  size_t   off = 0;
  buf[ 0 ] = '\0';
  for ( bool ok = rec.first( uid ); ok; ok = rec.next( uid ) ) {
    this->uid_name( uid, buf, off, buflen );
    if ( off < buflen )
      buf[ off++ ] = ' ';
  }
  if ( off > 0 )
    buf[ off - 1 ] = '\0';
  return buf;
}

#if 0
bool
AdjDistance::push_transport( UserBridge &dest,
                             TransportRoute &rte,
                             uint32_t &tos ) noexcept
{
  uint32_t uid;
  for ( bool ok = rte.uid_connected.first( uid ); ok;
        ok = rte.uid_connected.next( uid ) ) {
    this->visit[ uid ] = 0;
    if ( this->user_db.bridge_tab.ptr[ uid ] == NULL )
      continue;
    UserBridge &n = *this->user_db.bridge_tab.ptr[ uid ];

    for ( size_t i = 0; i < n.adjacency.count; i++ ) {
      BitSpace * set = n.adjacency.ptr[ i ];
      uint32_t   uid2;
      if ( set == NULL )
        continue;
      if ( set->is_member( dest.uid ) ) {
        /*this->print( "found_1", dest.uid, 1 );*/
        return true;
      }
      for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
        if ( this->visit[ uid2 ] > 1 ) {
          /*this->print( "push", uid2, 1 );*/
          this->visit[ uid2 ] = 1;
          this->stack[ tos ].uid  = uid2;
          this->stack[ tos ].dist = 1;
          tos++;
        }
      }
    }
  }
  return false;
}
#endif
void
AdjDistance::print( const char *what,  TransportRoute &rte,  uint32_t uid,
                    uint32_t d ) noexcept
{
  printf( "%s to %s: %s(%u) d=%u\n", what, rte.name,
          this->user_db.bridge_tab.ptr[ uid ]->peer.user.val, uid, d );
}
void
AdjDistance::print( const char *what,  uint32_t uid,  uint32_t d ) noexcept
{
  printf( "%s: %s(%u) d=%u\n", what,
          this->user_db.bridge_tab.ptr[ uid ]->peer.user.val, uid, d );
}
#if 0
uint32_t
AdjDistance::calc_min( UserBridge &start,  UserBridge &dest ) noexcept
{
  if ( start.uid == dest.uid ) {
    this->print( "found", dest.uid, 0 );
    return 0;
  }
  BitSpace * set;
  size_t     i, uid;
  uint32_t   tos = 0;
  bool       ok;

  for ( i = 0; i < start.adjacency.count; i++ ) {
    set = start.adjacency[ i ];
    if ( set == NULL )
      continue;
    if ( set->is_member( dest.uid ) ) {
      this->print( "found", dest.uid, 1 );
      return 1;
    }
    for ( ok = set->first( uid ); ok; ok = set->next( uid ) ) {
      if ( this->visit[ uid ] > 1 ) {
        this->print( "push", uid, 1 );
        this->visit[ uid ] = 1;
        this->stack[ tos ].uid  = uid;
        this->stack[ tos ].dist = 1;
        tos++;
      }
    }
  }
  uint32_t max = this->max_uid,
           j, d;
  while ( tos > 0 ) {
    j = this->stack[ --tos ].uid;
    d = this->stack[ tos ].dist;
    this->print( "pop", j, d );
    if ( d + 1 >= max )
      continue;
    if ( this->user_db.bridge_tab[ j ] == NULL )
      continue;
    UserBridge &n = *this->user_db.bridge_tab[ j ];
    for ( i = 0; i < n.adjacency.count; i++ ) {
      set = n.adjacency[ i ];
      if ( set == NULL )
        continue;
      if ( set->is_member( dest.uid ) ) {
        this->print( "found", dest.uid, d + 1 );
        if ( this->visit[ dest.uid ] > d + 1 )
          this->visit[ dest.uid ] = d + 1;
        if ( d + 1 < max )
          max = d + 1;
      }
      else {
        for ( ok = set->first( uid ); ok; ok = set->next( uid ) ) {
          if ( this->visit[ uid ] > d + 1 ) {
            this->print( "push", uid, d + 1 );
            this->visit[ uid ] = d + 1;
            this->stack[ tos ].uid  = uid;
            this->stack[ tos ].dist = d + 1;
            tos++;
          }
        }
      }
    }
  }
  return max;
}
#endif
#if 0
uint32_t
AdjDistance::fill_to_edge( uint32_t tos,  PeerUidSet &visit ) noexcept
{
  uint32_t maxdist = 0;
  while ( tos > 0 ) {
    uint32_t uid = this->stack[ --tos ].uid,
             d   = this->stack[ tos ].dist;
    uint32_t count = this->adjacency_count( uid );
    if ( count == 0 )
      continue;
    if ( d >= maxdist )
      maxdist = d;
    for ( uint32_t i = 0; i < count; i++ ) {
      BitSpace * set = this->adjacency_set( uid, i );
      uint32_t   uid2;
      if ( set == NULL )
        continue;
      for ( bool ok = set->first( uid2 ); ok; ok = set->next( uid2 ) ) {
        if ( ! visit.test_set( uid2 ) ) {
          //printf( "%u,edge (%u,d=%u)\n", uid, uid2, d + 1 );
          this->stack[ tos ].uid  = uid2;
          this->stack[ tos ].dist = d + 1;
          tos++;
        }
      }
    }
  }
  return maxdist;
}
#endif
