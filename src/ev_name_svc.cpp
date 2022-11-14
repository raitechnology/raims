#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifndef _MSC_VER
#include <sys/socket.h>
#include <arpa/inet.h>
#else
#include <raikv/win.h>
#endif
#include <raims/ev_name_svc.h>
#include <raims/session.h>
#include <raims/transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

NameSvc::NameSvc( EvPoll &p,  SessionMgr &m,  UserDB &u,
                  ConfigTree::Transport &tp ) noexcept
       : mgr( m ), user_db( u ), tport( tp ), mcast_recv( p, *this ),
         mcast_send( p, *this ), connect_fail_count( 0 ),
         is_connected( false ), is_closed( true )
{
  this->inbox.val = 0;
}

bool
NameSvc::connect( void ) noexcept
{
  int mcast_send_opts =
      ( DEFAULT_UDP_CONNECT_OPTS | OPT_NO_DNS | OPT_AF_INET ) & ~OPT_AF_INET6,
      mcast_recv_opts =
      ( DEFAULT_UDP_LISTEN_OPTS  | OPT_NO_DNS | OPT_AF_INET ) & ~OPT_AF_INET6;
    /*ucast_recv_opts = mcast_recv_opts | OPT_UNICAST;*/
  char buf[ 256 ];
  PeerAddrStr paddr;
  struct sockaddr_in sa;
  socklen_t len = sizeof( sa );
  const char * ip = NULL;
  int x, port = 0; 

  if ( this->connect_fail_count > 0 && ! debug_name ) {
    mcast_send_opts &= ~OPT_VERBOSE;
    mcast_recv_opts &= ~OPT_VERBOSE;
  }
  this->is_closed = false;
  if ( ! this->tport.get_route_str( R_CONNECT, ip ) &&
       ! this->tport.get_route_str( R_LISTEN, ip ) )
    ip = default_name_mcast();
  if ( ! this->tport.get_route_int( R_PORT, port ) )
    port = default_name_port();

  if ( ::strchr( ip, ';' ) == NULL ) {
    ::snprintf( buf, sizeof( buf ), "%s%s", ip, default_name_mcast() );
    ip = buf;
  }
  if ( port == 0 )
    port = default_name_port();
  x = this->mcast_send.connect( ip, port, mcast_send_opts, "mcast_send", -1 );
  if ( x != 0 )
    goto fail;

  if ( this->mcast_send.mode != EvUdp::MCAST_CONNECT ) {
    fprintf( stderr, "name: not in mcast mode\n" );
    goto fail;
  }

  x = this->mcast_recv.listen2( ip, port, mcast_recv_opts, "mcast_recv", -1 );
  if ( x != 0 ) {
    fprintf( stderr, "name: failed to listen mcast_recv (%s:%d)\n", ip, port );
    goto fail;
  }
  if ( ::getsockname( this->mcast_recv.fd, (struct sockaddr *) &sa,
                      &len ) != 0 ) {
    perror( "name: getsockname" );
    goto fail;
  }
  this->inbox.ip.s_addr   = sa.sin_addr.s_addr;
  this->inbox.ip.sin_port = sa.sin_port;

  paddr.set_sock_addr( this->mcast_send.fd );
  printf( "name: connect %s -> %s\n", paddr.buf,
          this->mcast_send.peer_address.buf );

  x = ::snprintf( buf, sizeof( buf ), "%s.%s.send", this->tport.type.val,
                  this->tport.tport.val );
  this->mcast_send.set_name( buf, x );
  x = ::snprintf( buf, sizeof( buf ), "%s.%s.recv", this->tport.type.val,
                  this->tport.tport.val );
  this->mcast_recv.set_name( buf, x );
  this->connect_fail_count = 0;
  this->is_connected = true;
  this->start_transports();
  return true;
fail:
  if ( this->connect_fail_count++ == 0 || debug_name )
    printf( "%s %s: delayed until network %s available\n",
            this->tport.type.val, this->tport.tport.val, ip );
  this->close();
  this->is_closed = false;
  return false;
}

void
NameSvc::close( void ) noexcept
{
  if ( this->mcast_send.in_list( IN_ACTIVE_LIST ) )
    this->mcast_send.idle_push( EV_CLOSE );

  if ( this->mcast_recv.in_list( IN_ACTIVE_LIST ) )
    this->mcast_recv.idle_push( EV_CLOSE );

  this->is_closed    = true;
  this->is_connected = false;
}

void
NameSvc::start_transports( void ) noexcept
{
  for ( size_t i = 0; i < this->adverts.count; i++ ) {
    Advert &ad = this->adverts.ptr[ i ];
    if ( ad.rte->is_set( TPORT_IS_SHUTDOWN ) )
      this->mgr.start_transport( *ad.rte, true );
  }
}

void
EvNameConnect::send_msg( const void *data,  size_t len ) noexcept
{
  uint32_t nmsgs = ++this->out_nmsgs;
  mmsghdr * mhdr = (mmsghdr *) this->alloc_temp( sizeof( mmsghdr ) * nmsgs );
  iovec * iov    = (iovec *) this->alloc_temp( sizeof( iovec ) );
  iov->iov_base  = this->append( data, len );
  iov->iov_len   = len;
  if ( nmsgs > 1 )
    ::memcpy( mhdr, this->out_mhdr, sizeof( mhdr[ 0 ] ) * ( nmsgs - 1 ) );
  this->out_mhdr = mhdr;

  if ( debug_name )
    this->name.print_addr( "mcast", NULL );

  mmsghdr & oh = mhdr[ nmsgs - 1 ];
  oh.msg_hdr.msg_name       = NULL; /* sendto is connected */
  oh.msg_hdr.msg_namelen    = 0;
  oh.msg_hdr.msg_iov        = iov;
  oh.msg_hdr.msg_iovlen     = 1;
  oh.msg_hdr.msg_control    = NULL;
  oh.msg_hdr.msg_controllen = 0;
  oh.msg_hdr.msg_flags      = 0;
  oh.msg_len                = 0;
  this->out_nmsgs = nmsgs;
  this->msgs_sent++;
  this->idle_push( EV_WRITE );
}

void
EvNameListen::send_msg( const void *data,  size_t len,
                        NameInbox &inbox ) noexcept
{
  uint32_t nmsgs = ++this->out_nmsgs;
  mmsghdr * mhdr = (mmsghdr *) this->alloc_temp( sizeof( mmsghdr ) * nmsgs );
  iovec * iov    = (iovec *) this->alloc_temp( sizeof( iovec ) );
  iov->iov_base  = this->append( data, len );
  iov->iov_len   = len;
  if ( nmsgs > 1 )
    ::memcpy( mhdr, this->out_mhdr, sizeof( mhdr[ 0 ] ) * ( nmsgs - 1 ) );
  this->out_mhdr = mhdr;

  struct sockaddr_in * dest;
  dest = (struct sockaddr_in *) this->alloc_temp( sizeof( sockaddr_in ) );
  dest->sin_family = AF_INET;
  dest->sin_addr.s_addr = inbox.ip.s_addr;
  dest->sin_port = inbox.ip.sin_port;
  if ( debug_name )
    this->name.print_addr( "send", dest );

  mmsghdr & oh = mhdr[ nmsgs - 1 ];
  oh.msg_hdr.msg_name       = (void *) dest;
  oh.msg_hdr.msg_namelen    = sizeof( *dest );
  oh.msg_hdr.msg_iov        = iov;
  oh.msg_hdr.msg_iovlen     = 1;
  oh.msg_hdr.msg_control    = NULL;
  oh.msg_hdr.msg_controllen = 0;
  oh.msg_hdr.msg_flags      = 0;
  oh.msg_len                = 0;
  this->out_nmsgs = nmsgs;
  this->msgs_sent++;
  this->idle_push( EV_WRITE );
}

void
NameSvc::print_addr( const char *what,  const void *sa ) noexcept
{
  struct sockaddr_in * p = (struct sockaddr_in *) sa;

  if ( p != NULL && p->sin_family == AF_INET ) {
    char buf[ 256 ];
    inet_ntop( AF_INET, &p->sin_addr, buf, sizeof( buf ) );
    printf( "name %s %s: %s:%u\n", what, this->tport.tport.val, buf,
             ntohs( p->sin_port ) );
  }
  else {
    printf( "name %s %s: %s\n", what, this->tport.tport.val,
            this->mcast_send.peer_address.buf );
  }
}

void
EvNameListen::process( void ) noexcept
{
  uint32_t cnt = this->in_nmsgs - this->in_moff;
  void   * msg;
  size_t   msg_len;

  for ( uint32_t i = 0; i < cnt; i++ ) {
    uint32_t  j = this->in_moff++;
    mmsghdr & ih = this->in_mhdr[ j ];
    if ( ih.msg_hdr.msg_iovlen != 1 )
      continue;
    if ( debug_name )
      this->name.print_addr( "recv", ih.msg_hdr.msg_name );

    msg = ih.msg_hdr.msg_iov[ 0 ].iov_base;
    msg_len = ih.msg_len;
    if ( this->msg_in.unpack( msg, msg_len ) == 0 ) {
      this->name.user_db.on_name_svc( this->name, this->msg_in.msg );
      this->msgs_recv++;
    }
  }
  this->pop( EV_PROCESS );
  if ( ! this->test( EV_WRITE ) )
    this->clear_buffers();
}

void
EvNameListen::process_close( void ) noexcept
{
  this->EvSocket::process_close();
}

void
EvNameListen::release( void ) noexcept
{
  if ( this->name.mcast_send.in_list( IN_ACTIVE_LIST ) )
    this->name.mcast_send.idle_push( EV_CLOSE );
  else
    this->name.is_connected = false;
}

void
EvNameConnect::process( void ) noexcept
{
  this->pop( EV_PROCESS );
  this->clear_buffers();
}

void
EvNameConnect::process_close( void ) noexcept
{
  this->EvSocket::process_close();
}

void
EvNameConnect::release( void ) noexcept
{
  if ( this->name.mcast_recv.in_list( IN_ACTIVE_LIST ) )
    this->name.mcast_recv.idle_push( EV_CLOSE );
  else
    this->name.is_connected = false;
}

void
UserDB::mcast_name( NameSvc &name ) noexcept
{
  if ( ! name.is_connected ) {
    if ( name.is_closed )
      return;
    if ( ! name.connect() )
      return;
  }
  if ( name.adverts.count == 0 )
    return;

  AdvertList & adverts = name.adverts;
  for ( size_t i = 0; i < adverts.count; i++ ) {
    Advert &ad = adverts.ptr[ i ];
    if ( ! ad.rte->is_set( TPORT_IS_SHUTDOWN ) ) {
      if ( ( ad.ad_counter++ % 4 ) == 0 ||
             ad.is_newer( this->start_time ) )
        this->send_name_advert( name, *ad.rte, NULL );
    }
    else {
      ad.ad_counter = 0;
    }
    ad.rotate_start_recv();
  }
}

void
UserDB::send_name_advert( NameSvc &name,  TransportRoute &rte,
                          NameInbox *inbox ) noexcept
{
  uint64_t stamp = current_realtime_ns();
  StringVal mesh_url;
  if ( rte.mesh_id != NULL )
    mesh_url = rte.mesh_id->mesh_url;

  this->name_send_time = stamp;
  MsgEst e( X_NAME_SZ );
  e.user_hmac ()
   .seqno     ()
   .stamp     ()
   .start     ()
   .ret       ()
   .user      ( this->user.user.len )
   .create    ( this->user.create.len )
   .expires   ( this->user.expires.len )
   .tport     ( rte.transport.tport.len )
   .tport_type( rte.transport.type.len )
   .mesh_url  ( mesh_url.len )
   .conn_url  ( rte.conn_url.len )
   .pk_digest ();

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, X_NAME_SZ )
   .user_hmac ( this->bridge_id.hmac     )
   .seqno     ( ++this->name_send_seqno  )
   .stamp     ( stamp                    )
   .start     ( this->start_time         );
  if ( inbox == NULL )
    m.ret     ( name.inbox.val           );
  m.user      ( this->user.user.val,
                this->user.user.len      )
   .create    ( this->user.create.val,
                this->user.create.len    );
  if ( this->user.expires.len > 0 )
    m.expires ( this->user.expires.val,
                this->user.expires.len   );
  m.tport     ( rte.transport.tport.val,
                rte.transport.tport.len  )
   .tport_type( rte.transport.type.val,
                rte.transport.type.len   );
  if ( rte.is_set( TPORT_IS_MESH ) )
    m.mesh_url( mesh_url.val,
                mesh_url.len             );
  else if ( rte.is_set( TPORT_IS_LISTEN ) )
    m.conn_url( rte.conn_url.val, 
                rte.conn_url.len         );
  m.pk_digest ();

  m.close( e.sz, name_h, CABA_HEARTBEAT );
  m.sign_hb( X_NAME, X_NAME_SZ, *this->session_key, *this->hello_key );

  name.send_msg( m.msg, m.len(), inbox );
}

void
UserDB::on_name_svc( NameSvc &name,  CabaMsg *msg ) noexcept
{
  if ( name.adverts.count == 0 )
    return;
  MsgHdrDecoder dec( msg );
  if ( dec.decode_msg() != 0 )
    return;
  if ( ! dec.test_4( FID_TPORT, FID_TPORT_TYPE, FID_START, FID_STAMP ) )
    return;

  AdvertList & adverts = name.adverts;
  UserNonce    bridge_id;
  UserBridge * n = NULL;
  NameInbox    inbox;
  size_t       n_pos;
  uint64_t     start,
               stamp;
  const char * tport_name,
             * type_name,
             * mesh_url_addr,
             * conn_url_addr;
  uint32_t     uid,
               tport_len,
               type_len,
               mesh_url_len,
               conn_url_len;

  if ( ! dec.get_bridge( bridge_id.nonce ) ||
       ! dec.get_ival<uint64_t>( FID_SEQNO, dec.seqno ) )
    return;
  dec.get_ival<uint64_t>( FID_START, start );
  dec.get_ival<uint64_t>( FID_STAMP, stamp );
  if ( dec.test( FID_RET ) )
    dec.get_ival<uint64_t>( FID_RET, inbox.val );
  else
    inbox.val = 0;

  if ( this->node_ht->find( bridge_id.nonce, n_pos, uid ) ||
       this->zombie_ht->find( bridge_id.nonce, n_pos, uid ) ) {
    if ( uid == MY_UID )
      return;
    n = this->bridge_tab[ uid ];
    if ( n == NULL ) {
      d_name( "ignoring, nonce is null\n" );
      return;
    }
    if ( n->is_set( AUTHENTICATED_STATE ) ) {
      if ( ! dec.msg->verify( n->peer_key ) ) {
        fprintf( stderr, "ignoring msg, not verified\n" );
        return;
      }
    }
  }
  if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) ) {
    if ( n == NULL ) {
      HashDigest hello_key;
      if ( ! dec.get_hmac( FID_USER_HMAC, bridge_id.hmac ) )
        return;
      this->calc_hello_key( start, bridge_id.hmac, hello_key );

      if ( ! dec.msg->verify_hb( hello_key ) ) {
        fprintf( stderr, "ignoring msg, hello not verified\n" );
        return;
      }
      PeerEntry * peer = this->find_peer( dec, bridge_id.hmac );
      if ( peer != NULL )
        n = this->add_user2( bridge_id, *peer, start, hello_key );
      if ( n == NULL ) {
        fprintf( stderr, "ignoring msg, no user create\n" );
        return;
      }
    }
    else {
      if ( ! dec.msg->verify_hb( n->peer_hello ) ) {
        fprintf( stderr, "ignoring msg, hello not verified\n" );
        return;
      }
    }
  }
  if ( dec.seqno <= n->name_recv_seqno || stamp <= n->name_recv_time ) {
    d_name( "ignoring msg, out of order or replay %lu %lu\n",
            n->name_recv_seqno, n->name_recv_time );
    return;
  }
  n->name_recv_seqno = dec.seqno;
  n->name_recv_time  = stamp;
  tport_name    = (const char *) dec.mref[ FID_TPORT ].fptr;
  tport_len     = (uint32_t)     dec.mref[ FID_TPORT ].fsize;
  type_name     = (const char *) dec.mref[ FID_TPORT_TYPE ].fptr;
  type_len      = (uint32_t)     dec.mref[ FID_TPORT_TYPE ].fsize;

  if ( type_len == T_ANY_SZ && ::memcmp( type_name, T_ANY, T_ANY_SZ ) == 0 ) {
    for ( size_t i = 0; i < adverts.count; i++ ) {
      Advert &ad = adverts.ptr[ i ];
      if ( ad.rte->is_set( TPORT_IS_SHUTDOWN ) ||
           ! ad.rte->transport.tport.equals( tport_name, tport_len ) )
        continue;
      if ( ad.rte->transport.type.equals( T_ANY, T_ANY_SZ ) )
        continue;
      if ( inbox.val != 0 && ad.rte->is_set( TPORT_IS_LISTEN ) )
        this->send_name_advert( name, *ad.rte, &inbox );
    }
  }
  else if ( dec.test( FID_MESH_URL ) ) {
    mesh_url_addr = (const char *) dec.mref[ FID_MESH_URL ].fptr;
    mesh_url_len  = (uint32_t)     dec.mref[ FID_MESH_URL ].fsize;

    for ( size_t i = 0; i < adverts.count; i++ ) {
      Advert &ad = adverts.ptr[ i ];
      bool   type_change = false;
      if ( ad.rte->is_set( TPORT_IS_SHUTDOWN ) ||
           ! ad.rte->transport.tport.equals( tport_name, tport_len ) )
        continue;
      if ( ad.rte->transport.type.equals( T_ANY, T_ANY_SZ ) ) {
        ad.rte->change_any( T_MESH, name );
        type_change = true;
      }
      if ( ! ad.rte->transport.type.equals( type_name, type_len ) )
        continue;
      /* advert is already added to mesh */
      if ( ad.rte->uid_in_mesh->is_member( n->uid ) ) {
        ad.update_start_recv( start );
        continue;
      }
      /* if peer is newer, it does the connect */
      if ( this->start_time < start ) {
        if ( inbox.val != 0 )
          this->send_name_advert( name, *ad.rte, &inbox );
        else if ( type_change )
          this->send_name_advert( name, *ad.rte, NULL );
      }
      /* connect to this mesh */
      else {
        this->mesh_pending.update( *ad.rte, mesh_url_addr, mesh_url_len, 0,
                                   bridge_id.nonce, true );
      }
    }
  }
  else {
    if ( dec.test( FID_CONN_URL ) ) {
      conn_url_addr = (const char *) dec.mref[ FID_CONN_URL ].fptr;
      conn_url_len  = (uint32_t)     dec.mref[ FID_CONN_URL ].fsize;
    }
    else {
      conn_url_addr = NULL;
      conn_url_len  = 0;
    }
    for ( size_t i = 0; i < adverts.count; i++ ) {
      Advert &ad = adverts.ptr[ i ];
      bool type_change = false;
      if ( ad.rte->is_set( TPORT_IS_SHUTDOWN ) ||
           ! ad.rte->transport.tport.equals( tport_name, tport_len ) )
        continue;
      if ( ad.rte->transport.type.equals( T_ANY, T_ANY_SZ ) ) {
        ad.rte->change_any( T_TCP, name );
        type_change = true;
      }
      if ( ! ad.rte->transport.type.equals( type_name, type_len ) )
        continue;
      /* advert is already added to mesh */
      if ( ad.rte->uid_in_device->is_member( n->uid ) ) {
        ad.update_start_recv( start );
        continue;
      }
      /* if peer is connector */
      if ( ad.rte->is_set( TPORT_IS_LISTEN ) ) {
        if ( inbox.val != 0 && conn_url_addr == NULL )
          this->send_name_advert( name, *ad.rte, &inbox );
        else if ( type_change )
          this->send_name_advert( name, *ad.rte, NULL );
        else
          ad.update_start_recv( start );
      }
      /* connect to this tcp listener */
      else if ( conn_url_addr != NULL ) {
        this->mesh_pending.update( *ad.rte, conn_url_addr, conn_url_len, 0,
                                   bridge_id.nonce, false );
      }
      else {
        ad.update_start_recv( start );
      }
    }
  }
}
