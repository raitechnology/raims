#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __FAVOR_BSD
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <raims/msg.h>
#include <raims/sub_const.h>
#include <raimd/md_msg.h>
#include <raikv/route_ht.h>
#include <raikv/key_hash.h>
#include <linecook/linecook.h>

using namespace rai;
using namespace ms;
using namespace md;
using namespace kv;

struct IP_Addr {
  uint32_t addr;
  uint16_t port;
  uint16_t zero;

  IP_Addr( uint32_t a,  uint16_t p ) : addr( a ), port( p ), zero( 0 ) {}

  const char *value( void ) const { return (const char *) (void *) this; }
  size_t len( void ) const { return sizeof( *this ); }
  uint32_t hash( void ) const {
    return kv_hash_uint2( this->addr, this->port );
  }
};

struct IP_Pair {
  IP_Addr src, dest;

  IP_Pair( const iphdr *ip,  const tcphdr *tcp )
    : src( ip->saddr, ntohs( tcp->th_sport ) ),
      dest( ip->daddr, ntohs( tcp->th_dport ) ) {}

  const char *value( void ) const { return (const char *) (void *) this; }
  size_t len( void ) const { return sizeof( *this ); }
  uint32_t hash( void ) const {
    return this->src.hash() ^ this->dest.hash();
  }
};

struct PrintPair {
  uint32_t hash, pkt_count;
  uint16_t len;
  char     value[ sizeof( IP_Pair ) ];
};

struct PrintUser {
  uint32_t hash;
  char     user[ 64 ];
  uint32_t user_hash;
  uint16_t len;
  bool     is_resolved;
  char     value[ sizeof( IP_Addr ) ];

  void set_ip( const IP_Addr &addr ) {
    inet_ntop( AF_INET, &addr.addr, this->user, 64 );
    size_t len = ::strlen( this->user );
    ::snprintf( &this->user[ len ], 64 - len, ":%u", addr.port );
    this->is_resolved = false;
  }
};

struct LoopContext {
  RouteVec<PrintPair> conn;
  RouteVec<PrintUser> user;

  PrintUser tmp_user;
  uint32_t  max_user;
  double    start;
  bool      use_color;

  LoopContext() : max_user( 0 ), start( 0 ),
                  use_color( false ) {
    ::memset( &this->tmp_user, 0, sizeof( this->tmp_user ) );
  }

  PrintUser *get_user( const IP_Pair &pair,  bool src ) noexcept;
  void get_pair( const iphdr *ip,  const tcphdr *tcp,
                 PrintPair *&i,  PrintUser *&src,
                 PrintUser *&dest ) noexcept;
  static void resolve_source_user( CabaMsg &msg,  PrintUser &src ) noexcept;
  void print_msg( PrintUser &src,  PrintUser &dest,  CabaMsg &msg,
                  const PrintPair &i ) noexcept;
  static void fg_color( uint32_t colnum ) noexcept;
  static void bg_color( uint32_t colnum ) noexcept;
  void normal( void ) noexcept;
  void sub_color( const char *sub,  size_t sublen ) noexcept;
  void user_color( uint32_t h ) noexcept;
  void user_bg_color( uint32_t h ) noexcept;
  void print_prefix( PrintUser &src,  PrintUser &dest ) noexcept;
  void loop_packet( const struct pcap_pkthdr *h,
                    const u_char *packet ) noexcept;
};

void
LoopContext::fg_color( uint32_t colnum ) noexcept
{
  uint32_t r, g, b;
  r = 255 - ( colnum * 255 / 126 );
  g = ( colnum * 510 / 126 );
  b = ( colnum * 255 / 126 );
  if ( g > 255 ) g = 510 - g;
  printf( ANSI_BOLD ANSI_24BIT_FG_FMT, 255 - r, 255 - g, 255 - b );
}

void
LoopContext::bg_color( uint32_t colnum ) noexcept
{
  uint32_t r, g, b;
  r = 255 - ( colnum * 255 / 126 );
  g = ( colnum * 510 / 126 );
  b = ( colnum * 255 / 126 );
  if ( g > 255 ) g = 510 - g;
  printf( ANSI_24BIT_BG_FMT, 255 - r, 255 - g, 255 - b );
}

void
LoopContext::normal( void ) noexcept
{
  if ( this->use_color )
    printf( "%.*s", (int) ANSI_NORMAL_SIZE, ANSI_NORMAL );
}

void
LoopContext::sub_color( const char *sub,  size_t sublen ) noexcept
{
  if ( ! this->use_color )
    return;
  int i = 70;
  if ( sublen > 2 && sub[ 0 ] == '_' ) {
    switch ( sub[ 1 ] ) {
      case 'I': i = 0; break;
      case 'M': i = 10; break;
      case 'Z': i = 20; break;
      case 'S': i = 30; break;
      case 'P': i = 40; break;
      case 'N': i = 50; break;
      case 'X': i = 60; break;
      default: break;
    }
  }
  fg_color( 126 - i );
}

void
LoopContext::user_color( uint32_t h ) noexcept
{
  if ( this->use_color )
    fg_color( h % 127 );
}

void
LoopContext::user_bg_color( uint32_t h ) noexcept
{
  if ( this->use_color )
    bg_color( h % 127 );
}

PrintUser *
LoopContext::get_user( const IP_Pair &pair,  bool src ) noexcept
{
  const IP_Addr & addr = ( src ? pair.src : pair.dest );
  RouteLoc loc;
  PrintUser * u;

  if ( src ) {
    u = this->user.upsert( addr.hash(), addr.value(), addr.len(), loc );
    if ( loc.is_new ) {
      u->set_ip( addr );
      u->user_hash = u->hash;
    }
    return u;
  }
  u = this->user.find( addr.hash(), addr.value(), addr.len() );
  if ( u != NULL )
    return u;
  this->tmp_user.user_hash = 0;
  this->tmp_user.set_ip( addr );
  return &this->tmp_user;
}

void
LoopContext::get_pair( const iphdr *ip,  const tcphdr *tcp,
                       PrintPair *&i,  PrintUser *&src,
                       PrintUser *&dest ) noexcept
{
  IP_Pair pair( ip, tcp );
  RouteLoc loc;
  i = this->conn.upsert( pair.hash(), pair.value(), pair.len(), loc );
  if ( loc.is_new ) {
    i->pkt_count = 0;
  }
  src  = this->get_user( pair, true ),
  dest = this->get_user( pair, false );
}

void
LoopContext::resolve_source_user( CabaMsg &msg,  PrintUser &src ) noexcept
{
  if ( ( msg.sublen == X_HB_SZ &&
         ::memcmp( msg.sub, X_HB, X_HB_SZ ) == 0 ) ||
       ( msg.sublen == X_HELLO_SZ &&
         ::memcmp( msg.sub, X_HELLO, X_HELLO_SZ ) == 0 ) ||
       ( msg.sublen > 25 &&
         ::memcmp( &msg.sub[ msg.sublen - 5 ], "." _AUTH, 5 ) == 0 ) ) {
    MDFieldIter * iter = NULL;
    MDReference   mref;
    if ( msg.get_field_iter( iter ) == 0 &&
         iter->find( "user_s2", 8, mref ) == 0 ) {
      size_t len = mref.fsize;
      if ( len > 63 ) len = 63;
      ::memcpy( src.user, mref.fptr, len );
      src.user[ len ] = '\0';
      src.user_hash = kv_crc_c( src.user, len, 1 );
      src.is_resolved = true;
    }
  }
}

void
LoopContext::print_prefix( PrintUser &src,  PrintUser &dest ) noexcept
{
  if ( this->use_color )
    this->user_bg_color( src.user_hash );
  printf( " " );
  if ( this->use_color )
    this->user_bg_color( dest.user_hash );
  printf( " " );
  if ( this->use_color )
    this->normal();
  printf( " " );
}

void
LoopContext::print_msg( PrintUser &src,  PrintUser &dest,  CabaMsg &msg,
                        const PrintPair & ) noexcept
{
  MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );

  MDFieldIter * f = NULL;
  MDName        nm;
  MDReference   mref;

  if ( msg.get_field_iter( f ) != 0 )
    return;
  for ( int x = f->first(); x == 0; x = f->next() ) {
    if ( f->get_name( nm ) != 0 )
      continue;
    this->print_prefix( src, dest );
    switch ( fid_value( nm.fid ) ) {
      case FID_ADJACENCY:
      case FID_PEER_DB: {
        if ( f->get_reference( mref ) == 0 ) {
          char fname_buf[ 256 + 16 ];
          size_t fname_len = sizeof( fname_buf );
          f->fname_string( fname_buf, fname_len );
          printf( "%-18s : {\n", fname_buf );
          CabaMsg * sub = msg.submsg( mref.fptr, mref.fsize );
          MDFieldIter * g = NULL;
          if ( sub != NULL && sub->get_field_iter( g ) == 0 ) {
            for ( int x = g->first(); x == 0; x = g->next() ) {
              this->print_prefix( src, dest );
              g->print( &mout, 5, "%-18s : ", NULL );
            }
          }
          this->print_prefix( src, dest );
          printf( "}" );
        }
        break;
      }
      default:
        f->print( &mout, 0, "%-18s : ", NULL );
        break;
    }
    printf( "\n" );
  }
}

void
LoopContext::loop_packet( const struct pcap_pkthdr *h,
                          const u_char *packet ) noexcept
{
  const ether_header * eptr = (ether_header *) packet;
  size_t off = sizeof( ether_header );
  size_t len = h->caplen;

  if ( off >= len )
    return;
  if ( eptr->ether_type != htons( ETHERTYPE_IP ) )
    return;

  const iphdr * ip = (iphdr *) &packet[ off ];
  if ( off + sizeof( tcphdr ) >= len )
    return;
  if ( ip->protocol != IPPROTO_TCP )
    return;

  off += ip->ihl * 4;
  if ( off >= len )
    return;
  const tcphdr * tcp = (tcphdr *) &packet[ off ];
  off += tcp->th_off * 4;

  if ( off >= len )
    return;

  PrintPair * i;
  PrintUser * src,
            * dest;
  this->get_pair( ip, tcp, i, src, dest );

  double captime = (double) h->ts.tv_sec +
                   (double) h->ts.tv_usec / 1000000.0;
  bool first = true;
  if ( start == 0 )
    start = captime;
  MDDict * d = MsgFrameDecoder::msg_dict;
  do {
    MDMsgMem  mem;
    CabaMsg * msg = CabaMsg::unpack( (void *) &packet[ off ], 0, len - off, 0,
                                     d, &mem );
    if ( msg != NULL ) {
      if ( ! src->is_resolved )
        this->resolve_source_user( *msg, *src );

      if ( first ) {
        printf( "\n[packet %s.%u] [caplen %u] [timeoff %.3f]\n",
                src->user, ++i->pkt_count, h->caplen, captime - start );
        first = false;
      }
      this->sub_color( msg->sub, msg->sublen );
      printf( "%.*s", msg->sublen, msg->sub ); this->normal();
      printf( " ... " );
      this->user_color( src->user_hash ); printf( "%s", src->user );
      this->normal();
      printf( " -> " );
      this->user_color( dest->user_hash ); printf( "%s", dest->user );
      this->normal();
      printf( "\n" );

      this->print_msg( *src, *dest, *msg, *i );
      off += msg->msg_end;
    }
    else {
      printf( "incomplete ... %s -> %s\n", src->user, dest->user );
      MDOutput mout;
      mout.print_hex( &packet[ off ], len - off );
      break;
    }
  } while ( off < len );
}

static void
loop_packet( u_char *user, const struct pcap_pkthdr *h,
             const u_char *packet ) noexcept
{
  ((LoopContext *) user)->loop_packet( h, packet );
}

int
main( int argc, char *argv[] )
{
  int i = 1;
  if ( argc < 2 || ::strcmp( argv[ 1 ], "-h" ) == 0 ) {
    printf( "usage: %s [-c] pcap\n", argv[ 0 ] );
    return 1;
  }
  LoopContext ctx;
  if ( argc == 3 && ::strcmp( argv[ 1 ], "-c" ) == 0 ) {
    ctx.use_color = true;
    i = 2;
  }
  md_init_auto_unpack();
  CabaMsg::init_auto_unpack();
  char errbuf[ PCAP_ERRBUF_SIZE ];
  pcap_t *pcap = pcap_open_offline( argv[ i ], errbuf );
  if ( pcap == NULL ) {
    fprintf( stderr, "%s\n", errbuf );
    return 1;
  }
  pcap_loop( pcap, -1, loop_packet, (u_char *) &ctx );

  return 0;
}


