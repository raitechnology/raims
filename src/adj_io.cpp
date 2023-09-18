#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/adj_graph.h>
#include <raimd/json_msg.h>

using namespace rai;
using namespace kv;
using namespace md;
using namespace ms;

static const uint32_t COST_DEFAULT = 1000;

void
AdjGraphOut::print( void ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUserTab & user_tab = this->graph.user_tab;
  for ( uint32_t idx = 0; idx < user_tab.count; idx++ ) {
    AdjUser *u = user_tab.ptr[ idx ];
    for ( uint32_t j = 0; j < u->links.count; j++ ) {
      AdjLink *l = u->links.ptr[ j ];
      o.printf( "%s -> %s %s %u %u %u %u\n",
               l->a.user.val, l->b.user.val, l->tport.val,
               l->cost[ 0 ], l->cost[ 1 ], l->cost[ 2 ], l->cost[ 3 ] );
    }
    o.puts( "---\n" );
  }
}

void
AdjGraphOut::print_tree( uint8_t p,  bool print_unused ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUserTab & user_tab = this->graph.user_tab;
  for ( uint32_t idx = 0; idx < user_tab.count; idx++ ) {
    AdjUser   * u   = user_tab.ptr[ idx ];
    AdjFwdTab & fwd = u->fwd[ p ];
    BitSpace    unused;
    uint32_t    src;
    o.printf( "%u. %s\n", idx, u->user.val );
    for ( src = 0; src < u->links.count; src++ ) {
      uint32_t j;
      for ( j = 0; j < fwd.links.count; j++ ) {
        if ( fwd.src.ptr[ j ] == src )
          break;
      }
      if ( j == fwd.links.count ) {
        if ( print_unused )
          unused.add( src );
      }
      else {
        this->print_tree_link( 2, fwd, src, j, p );
      }
    }
    if ( print_unused ) {
      for ( bool b = unused.first( src ); b; b = unused.next( src ) ) {
        AdjLink * link = u->links.ptr[ src ];
        o.printf( "  :%u: %s -/ %s %s (not-used)\n", link->cost[ p ],
                link->a.user.val, link->b.user.val, link->tport.val );
      }
    }
  }
}

void
AdjGraphOut::print_tree_link( uint32_t indent,  AdjFwdTab &fwd,  uint32_t src,
                              uint32_t j,  uint8_t p ) noexcept
{
  ArrayOutput & o = this->out;
  uint32_t  cost = fwd.cost.ptr[ j ];
  AdjLink * link = fwd.links.ptr[ j ];

  uint32_t dest_idx = link->b.idx;
  o.printf( "%*s[%u] %s -> %s %s(%c)\n", indent, "", cost,
          link->a.user.val, link->b.user.val,
          link->tport.val, link->dest[ p ].is_member( dest_idx ) ? '+' : '-' );

  for ( uint32_t k = j + 1; k < fwd.links.count; k++ ) {
    if ( fwd.src.ptr[ k ] == src &&
         &fwd.links.ptr[ k ]->a == &link->b ) {
      this->print_tree_link( indent + 2, fwd, src, k, p );
    }
  }
}

void
AdjGraphOut::print_web_paths( uint32_t start_idx ) noexcept
{
  ArrayOutput & o = this->out;
  o.puts( "[\n" );
  for ( uint8_t p = 0; p < 4; p++ ) {
    this->print_web_path( p, start_idx );
    if ( p < 3 ) o.puts( ",\n" );
  }
  o.puts( "]\n" );
}

void
AdjGraphOut::print_web_path( uint8_t p,  uint32_t start_idx ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUser   * u   = this->graph.user_tab.ptr[ start_idx ];
  AdjFwdTab & fwd = u->fwd[ p ];
  uint32_t    src;

  o.printf( "{\n\"nodes\": [\n"
          "{\"user\": \"%s\", \"uid\": %u, \"step\": %u, \"cost\": %u}",
          u->user.val, u->idx, 0, 0 );
  for ( src = 0; src < u->links.count; src++ ) {
    uint32_t j;
    for ( j = 0; j < fwd.links.count; j++ ) {
      if ( fwd.src.ptr[ j ] == src )
        break;
    }
    if ( j < fwd.links.count )
      this->print_web_path_node( 1, fwd, src, j );
  }
  o.puts( " ],\n\"links\": [\n" );
  bool first = true;
  for ( src = 0; src < u->links.count; src++ ) {
    uint32_t j;
    for ( j = 0; j < fwd.links.count; j++ ) {
      if ( fwd.src.ptr[ j ] == src )
        break;
    }
    if ( j < fwd.links.count ) {
      this->print_web_path_link( 0, fwd, src, j, first );
      first = false;
    }
  }
  o.puts( " ]\n}\n" );
}

void
AdjGraphOut::print_web_path_node( uint32_t step,  AdjFwdTab &fwd,  uint32_t src,
                                  uint32_t j ) noexcept
{
  ArrayOutput & o = this->out;
  uint32_t  cost = fwd.cost.ptr[ j ];
  AdjLink * link = fwd.links.ptr[ j ];

  o.printf( ",\n{\"user\": \"%s\", \"uid\": %u, \"step\": %u, \"cost\": %u}",
          link->b.user.val, link->b.idx, step, cost );

  for ( uint32_t k = j + 1; k < fwd.links.count; k++ ) {
    if ( fwd.src.ptr[ k ] == src &&
         &fwd.links.ptr[ k ]->a == &link->b ) {
      this->print_web_path_node( step + 1, fwd, src, k );
    }
  }
}

void
AdjGraphOut::print_web_path_link( uint32_t step,  AdjFwdTab &fwd,  uint32_t src,
                                  uint32_t j,  bool first ) noexcept
{
  ArrayOutput & o = this->out;
  AdjLink * link = fwd.links.ptr[ j ];

  o.printf( "%s{\"source\": %u, \"target\": %u, \"step\": %u}",
          ! first ? ",\n" : "", link->a.idx, link->b.idx, step );
  for ( uint32_t k = j + 1; k < fwd.links.count; k++ ) {
    if ( fwd.src.ptr[ k ] == src &&
         &fwd.links.ptr[ k ]->a == &link->b ) {
      this->print_web_path_link( step + 1, fwd, src, k, false );
    }
  }
}

void
AdjGraphOut::print_fwd( uint8_t p ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUserTab & user_tab = this->graph.user_tab;
  for ( uint32_t idx = 0; idx < user_tab.count; idx++ ) {
    AdjUser *u = user_tab.ptr[ idx ];
    o.printf( "%s\n", u->user.val );
    for ( uint32_t j = 0; j < u->links.count; j++ ) {
      bool first = true;
      uint32_t idx = 0;
      for ( bool b = u->links.ptr[ j ]->dest[ p ].first( idx ); b;
            b = u->links.ptr[ j ]->dest[ p ].next( idx ) ) {
        if ( first ) {
          o.printf( "  %s ->", u->links.ptr[ j ]->tport.val );
          first = false;
        }
        o.printf( " (%s)", user_tab.ptr[ idx ]->user.val );
      }
      if ( ! first )
        o.puts( "\n" );
    }
    for ( uint32_t idx2 = 0; idx2 < user_tab.count; idx2++ ) {
      if ( idx2 == idx )
        continue;
      bool first = true;
      AdjUser *u2 = user_tab.ptr[ idx2 ];
      AdjFwdTab & fwd = u2->fwd[ p ];
      for ( uint32_t j = 0; j < fwd.links.count; j++ ) {
        if ( &fwd.links.ptr[ j ]->a == u ) {
          uint32_t src = fwd.src.ptr[ j ];
          if ( first ) {
            o.printf( "> %s:\n", u2->user.val );
            first = false;
          }

          AdjLink * link = fwd.links.ptr[ j ];
          BitSpace path;
          uint32_t k, count = 0;
          o.printf( "  %s -> (%s)", link->tport.val, link->b.user.val );

          for ( k = j + 1; k < fwd.links.count; k++ ) {
            if ( fwd.src.ptr[ k ] == src &&
                 &fwd.links.ptr[ k ]->a == &link->b ) {
              path.add( k );
              count++;
            }
          }
          while ( count != 0 ) {
            path.first( k );
            path.remove( k );
            count--;
            link = fwd.links.ptr[ k ];
            o.printf( " (%s)", link->b.user.val );
            for ( k = k + 1; k < fwd.links.count; k++ ) {
              if ( fwd.src.ptr[ k ] == src &&
                   &fwd.links.ptr[ k ]->a == &link->b ) {
                path.add( k );
                count++;
              }
            }
          }
          o.puts( "\n" );
        }
      }
    }
  }
}

void
AdjGraphOut::print_cost( AdjLink &link ) noexcept
{
  ArrayOutput & o = this->out;
  if ( ! link.cost_equals( COST_DEFAULT ) ) {
    if ( ! link.cost_equals( link.cost[ 0 ] ) ) {
      if ( ! this->is_cfg )
        o.printf( " : %u %u", link.cost[ 0 ], link.cost[ 1 ] );
      else
        o.printf( "      cost: [ %u, %u", link.cost[ 0 ], link.cost[ 1 ] );
      if ( link.cost[ 0 ] != link.cost[ 2 ] ||
           link.cost[ 1 ] != link.cost[ 3 ] ) {
        if ( ! this->is_cfg )
          o.printf( " %u %u", link.cost[ 2 ], link.cost[ 3 ] );
        else
          o.printf( ", %u, %u", link.cost[ 2 ], link.cost[ 3 ] );
      }
      if ( this->is_cfg )
        o.puts( " ]\n" );
    }
    else {
      if ( ! this->is_cfg )
        o.printf( " : %u", link.cost[ 0 ] );
      else
        o.printf( "      cost: %u\n", link.cost[ 0 ] );
    }
  }
  if ( ! this->is_cfg )
    o.puts( "\n" );
}

void
AdjGraphOut::print_graph( void ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUserTab & user_tab = this->graph.user_tab;
  StringVal tcp_type( "tcp", 3 ),
            mesh_type( "mesh", 4 ),
            pgm_type( "pgm", 3 );
  AdjLinkTab tcp, mesh, pgm;
  if ( ! this->is_cfg ) {
    o.puts( "node" );
    for ( uint32_t idx = 0; idx < user_tab.count; idx++ ) {
      AdjUser *u = user_tab.ptr[ idx ];
      o.printf( " %s", u->user.val );
    }
    o.puts( "\n" );
  }
  for ( uint32_t idx = 0; idx < user_tab.count; idx++ ) {
    AdjUser *u = user_tab.ptr[ idx ];
    for ( uint32_t j = 0; j < u->links.count; j++ ) {
      AdjLink *link = u->links.ptr[ j ];
      if ( link->type.equals( tcp_type ) )
        tcp.push( link );
      else if ( link->type.equals( mesh_type ) )
        mesh.push( link );
      else if ( link->type.equals( pgm_type ) )
        pgm.push( link );
    }
  }
  this->print_tcp( tcp );
  this->print_mesh( mesh, false );
  this->print_mesh( pgm, true );
}

void
AdjGraphOut::print_mesh( AdjLinkTab &mesh,  bool is_pgm ) noexcept
{
  ArrayOutput & o = this->out;
  while ( mesh.count > 0 ) {
    AdjLink *link = mesh.first();
    BitSpace used;
    if ( ! this->is_cfg )
      o.printf( "%s_%s", link->type.val, link->tport.val );
    else {
      o.printf(   "  - tport: %s\n"
                  "    type: %s\n"
                  "    route:\n",
                  link->tport.val, link->type.val );

      if ( is_pgm ) {
        uint32_t x = ( 100 + this->tport_counter ) % 256,
                 y = ( 200 + this->tport_counter ) % 256,
                 z = ( 1   + this->tport_counter ) % 256;
        o.printf( "      connect: ;238.%u.%u.%u\n", x, y, z );
        this->tport_counter++;
      }
      else if ( this->use_loopback ) {
        o.puts(   "      device: 127.0.0.1\n" );
      }
      else {
        o.printf( "      port: %u\n"
                  "      listen: *\n",
                  this->tport_counter++ + 5000 );
      }
    }
    for ( uint32_t j = 0; j < mesh.count; ) {
      AdjLink *test = mesh.ptr[ j ];
      if ( test->tport.equals( link->tport ) ) {
        if ( ! used.test_set( test->a.idx ) ) {
          if ( ! this->is_cfg )
            o.printf( " %s", test->a.user.val );
        }
        mesh.pop( j );
      }
      else {
        j++;
      }
    }
    if ( this->is_cfg ) {
      uint32_t i;
      if ( ! this->use_loopback && ! is_pgm ) {
        o.puts( "      connect: " );
        if ( used.count() > 1 )
          o.puts( "[ " );
      }
      bool first = true;
      for ( bool b = used.first( i ); b; b = used.next( i ) ) {
        AdjUser *u = this->graph.user_tab.ptr[ i ];
        if ( ! this->use_loopback && ! is_pgm ) {
          o.printf( "%s%s", ( first ? "" : ", " ), u->user.val );
          first = false;
        }
        this->args.add( *u, *link, CONNECT );
      }
      if ( ! this->use_loopback && ! is_pgm )
        o.printf( "%s\n", ( used.count() > 1 ) ? " ]" : "" );
    }
    this->print_cost( *link );
  }
}

void
AdjGraphOut::print_tcp( AdjLinkTab &tcp ) noexcept
{
  uint32_t i, j, k = 0;
  bool eat_single_connections = false;

  while ( k < tcp.count ) {
    AdjLink *link = tcp.ptr[ k ],
            *test;
    BitSpace used;

    for ( j = 0; j < tcp.count; ) {
      test = tcp.ptr[ j ];
      if ( test != link && &link->a == &test->a &&
           link->tport.equals( test->tport ) ) {
        used.add( test->b.idx );
        tcp.pop( j );
      }
      else {
        j++;
      }
    }
    if ( used.is_empty() ) {
      if ( ! eat_single_connections ) {
        if ( ++k == tcp.count ) {
          eat_single_connections = true;
          k = 0;
        }
        continue;
      }
      this->print_link( *link );
      tcp.pop( 0 );
      for ( j = 0; j < tcp.count; j++ ) {
        test = tcp.ptr[ j ];
        if ( &test->a == &link->b && &test->b == &link->a ) {
          tcp.pop( j );
          break;
        }
      }
    }
    else {
      this->print_link( *link );
      for ( bool b = used.first( i ); b; b = used.next( i ) ) {
        AdjUser * u = this->graph.user_tab.ptr[ i ];
        this->print_connect( *link, *u );
      }
      for ( j = 0; j < tcp.count; j++ ) {
        if ( tcp.ptr[ j ] == link ) {
          tcp.pop( j );
          break;
        }
      }
      used.add( link->b.idx );
      for ( bool b = used.first( i ); b; b = used.next( i ) ) {
        for ( j = 0; j < tcp.count; j++ ) {
          test = tcp.ptr[ j ];
          if ( &link->a == &test->b && test->a.idx == i ) {
            tcp.pop( j );
            break;
          }
        }
      }
    }
    this->print_cost( *link );
  }
}

void
AdjGraphOut::print_link( AdjLink &link ) noexcept
{
  ArrayOutput & o = this->out;
  if ( ! this->is_cfg ) {
    o.printf( "%s_%s %s %s", link.type.val, link.tport.val,
            link.a.user.val, link.b.user.val );
  }
  else {
    o.printf(   "  - tport: %s\n"
                "    type: %s\n"
                "    route:\n",
              link.tport.val, link.type.val );
    if ( this->use_loopback ) {
      o.puts(   "      device: 127.0.0.1\n" );
    }
    else {
      o.printf( "      port: %u\n"
                "      listen: *\n"
                "      connect: %s\n",
                this->tport_counter++ + 5000,
                link.a.user.val );
    }
    this->args.add( link.a, link, LISTEN );
    this->args.add( link.b, link, CONNECT );
  }
}

void
AdjGraphOut::print_connect( AdjLink &link,  AdjUser &u ) noexcept
{
  if ( ! this->is_cfg ) {
    ArrayOutput & o = this->out;
    o.printf( " %s", u.user.val );
  }
  else {
    this->args.add( u, link, CONNECT );
  }
}

static int
split_args( char *buf, const char *args[ 500 ] ) noexcept
{
  int i = 0, argc = 0;
  for (;;) {
    while ( buf[ i ] <= ' ' && buf[ i ] != '\0' )
      buf[ i++ ] = '\0';
    if ( buf[ i ] == '\0' || argc == 100 )
      return argc;
    args[ argc++ ] = &buf[ i ];
    while ( buf[ i ] > ' ' )
      i++;
  }
}

static void
parse_cost( const char **args,  int argc,  uint32_t *cost ) noexcept
{
  int i = 0;
  for ( ; i < 4 && i < argc; i++ ) {
    int n = atoi( args[ i ] );
    cost[ i ] = ( n == 0 ? COST_DEFAULT : n );
  }
  if ( i <= 1 ) {
    if ( i == 0 ) cost[ 0 ] = COST_DEFAULT;
    cost[ 1 ] = cost[ 2 ] = cost[ 3 ] = cost[ 0 ];
  }
  if ( i == 2 ) {
    cost[ 2 ] = cost[ 0 ];
    cost[ 3 ] = cost[ 1 ];
  }
  if ( i == 3 )
    cost[ 3 ] = cost[ 0 ];
}

int
AdjGraph::load_graph( StringTab &str_tab,  const char *p,
                      size_t size,  uint32_t &start_uid ) noexcept
{
  static uint32_t default_cost[ 4 ] =
    { COST_DEFAULT, COST_DEFAULT, COST_DEFAULT, COST_DEFAULT };

  const char * args[ 500 ];
  int          argc, ln = 0;
  char         buf[ 8 * 1024 ],
               start[ 80 ];
  uint32_t     cost_val[ 4 ],
             * cost;
  const char * end = &p[ size ];
  size_t       start_len;

  start[ 0 ] = '\0';
  start_len  = 0;
  start_uid  = 0;
  while ( p < end ) {
    size_t       linelen = end - p;
    const char * eol     = (const char *) ::memchr( p, '\n', linelen );

    if ( eol == NULL )
      eol = end;

    linelen = eol - p;
    if ( linelen > sizeof( buf ) - 1 )
      linelen = sizeof( buf ) - 1;
    ::memcpy( buf, p, linelen );
    buf[ linelen ] = '\0';
    p = &eol[ 1 ];

    ln++;
    argc = split_args( buf, args );
    if ( argc == 0 )
      continue;
    if ( ::strcmp( args[ 0 ], "start" ) == 0 ) {
      if ( argc > 1 ) {
        start_len = ::strlen( args[ 1 ] );
        if ( start_len > sizeof( start ) - 1 )
          start_len = sizeof( start ) - 1;
        ::memcpy( start, args[ 1 ], start_len );
        start[ start_len ] = '\0';
      }
      continue;
    }
    if ( ::strcmp( args[ 0 ], "node" ) == 0 ) {
      for ( int i = 1; i < argc; i++ ) {
        StringVal a( args[ i ], ::strlen( args[ i ] ) );
        str_tab.add_string( a );
        this->add_user( a );
      }
      continue;
    }

    cost = default_cost;
    for ( int k = 1; k < argc; k++ ) {
      if ( args[ k ][ 0 ] == ':' ) {
        parse_cost( &args[ k + 1 ], argc - ( k + 1 ), cost_val );
        cost = cost_val;
        argc = k;
        break;
      }
    }
    char type[ 5 ];
    int32_t i = 0;
    const char * s = args[ 0 ], * name;
    for ( ; *s != '\0' && *s != ' ' && *s != '_'; s++ ) {
      if ( i < 4 )
        type[ i++ ] = *s;
    }
    type[ i < 4 ? i : 4 ] = '\0';
    if ( *s == '_' )
      name = s + 1;
    else
      name = type;

    if ( ::strcmp( type, "link" ) == 0 )
      ::strcpy( type, "tcp" );

    StringVal tp( name, ::strlen( name ) ),
              ty( type, ::strlen( type ) );
    str_tab.add_string( tp );
    str_tab.add_string( ty );

    if ( ::strcmp( type, "tcp" ) == 0 ) {
      if ( argc < 3 )
        continue;

      StringVal a( args[ 1 ], ::strlen( args[ 1 ] ) ),
                b( args[ 2 ], ::strlen( args[ 2 ] ) );
      this->add_conn( str_tab.add( a ), str_tab.add( b ), tp, ty, cost, 4 );

      for ( int i = 3; i < argc; i++ ) {
        StringVal c( args[ i ], ::strlen( args[ i ] ) );
        this->add_conn( a, str_tab.add( c ), tp, ty, cost, 4 );
      }
    }
    else {
      for ( int i = 1; i < argc; i++ ) {
        StringVal a( args[ i ], ::strlen( args[ i ] ) );
        str_tab.add_string( a );
        for ( int j = i + 1; j < argc; j++ ) {
          StringVal b( args[ j ], ::strlen( args[ j ] ) );
          this->add_conn( a, str_tab.add( b ), tp, ty, cost, 4 );
        }
      }
    }
  }
  if ( start_len > 0 ) {
    StringVal a( start, start_len );
    str_tab.add_string( a );
    AdjUser * u = this->add_user( a );
    start_uid = u->idx;
  }
  return 0;
}

namespace {
struct AdjRec {
  char     user[ 256 ],
           adj[ 256 ],
           tport[ 256 ],
           type[ 16 ];
  uint32_t cost[ 4 ],
           rem,
           prune;
  size_t iter_map( MDIterMap mp[ 10 ] ) {
    size_t n = 0;
    ::memset( (void *) this, 0, sizeof( *this ) );
    mp[ n++ ].string( "user" , user    , sizeof( user    ) );
    mp[ n++ ].string( "adj"  , adj     , sizeof( adj     ) );
    mp[ n++ ].string( "tport", tport   , sizeof( tport   ) );
    mp[ n++ ].string( "type" , type    , sizeof( type    ) );
    mp[ n++ ].uint  ( "cost" , &cost[0], sizeof( cost[0] ) );
    mp[ n++ ].uint  ( "cost2", &cost[1], sizeof( cost[1] ) );
    mp[ n++ ].uint  ( "cost3", &cost[2], sizeof( cost[2] ) );
    mp[ n++ ].uint  ( "cost4", &cost[3], sizeof( cost[3] ) );
    mp[ n++ ].uint  ( "rem"  , &rem    , sizeof( rem     ) );
    mp[ n++ ].uint  ( "prune", &prune  , sizeof( prune   ) );
    return 10;
  }
  size_t iter_user( MDIterMap *mp ) {
    ::memset( this->user, 0, sizeof( this->user ) );
    mp->string( "user", this->user, sizeof( this->user ) );
    return 1;
  }
  void print( void ) {
    printf( "%s %s %s %s %u %u\n", this->user, this->adj, this->tport,
            this->type, this->cost[ 0 ], this->rem );
  }
};
}

static size_t
strlen_dig( const char *s,  uint32_t &id ) noexcept
{
  size_t len = ::strlen( s ), i = len;
  id = 0;
  while ( i > 0 && s[ i - 1 ] >= '0' && s[ i - 1 ] <= '9' )
    id = id * 10 + ( s[ --i ] - '0' );
  if ( i > 0 && i < len && s[ i - 1 ] == '.' )
    return i - 1;
  id = 0;
  return len;
}

int
AdjGraph::load_json( StringTab &str_tab,  void *data,  size_t data_size,
                     bool is_yaml ) noexcept
{
  JsonMsgCtx ctx;
  MDReference mref;

  int status = ctx.parse( data, 0, data_size, NULL, this->mem, is_yaml );
  if ( status != 0 ) {
    fprintf( stderr, "JSON parse error, status %d/%s\n",
             status, Err::err( status )->descr );
    if ( ctx.input != NULL ) {
      fprintf( stderr, "line %u col %u\n", (uint32_t) ctx.input->line_count,
               (uint32_t) ( ctx.input->offset - ctx.input->line_start + 1 ) );
    }
    return status;
  }
  /*MDOutput mout;
  ctx.msg->print( &mout );*/
  if ( ctx.msg != NULL && ctx.msg->get_reference( mref ) == 0 &&
       mref.ftype == MD_ARRAY ) {
    size_t i, num_entries = mref.fsize;
    MDReference aref;
    MDMsg *m;
    AdjRec rec;
    uint32_t uid, uid2, tid;
    if ( mref.fentrysz > 0 )
      num_entries /= mref.fentrysz;
    for ( i = 0; i < num_entries; i++ ) {
      if ( ctx.msg->get_array_ref( mref, i, aref ) == 0 &&
           aref.ftype == MD_MESSAGE &&
           ctx.msg->get_sub_msg( aref, m, NULL ) == 0 ) {
        MDIterMap map;
        MDIterMap::get_map( *m, &map, rec.iter_user( &map ) );
        if ( rec.user[ 0 ] != '\0' ) {
          StringVal a( rec.user, strlen_dig( rec.user, uid ) );
          str_tab.add_string( a );
          this->add_user( a, uid );
        }
      }
    }
    AdjUser * last_user = NULL;
    for ( i = 0; i < num_entries; i++ ) {
      if ( ctx.msg->get_array_ref( mref, i, aref ) == 0 &&
           aref.ftype == MD_MESSAGE &&
           ctx.msg->get_sub_msg( aref, m, NULL ) == 0 ) {
        MDIterMap map[ 10 ];
        size_t n = MDIterMap::get_map( *m, map, rec.iter_map( map ) );
        StringVal adj( rec.adj, strlen_dig( rec.adj, uid ) ),
                  tp( rec.tport, strlen_dig( rec.tport, tid ) ),
                  ty( rec.type, ::strlen( rec.type ) ) ;
        if ( rec.user[ 0 ] != '\0' ) {
          StringVal a( rec.user, strlen_dig( rec.user, uid2 ) );
          str_tab.add_string( a );
          last_user = this->add_user( a, uid2 );
        }
        str_tab.add_string( adj );
        AdjUser * adj_user = this->add_user( adj, uid );
        str_tab.add_string( tp );
        str_tab.add_string( ty );
        uint32_t cnt   = ( n == 10 ? 4 : 1 ),
                 prune = ( n == 10 ? rec.prune : 0xff );
        this->add_link( last_user, adj_user, tp, ty, rec.cost, cnt, prune );
      }
    }
  }
  return 0;
}

#include <raims/user.h>

void
AdjGraphOut::print_config( const char *fn ) noexcept
{
  const char *p, *cfg = fn;
  char buf[ 256 ];
  if ( (p = ::strrchr( fn, '/' )) != NULL )
    fn = p + 1;
  if ( (p = ::strrchr( fn, '\\' )) != NULL )
    fn = p + 1;
  size_t prefix_len = fn - cfg;
  if ( (p = ::strchr( fn, '.' )) != NULL ) {
    size_t len = p - fn;
    if ( len > sizeof( buf ) - 1 )
      len = sizeof( buf ) - 1;
    ::memcpy( buf, fn, len );
    buf[ len ] = '\0';
    fn = buf;
  }
  this->is_cfg = true;
  ArrayOutput & o = this->out;
  rai::ms::CryptPass  pass;
  rai::ms::ServiceBuf svc;
  void * salt;
  size_t salt_len = 0;
  salt = pass.gen_salt( salt_len );
  rai::ms::init_kdf( salt, salt_len );
  pass.gen_pass();
  svc.gen_key( fn , ::strlen( fn ), pass );
  o.s( "services:\n"
       "  - svc: " ).s( fn ).s( "\n" )
   .s( "    create: " ).s( svc.create ).s( "\n" )
   .s( "    pri: " ).s( svc.pri ).s( "\n" )
   .s( "    pub: " ).s( svc.pub ).s( "\n" )
   .s( "parameters:\n" )
   .s( "  salt_data: " ).s( (char *) salt ).s( "\n" )
   .s( "  pass_data: " ).s( (char *) pass.pass ).s( "\n" )
   .s( "transports:\n" );
  this->print_graph();

  AdjUserTab & user_tab = this->graph.user_tab;
  for ( uint32_t i = 0; i < user_tab.count; i++ ) {
    AdjUser * u = user_tab.ptr[ i ];
    o.printf( "# ms_server -d %.*s%s.yaml -u %s", (int) prefix_len, cfg, fn,
              u->user.val );
    uint32_t j, cnt = 0, connect_cnt = 0, listen_cnt = 0;
    for ( j = 0; j < this->args.count; j++ ) {
      TPortArg &arg = this->args.ptr[ j ];
      if ( arg.user == u ) {
        o.printf( "%s %s.%s", cnt == 0 ? " -t" : "", arg.link->tport.val,
                  ( arg.op ? "connect" : "listen" ) );
        connect_cnt += ( arg.op == CONNECT );
        listen_cnt  += ( arg.op == LISTEN );
        cnt++;
      }
    }
    o.puts( "\n" );
    if ( cnt > 0 ) {
      o.puts( "# startup:\n" );
      if ( listen_cnt > 0 ) {
        o.puts( "#   listen:\n" );
        for ( j = 0; j < this->args.count; j++ ) {
          TPortArg &arg = this->args.ptr[ j ];
          if ( arg.user == u && arg.op == LISTEN ) {
            o.printf( "#     - %s\n", arg.link->tport.val );
          }
        }
      }
      if ( connect_cnt > 0 ) {
        o.puts( "#   connect:\n" );
        for ( j = 0; j < this->args.count; j++ ) {
          TPortArg &arg = this->args.ptr[ j ];
          if ( arg.user == u && arg.op == CONNECT ) {
            o.printf( "#     - %s\n", arg.link->tport.val );
          }
        }
      }
    }
  }
}

bool
rai::ms::compute_message_graph( const char *start,  const char *network,
                                size_t network_len,
                                kv::ArrayOutput &out ) noexcept
{
  MDMsgMem  tmp_mem;
  AdjGraph  graph( tmp_mem );
  StringTab str_tab( tmp_mem );
  uint32_t  start_uid = 0;
  bool      ok = false;

  if ( graph.load_graph( str_tab, network, network_len, start_uid ) == 0 ) {
    AdjGraphOut put( graph, out );
    if ( start != NULL ) {
      AdjUserTab & user_tab = graph.user_tab;
      size_t len = ::strlen( start );
      for ( uint32_t i = 0; i < user_tab.count; i++ ) {
        AdjUser * u = user_tab.ptr[ i ];
        if ( u->user.equals( start, len ) ) {
          start_uid = u->idx;
          break;
        }
      }
    }
    put.print_web_paths( start_uid );
    ok = true;
  }
  graph.reset();
  return ok;
}
