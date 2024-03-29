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
  ArrayOutput & o        = this->out;
  AdjUserTab  & user_tab = this->graph.user_tab;

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
AdjGraphOut::print_tree( uint16_t p,  bool print_unused ) noexcept
{
  ArrayOutput & o        = this->out;
  AdjUserTab  & user_tab = this->graph.user_tab;

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
                              uint32_t j,  uint16_t p ) noexcept
{
  ArrayOutput & o = this->out;
  uint32_t      cost = fwd.cost.ptr[ j ];
  AdjLink     * link = fwd.links.ptr[ j ];

  uint32_t dest_idx = link->b.idx;
  o.printf( "%*s[%u] %s -> %s %s(%c/%u)\n", indent, "", cost,
          link->a.user.val, link->b.user.val, link->tport.val,
          link->dest[ p ].is_member( dest_idx ) ? '+' : '-',
          link->link_num );

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
  uint32_t      path_count = this->graph.path_count;
  o.puts( "[\n" );
  for ( uint16_t p = 0; p < path_count; p++ ) {
    this->print_web_path( p, start_idx );
    if ( p < path_count - 1 ) o.puts( ",\n" );
  }
  o.puts( "]\n" );
}

void
AdjGraphOut::print_web_path( uint16_t p,  uint32_t start_idx ) noexcept
{
  ArrayOutput  & o = this->out;
  AdjUserTab   & user_tab = this->graph.user_tab;
  if ( start_idx >= user_tab.count )
    return;
  AdjUser      * u        = user_tab.ptr[ start_idx ];
  AdjFwdTab    & fwd      = u->fwd[ p ];
  uint32_t       i, src;
  UIntArrayCount path_step, path_cost;

  for ( i = 0; i < user_tab.count; i++ ) {
    path_step.push( (uint32_t) -1 );
    path_cost.push( (uint32_t) 0 );
  }
  path_step.ptr[ start_idx ] = 0;
  for ( src = 0; src < u->links.count; src++ ) {
    uint32_t j;
    for ( j = 0; j < fwd.links.count; j++ ) {
      if ( fwd.src.ptr[ j ] == src )
        break;
    }
    if ( j < fwd.links.count ) {
      this->step_web_path_node( 1, fwd, src, j, path_step, path_cost );
    }
  }
  o.puts( "{\n\"nodes\": [\n" );
  for ( i = 0; i < user_tab.count; i++ ) {
    AdjUser * n = user_tab.ptr[ i ];
    o.printf( "%s{\"user\": \"%s\", \"uid\": %u, \"step\": %d, \"cost\": %u}",
              ( i == 0 ? "" : ",\n" ),
              n->user.val, i, path_step.ptr[ i ], path_cost.ptr[ i ] );
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
AdjGraphOut::step_web_path_node( uint32_t step,  AdjFwdTab &fwd,  uint32_t src,
                                 uint32_t j,  UIntArrayCount &path_step,
                                 UIntArrayCount &path_cost ) noexcept
{
  uint32_t  cost = fwd.cost.ptr[ j ];
  AdjLink * link = fwd.links.ptr[ j ];

  /*o.printf( ",\n{\"user\": \"%s\", \"uid\": %u, \"step\": %u, \"cost\": %u}",
          link->b.user.val, link->b.idx, step, cost );*/
  uint32_t k = link->b.idx;
  path_step.ptr[ k ] = step;
  path_cost.ptr[ k ] = cost;

  for ( uint32_t k = j + 1; k < fwd.links.count; k++ ) {
    if ( fwd.src.ptr[ k ] == src &&
         &fwd.links.ptr[ k ]->a == &link->b ) {
      this->step_web_path_node( step + 1, fwd, src, k, path_step, path_cost );
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
AdjGraphOut::print_mask( uint16_t p ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUserTab & user_tab = this->graph.user_tab;
  for ( uint32_t idx = 0; idx < user_tab.count; idx++ ) {
    AdjUser   * u   = user_tab.ptr[ idx ];
    AdjFwdTab & fwd = u->fwd[ p ];
    o.printf( "(%s", u->user.val );
    for ( uint32_t i = 0; i < fwd.links.count; i++ )
      o.printf( ",%u", fwd.links.ptr[ i ]->link_num );
    o.puts( ") " );
  }
  o.puts( "\n" );
}

void
AdjGraphOut::print_fwd( uint16_t p ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUserTab & user_tab = this->graph.user_tab;
  for ( uint32_t idx = 0; idx < user_tab.count; idx++ ) {
    AdjUser *u = user_tab.ptr[ idx ];
    o.printf( "%s\n", u->user.val );
    for ( uint32_t j = 0; j < u->links.count; j++ ) {
      bool first = true;
      uint32_t idx = 0;
      AdjLink  * link = u->links.ptr[ j ];
      BitSpace & dest = link->dest[ p ];
      for ( bool b = dest.first( idx ); b; b = dest.next( idx ) ) {
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

char *
AdjCost::str( char *buf,  size_t len ) const noexcept
{
  this->str_size( buf, len );
  return buf;
}

size_t
AdjCost::str_size( char *buf,  size_t len ) const noexcept
{
  char op = this->op();
  int n;
  if ( op == ' ' )
    n = ::snprintf( buf, len, "%u", this->max_cost );
  else
    n = ::snprintf( buf, len, "%u%c%u%c%u/%u", this->max_cost, op,
                    this->min_cost, op, this->path.num, this->path.count );
  return n;
}

void
AdjGraphOut::print_cost( AdjLink &link ) noexcept
{
  ArrayOutput & o = this->out;
  if ( ! link.cost.equals( COST_DEFAULT ) ) {
    if ( ! this->is_cfg )
      o.puts( " : " );
    else
      o.puts( "      cost: " );
    char op = link.cost.op();
    if ( op == ' ' )
      o.printf( "%u\n", link.cost.max_cost );
    else
      o.printf( "%u%c%u%c%u/%u\n", link.cost.max_cost, op,
            link.cost.min_cost, op, link.cost.path.num, link.cost.path.count );
      /*o.printf( "%u%c%u/%u", link.cost.max_cost, link.cost.op(),
                link.cost.path.num, link.cost.path.count );*/
  }
  else {
    if ( ! this->is_cfg )
      o.puts( "\n" );
  }
}

void
AdjGraphOut::print_graph( uint32_t start_idx ) noexcept
{
  ArrayOutput & o = this->out;
  AdjUserTab & user_tab = this->graph.user_tab;
  StringVal tcp_type( "tcp", 3 ),
            mesh_type( "mesh", 4 ),
            pgm_type( "pgm", 3 );
  AdjLinkTab tcp, mesh, pgm;
  if ( user_tab.count == 0 )
    return;
  if ( ! this->is_cfg ) {
    o.printf( "start %s\n", user_tab.ptr[ start_idx ]->user.val );
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
  BitSpace unused;
  uint32_t i, j, k;

  for ( i = 0; i < mesh.count; i++ )
    unused.add( i );

  while ( unused.first( k ) ) {
    AdjLink *link = mesh.ptr[ k ];
    BitSpace used;
    unused.remove( k );
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
    for ( bool b = unused.first( j ); b; b = unused.next( j ) ) {
      AdjLink *test = mesh.ptr[ j ];
      if ( test->tport.equals( link->tport ) ) {
        if ( ! used.test_set( test->a.idx ) ) {
          if ( ! used.test_set( link->a.idx ) ) {
            if ( ! this->is_cfg )
              o.printf( " %s", link->a.user.val );
          }
          if ( ! this->is_cfg )
            o.printf( " %s", test->a.user.val );
        }
        unused.remove( j );
      }
    }
    if ( this->is_cfg ) {
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
  ArrayCount< BitSpace, 4 > queue;
  BitSpace  unused,
            used;
  AdjLink * link,
          * test;
  uint32_t  i, j, k = 0;

  for ( i = 0; i < tcp.count; i++ )
    unused.add( i );

  /* find star connections */
  for ( bool b = unused.first( k ); b; b = unused.next( k ) ) {
    link = tcp.ptr[ k ];
    used.zero();
    for ( bool b = unused.first( j ); b; b = unused.next( j ) ) {
      if ( j != k ) {
        test = tcp.ptr[ j ];
        if ( &link->a == &test->a && link->tport.equals( test->tport ) ) {
          used.add( j );
          unused.remove( j );
        }
      }
    }
    if ( ! used.is_empty() ) {
      unused.remove( k );
      used.add( k );
      BitSpace &n = queue.push( NULL );
      n.add( used );
    }
  }
  /* star with multiple connections */
  for ( size_t x = 0; x < queue.count; x++ ) {
    BitSpace &n = queue[ x ];
    link = NULL;
    for ( bool b = n.first( k ); b; b = n.next( k ) ) {
      AdjLink * cur = tcp.ptr[ k ];
      if ( link == NULL ) {
        link = cur;
        this->print_link( *link );
      }
      else {
        AdjUser * u = &cur->b;
        this->print_connect( *link, *u );
      }
      for ( bool c = unused.first( j ); c; c = unused.next( j ) ) {
        test = tcp.ptr[ j ];
        if ( &test->a == &cur->b && &test->b == &cur->a ) {
          unused.remove( j );
          break;
        }
      }
    }
    n.reset();
    this->print_cost( *link );
  }
  /* single connections */
  for ( bool b = unused.first( k ); b; b = unused.next( k ) ) {
    link = tcp.ptr[ k ];

    this->print_link( *link );
    this->print_cost( *link );

    unused.remove( k );
    for ( bool b = unused.first( j ); b; b = unused.next( j ) ) {
      test = tcp.ptr[ j ];
      if ( &test->a == &link->b && &test->b == &link->a ) {
        unused.remove( j );
        break;
      }
    }
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

int
AdjCost::parse( const char **args,  size_t argc ) noexcept
{
  if ( argc == 1 )
    return this->parse( args[ 0 ], ::strlen( args[ 0 ] ) );

  this->set( COST_DEFAULT, COST_DEFAULT, 0, 1 );
  UIntArrayCount cost_array;
  for ( size_t i = 0; i < argc; i++ ) {
    uint32_t n = atoi( args[ i ] );
    if ( n != 0 )
      cost_array.push( n );
  }
  if ( cost_array.count > 0 )
    this->set( cost_array.ptr, cost_array.count );
  return COST_OK;
}

int
AdjCost::parse( const char *str,  size_t len ) noexcept
{
  UIntArrayCount cost_array;
  char     op    = 0;
  uint32_t val   = 0,
           cost  = 0,
           cost1 = 0,
           num   = 0;
  int      x     = COST_OK;

  this->set( COST_DEFAULT, COST_DEFAULT, 0, 1 );
  for ( size_t i = 0; i < len; i++ ) {
    if ( str[ i ] >= '0' && str[ i ] <= '9' )
      val = val * 10 + (uint32_t) ( str[ i ] - '0' );
    else if ( str[ i ] == '-' || str[ i ] == '_' || str[ i ] == '=' ||
              str[ i ] == '^' ) {
      cost1 = cost;
      cost  = val;
      val   = 0;
      op    = str[ i ];
    }
    else if ( str[ i ] == '/' ) {
      num  = val;
      val  = 0;
    }
    else if ( str[ i ] == ' ' ) {
      if ( val > 0 )
        cost_array.push( val );
      val = 0;
    }
    else if ( str[ i ] == 'X' || str[ i ] == 'N' ) {
      x = COST_X;
    }
    else {
      if ( str[ i ] < ' ' )
        break;
      return BAD_FMT;
    }
  }
  if ( op == 0 ) {
    if ( val != 0 ) {
      if ( cost_array.count > 0 ) {
        cost_array.push( val );
        this->set( cost_array.ptr, cost_array.count );
        return 0;
      }
      this->max_cost = val;
      this->min_cost = val;
      return COST_OK;
    }
    return EMPTY_COST;
  }
  if ( cost == 0 )
    return EMPTY_COST;
  if ( val == 0 || num >= val )
    return EMPTY_PATH;
  if ( cost1 != 0 && cost1 > cost && cost != 0 ) {
    this->max_cost = cost1;
    this->min_cost = cost;
  }
  else {
    this->max_cost = cost;
    switch ( op ) {
      case '-': this->min_cost = cost - cost / 10; break;
      case '_': this->min_cost = cost / 10; break;
      case '=': this->min_cost = cost / 100; break;
      case '^': this->min_cost = cost / 1000; break;
      default:  this->min_cost = 0;
    }
  }
  if ( this->min_cost == 0 || this->max_cost == 0 )
    return BAD_COST;
  this->path.num   = num;
  this->path.count = val;
  return x;
}

int
AdjGraph::load_graph( StringTab &str_tab,  const char *p,
                      size_t size,  uint32_t &start_uid ) noexcept
{
  const char * args[ 500 ], **argv;
  int          argc, ln = 0, stmt;
  char         buf[ 8 * 1024 ],
               start[ 80 ];
  StringVal    tport, type;
  UserArray    users;
  AdjCost      default_cost( COST_DEFAULT ),
               cost;
  int          cstatus = AdjCost::COST_OK;
  const char * end = &p[ size ];
  size_t       start_len;

  start[ 0 ] = '\0';
  start_len  = 0;
  start_uid  = 0;
  stmt       = G_NONE;
  cost       = default_cost;
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
    while ( linelen > 0 && buf[ linelen - 1 ] <= ' ' )
      buf[ --linelen ] = '\0';
    if ( linelen == 0 || buf[ 0 ] == '#' )
      continue;

    ln++;
    argc = split_args( buf, args );
    argv = args;
    if ( argc == 0 )
      continue;

    if ( args[ 0 ] == (const char *) buf ) {

      if ( ::strcmp( args[ 0 ], "start" ) == 0 ) {
        stmt = G_START;
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
        stmt = G_NODE;
        this->add_users( str_tab, &args[ 1 ], argc - 1 );
        continue;
      }

      size_t len = ::strlen( args[ 0 ] );
      bool   add_string = true;
      if ( ( len > 4 && ::strncmp( args[ 0 ], "tcp_", 4 ) == 0 ) ||
           ( len > 5 && ::strncmp( args[ 0 ], "link_", 5 ) == 0 ) ) {
        if ( stmt >= G_LINK )
          this->link_users( str_tab, users, tport, type, cost, cstatus, stmt );
        stmt = G_LINK;
        cost = default_cost;
        cstatus = AdjCost::COST_OK;
        if ( args[ 0 ][ 3 ] == '_' )
          tport = StringVal( &args[ 0 ][ 4 ], len - 4 );
        else
          tport = StringVal( &args[ 0 ][ 5 ], len - 5 );
        type = StringVal( "tcp", 3 );
      }
      else if ( len > 5 && ::strncmp( args[ 0 ], "mesh_", 5 ) == 0 ) {
        if ( stmt >= G_LINK )
          this->link_users( str_tab, users, tport, type, cost, cstatus, stmt );
        stmt = G_MESH;
        cost = default_cost;
        cstatus = AdjCost::COST_OK;
        type = StringVal( "mesh", 4 );
        tport = StringVal( &args[ 0 ][ 5 ], len - 5 );
      }
      else if ( len > 5 && ::strncmp( args[ 0 ], "cube_", 5 ) == 0 ) {
        if ( stmt >= G_CUBE )
          this->link_users( str_tab, users, tport, type, cost, cstatus, stmt );
        stmt = G_CUBE;
        cost = default_cost;
        cstatus = AdjCost::COST_OK;
        type = StringVal( "tcp", 3 );
        tport = StringVal( &args[ 0 ][ 5 ], len - 5 );
      }
      else if ( len > 4 && ::strncmp( args[ 0 ], "pgm_", 4 ) == 0 ) {
        if ( stmt >= G_LINK )
          this->link_users( str_tab, users, tport, type, cost, cstatus, stmt );
        stmt = G_PGM;
        cost = default_cost;
        cstatus = AdjCost::COST_OK;
        type = StringVal( "pgm", 3 );
        tport = StringVal( &args[ 0 ][ 4 ], len - 4 );
      }
      else {
        add_string = false;
      }
      if ( add_string ) {
        str_tab.add_string( tport );
        str_tab.add_string( type );
        argv++;
        argc--;
      }
    }
    else if ( stmt == G_NODE ) {
      this->add_users( str_tab, args, argc );
      continue;
    }

    int k;
    for ( k = 0; k < argc; k++ ) {
      if ( argv[ k ][ 0 ] == ':' ) {
        cstatus = cost.parse( &argv[ k + 1 ], argc - ( k + 1 ) );
        argc = k;
        break;
      }
    }

    switch ( stmt ) {
      case G_LINK:
      case G_MESH:
      case G_PGM:
      case G_CUBE:
        for ( k = 0; k < argc; k++ ) {
          StringVal v( argv[ k ], ::strlen( argv[ k ] ) );
          str_tab.add_string( v );
          users.push( v );
        }
        break;
      default:
        fprintf( stderr, "unknown stmt on line %u\n", ln );
        break;
    }
  }
  if ( stmt >= G_LINK )
    this->link_users( str_tab, users, tport, type, cost, cstatus, stmt );
  if ( start_len > 0 ) {
    StringVal a( start, start_len );
    str_tab.add_string( a );
    AdjUser * u = this->add_user( a );
    start_uid = u->idx;
  }
  return 0;
}

void
AdjGraph::add_users( StringTab &str_tab,  const char **args,
                     int argc ) noexcept
{
  for ( int i = 0; i < argc; i++ ) {
    StringVal a( args[ i ], ::strlen( args[ i ] ) );
    str_tab.add_string( a );
    this->add_user( a );
  }
}

void
AdjGraph::link_users( StringTab &str_tab,  UserArray &users,  StringVal &tport,
                      StringVal &type,  AdjCost &cost,  int cstatus,
                      int stmt ) noexcept
{
  StringVal * tport_ptr = &tport;
  StringVal   tport_tmp, tport_tmp2;
  if ( users.count > 1 ) {
    for (;;) {
      if ( cstatus == AdjCost::COST_X ) {
        char tmp[ 256 ];
        CatPtr cat( tmp );
        size_t n = cat.s( tport.val ).s( "_" ).i( cost.path.num + 1 ).end();
        tport_tmp = StringVal( tmp, n );
        str_tab.add_string( tport_tmp );
        tport_ptr = &tport_tmp;
      }
      if ( stmt == G_LINK ) {
        StringVal a( users.ptr[ 0 ] ),
                  b( users.ptr[ 1 ] );
        this->add_conn( a, b, *tport_ptr, type, cost );

        for ( size_t i = 2; i < users.count; i++ ) {
          StringVal c( users.ptr[ i ] );
          this->add_conn( a, c, *tport_ptr, type, cost );
        }
      }
      else if ( stmt == G_CUBE ) {
        StringVal tport_base = *tport_ptr;
        for ( size_t i = 0; i < users.count; i++ ) {
          StringVal a( users.ptr[ i ] );
          char tmp[ 256 ];
          CatPtr cat( tmp );
          size_t n = cat.s( tport_base.val ).s( "_v" ).u( i + 1 ).end();
          tport_tmp2 = StringVal( tmp, n );
          str_tab.add_string( tport_tmp2 );
          for ( size_t j = 1; j < users.count; j *= 2 ) {
            size_t k =  i ^ j;
            if ( k < users.count ) {
              StringVal b( users.ptr[ k ] );
              this->add_conn( a, b, tport_tmp2, type, cost );
            }
          }
        }
      }
      else {
        for ( size_t i = 0; i < users.count; i++ ) {
          StringVal a( users.ptr[ i ] );
          for ( size_t j = i + 1; j < users.count; j++ ) {
            StringVal b( users.ptr[ j ] );
            this->add_conn( a, b, *tport_ptr, type, cost );
          }
        }
      }
      if ( cstatus != AdjCost::COST_X )
        break;
      if ( ++cost.path.num >= cost.path.count )
        break;
    }
  }
  users.count = 0;
}

namespace {
struct AdjRec {
  char     user[ 256 ],
           adj[ 256 ],
           tport[ 256 ],
           type[ 16 ];
  uint32_t cost[ 4 ],
           rem;
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
  if ( i > 2 && s[ i - 1 ] == '*' && s[ i - 2 ] == '.' ) {
    id = 0;
    return i - 2;
  }
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
        uint32_t cnt   = ( n == 10 ? 4 : 1 );
        AdjCost cost( rec.cost, cnt );
        this->add_link( last_user, adj_user, tp, ty, cost );
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
   .s( "    users:\n" );

  AdjUserTab & user_tab = this->graph.user_tab;
  for ( uint32_t i = 0; i < user_tab.count; i++ ) {
    AdjUser * u = user_tab.ptr[ i ];
    svc.add_user( u->user.val, u->user.len );
  }
  svc.sign_users( NULL, pass );
  for ( UserElem *e = svc.users.hd; e != NULL; e = e->next ) {
    o.s( "      \"" ).b( e->user.user, e->user.user_len ).s( "\": \"" )
     .b( e->sig, e->sig_len ).s( "\"\n" );
  }

  o.s( "parameters:\n" )
   .s( "  salt_data: " ).b( (char *) salt, salt_len ).s( "\n" )
   .s( "  pass_data: " ).b( (char *) pass.pass, pass.pass_len ).s( "\n" )
   .s( "transports:\n" );
  this->print_graph( 0 );

  bool first_user = true;
  for ( uint32_t i = 0; i < user_tab.count; i++ ) {
    AdjUser  * u    = user_tab.ptr[ i ];
    UserElem * elem = svc.users.find( u->user.val, u->user.len );
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
      if ( first_user ) {
        o.s( "users:\n" );
        first_user = false;
      }
      o.s( "  - user: "   ).s( u->user.val ).s( "\n" )
       .s( "    svc: "    ).b( svc.service, svc.service_len ).s( "\n" )
       .s( "    create: " ).b( elem->user.create, elem->user.create_len ).s( "\n" )
       .s( "    pri: "    ).b( elem->user.pri, elem->user.pri_len ).s( "\n" )
       .s( "    pub: "    ).b( elem->user.pub, elem->user.pub_len ).s( "\n" )
       .s( "    startup:\n" );

      if ( listen_cnt > 0 ) {
        o.puts( "      listen:\n" );
        for ( j = 0; j < this->args.count; j++ ) {
          TPortArg &arg = this->args.ptr[ j ];
          if ( arg.user == u && arg.op == LISTEN ) {
            o.printf( "        - %s\n", arg.link->tport.val );
          }
        }
      }
      if ( connect_cnt > 0 ) {
        o.puts( "      connect:\n" );
        for ( j = 0; j < this->args.count; j++ ) {
          TPortArg &arg = this->args.ptr[ j ];
          if ( arg.user == u && arg.op == CONNECT ) {
            o.printf( "        - %s\n", arg.link->tport.val );
          }
        }
      }
    }
  }
}

