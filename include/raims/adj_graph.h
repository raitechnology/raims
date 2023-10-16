#ifndef __rai_raims__adj_graph_h__
#define __rai_raims__adj_graph_h__

#include <raimd/md_msg.h>
#include <raikv/bit_set.h>
#include <raims/string_tab.h>

namespace rai {
namespace ms {

struct AdjLink;
struct AdjLinkTab : public kv::ArrayCount<AdjLink *, 8> {};
typedef kv::ArrayCount<uint32_t, 16> UIntArrayCount;
typedef kv::ArrayCount<kv::BitSpace, 16> BitSpaceArray;
typedef kv::ArrayCount<StringVal, 16> UserArray;

struct AdjFwdTab {
  AdjLinkTab     links;
  UIntArrayCount cost,
                 src;
  void reset( void ) noexcept;
};
typedef kv::ArrayCount<AdjFwdTab, 16> AdjFwdArray;

struct AdjUser {
  StringVal   user;
  AdjLinkTab  links;
  AdjFwdArray fwd;
  uint32_t    idx,
              uid;
  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjUser( StringVal *u,  uint32_t i ) : user( *u ), idx( 0 ), uid( i ) {}
  void reset( void ) noexcept;
};

struct AdjPath {
  uint16_t num,
           count;
  AdjPath() {}
  AdjPath( uint16_t p,  uint16_t n ) : num( p ), count( n ) {}
  AdjPath( const AdjPath &p ) : num( p.num ), count( p.count ) {}
  AdjPath & operator=( const AdjPath &p ) {
    this->num   = p.num;
    this->count = p.count;
    return *this;
  }
  bool equals( const AdjPath &p ) const {
    return p.num   == this->num &&
           p.count == this->count;
  }
};

struct AdjCost {
  uint32_t max_cost,
           min_cost;
  AdjPath  path;
  AdjCost() {}
  AdjCost( uint32_t c ) : max_cost( c ), min_cost( c ), path( 0, 1 ) {}
  AdjCost( const AdjCost &c ) :
    max_cost( c.max_cost ), min_cost( c.min_cost ), path( c.path ) {}
  AdjCost( const uint32_t *cost,  size_t count ) {
    this->set( cost, count );
  }
  AdjCost & operator=( const AdjCost &c ) {
    this->max_cost = c.max_cost;
    this->min_cost = c.min_cost;
    this->path     = c.path;
    return *this;
  }
  enum { COST_OK = 0, BAD_FMT, EMPTY_COST, EMPTY_PATH, BAD_COST, COST_X };
  int parse( const char *str,  size_t len ) noexcept;
  int parse( const char **args,  size_t argc ) noexcept;
  char * str( char *buf,  size_t len ) const noexcept;
  size_t str_size( char *buf,  size_t len ) const noexcept;
  void set( uint32_t cost ) {
    this->max_cost   = this->min_cost = cost;
    this->path.num   = 0;
    this->path.count = 1;
  }
  void set( uint32_t min_cost,  uint32_t max_cost,  uint16_t p,  uint16_t n ) {
    this->max_cost   = max_cost;
    this->min_cost   = min_cost;
    this->path.num   = p;
    this->path.count = n;
  }
  void set( const uint32_t *cost,  size_t count ) {
    size_t i;
    bool all_same = true;
    for ( i = 1; i < count; i++ )
      all_same &= ( cost[ 0 ] == cost[ i ] );
    if ( all_same )
      return this->set( cost[ 0 ] );
    if ( count == 4 && cost[ 0 ] == cost[ 2 ] && cost[ 1 ] == cost[ 3 ] )
      count = 2;
    for ( i = 0; ; i++ ) {
      uint32_t min_cost = cost[ i ],
               max_cost = cost[ ( i + 1 ) % count ];
      if ( min_cost < max_cost )
        return this->set( min_cost, max_cost, i, count );
    }
  }
  uint32_t operator[]( uint16_t p ) const {
    if ( p % this->path.count == this->path.num )
      return this->min_cost;
    return this->max_cost;
  }
  bool equals( const AdjCost &c ) const {
    return c.max_cost == this->max_cost && c.min_cost == this->min_cost &&
           this->path.equals( c.path );
  }
  bool equals( uint32_t cost ) const {
    return this->max_cost == this->min_cost && cost == this->max_cost;
  }
  char op( void ) const {
    if ( this->path.num == 0 && this->path.count == 1 )
      return ' ';
    return '_';
#if 0
    if ( this->min_cost + this->max_cost / 10 == this->max_cost )
      return '-';
    if ( this->min_cost == this->max_cost / 10 )
      return '_';
    if ( this->min_cost == this->max_cost / 100 )
      return '=';
    return '^';
#endif
  }
};

struct AdjLink {
  AdjUser      & a,       /* source of link */
               & b;       /* dest of link */
  BitSpaceArray  dest;    /* map of users reached for each path */
  StringVal      tport,   /* name of link */
                 type;    /* type: tcp, mesh, pgm */
  AdjCost        cost;    /* cost of link */
  uint32_t       tid,     /* transport id at user a */
                 link_num,/* globally inique link number */
                 idx;     /* index a.links[] */
  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjLink( AdjUser *u1,  AdjUser *u2,  StringVal *tp,  StringVal *ty,
           AdjCost *c,  uint32_t id,  uint32_t n,  uint32_t i )
      : a( *u1 ), b( *u2 ), tport( *tp ), type( *ty ), cost( *c ), tid( id ),
        link_num( n ), idx( i ) {}
  void reset( void ) noexcept;
};

struct AdjUserTab : public kv::ArrayCount<AdjUser *, 32> {
  kv::UIntHashTab * ht;
  AdjUserTab() : ht( 0 ) {}
  AdjUser * find( StringVal &user,  uint32_t uid ) noexcept;
  void add( AdjUser *u ) noexcept;
  void reset( void ) noexcept;
};

struct AdjVisit {
  kv::BitSpace   user; /* track which users visited */
  UIntArrayCount cost, /* cost of transitions */
                 src;  /* the source link used to get here (the user link idx) */
};

struct AdjInconsistent {
  UIntArrayCount src,
                 missing;
  kv::BitSpace   visit,
                 found;
  AdjLinkTab     missing_links;
  uint32_t       start_idx;
};

struct LCM : public kv::ArrayCount<uint32_t, 16> {
  kv::ArraySpace<uint32_t, 16> tmp;
  uint32_t val;
  uint32_t add( uint32_t x ) noexcept;
  void reset( void ) {
    this->clear();
    this->tmp.reset();
  }
};

struct AdjGraph {
  AdjUserTab     user_tab;   /* users in the graph with the links */
  md::MDMsgMem & mem;        /* allocation for graph structures and names */
  LCM            lcm;        /* least common multiple */
  uint32_t       link_count, /* total count of links */
                 path_count, /* number paths calculated and recommended */
                 max_links,  /* max number of links a single user has */
                 max_alt;    /* max alt paths available from any one user */

  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjGraph( md::MDMsgMem &m ) : mem( m ), link_count( 0 ), path_count( 1 ),
                                max_links( 0 ), max_alt( 0 ) {}
  void reset( void ) {
    this->link_count = 0;
    this->path_count = 1;
    this->max_links  = 0;
    this->max_alt    = 0;
    this->lcm.reset();
    this->user_tab.reset();
  }
  void compute_forward_set( uint16_t p ) noexcept;
  uint32_t get_min_cost( uint16_t p,  AdjVisit &visit,  AdjLinkTab &links,
                         kv::BitSpace &dup,  uint32_t &dup_count ) noexcept;
  void add_fwd_set( AdjFwdTab &fwd,  AdjLink &link,  AdjVisit &visit,
                    uint32_t cost ) noexcept;
  AdjUser *add_user( StringVal &a,  uint32_t uid = 0 ) noexcept;

  void add_link( StringVal &a,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 AdjCost &cost,  uint32_t tid = 0 ) {
    this->add_link( this->add_user( a ), this->add_user( b ), tp, ty, cost, tid );
  }
  void add_link( AdjUser *u1,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 AdjCost &cost,  uint32_t tid = 0 ) {
    this->add_link( u1, this->add_user( b ), tp, ty, cost, tid );
  }
  void add_link( AdjUser *u1,  AdjUser *u2,  StringVal &tp,  StringVal &ty,
                 AdjCost &cost,  uint32_t tid = 0 ) noexcept;

  void add_conn( StringVal &a,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 AdjCost &cost ) {
    this->add_conn( this->add_user( a ), this->add_user( b ), tp, ty, cost );
  }
  void add_conn( AdjUser *u1,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 AdjCost &cost ) {
    this->add_conn( u1, this->add_user( b ), tp, ty, cost );
  }
  void add_conn( AdjUser *u1,  AdjUser *u2,  StringVal &tp,  StringVal &ty,
                 AdjCost &cost ) noexcept;

  int load_json( StringTab &str_tab,  void *data,  size_t data_size,
                 bool is_yaml ) noexcept;
  int load_graph( StringTab &str_tab,  const char *p,
                  size_t size,  uint32_t &start_uid ) noexcept;
  void add_users( StringTab &str_tab,  const char **args,  int argc ) noexcept;
  void link_users( StringTab &str_tab,  UserArray &users,  StringVal &tport,
                   StringVal &type,  AdjCost &cost,  int cstatus,
                   bool is_tcp ) noexcept;
  void init_inconsistent( uint32_t src_idx,  AdjInconsistent &inc ) noexcept;
  void find_inconsistent( AdjInconsistent &inc ) noexcept;

  template<class Obj, class... Ts>
  Obj *make( Ts... args ) {
    return new ( this->mem.make( sizeof( Obj ) ) ) Obj( args... );
  }
};

enum {
  LISTEN  = 0,
  CONNECT = 1
};
struct TPortArg {
  AdjUser * user;
  AdjLink * link;
  int       op;
  TPortArg( AdjUser &u,  AdjLink &l,  int t )
    : user( &u ), link( &l ), op( t ) {}
  TPortArg & operator=( const TPortArg &a ) {
    this->user = a.user;
    this->link = a.link;
    this->op   = a.op;
    return *this;
  }
};
struct AdjServerArgs : public kv::ArrayCount<TPortArg, 32> {
  void add( AdjUser &u,  AdjLink &l,  int t ) {
    this->push( TPortArg( u, l, t ) );
  }
};

struct AdjGraphOut {
  AdjGraph        & graph;
  kv::ArrayOutput & out;
  AdjServerArgs     args;
  uint32_t          tport_counter;
  bool              is_cfg,
                    use_loopback;

  AdjGraphOut( AdjGraph &g,  kv::ArrayOutput &o )
    : graph( g ), out( o ), tport_counter( 0 ), is_cfg( false ),
      use_loopback( false ) {}

  void print( void ) noexcept;

  void print_tree( uint16_t p,  bool print_unused ) noexcept;
  void print_tree_link( uint32_t indent,  AdjFwdTab &fwd,  uint32_t src,
                        uint32_t j,  uint16_t p ) noexcept;

  void print_web_paths( uint32_t start_idx ) noexcept;
  void print_web_path( uint16_t p,  uint32_t start_idx ) noexcept;
  void step_web_path_node( uint32_t step,  AdjFwdTab &fwd,  uint32_t src,
                           uint32_t j,  UIntArrayCount &path_step,
                           UIntArrayCount &path_cost ) noexcept;
  void print_web_path_link( uint32_t step,  AdjFwdTab &fwd, uint32_t src,
                            uint32_t j,  bool first ) noexcept;

  void print_mask( uint16_t p ) noexcept;
  void print_fwd( uint16_t p ) noexcept;

  void print_graph( void ) noexcept;
  void print_mesh( AdjLinkTab &mesh,  bool is_pgm ) noexcept;
  void print_tcp( AdjLinkTab &tcp ) noexcept;
  void print_link( AdjLink &link ) noexcept;
  void print_connect( AdjLink &link,  AdjUser &u ) noexcept;
  void print_cost( AdjLink &link ) noexcept;
  void print_config( const char *fn ) noexcept;
};

bool compute_message_graph( const char *start,  const char *network,
                            size_t network_len,
                            kv::ArrayOutput &out ) noexcept;
}
}
#endif
