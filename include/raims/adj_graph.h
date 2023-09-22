#ifndef __rai_raims__adj_graph_h__
#define __rai_raims__adj_graph_h__

#include <raimd/md_msg.h>
#include <raikv/bit_set.h>
#include <raims/string_tab.h>

namespace rai {
namespace ms {

struct AdjLink;
struct AdjLinkTab : public kv::ArrayCount<AdjLink *, 8> {};
typedef kv::ArrayCount<uint32_t, 32> UIntArrayCount;

struct AdjFwdTab {
  AdjLinkTab     links;
  UIntArrayCount cost,
                 src;
  void reset( void ) noexcept;
};

struct AdjUser {
  StringVal  user;
  AdjLinkTab links;
  AdjFwdTab  fwd[ 4 ];
  uint32_t   idx,
             uid;
  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjUser( StringVal *u,  uint32_t i ) : user( *u ), idx( 0 ), uid( i ) {}
  void reset( void ) noexcept;
};

struct AdjLink {
  AdjUser    & a,
             & b;
  kv::BitSpace dest[ 4 ];
  StringVal    tport,
               type;
  uint32_t     cost[ 4 ],
               prune,
               tid;
  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjLink( AdjUser *u1,  AdjUser *u2,  StringVal *tp,  StringVal *ty,
           uint32_t * c,  uint32_t cnt,  uint32_t pr,  uint32_t id )
      : a( *u1 ), b( *u2 ), tport( *tp ), type( *ty ), prune( pr ), tid( id ) {
    for ( uint32_t i = 0; i < 4; i++ ) this->cost[ i ] = c[ i % cnt ];
  }
  bool cost_equals( uint32_t c ) const {
    bool b = true;
    for ( uint32_t i = 0; i < 4; i++ )
      b &= ( this->cost[ i ] == c );
    return b;
  }
  bool cost_equals( uint32_t *c ) const {
    bool b = true;
    for ( uint32_t i = 0; i < 4; i++ )
      b &= ( this->cost[ i ] == c[ i ] );
    return b;
  }
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
  kv::BitSpace   user;
  UIntArrayCount cost,
                 src;
};

struct AdjInconsistent {
  UIntArrayCount src,
                 missing;
  kv::BitSpace   visit,
                 found;
  AdjLinkTab     missing_links;
  uint32_t       start_idx;
};

struct AdjGraph {
  AdjUserTab     user_tab;
  md::MDMsgMem & mem;

  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjGraph( md::MDMsgMem &m ) : mem( m ) {}

  void reset( void ) {
    this->user_tab.reset();
  }
  void compute_forward_set( uint8_t p ) noexcept;
  uint32_t get_min_cost( uint8_t p,  AdjVisit &visit ) noexcept;
  void add_fwd_set( uint8_t p,  uint32_t src_id,  AdjVisit &visit,
                    uint32_t min_cost ) noexcept;
  AdjUser *add_user( StringVal &a,  uint32_t uid = 0 ) noexcept;

  void add_link( StringVal &a,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 uint32_t *cost,  uint32_t cnt,  uint32_t prune = -1,
                 uint32_t tid = 0 ) {
    this->add_link( this->add_user( a ), this->add_user( b ), tp, ty,
                    cost, cnt, prune, tid );
  }
  void add_link( AdjUser *u1,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 uint32_t *cost,  uint32_t cnt,  uint32_t prune = -1,
                 uint32_t tid = 0 ) {
    this->add_link( u1, this->add_user( b ), tp, ty, cost, cnt, prune, tid );
  }
  void add_link( AdjUser *u1,  AdjUser *u2,  StringVal &tp,  StringVal &ty,
                 uint32_t *cost,  uint32_t cnt,  uint32_t prune = -1,
                 uint32_t tid = 0 ) noexcept;

  void add_conn( StringVal &a,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 uint32_t *cost,  uint32_t cnt,  uint32_t prune = -1 ) {
    this->add_conn( this->add_user( a ), this->add_user( b ), tp, ty,
                    cost, cnt, prune );
  }
  void add_conn( AdjUser *u1,  StringVal &b,  StringVal &tp,  StringVal &ty,
                 uint32_t *cost,  uint32_t cnt,  uint32_t prune = -1 ) {
    this->add_conn( u1, this->add_user( b ), tp, ty, cost, cnt, prune );
  }
  void add_conn( AdjUser *u1,  AdjUser *u2,  StringVal &tp,  StringVal &ty,
                 uint32_t *cost,  uint32_t cnt,  uint32_t prune = -1 ) noexcept;

  int load_json( StringTab &str_tab,  void *data,  size_t data_size,
                 bool is_yaml ) noexcept;
  int load_graph( StringTab &str_tab,  const char *p,
                  size_t size,  uint32_t &start_uid ) noexcept;

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

  void print_tree( uint8_t p,  bool print_unused ) noexcept;
  void print_tree_link( uint32_t indent,  AdjFwdTab &fwd,  uint32_t src,
                        uint32_t j,  uint8_t p ) noexcept;

  void print_web_paths( uint32_t start_idx ) noexcept;
  void print_web_path( uint8_t p,  uint32_t start_idx ) noexcept;
  void step_web_path_node( uint32_t step,  AdjFwdTab &fwd,  uint32_t src,
                           uint32_t j,  UIntArrayCount &path_step,
                           UIntArrayCount &path_cost ) noexcept;
  void print_web_path_link( uint32_t step,  AdjFwdTab &fwd, uint32_t src,
                            uint32_t j,  bool first ) noexcept;

  void print_fwd( uint8_t p ) noexcept;

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
