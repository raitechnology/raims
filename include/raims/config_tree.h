#ifndef __rai__raims__config_tree_h__
#define __rai__raims__config_tree_h__

#include <raikv/dlinklist.h>
#include <raikv/util.h>
#include <raikv/array_space.h>
#include <raims/string_tab.h>
#include <raimd/json.h>

namespace rai {
namespace ms {

#ifdef _MSC_VER
#define __attribute__(x)
#endif
struct ConfigErrPrinter : public md::MDOutput {
  virtual int puts( const char *s ) noexcept;
  virtual int printf( const char *fmt,  ... ) noexcept
    __attribute__((format(printf,2,3)));
};
struct ConfigFilePrinter : public md::MDOutput {
  FILE * fp;
  ConfigFilePrinter() : fp( 0 ) {}
  ~ConfigFilePrinter() noexcept;
  int open( const char *path ) noexcept;
  void close( void ) noexcept;
  virtual int puts( const char *s ) noexcept;
  virtual int printf( const char *fmt,  ... ) noexcept;
};
struct ConfigDirPrinter : public ConfigFilePrinter {
  const StringVal & dir_name;
  ConfigDirPrinter( const StringVal &d ) : dir_name( d ) {}
  int open( const char *kind,  const StringVal &sv ) noexcept;
};

enum WhichYaml {
  PRINT_USERS             = 1,
  PRINT_SERVICES          = 2,
  PRINT_TRANSPORTS        = 4,
  PRINT_GROUPS            = 8,
  PRINT_PARAMETERS        = 16,
  PRINT_HOSTS             = 32,
  PRINT_STARTUP           = 64,
  PRINT_EXCLUDE_TEMPORARY = 512,
  PRINT_NORMAL            = 1|2|4|8|16|32|64
};

struct ConfigTree {
  struct Group;
  struct Service;

  /* field : value */
  struct StringPair {
    void * operator new( size_t, void *ptr ) { return ptr; }
    StringPair * next;
    StringVal    name,    /* route var name */
                 value;   /* route var value */
    StringPair() : next( 0 ) {}
    StringPair( const StringPair &sp ) : next( 0 ), name( sp.name ),
      value( sp.value ) {}
    StringPair( const StringVal &nm,  const StringVal &val ) : next( 0 ),
      name( nm ), value( val ) {}
  };
  struct PairList : public kv::SLinkList<StringPair> {
    StringPair *get_pair( const char *name,  size_t len ) {
      for ( StringPair *p = this->hd; p; p = p->next ) {
        if ( p->name.equals( name, len ) )
          return p;
      }
      return NULL;
    }
    bool get_val( const char *name,  size_t len,  const char *&val ) {
      StringPair *p = this->get_pair( name, len );
      if ( p != NULL ) {
        val = p->value.val;
        return true;
      }
      val = NULL;
      return false;
    }
    bool get_val( const char *name,  const char *&val ) {
      return this->get_val( name, ::strlen( name ), val );
    }
    bool get_int( const char *name,  size_t len,  int &val ) {
      StringPair *p = this->get_pair( name, len );
      if ( p == NULL )
        return false;
      return p->value.get_int( val );
    }
    bool get_int( const char *name,  int &val ) {
      return this->get_int( name, ::strlen( name ), val );
    }
    bool get_bool( const char *name,  size_t len,  bool &val ) {
      StringPair *p = this->get_pair( name, len );
      if ( p == NULL )
        return false;
      return p->value.get_bool( val );
    }
    bool get_bool( const char *name,  bool &val ) {
      return this->get_bool( name, ::strlen( name ), val );
    }
  };
  struct StringPairArray : public kv::ArrayCount< StringPair *, 8 > {
  };
  /* [ array of strings ] */
  struct StringList {
    void * operator new( size_t, void *ptr ) { return ptr; }
    StringList * next;
    StringVal    val;    /* a subject or a user */
    StringList() : next( 0 ) {}
    StringList( const StringList &sl ) : next( 0 ), val( sl.val ) {}
  };
  typedef kv::SLinkList<StringList> StrList;

  struct User {
    void * operator new( size_t, void *ptr ) { return ptr; }
    User    * next;
    StringVal user,        /* user name */
              svc,         /* service name */
              create,      /* create time */
              expires,     /* if/when expires */
              revoke,      /* revoke time */
              pri,         /* pri base64 */
              pub;         /* pub base64 */
    uint32_t  user_id;     /* count 0 -> user_cnt */
    bool      is_temp;
                   /*entitle_cnt;*/ /* count of entitle[] */
    User() : next( 0 ), user_id( 0 ) {}
    User( const User &u ) : next( 0 ), user( u.user ), svc( u.svc ),
      create( u.create ), expires( u.expires ), revoke( u.revoke ),
      pri( u.pri ), pub( u.pub ), user_id( u.user_id ), is_temp( false ) {}
  };
  typedef kv::SLinkList< User > UserList;
  /* parameters : { string_pair_list } */
  struct Parameters {
    void * operator new( size_t, void *ptr ) { return ptr; }
    Parameters * next;
    PairList list;

    Parameters() : next( 0 ) {}
  };
  struct ParametersList : public kv::SLinkList< Parameters > {
    StringPair* find_sp( const char *name,  size_t name_len ) noexcept;
    bool find( const char *name,  const char *&value,
               const char *def_value = NULL ) noexcept;
    void set( StringTab &st,  const char *name,
              const char *value ) noexcept;
    void set( StringTab &st,  const char *name, bool value ) {
      this->set( st, name, value ? "true" : "false" );
    }
    bool remove( StringTab &st,  const char *name ) noexcept;
  };
  /* services : { svc : name, type : t, subject : [ arr ], route : { f:v } } */
  struct Service {
    void * operator new( size_t, void *ptr ) { return ptr; }
    Service * next;
    StringVal svc,        /* service name */
              create,     /* create time */
              pri,        /* rsa private key */
              pub;        /* rsa public key */
    PairList  users,      /* users signed */
              revoke;     /* users reovked */
    uint32_t  service_id; /* count 0 -> service_cnt */
    Service() : next( 0 ), service_id( 0 ) {}
    Service( const Service &s ) : next( 0 ), svc( s.svc ), create( s.create ),
      pri( s.pri ), pub( s.pub ), service_id( s.service_id ) {}
  };
  typedef kv::SLinkList< Service > ServiceList;
  /* transports : { tport : name, type : t, route : { f:v } } */
  struct Transport {
    void * operator new( size_t, void *ptr ) { return ptr; }
    Transport * next;
    StringVal   tport;    /* service name */
    StringVal   type;     /* route type, rv, nats, .. */
    uint32_t    tport_id; /* count 0 -> tport_cnt */
    bool        is_temp;
    PairList    route;    /* route parameters */
    Transport() : next( 0 ), tport_id( 0 ), is_temp( false ) {}
    Transport( const Transport &t ) : next( 0 ), tport( t.tport ),
      type( t.type ), tport_id( t.tport_id ) {}
    void print_y( md::MDOutput &p ) const noexcept;
    bool get_route_str( const char *name,  const char *&value ) {
      return this->route.get_val( name, value );
    }
    bool get_route_int( const char *name,  int &value ) {
      return this->route.get_int( name, value );
    }
    bool get_route_bool( const char *name,  bool &value ) {
      return this->route.get_bool( name, value );
    }
    void get_route_pairs( const char *name,  StringPairArray &el ) noexcept;

    static int get_host_port( const char *&hostp,  char *host,  size_t &len,
                              ParametersList &hosts ) noexcept;
    static bool is_wildcard( const char *host ) noexcept;
  };
  typedef kv::SLinkList< Transport > TransportList;
  /* groups : { group : name, users : [ arr ] } */
  struct Group {
    void * operator new( size_t, void *ptr ) { return ptr; }
    Group   * next;
    StringVal group;    /* group name */
    uint32_t  group_id; /* count 0 -> group_cnt */
    StrList   users;    /* list of users belonging to group */
    Group() : next( 0 ), group_id( 0 ) {}
    Group( const Group &g ) : next( 0 ), group( g.group ),
      group_id( g.group_id ) {}
  };
  typedef kv::SLinkList< Group > GroupList;

  struct TransportArray : public kv::ArrayCount< StringVal, 8 > {
    void push( const StringVal &tport ) {
      (*this)[ this->count ] = tport;
    }
    void push( const Transport *tport ) {
      (*this)[ this->count ] = tport->tport;
    }
    void push_unique( const Transport *tport ) {
      for ( size_t i = 0; i < this->count; i++ )
        if ( tport->tport.equals( this->ptr[ i ] ) )
          return;
      this->push( tport->tport );
    }
    void push_unique( const StringVal &tport ) {
      for ( size_t i = 0; i < this->count; i++ )
        if ( tport.equals( this->ptr[ i ] ) )
          return;
      this->push( tport );
    }
  };
  void * operator new( size_t, void *ptr ) { return ptr; }

  UserList       users;         /* users : [ Group array ] */
  ServiceList    services;      /* services : [ Service array ] */
  TransportList  transports;    /* transports : [ Transport array ] */
  GroupList      groups;        /* groups : [ Group array ] */
  ParametersList parameters,    /* parameters : { string list } */
                 startup,       /* startup : { string list } */
                 hosts;         /* hosts : { string list } */
  uint32_t       user_cnt,      /* count of user[] */
                 service_cnt,   /* count of service[] */
                 transport_cnt, /* count of transport[] */
                 group_cnt;     /* count of group[] */
  StringVal      cfg_name;
  bool           is_dir;
  ConfigTree() : /* user( 0 ), service( 0 ), transport( 0 ), group( 0 ),*/
         user_cnt( 0 ), service_cnt( 0 ), transport_cnt( 0 ), group_cnt( 0 ),
         is_dir( false ) {}
  int save_tport( const ConfigTree::Transport &tport ) const noexcept;
  int save_startup( const TransportArray &listen,
                    const TransportArray &connect ) const noexcept;
  int save_file( const TransportArray &listen,
                 const TransportArray &connect ) const noexcept;
  int save_new( void ) const noexcept;
  void print_js( md::MDOutput &p, int which, 
              const StringVal *filter = NULL,
              const ConfigTree::TransportArray *listen = NULL,
              const ConfigTree::TransportArray *connect = NULL ) const noexcept;
  void print_y( md::MDOutput &p, int which, 
              const StringVal *filter = NULL,
              const ConfigTree::TransportArray *listen = NULL,
              const ConfigTree::TransportArray *connect = NULL ) const noexcept;
  bool resolve( const char *us,  User *&usrp,  Service *&svcp ) noexcept;

  Service   * find_service( const char *svc,  size_t len ) noexcept;
  User      * find_user( Service &svc,  const char *usr,  size_t len ) noexcept;
  Transport * find_transport( const char *tport,  size_t len,
                              bool *conn = NULL ) noexcept;
  void set_route_str( ConfigTree::Transport &t,  StringTab &st,
                      const char *name,  const char *value,
                      size_t value_len ) noexcept;
  static bool string_to_uint( const char *s,  uint64_t &ival ) noexcept;
  static bool string_to_bytes( const char *s,  uint64_t &bytes ) noexcept;
  static bool string_to_secs( const char *s,  uint64_t &secs ) noexcept;
  static bool string_to_nanos( const char *s,  uint64_t &nanos ) noexcept;
  static bool string_to_bool( const char *s,  bool &b ) noexcept;
};

struct ConfigDB;
struct ConfigStartup {
  StringTab  & str;
  md::MDMsgMem mem;
  ConfigTree * tree;

  ConfigStartup( StringTab &st ) : str( st ), tree( 0 ) {}

  void copy( ConfigTree &t,  ConfigTree::TransportArray *listen = NULL,
             ConfigTree::TransportArray *connect = NULL ) noexcept;
  void copy_pair_list( ConfigDB &db,  const ConfigTree::PairList &list,
                       ConfigTree::PairList &cp_list ) noexcept;
  void copy_string_list( ConfigDB &db,  const ConfigTree::StrList &list,
                         ConfigTree::StrList &cp_list ) noexcept;
};

struct ConfigJson {
  md::MDMsgMem mem;

  ConfigJson() {}

  template<class Obj, class... Ts> /* node constructor, puts nodes in mem */
  Obj *make( Ts... args ) {
    return new ( this->mem.make( sizeof( Obj ) ) ) Obj( args... );
  }
  md::JsonValue * copy( const ConfigTree *tree, int which,
                        const StringVal *filter = NULL,
                        const ConfigTree::TransportArray *listen = NULL,
                        const ConfigTree::TransportArray *connect  = NULL) noexcept;
  md::JsonValue * copy( const ConfigTree::User &u ) noexcept;
  md::JsonValue * copy( const ConfigTree::Service &s ) noexcept;
  md::JsonValue * copy( const ConfigTree::Transport &t ) noexcept;
  md::JsonValue * copy( const ConfigTree::Group &g ) noexcept;
  md::JsonValue * copy( const ConfigTree::PairList &pl ) noexcept;
  md::JsonValue * copy( const ConfigTree::StrList &sl ) noexcept;
  md::JsonValue * copy( const StringVal &s ) noexcept;
  md::JsonObject * copy( const ConfigTree::ParametersList &list ) noexcept;
  md::JsonString * make_hostid( uint32_t ival ) noexcept;

  void push_array( md::JsonArray *&a,  md::JsonValue *v ) noexcept;
  void push_field( md::JsonObject *&o, const StringVal &s,
                   md::JsonValue *v ) noexcept;
  void push_field( md::JsonObject *&o, md::JsonString &s,
                   md::JsonValue *v ) noexcept;
  void push_field_s( md::JsonObject *&o, const StringVal &s,
                     const StringVal &v ) {
    if ( ! v.is_null() )
      this->push_field( o, s, this->copy( v ) );
  }
};

}
}
#endif
