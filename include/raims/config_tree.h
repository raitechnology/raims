#ifndef __rai__raims__config_tree_h__
#define __rai__raims__config_tree_h__

#include <raikv/dlinklist.h>
#include <raikv/util.h>
#include <raikv/array_space.h>
#include <raims/string_tab.h>

namespace rai {
namespace ms {

#ifdef _MSC_VER
#define __attribute__(x)
#endif
struct ConfigPrinter {
  virtual int printf( const char *fmt,  ... ) noexcept
    __attribute__((format(printf,2,3)));
};
struct ConfigErrPrinter : public ConfigPrinter {
  virtual int printf( const char *fmt,  ... ) noexcept
    __attribute__((format(printf,2,3)));
};

enum WhichYaml {
  PRINT_USERS           = 1,
  PRINT_SERVICES        = 2,
  PRINT_TRANSPORTS      = 4,
  PRINT_GROUPS          = 8,
  PRINT_PARAMETERS      = 16,
  PRINT_NORMAL          = 31,
  PRINT_HDR             = 32,
  PRINT_STARTUP         = 64,
  PRINT_EXCLUDE_STARTUP = 128
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
    void print_js( ConfigPrinter &p ) const noexcept;
    void print_y( ConfigPrinter &p ) const noexcept;
    const StringPair *print_ylist( ConfigPrinter &p, int i ) const noexcept;
    const StringPair *print_jslist( ConfigPrinter &p, int i,
                                    const char *&nl ) const noexcept;
    const StringPair *print_jsarr( ConfigPrinter &p, int i,
                                   const char *&nl ) const noexcept;
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
  /* [ array of strings ] */
  struct StringList {
    void * operator new( size_t, void *ptr ) { return ptr; }
    StringList * next;
    StringVal    val;    /* a subject or a user */
    StringList() : next( 0 ) {}
    void print_js( ConfigPrinter &p ) const noexcept;
    void print_y( ConfigPrinter &p ) const noexcept;
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
                   /*entitle_cnt;*/ /* count of entitle[] */
    User() : next( 0 ), /*service( 0 ),*/ user_id( 0 ) {}
    void print_js( ConfigPrinter &p,  int i,  char c = 0 ) const noexcept;
    void print_y( ConfigPrinter &p,  int i ) const noexcept;
  };
  /* parameters : { string_pair_list } */
  struct Parameters {
    void * operator new( size_t, void *ptr ) { return ptr; }
    Parameters * next;
    PairList parms;

    Parameters() {}
    void print_js( ConfigPrinter &p,  int i,  char c = 0 ) const noexcept;
    void print_y( ConfigPrinter &p,  int i ) const noexcept;
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
    Service() : next( 0 ), /*user( 0 ),*/ service_id( 0 )/*, user_cnt( 0 )*/{}
    void print_js( ConfigPrinter &p,  int i ) const noexcept;
    void print_y( ConfigPrinter &p,  int i ) const noexcept;
  };
  /* transports : { tport : name, type : t, route : { f:v } } */
  struct Transport {
    void * operator new( size_t, void *ptr ) { return ptr; }
    Transport * next;
    StringVal   tport;    /* service name */
    StringVal   type;     /* route type, rv, nats, .. */
    uint32_t    tport_id; /* count 0 -> tport_cnt */
    PairList    route;    /* route parameters */
    Transport() : next( 0 ), tport_id( 0 ) {}
    void print_js( ConfigPrinter &p,  int i ) const noexcept;
    void print_y( ConfigPrinter &p,  int i ) const noexcept;
    bool get_route_str( const char *name,  const char *&value ) {
      return this->route.get_val( name, value );
    }
    bool get_route_int( const char *name,  int &value ) {
      return this->route.get_int( name, value );
    }
    bool get_route_bool( const char *name,  bool &value ) {
      return this->route.get_bool( name, value );
    }
    static int get_host_port( const char *&hostp,  char *host,
                              size_t &len ) noexcept;
    static bool is_wildcard( const char *host ) noexcept;
  };
  /* groups : { group : name, users : [ arr ] } */
  struct Group {
    void * operator new( size_t, void *ptr ) { return ptr; }
    Group   * next;
    StringVal group;    /* group name */
    uint32_t  group_id; /* count 0 -> group_cnt */
    StrList   users;    /* list of users belonging to group */
    Group() : next( 0 ), group_id( 0 ) {}
    void print_js( ConfigPrinter &p,  int i ) const noexcept;
    void print_y( ConfigPrinter &p,  int i ) const noexcept;
  };

  typedef kv::SLinkList< User >       UserList;
  typedef kv::SLinkList< Service >    ServiceList;
  typedef kv::SLinkList< Transport >  TransportList;
  typedef kv::SLinkList< Group >      GroupList;
  typedef kv::SLinkList< Parameters > ParametersList;

  struct TransportArray : public kv::ArrayCount< Transport *, 4 > {
    void push( Transport *tport ) {
      (*this)[ this->count ] = tport;
    }
    void push_unique( Transport *tport ) {
      for ( size_t i = 0; i < this->count; i++ )
        if ( tport == this->ptr[ i ] )
          return;
      this->push( tport );
    }
  };

  void * operator new( size_t, void *ptr ) { return ptr; }

  UserList       users;         /* users : [ Group array ] */
  ServiceList    services;      /* services : [ Service array ] */
  TransportList  transports;    /* transports : [ Transport array ] */
  GroupList      groups;        /* groups : [ Group array ] */
  ParametersList parameters;    /* parameters : { string list } */
  uint32_t       user_cnt,      /* count of user[] */
                 service_cnt,   /* count of service[] */
                 transport_cnt, /* count of transport[] */
                 group_cnt;     /* count of group[] */
  StringVal      dir_name;
  ConfigTree() : /* user( 0 ), service( 0 ), transport( 0 ), group( 0 ),*/
         user_cnt( 0 ), service_cnt( 0 ), transport_cnt( 0 ), group_cnt( 0 ) {}
  int save_tport( const ConfigTree::Transport &tport ) const noexcept;
  int save_parameters( const TransportArray &listen,
                       const TransportArray &connect ) const noexcept;
  void print_parameters_y( ConfigPrinter &p,
                           int which,  const char *name,  size_t namelen,
                           const TransportArray &listen,
                           const TransportArray &connect ) const noexcept;
  void print_parameters_js( ConfigPrinter &p,
                            int which,  const char *name,  size_t namelen,
                            const TransportArray &listen,
                            const TransportArray &connect ) const noexcept;
  bool save_new( void ) const noexcept;
  void print_js( ConfigPrinter &p ) const noexcept;
  void print_js( ConfigPrinter &p, int which,
                 const char *name = NULL,  size_t namelen = 0 ) const noexcept;
  void print_y( ConfigPrinter &p, int &did_which,  int which = PRINT_NORMAL,
                const char *name = NULL,  size_t namelen = 0 ) const noexcept;
  bool resolve( const char *us,  User *&usrp,  Service *&svcp ) noexcept;

  Service   * find_service( const char *svc,  size_t len ) noexcept;
  User      * find_user( Service &svc,  const char *usr,  size_t len ) noexcept;
  Transport * find_transport( const char *tport,  size_t len,
                              bool *conn = NULL ) noexcept;
  bool        find_parameter( const char *name,  const char *&value,
                              const char *def_value = NULL ) noexcept;
};

}
}
#endif
