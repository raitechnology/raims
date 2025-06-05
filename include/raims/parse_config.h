#ifndef __rai__raims__parse_config_h__
#define __rai__raims__parse_config_h__

#include <raikv/route_ht.h>
#include <raims/config_tree.h>

namespace rai {
namespace ms {

struct ArrayParse;
struct ObjectParse;

/* config parser */
struct ConfigDB {
  struct InodeStack;

  ConfigTree   & cfg;      /* result of parse */
  md::MDMsgMem & mem;      /* all config tree memory in here */
  InodeStack   * ino_stk;  /* stack of inodes for recursion check */
  StringTab    & str;      /* unique string table */
  const char   * filename; /* for error printing */

  ConfigTree::User       * u; /* temp parse nodes */
  ConfigTree::Service    * s;
  ConfigTree::Transport  * t;
  ConfigTree::Group      * g;

  ConfigDB( ConfigTree &t,  md::MDMsgMem &m,  InodeStack *stk,
            StringTab &st )
    : cfg( t ), mem( m ), ino_stk( stk ), str( st ), filename( NULL ),
      u( 0 ), s( 0 ), t( 0 ), g( 0 )/*, star_id( 0 ), gt_id( 0 )*/ {}

  template<class Obj, class... Ts> /* node constructor, puts nodes in mem */
  Obj *make( Ts... args ) {
    return new ( this->mem.make( sizeof( Obj ) ) ) Obj( args... );
  }

  static ConfigTree * parse_tree( const char *cfg_name,  StringTab &st,
                                  md::MDOutput &err ) noexcept;
  static ConfigTree * parse_dir( const char *dir_name,  StringTab &st,
                                 md::MDOutput &err ) noexcept;
  static ConfigTree * parse_jsfile( const char *fn,  StringTab &st,
                                    md::MDOutput &err ) noexcept;
  static ConfigTree * parse_fd( int fd,  StringTab &st,  md::MDOutput &err ) noexcept;

  int parse_glob( const char *fn,  uint32_t &match ) noexcept;
  int parse_file( const char *fn ) noexcept;
  int parse_stream( int fd ) noexcept;
  int parse_jsconfig( const char *buf,  size_t buflen,  const char *fn ) noexcept;
  int config_string( const char *what, md::MDMsg &msg,
                     md::MDReference &mref,  StringVal &str ) noexcept;
  int config_array( const char *what, md::MDMsg &msg,
                    md::MDReference &mref,
                    ConfigTree::StrList &list ) noexcept;
  int parse_pairs( const char *where,  md::MDMsg &msg,
                   ConfigTree::PairList &list ) noexcept;
  int config_pair( const char *what, md::MDMsg &msg,  const md::MDName &name,
                   md::MDReference &mref, ConfigTree::PairList &list ) noexcept;
  int config_array( const char *where,  md::MDMsg &msg,  const md::MDName &name,
                  md::MDReference &mref,  ConfigTree::PairList &list ) noexcept;
  void create_user( void ) noexcept;
  void create_service( void ) noexcept;
  void create_transport( void ) noexcept;
  void create_group( void ) noexcept;

  int parse_object( const char *where,  md::MDMsg &msg,
                    const ObjectParse &obj ) noexcept;
  int parse_object_array( const char *where,  md::MDMsg &msg,
                          md::MDReference &mref,
                          const ObjectParse &obj ) noexcept;
  int parse_object_list( const char *where, md::MDMsg &msg,
                         md::MDName &name,  md::MDReference &mref,
                         ConfigTree::ParametersList &parms ) noexcept;
  int parse_include( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_services( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_transports( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_groups( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_parameters( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_startup( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_hosts( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_library( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;

  int parse_users_user( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_svc( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_create( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_expires( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_revoke( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_pri( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_pub( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_parameters( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_startup( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;

  int parse_services_svc( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_services_create( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_services_pri( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_services_pub( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_services_users( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_services_revoke( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_transports_tport( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_transports_type( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_transports_route( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;

  int parse_groups_group( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_groups_users( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;

  void check_null( ConfigTree::PairList &list ) noexcept;
  void check_null( ConfigTree::StrList  &list ) noexcept;
  bool check_strings( md::MDOutput &p ) noexcept;
  bool check_string( StringVal &s,  StringTab &str,
                     const char *where,  md::MDOutput &p ) noexcept;
  bool check_strings( ConfigTree::User &u,  StringTab &str,
                      md::MDOutput &p ) noexcept;
  bool check_strings( ConfigTree::StringPair &pa,  StringTab &str,
                      const char *where,  md::MDOutput &p ) noexcept;
  bool check_strings( ConfigTree::StringList &l,  StringTab &str,
                      const char *where,  md::MDOutput &p ) noexcept;
  bool check_strings( ConfigTree::Service &svc,  StringTab &str,
                      md::MDOutput &p ) noexcept;
  bool check_strings( ConfigTree::Transport &tport,  StringTab &str,
                      md::MDOutput &p ) noexcept;
  bool check_strings( ConfigTree::Group &grp,  StringTab &str,
                      md::MDOutput &p ) noexcept;
  bool check_strings( ConfigTree::Parameters &pa,  StringTab &str,
                      md::MDOutput &p ) noexcept;
};

struct ArrayParse {
  const md::MDName name;
  int ( ConfigDB::*parse )( md::MDMsg &, md::MDName &, md::MDReference & );
  const MDType type;

  ArrayParse( const char *n,
           int ( ConfigDB::*p )( md::MDMsg &, md::MDName &, md::MDReference & ),
                 MDType t ) :
    name( n ), parse( p ), type( t ) {}
};

struct ObjectParse {
  const ArrayParse * parse;
  size_t             parse_size;
  void ( ConfigDB::*create )( void );

  ObjectParse( const ArrayParse *p,  size_t sz,
                void ( ConfigDB::*c )( void ) )
    : parse( p ), parse_size( sz ), create( c ) {}
};

}
}
#endif
