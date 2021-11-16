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
  /*uint32_t star_id, gt_id;*/

  ConfigDB( ConfigTree &t,  md::MDMsgMem &m,  InodeStack *stk,
            StringTab &st )
    : cfg( t ), mem( m ), ino_stk( stk ), str( st ), filename( NULL ),
      u( 0 ), s( 0 ), t( 0 ), g( 0 )/*, star_id( 0 ), gt_id( 0 )*/ {}
#if 0
  bool subscribes_everything( const StringVal &str ) {
    return str.id == this->gt_id;
  }
  bool includes_all_users( const StringVal &str ) {
    return str.id == this->star_id;
  }
  bool includes_all_svcs( const StringVal &str ) {
    return str.id == this->star_id;
  }
#endif
  template<class Obj> /* node constructor, puts nodes in mem */
  Obj *make( void ) {
    return new ( this->mem.make( sizeof( Obj ) ) ) Obj();
  }

  static ConfigTree * parse_dir( const char *dir_name, StringTab &st,
                                 ConfigPrinter &err ) noexcept;
  static ConfigTree * parse_jsfile( const char *fn, StringTab &st,
                                    ConfigPrinter &err ) noexcept;
  int parse_glob( const char *fn ) noexcept;
  int parse_fd( const char *fn,  int fd ) noexcept;
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
  int parse_include( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_services( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_transports( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_groups( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_parameters( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;

  int parse_users_user( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_svc( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_create( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_expires( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_revoke( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_pri( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;
  int parse_users_pub( md::MDMsg &, md::MDName &, md::MDReference & ) noexcept;

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
  bool check_strings( ConfigPrinter &p ) noexcept;
  bool check_string( StringVal &s,  StringTab &str,
                     const char *where,  ConfigPrinter &p ) noexcept;
  bool check_strings( ConfigTree::User &u,  StringTab &str,
                      ConfigPrinter &p ) noexcept;
  bool check_strings( ConfigTree::StringPair &pa,  StringTab &str,
                      const char *where,  ConfigPrinter &p ) noexcept;
  bool check_strings( ConfigTree::StringList &l,  StringTab &str,
                      const char *where,  ConfigPrinter &p ) noexcept;
  bool check_strings( ConfigTree::Service &svc,  StringTab &str,
                      ConfigPrinter &p ) noexcept;
  bool check_strings( ConfigTree::Transport &tport,  StringTab &str,
                      ConfigPrinter &p ) noexcept;
  bool check_strings( ConfigTree::Group &grp,  StringTab &str,
                      ConfigPrinter &p ) noexcept;
  bool check_strings( ConfigTree::Parameters &pa,  StringTab &str,
                      ConfigPrinter &p ) noexcept;
};

struct ArrayParse {
  const md::MDName name;
  int ( ConfigDB::*parse )( md::MDMsg &, md::MDName &, md::MDReference & );
  const md::MDType type;

  ArrayParse( const char *n,
           int ( ConfigDB::*p )( md::MDMsg &, md::MDName &, md::MDReference & ),
               md::MDType t ) :
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
