#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raikv/util.h>
#include <raikv/os_file.h>
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
#include <glob.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <raimd/json_msg.h>
#include <raikv/key_hash.h>
#include <raims/parse_config.h>
#include <raims/gen_config.h>
#include <raims/config_const.h>

using namespace rai;
using namespace md;
using namespace kv;
using namespace ms;
#define ASZ( ar ) ( sizeof( ar ) / sizeof( ar[ 0 ] ) )
#define SZ( s )   s, ( sizeof( s ) - 1 )

static StringVal users_s     ( SZ( "users"      ) ),
                 services_s  ( SZ( "services"   ) ),
                 transports_s( SZ( "transports" ) ),
                 groups_s    ( SZ( "groups"     ) ),
                 parameters_s( SZ( "parameters" ) ),
                 startup_s   ( SZ( "startup"    ) ),
                 hosts_s     ( SZ( "hosts"      ) ),
                 listen_s    ( R_LISTEN, R_LISTEN_SZ ),
                 connect_s   ( R_CONNECT, R_CONNECT_SZ );
static struct ArrayParse top_level[] = {
  { "users",      &ConfigDB::parse_users,      MD_ARRAY },
  { "services",   &ConfigDB::parse_services,   MD_ARRAY },
  { "transports", &ConfigDB::parse_transports, MD_ARRAY },
  { "groups",     &ConfigDB::parse_groups,     MD_ARRAY },
  { "include",    &ConfigDB::parse_include,    MD_STRING },
  { "parameters", &ConfigDB::parse_parameters, MD_MESSAGE },
  { "startup",    &ConfigDB::parse_startup,    MD_MESSAGE },
  { "hosts",      &ConfigDB::parse_hosts,      MD_MESSAGE }
};
static ObjectParse top_obj = {
  top_level, ASZ( top_level ), NULL
};
static StringVal user_s   ( SZ( "user"    ) ),
                 svc_s    ( SZ( "svc"     ) ),
                 create_s ( SZ( "create"  ) ),
                 expires_s( SZ( "expires" ) ),
                 revoke_s ( SZ( "revoke"  ) ),
                 pri_s    ( SZ( "pri"     ) ),
                 pub_s    ( SZ( "pub"     ) );
static struct ArrayParse users_fields[] = {
  { "user",    &ConfigDB::parse_users_user,    MD_STRING },
  { "svc",     &ConfigDB::parse_users_svc,     MD_STRING },
  { "create",  &ConfigDB::parse_users_create,  MD_STRING },
  { "expires", &ConfigDB::parse_users_expires, MD_STRING },
  { "revoke",  &ConfigDB::parse_users_revoke,  MD_STRING },
  { "pri",     &ConfigDB::parse_users_pri,     MD_STRING },
  { "pub",     &ConfigDB::parse_users_pub,     MD_STRING }
};
static struct ObjectParse users_obj = {
  users_fields, ASZ( users_fields ), &ConfigDB::create_user
};

static struct ArrayParse svcs_fields[] = {
  { "svc",     &ConfigDB::parse_services_svc,    MD_STRING },
  { "create",  &ConfigDB::parse_services_create, MD_STRING },
  { "pri",     &ConfigDB::parse_services_pri,    MD_STRING },
  { "pub",     &ConfigDB::parse_services_pub,    MD_STRING },
  { "users",   &ConfigDB::parse_services_users,  MD_MESSAGE },
  { "revoke",  &ConfigDB::parse_services_revoke, MD_MESSAGE }
};
static struct ObjectParse svcs_obj = {
  svcs_fields, ASZ( svcs_fields ), &ConfigDB::create_service
};
static StringVal tport_s( SZ( "tport" ) ),
                 type_s ( SZ( "type"  ) ),
                 route_s( SZ( "route" ) );
static struct ArrayParse tports_fields[] = {
  { "tport", &ConfigDB::parse_transports_tport, MD_STRING },
  { "type",  &ConfigDB::parse_transports_type,  MD_STRING },
  { "route", &ConfigDB::parse_transports_route, MD_MESSAGE }
};
static struct ObjectParse tports_obj = {
  tports_fields, ASZ( tports_fields ), &ConfigDB::create_transport
};
static StringVal group_s( SZ( "group" ) );
static struct ArrayParse grps_fields[] = {
  { "group", &ConfigDB::parse_groups_group, MD_STRING },
  { "users", &ConfigDB::parse_groups_users, MD_NODATA }
};
static struct ObjectParse grps_obj = {
  grps_fields , ASZ( grps_fields ), &ConfigDB::create_group
};
#undef SZ
#undef ASZ

static ObjectParse &
resolve_obj( MDMsg &msg ) noexcept
{
  static const size_t num_objects = 5;
  ObjectParse * obj[ num_objects ] = {
    &top_obj, &users_obj, &tports_obj, &svcs_obj, &grps_obj
  };
  MDFieldIter * iter;
  MDName        name;
  size_t        i, j;

  if ( msg.get_field_iter( iter ) == 0 &&
       iter->first() == 0 &&
       iter->get_name( name ) == 0 ) {
    for ( i = 0; i < num_objects; i++ ) {
      if ( name.equals( obj[ i ]->parse[ 0 ].name ) )
        return *obj[ i ];
    }
    for ( i = 0; i < num_objects; i++ ) {
      for ( j = 1; j < obj[ i ]->parse_size; j++ )
        if ( name.equals( obj[ i ]->parse[ j ].name ) )
          return *obj[ i ];
    }
  }
  return top_obj;
}

struct ConfigDB::InodeStack {
  size_t   tos;
  uint64_t stk[ 1000 ];

  InodeStack() : tos( 0 ) {}

  bool push( const char *fn,  uint64_t node ) {
    if ( this->tos == sizeof( this->stk ) / sizeof( this->stk[ 0 ] ) )
      return false;
    if ( node == 0 )
      node = kv_hash_murmur64( fn, ::strlen( fn ), 0 );
    for ( size_t i = 0; i < this->tos; i++ ) {
      if ( this->stk[ i ] == node ) {
        /*fprintf( stderr, "ino %" PRIu64 " repeat, fn: \"%s\"\n",
                 (uint64_t) node, fn );*/
        return false;
      }
    }
    this->stk[ this->tos++ ] = node;
    return true;
  }
  void pop( void ) { --this->tos; }
};

ConfigTree *
ConfigDB::parse_tree( const char *cfg_name,  StringTab &st,
                      MDOutput &err ) noexcept
{
  ConfigTree * tree;
  if ( cfg_name == NULL || ::strcmp( cfg_name, "-" ) == 0 ) {
    tree = ConfigDB::parse_fd( 0, st, err );
  }
  else {
    os_stat      stbuf;
    if ( os_fstat( cfg_name, &stbuf ) < 0 || ( stbuf.st_mode & S_IFDIR ) == 0 ) {
      tree = ConfigDB::parse_jsfile( cfg_name, st, err );
      if ( tree != NULL ) {
        st.ref_string( cfg_name, ::strlen( cfg_name ), tree->cfg_name );
        tree->is_dir = false;
      }
    }
    else
      tree = ConfigDB::parse_dir( cfg_name, st, err );
  }
  return tree;
}
 
ConfigTree *
ConfigDB::parse_dir( const char *dir_name,  StringTab &st,
                     MDOutput &err ) noexcept
{
  char path[ 1024 ];
  int  n;
  n = ::snprintf( path, sizeof( path ), "%s/config.yaml", dir_name );
  if ( n > 0 && (size_t) n < sizeof( path ) ) {
    ConfigTree *tree = parse_jsfile( path, st, err );
    if ( tree != NULL ) {
      st.ref_string( dir_name, ::strlen( dir_name ), tree->cfg_name );
      tree->is_dir = true;
    }
    return tree;
  }
  fprintf( stderr, "dir_name too long\n" );
  return NULL;
}

ConfigTree *
ConfigDB::parse_jsfile( const char *fn,  StringTab &st, MDOutput &err ) noexcept
{
  ConfigTree * tree = new ( st.mem.make( sizeof( ConfigTree ) ) ) ConfigTree();
  InodeStack   ino;
  ConfigDB     db( *tree, st.mem, &ino, st );
  uint32_t     match;

  db.filename = fn;

  if ( db.parse_glob( fn, match ) != 0 || ! db.check_strings( err ) ) {
    fprintf( stderr, "Parse failed \"%s\"\n", fn );
    return NULL;
  }
  if ( match == 0 ) {
    fprintf( stderr, "Config not found: \"%s\"\n", fn );
    return NULL;
  }
  return tree;
}

ConfigTree *
ConfigDB::parse_fd( int fd,  StringTab &st,  MDOutput &err ) noexcept
{
  ConfigTree * tree = new ( st.mem.make( sizeof( ConfigTree ) ) ) ConfigTree();
  InodeStack   ino;
  ConfigDB     db( *tree, st.mem, &ino, st );

  db.filename = "(fd-input)";
  if ( db.parse_stream( fd ) != 0 || ! db.check_strings( err ) ) {
    fprintf( stderr, "Parse failed, fd %d\n", fd );
    return NULL;
  }
  return tree;
}

void
ConfigStartup::copy( ConfigTree &tree,
                     ConfigTree::TransportArray *listen,
                     ConfigTree::TransportArray *connect ) noexcept
{
  this->mem.reuse();

  ConfigTree * cp = new ( this->mem.make( sizeof( ConfigTree ) ) ) ConfigTree();
  ConfigDB     db( *cp, this->mem, NULL, this->str );

  for ( ConfigTree::User *u = tree.users.hd; u != NULL; u = u->next ) {
    if ( ! u->is_temp ) {
      ConfigTree::User *u_cp = db.make<ConfigTree::User>( *u );
      cp->users.push_tl( u_cp );
    }
  }
  for ( ConfigTree::Service *s = tree.services.hd; s != NULL; s = s->next ) {
    ConfigTree::Service *s_cp = db.make<ConfigTree::Service>( *s );
    cp->services.push_tl( s_cp );
    this->copy_pair_list( db, s->users, s_cp->users );
    this->copy_pair_list( db, s->revoke, s_cp->revoke );
  }
  for ( ConfigTree::Transport *t = tree.transports.hd; t != NULL; t = t->next ) {
    if ( ! t->is_temp ) {
      ConfigTree::Transport *t_cp = db.make<ConfigTree::Transport>( *t );
      cp->transports.push_tl( t_cp );
      this->copy_pair_list( db, t->route, t_cp->route );
    }
  }
  for ( ConfigTree::Group *g = tree.groups.hd; g != NULL; g = g->next ) {
    ConfigTree::Group *g_cp = db.make<ConfigTree::Group>( *g );
    cp->groups.push_tl( g_cp );
    this->copy_string_list( db, g->users, g_cp->users );
  }
  for ( ConfigTree::Parameters *p = tree.parameters.hd; p != NULL; p = p->next ) {
    if ( p->list.hd == NULL ) continue;
    ConfigTree::Parameters *p_cp = db.make<ConfigTree::Parameters>();
    this->copy_pair_list( db, p->list, p_cp->list );
    cp->parameters.push_tl( p_cp );
  }
  if ( listen == NULL && connect == NULL ) {
    for ( ConfigTree::Parameters *p = tree.startup.hd; p != NULL; p = p->next ) {
      if ( p->list.hd == NULL ) continue;
      ConfigTree::Parameters *p_cp = db.make<ConfigTree::Parameters>();
      this->copy_pair_list( db, p->list, p_cp->list );
      cp->startup.push_tl( p_cp );
    }
  }
  else {
    ConfigTree::Parameters *p_cp = db.make<ConfigTree::Parameters>();
    uint32_t i;
    cp->startup.push_tl( p_cp );
    if ( listen != NULL && listen->count > 0 ) {
      for ( i = 0; i < listen->count; i++ ) {
        ConfigTree::StringPair *p =
          db.make<ConfigTree::StringPair>( listen_s, listen->ptr[ i ] );
        p_cp->list.push_tl( p );
      }
    }
    if ( connect != NULL && connect->count > 0 ) {
      for ( i = 0; i < connect->count; i++ ) {
        ConfigTree::StringPair *p =
          db.make<ConfigTree::StringPair>( connect_s, connect->ptr[ i ] );
        p_cp->list.push_tl( p );
      }
    }
  }
  for ( ConfigTree::Parameters *p = tree.hosts.hd; p != NULL; p = p->next ) {
    if ( p->list.hd == NULL ) continue;
    ConfigTree::Parameters *p_cp = db.make<ConfigTree::Parameters>();
    this->copy_pair_list( db, p->list, p_cp->list );
    cp->hosts.push_tl( p_cp );
  }
  cp->user_cnt      = tree.user_cnt;
  cp->service_cnt   = tree.service_cnt;
  cp->transport_cnt = tree.transport_cnt;
  cp->group_cnt     = tree.group_cnt;
  cp->cfg_name      = tree.cfg_name;
  cp->is_dir        = tree.is_dir;

  this->tree = cp;
}

void
ConfigStartup::copy_pair_list( ConfigDB &db,  const ConfigTree::PairList &list,
                               ConfigTree::PairList &cp_list ) noexcept
{
  for ( const ConfigTree::StringPair *sp = list.hd; sp != NULL; sp = sp->next ) {
    ConfigTree::StringPair *p = db.make<ConfigTree::StringPair>( *sp );
    cp_list.push_tl( p );
  }
}

void
ConfigStartup::copy_string_list( ConfigDB &db,  const ConfigTree::StrList &list,
                                 ConfigTree::StrList &cp_list ) noexcept
{
  for ( const ConfigTree::StringList *sl = list.hd; sl != NULL; sl = sl->next ) {
    ConfigTree::StringList *p = db.make<ConfigTree::StringList>( *sl );
    cp_list.push_tl( p );
  }
}

static bool inline pass_filter( const StringVal *filter, const StringVal &val ){
  return filter == NULL || filter->is_null() || filter->equals( val );
}

JsonValue *
ConfigJson::copy( const ConfigTree *tree,  int which,  const StringVal *filter,
                  const ConfigTree::TransportArray *listen,
                  const ConfigTree::TransportArray *connect ) noexcept
{
  JsonArray  * users      = NULL,
             * services   = NULL,
             * transports = NULL,
             * groups     = NULL;
  JsonObject * parameters = NULL,
             * startup    = NULL,
             * hosts      = NULL,
             * cfg        = NULL;
  this->mem.reuse();

  if ( tree == NULL ) {
    which = 0;
    if ( listen != NULL || connect != NULL )
      which |= PRINT_STARTUP;
  }
  if ( ( which & PRINT_SERVICES ) != 0 ) {
    for ( const ConfigTree::Service *s = tree->services.hd; s != NULL; s = s->next ) {
      if ( pass_filter( filter, s->svc ) )
        this->push_array( services, this->copy( *s ) );
    }
  }
  if ( ( which & PRINT_USERS ) != 0 ) {
    for ( const ConfigTree::User *u = tree->users.hd; u != NULL; u = u->next ) {
      if ( pass_filter( filter, u->user ) ) {
        if ( ! u->is_temp || ( which & PRINT_EXCLUDE_TEMPORARY ) == 0 ) {
          this->push_array( users, this->copy( *u ) );
        }
      }
    }
  }
  if ( ( which & PRINT_TRANSPORTS ) != 0 ) {
    for ( const ConfigTree::Transport *t = tree->transports.hd; t != NULL; t = t->next ) {
      if ( pass_filter( filter, t->tport ) )
        if ( ! t->is_temp || ( which & PRINT_EXCLUDE_TEMPORARY ) == 0 )
          this->push_array( transports, this->copy( *t ) );
    }
  }
  if ( ( which & PRINT_GROUPS ) != 0 ) {
    for ( const ConfigTree::Group *g = tree->groups.hd; g != NULL; g = g->next ) {
      if ( pass_filter( filter, g->group ) )
        this->push_array( groups, this->copy( *g ) );
    }
  }
  if ( ( which & PRINT_PARAMETERS ) != 0 ) {
    parameters = this->copy( tree->parameters );
  }
  if ( ( which & PRINT_STARTUP ) != 0 ) {
    if ( listen == NULL && connect == NULL ) {
      startup = this->copy( tree->startup );
    }
    else {
      JsonArray *ar;
      uint32_t i;
      if ( listen != NULL && listen->count > 0 ) {
        ar = NULL;
        for ( i = 0; i < listen->count; i++ )
          this->push_array( ar, this->copy( listen->ptr[ i ] ) );
        this->push_field( startup, listen_s, ar );
      }
      if ( connect != NULL && connect->count > 0 ) {
        ar = NULL;
        for ( i = 0; i < connect->count; i++ )
          this->push_array( ar, this->copy( connect->ptr[ i ] ) );
        this->push_field( startup, connect_s, ar );
      }
    }
  }

  if ( ( which & PRINT_HOSTS ) != 0 ) {
    hosts = this->copy( tree->hosts );
  }
  if ( parameters != NULL ) this->push_field( cfg, parameters_s, parameters );
  if ( services != NULL )   this->push_field( cfg, services_s, services );
  if ( users != NULL )      this->push_field( cfg, users_s, users );
  if ( hosts != NULL )      this->push_field( cfg, hosts_s, hosts );
  if ( transports != NULL ) this->push_field( cfg, transports_s, transports );
  if ( groups != NULL )     this->push_field( cfg, groups_s, groups );
  if ( startup != NULL )    this->push_field( cfg, startup_s, startup );
  return cfg;
}

JsonObject *
ConfigJson::copy( const ConfigTree::ParametersList &list ) noexcept
{
  JsonObject * o = NULL;
  for ( const ConfigTree::Parameters *p = list.hd; p != NULL; p = p->next ) {
    JsonObject *l = (JsonObject *) this->copy( p->list );
    if ( o == NULL )
      o = l;
    else {
      for ( size_t i = 0; i < l->length; i++ )
        this->push_field( o, l->val[ i ].name, l->val[ i ].val );
    }
  }
  return o;
}

JsonValue *
ConfigJson::copy( const ConfigTree::User &u ) noexcept
{
  JsonObject * user = NULL;
  this->push_field_s( user, user_s, u.user );
  this->push_field_s( user, svc_s, u.svc );
  this->push_field_s( user, create_s, u.create );
  this->push_field_s( user, expires_s, u.expires );
  this->push_field_s( user, revoke_s, u.revoke );
  this->push_field_s( user, pri_s, u.pri );
  this->push_field_s( user, pub_s, u.pub );
  return user;
}

JsonValue *
ConfigJson::copy( const ConfigTree::Service &s ) noexcept
{
  JsonObject * svc = NULL;
  this->push_field_s( svc, svc_s, s.svc );
  this->push_field_s( svc, create_s, s.create );
  this->push_field_s( svc, pri_s, s.pri );
  this->push_field_s( svc, pub_s, s.pub );
  if ( s.users.hd != NULL )
    this->push_field( svc, users_s, this->copy( s.users ) );
  if ( s.revoke.hd != NULL )
    this->push_field( svc, revoke_s, this->copy( s.revoke ) );
  return svc;
}

JsonValue *
ConfigJson::copy( const ConfigTree::Transport &t ) noexcept
{
  JsonObject * tport = NULL;
  if ( t.is_temp && t.route.hd == NULL )
    return NULL;
  this->push_field_s( tport, tport_s, t.tport );
  this->push_field_s( tport, type_s, t.type );
  if ( t.route.hd != NULL )
    this->push_field( tport, route_s, this->copy( t.route ) );
  return tport;
}

JsonValue *
ConfigJson::copy( const ConfigTree::Group &g ) noexcept
{
  JsonObject * grp = NULL;
  this->push_field_s( grp, group_s, g.group );
  if ( g.users.hd != NULL )
    this->push_field( grp, users_s, this->copy( g.users ) );
  return grp;
}

JsonValue *
ConfigJson::copy( const ConfigTree::PairList &pl ) noexcept
{
  JsonObject * list = NULL;
  for ( const ConfigTree::StringPair *x = pl.hd; x != NULL; ) {
    if ( x->next == NULL || ! x->name.equals( x->next->name ) ) {
      this->push_field( list, x->name, this->copy( x->value ) );
      x = x->next;
    }
    else {
      JsonArray *ar = this->make<JsonArray>();
      this->push_array( ar, this->copy( x->value ) );
      this->push_array( ar, this->copy( x->next->value ) );
      x = x->next;
      while ( x->next != NULL && x->name.equals( x->next->name ) ) {
        this->push_array( ar, this->copy( x->next->value ) );
        x = x->next;
      }
      this->push_field( list, x->name, ar );
      x = x->next;
    }
  }
  return list;
}

JsonValue *
ConfigJson::copy( const ConfigTree::StrList &sl ) noexcept
{
  JsonArray * ar = NULL;
  for ( const ConfigTree::StringList *p = sl.hd; p != NULL; p = p->next ) {
    this->push_array( ar, this->copy( p->val ) );
  }
  return ar;
}

JsonValue *
ConfigJson::copy( const StringVal &s ) noexcept
{
  JsonString * str = this->make<JsonString>();
  str->val    = (char *) s.val;
  str->length = s.len;
  return str;
}

void
ConfigJson::push_array( JsonArray *&a,  JsonValue *v ) noexcept
{
  size_t oldsz = 0, newsz;
  if ( v != NULL ) {
    if ( a == NULL )
      a = this->make<JsonArray>();
    else
      oldsz = sizeof( a->val[ 0 ] ) * a->length;
    newsz = oldsz + sizeof( a->val[ 0 ] );
    this->mem.extend( oldsz, newsz, &a->val );
    a->val[ a->length++ ] = v;
  }
}

void
ConfigJson::push_field( JsonObject *&o,  const StringVal &s,
                        JsonValue *v ) noexcept
{
  size_t oldsz = 0, newsz;
  if ( v != NULL ) {
    if ( o == NULL )
      o = this->make<JsonObject>();
    else
      oldsz = sizeof( o->val[ 0 ] ) * o->length;
    newsz = oldsz + sizeof( o->val[ 0 ] );
    this->mem.extend( oldsz, newsz, &o->val );
    o->val[ o->length ].name.val    = (char *) s.val;
    o->val[ o->length ].name.length = s.len;
    o->val[ o->length++ ].val       = v;
  }
}

void
ConfigJson::push_field( JsonObject *&o,  JsonString &s,  JsonValue *v ) noexcept
{
  StringVal str( s.val, s.length );
  this->push_field( o, str, v );
}

JsonString *
ConfigJson::make_hostid( uint32_t ival ) noexcept
{
  #define hex( i ) ( ( i ) < 10 ? ( '0' + ( i ) ) : ( 'A' + ( ( i ) - 10 ) ) )
  JsonString * s = this->make<JsonString>();
  char * sval = (char *) this->mem.make( 9 );
  s->val = sval;
  for ( int i = 0; i < 4; i++ ) {
    sval[ i * 2 + 1 ] = hex( ival & 0xfU ); ival >>= 4;
    sval[ i * 2 + 0 ] = hex( ival & 0xfU ); ival >>= 4;
  }
  sval[ 8 ] = '\0';
  s->length = 8;
  #undef hex
  return s;
}

#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
struct Glob {
  glob_t   g;
  uint32_t i;
  int      status;
  Glob( const char *spec ) : i( 0 ) {
    this->status = ::glob( spec, GLOB_MARK | GLOB_TILDE, NULL, &this->g );
  }
  ~Glob() {
    if ( this->status == 0 )
      ::globfree( &this->g );
  }
  const char *first( void ) {
    this->i = 0;
    if ( this->status != 0 || this->i >= g.gl_pathc )
      return NULL;
    return this->g.gl_pathv[ this->i++ ];
  }
  const char *next( void ) {
    if ( this->status != 0 || this->i >= g.gl_pathc )
      return NULL;
    return this->g.gl_pathv[ this->i++ ];
  }
};
#else
struct Glob {
  struct _finddata_t fileinfo;
  intptr_t     ptr;
  const char * dir;
  int          dirlen;
  char         buf[ _MAX_PATH ];
  uint32_t     i;
  
  Glob( const char *spec ) : i( 0 ) {
    this->ptr = _findfirst( spec, &this->fileinfo );
    this->dir = ::strrchr( spec, '/' );
    if ( this->dir == NULL )
      this->dir = ::strrchr( spec, '\\' );
    if ( this->dir != NULL ) {
      this->dirlen = (int) ( this->dir - spec );
      this->dir    = spec;
    }
    else {
      this->dirlen = 0;
    }
  }
  const char *get_path( void ) {
    if ( this->dir == NULL )
      return this->fileinfo.name;
    CatPtr p( this->buf );
    size_t namelen = ::strlen( this->fileinfo.name );
    if ( namelen + this->dirlen + 2 <= sizeof( this->buf ) ) {
      p.x( this->dir, this->dirlen )
       .s( "/" )
       .x( this->fileinfo.name, namelen )
       .end();
      char *slash = buf;
      while ( (slash = ::strchr( slash, '\\' )) != NULL )
        *slash++ = '/';
      return this->buf;
    }
    return NULL;
  }
  const char *first( void ) {
    if ( this->ptr == -1 )
      return NULL;
    this->i++;
    return this->get_path();
  }
  const char *next( void ) {
    if ( this->ptr == -1 )
      return NULL;
    if ( _findnext( this->ptr, &this->fileinfo ) != 0 )
      return NULL;
    this->i++;
    return this->get_path();
  }
};
#endif

int
ConfigDB::parse_glob( const char *fn,  uint32_t &match ) noexcept
{
  int status = 0;
  Glob g( fn );
  const char *path = g.first();
  if ( path != NULL ) {
    do {
      status = this->parse_file( path );
      if ( status != 0 )
        break;
    } while ( (path = g.next()) != NULL );
  }
  match = g.i;
  return status;
}

int
ConfigDB::parse_file( const char *fn ) noexcept
{
  MapFile map( fn );
  os_stat st;
  int status;

  status = os_fstat( fn, &st );
  if ( status < 0 )
    perror( fn );
  /* recursion check */
  else if ( st.st_size > 0 ) {
    if ( ! this->ino_stk->push( fn, (uint64_t) st.st_ino ) )
      status = 0;
    else {
      if ( ! map.open() )
        status = -1;
      else
        status = this->parse_jsconfig( (char *) map.map, map.map_size, fn );
      this->ino_stk->pop();
    }
  }
  return status;
}

int
ConfigDB::parse_stream( int fd ) noexcept
{
  MDMsgMem   tmp_mem;
  JsonMsgCtx ctx;
  int        status;

  status = ctx.parse_fd( fd, NULL, &tmp_mem, true );
  if ( status != 0 ) {
    fprintf( stderr, "JSON parse error in fd %d, status %d/%s\n", fd,
             status, Err::err( status )->descr );
    if ( ctx.input != NULL ) {
      fprintf( stderr, "line %u col %u\n", (uint32_t) ctx.input->line_count,
               (uint32_t) ( ctx.input->offset - ctx.input->line_start + 1 ) );
    }
    return status;
  }
  return this->parse_object( "(fd-input)", *ctx.msg, resolve_obj( *ctx.msg ) );
}

int
ConfigDB::parse_jsconfig( const char *buf,  size_t buflen,
                          const char *fn ) noexcept
{
  MDMsgMem   tmp_mem;
  JsonMsgCtx ctx;
  size_t     len = ( fn != NULL ? ::strlen( fn ) : 0 );
  int        status;
  bool       is_yaml;

  if ( len > 5 && kv_strcasecmp( &fn[ len - 5 ], ".yaml" ) == 0 )
    is_yaml = true;
  else
    is_yaml = false;
  status = ctx.parse( (void *) buf, 0, buflen, NULL, &tmp_mem, is_yaml );
  if ( status != 0 ) {
    fprintf( stderr, "JSON parse error in \"%s\", status %d/%s\n", fn,
             status, Err::err( status )->descr );
    if ( ctx.input != NULL ) {
      fprintf( stderr, "line %u col %u\n", (uint32_t) ctx.input->line_count,
               (uint32_t) ( ctx.input->offset - ctx.input->line_start + 1 ) );
    }
    return status;
  }
  return this->parse_object( fn, *ctx.msg, resolve_obj( *ctx.msg ) );
}

static bool
is_absolute_path( const char *fn,  size_t len ) noexcept
{
  if ( len == 0 )
    return false;
  if ( fn[ 0 ] != '/' ) {
    if ( fn[ 0 ] == '~' ) { /* ~/ or ~user/ */
      if ( ::memchr( fn, '/', len ) != NULL )
        return true; /* ~/ or ~user/ */
    }
    return false; /* no ~ or no slash */
  }
  return true; /* starts with / */
}

/* parse include : str */
int
ConfigDB::parse_include( MDMsg &msg, MDName &, MDReference &mref ) noexcept
{
  char * buf;
  size_t len;
  int    status;

  if ( (status = msg.get_string( mref, buf, len )) == 0 ) {
    char inc_file[ 1024 ];
    const char *slash;
    int n;
    if ( this->filename == NULL ||
         is_absolute_path( buf, len ) ||
         (slash = ::strrchr( this->filename, '/' )) == NULL )
      n = ::snprintf( inc_file, sizeof( inc_file ), "%.*s", (int) len, buf );
    else
      n = ::snprintf( inc_file, sizeof( inc_file ), "%.*s/%.*s",
                      (int) ( slash - this->filename ), this->filename,
                      (int) len, buf );
    if ( n > 0 && (size_t) n < sizeof( inc_file ) ) {
      const char *old = this->filename;
      uint32_t    match;
      this->filename = inc_file;
      status = this->parse_glob( inc_file, match );
      this->filename = old;
    }
    else {
      fprintf( stderr, "include file too long\n" );
      status = -1;
    }
  }
  return status;
}

int
ConfigFilePrinter::open( const char *path ) noexcept
{
  if ( this->MDOutput::open( path, "wb" ) != 0 ) {
    fprintf( stderr, "unable to write %s: %d/%s\n", path, errno,
             strerror( errno ) );
    return -1;
  }
  return 0;
}

int
ConfigDirPrinter::open( const char *kind,  const StringVal &sv ) noexcept
{
  const char * sep = "/";
  char path[ 1024 ];
  if ( this->dir_name.len == 0 )
    sep = "";
  if ( this->dir_name.len + sv.len + ::strlen( kind ) + 11 > sizeof( path ) ) {
    fprintf( stderr, "dir name too long\n" );
    return -1;
  }
  CatPtr p( path );
  p.x( this->dir_name.val, this->dir_name.len )
   .s( sep )
   .s( kind )
   .x( sv.val, sv.len )
   .s( ".yaml.new" )
   .end();

  if ( this->ConfigFilePrinter::open( path ) != 0 ) {
    fprintf( stderr, "unable to write %s: %d/%s\n", path, errno,
             strerror( errno ) );
    return -1;
  }
  return 0;
}

int
ConfigTree::save_tport( const ConfigTree::Transport &tport ) const noexcept
{
  ConfigDirPrinter out( this->cfg_name );
  if ( out.open( "tport_", tport.tport ) != 0 )
    return -1;
  ConfigJson cfg;
  JsonValue *val = cfg.copy( tport );
  if ( val != NULL )
    val->print_yaml( &out );
  return 0;
}

int
ConfigTree::save_startup( const TransportArray &listen,
                          const TransportArray &connect ) const noexcept
{
  ConfigDirPrinter out( this->cfg_name );
  StringVal        mt;
  if ( out.open( "startup", mt ) != 0 )
    return -1;
  ConfigJson cfg;
  JsonValue *val = cfg.copy( NULL, PRINT_STARTUP, NULL, &listen, &connect );
  if ( val != NULL )
    val->print_yaml( &out );
  return 0;
}

int
ConfigTree::save_file( const TransportArray &listen,
                       const TransportArray &connect ) const noexcept
{
  ConfigFilePrinter out;
  char path[ 1024 ];
  if ( this->cfg_name.len + 5 > sizeof( path ) ) {
    fprintf( stderr, "cfg name too long\n" );
    return -1;
  }
  CatPtr p( path );
  p.x( this->cfg_name.val, this->cfg_name.len )
   .s( ".new" )
   .end();
  if ( out.open( path ) != 0 )
    return -1;

  ConfigJson cfg;
  JsonValue *val = cfg.copy( this, PRINT_EXCLUDE_TEMPORARY | PRINT_NORMAL,
                             NULL, &listen, &connect );
  if ( val != NULL )
    val->print_yaml( &out );
  return 0;
}

int
ConfigTree::save_new( void ) const noexcept
{
  GenFileList ops;
  char path_buf[ 1024 ];
  if ( this->cfg_name.len + 12 > sizeof( path_buf ) ) {
    fprintf( stderr, "cfg name too long\n" );
    return -1;
  }
  if ( this->is_dir ) {
    const char * sep = "/";
    if ( this->cfg_name.len == 0 )
      sep = "";
    CatPtr p( path_buf );
    p.x( this->cfg_name.val, this->cfg_name.len )
     .s( sep )
     .s( "*.yaml.new" )
     .end();

    Glob g( path_buf );
    const char *path;
    if ( (path = g.first() ) == NULL )
      return 0;

    do {
      static const char run_file[] = "startup.yaml.new";
      static const char param_file[] = "param.yaml.new";
      static size_t run_file_size = sizeof( run_file ) - 1;
      static size_t param_file_size = sizeof( param_file ) - 1;
      const char * descr;
      GenFileTrans * t =
        GenFileTrans::create_file_path( GEN_CREATE_FILE, path );
      if ( t->len >= run_file_size &&
           ::strcmp( &t->path[ t->len - run_file_size ], run_file ) == 0 )
        descr = "startup config";
      else if ( t->len >= param_file_size &&
           ::strcmp( &t->path[ t->len - param_file_size ], param_file ) == 0 )
        descr = "parameter config";
      else
        descr = "transport";
      GenFileTrans::trans_if_neq( t, descr, ops );
    } while ( (path = g.next()) != NULL );
  }
  else {
    CatPtr p( path_buf );
    p.x( this->cfg_name.val, this->cfg_name.len )
     .s( ".new" )
     .end();

    GenFileTrans * t =
      GenFileTrans::create_file_path( GEN_OVERWRITE_FILE, path_buf );
    GenFileTrans::trans_if_neq( t, "config file", ops );
  }
  size_t count = ops.print_files();
  if ( ops.commit_phase1() ) {
    ops.commit_phase2();
    return (int) count;
  }
  ops.abort();
  return 0;
}

bool
ConfigTree::resolve( const char *us,  User *&usrp,  Service *&svc ) noexcept
{
  const char * p,
             * sv    = NULL;
  size_t       u_len = 0,
               s_len = 0;
  if ( us != NULL ) {
    if ( (p = ::strchr( us, '.' )) != NULL ) {
      sv    = &p[ 1 ];
      u_len = p - us;
      s_len = ::strlen( sv );
    }
    else {
      s_len = ::strlen( us );
      sv    = us;
      us    = NULL;
    }
  }
  usrp = NULL;
  if ( sv != NULL )
    svc = this->find_service( sv, s_len ); /* us == service */
  if ( svc != NULL )
    usrp = this->find_user( *svc, us, u_len ); /* user.service */
  if ( svc != NULL && usrp != NULL )
    return true;

  if ( svc == NULL ) {
    svc = this->services.hd;
    if ( usrp == NULL ) {
      usrp = this->find_user( *svc, sv, s_len ); /* us == user, service = default */
      if ( usrp != NULL )
        return true;
    }
  }
  if ( svc == NULL )
    svc = this->services.hd;
  if ( svc == NULL )
    fprintf( stderr, "No service %.*s configured\n", (int) s_len, sv );
  /*else if ( usrp == NULL )
    fprintf( stderr, "No user %.*s configured\n", (int) u_len, us );*/
  return false;
}

ConfigTree::User *
ConfigTree::find_user( ConfigTree::Service &svc,  const char *usr,
                       size_t len ) noexcept
{
  if ( usr == NULL || len == 0 )
    return NULL;
  for ( ConfigTree::User *u = this->users.hd; u != NULL; u = u->next ) {
    if ( u->user.equals( usr, len ) && u->svc.equals( svc.svc ) )
      return u;
  }
  return NULL;
}

ConfigTree::Service *
ConfigTree::find_service( const char *svc,  size_t len ) noexcept
{
  if ( svc == NULL || len == 0 )
    return NULL;
  for ( ConfigTree::Service * s = this->services.hd; s != NULL; s = s->next ) {
    if ( s->svc.equals( svc, len ) )
      return s;
  }
  return NULL;
}

ConfigTree::Transport *
ConfigTree::find_transport( const char *tport,  size_t len,
                            bool *conn ) noexcept
{
  const char * p;
  size_t t_len = len;
  if ( conn != NULL )
    *conn = true;
  if ( tport == NULL || len == 0 )
    return NULL;
  /* if tport.conn or tport.listen */
  if ( conn != NULL ) {
    if ( (p = ::strchr( tport, '.' )) != NULL ) {
      t_len = p - tport;
      if ( p[ 1 ] == 'c' || p[ 1 ] == 'C' )
        *conn = true;
      else
        *conn = false;
    }
  }
  for ( ConfigTree::Transport * t = this->transports.hd; t != NULL;
        t = t->next ) {
    if ( t->tport.equals( tport, t_len ) )
      return t;
  }
  return NULL;
}

/* new User node */
void
ConfigDB::create_user( void ) noexcept
{
  this->cfg.users.push_tl( this->u = this->make<ConfigTree::User>() );
  this->u->user_id = this->cfg.user_cnt++;
}
/* new Service node */
void
ConfigDB::create_service( void ) noexcept
{
  this->cfg.services.push_tl( this->s = this->make<ConfigTree::Service>() );
  this->s->service_id = this->cfg.service_cnt++;
}
/* new Transport node */
void
ConfigDB::create_transport( void ) noexcept
{
  this->cfg.transports.push_tl( this->t = this->make<ConfigTree::Transport>() );
  this->t->tport_id = this->cfg.transport_cnt++;
}
/* new Group node */
void
ConfigDB::create_group( void ) noexcept
{
  this->cfg.groups.push_tl( this->g = this->make<ConfigTree::Group>() );
  this->g->group_id = this->cfg.group_cnt++;
}
/* create a string ref using StringTab::get_string() */
int
ConfigDB::config_string( const char *what,  MDMsg &msg,
                         MDReference &mref,  StringVal &str ) noexcept
{
  char * buf;
  size_t len;
  int    status;

  if ( (status = msg.get_string( mref, buf, len )) == 0 ) {
    this->str.ref_string( buf, len, str );
  }
  else {
    fprintf( stderr, "String in %s, status %d/%s\n", what, status,
             Err::err( status )->descr );
  }
  return status;
}
/* walk through and array, creating a list of strings */
int
ConfigDB::config_array( const char *what,  MDMsg &msg,  MDReference &mref,
                        ConfigTree::StrList &list ) noexcept
{
  ConfigTree::StringList * item;
  MDReference aref;
  char      * buf;
  size_t      len;
  int         status = 0;

  if ( mref.ftype == MD_ARRAY ) {
    size_t num_entries = mref.fsize;
    if ( mref.fentrysz > 0 )
      num_entries /= mref.fentrysz;
    for ( size_t i = 0; i < num_entries; i++ ) {
      if ( (status = msg.get_array_ref( mref, i, aref )) == 0 ) {
        if ( (status = msg.get_string( aref, buf, len )) == 0 ) {
          item = this->make<ConfigTree::StringList>();
          this->str.ref_string( buf, len, item->val );
          list.push_tl( item );
        }
      }
    }
  }
  else {
    if ( (status = msg.get_string( mref, buf, len )) == 0 ) {
      item = this->make<ConfigTree::StringList>();
      this->str.ref_string( buf, len, item->val );
      list.push_tl( item );
    }
  }
  if ( status != 0 )
    fprintf( stderr, "Array in %s, status %d/%s\n", what, status,
             Err::err( status )->descr );
  return status;
}

static bool
match_types( MDType want,  MDType found )
{
  if ( want == MD_NODATA ) {
    if ( found == MD_STRING || found == MD_DECIMAL || found == MD_ARRAY )
      return true;
  }
  if ( want == MD_STRING ) {
    if ( found == MD_STRING || found == MD_DECIMAL )
      return true;
  }
  return want == found;
}
/* walk through object, mapping keywords in ObjectParse to parse functions 
 * { field : value, ... field : value } */
int
ConfigDB::parse_object( const char *where,  MDMsg &msg,
                        const ObjectParse &obj ) noexcept
{
  MDFieldIter * iter;
  MDName        name;
  MDReference   mref;
  size_t        i;
  int           status;

  if ( (status = msg.get_field_iter( iter )) != 0 )
    return status;
  if ( (status = iter->first()) != 0 ) {
    if ( status == Err::NOT_FOUND )
      return 0;
    return status;
  }
  bool called_constructor = false;
  do {
    if ( iter->get_name( name ) != 0 ) {
      fprintf( stderr, "Expecting a field in \"%s\"\n", where );
      continue;
    }
    if ( iter->get_reference( mref ) != 0 ) {
      fprintf( stderr, "Expecting a field value in \"%s\"\n", where );
      continue;
    }
    for ( i = 0; i < obj.parse_size; i++ ) {
      if ( name.equals( obj.parse[ i ].name ) ) {
        if ( ! match_types( obj.parse[ i ].type, mref.ftype ) ) {
          MDType parse_type = obj.parse[ i ].type;
          if ( parse_type == MD_NODATA )
            parse_type = MD_ARRAY;
          fprintf( stderr, "Expecting a type \"%s\" in \"%s\", found \"%s\"\n",
                   md_type_str( parse_type ), where,
                   md_type_str( mref.ftype, mref.fsize ) );
          break;
        }
        if ( ! called_constructor ) {
          called_constructor = true;
          if ( obj.create != NULL )
            (this->*obj.create)();
        }
        if ( (status = (this->*obj.parse[ i ].parse)( msg, name, mref ) ) != 0 )
          return status;
        break;
      }
    }
    if ( i == obj.parse_size ) {
      for ( i = 0; i < obj.parse_size; i++ ) {
        if ( obj.parse[ i ].type == MD_MESSAGE ) {
          if ( ! called_constructor ) {
            called_constructor = true;
            if ( obj.create != NULL )
              (this->*obj.create)();
          }
          if ((status = (this->*obj.parse[ i ].parse)( msg, name, mref )) != 0 )
            return status;
          break;
        }
      }
      if ( i == obj.parse_size ) {
        fprintf( stderr, "Unexpected field \"%.*s\" in \"%s\", type \"%s\"\n",
                 (int) name.fnamelen, name.fname, where,
                 md_type_str( mref.ftype, mref.fsize ) );
      }
    }
  } while ( (status = iter->next()) == 0 );
  if ( status == Err::NOT_FOUND )
    return 0;
  return status;
}
/* parse an array of objects: [ obj, ..., obj ] */
int
ConfigDB::parse_object_array( const char *where, MDMsg &msg, MDReference &mref,
                              const ObjectParse &obj ) noexcept
{
  MDMsg     * amsg;
  MDReference aref;
  size_t      num_entries = mref.fsize;
  if ( mref.fentrysz > 0 )
    num_entries /= mref.fentrysz;

  for ( size_t i = 0; i < num_entries; i++ ) {
    if ( msg.get_array_ref( mref, i, aref ) != 0 ||
         aref.ftype != MD_MESSAGE ||
         msg.get_sub_msg( aref, amsg ) != 0 ||
         this->parse_object( where, *amsg, obj ) != 0 ) {
      fprintf( stderr, "Expecting array of objects in \"%s\", element %u\n",
               where, (uint32_t) i );
      return Err::BAD_SUB_MSG;
    }
  }
  return 0;
}
int
ConfigDB::parse_object_list( const char *where,  MDMsg &msg,  MDName &name,
                 MDReference &mref, ConfigTree::ParametersList &parms ) noexcept
{
  MDMsg * smsg;
  int     status;
  ConfigTree::Parameters * p = this->make<ConfigTree::Parameters>();
  if ( mref.ftype == MD_ARRAY )
    status = this->config_array( where, msg, name, mref, p->list );
  else if ( mref.ftype != MD_MESSAGE )
    status = this->config_pair( where, msg, name, mref, p->list );
  else {
    status = msg.get_sub_msg( mref, smsg );
    if ( status == 0 )
      status = this->parse_pairs( where, *smsg, p->list );
  }
  if ( status != 0 )
    fprintf( stderr, "Expecting an object in %s\n", where );
  parms.push_tl( p );
  return status;
}
/* parse User { user : u, svc : s, create : t, expires : t, revoke : t,
 *              pri : der, pub : der } */
int
ConfigDB::parse_users( MDMsg &msg, MDName &, MDReference &mref ) noexcept
{
  return this->parse_object_array( "users", msg, mref, users_obj );
}
/* parse Services { svc : s, subject : [ array ], type : t, route : { obj } } */
int
ConfigDB::parse_services( MDMsg &msg, MDName &, MDReference &mref ) noexcept
{
  return this->parse_object_array( "services", msg, mref, svcs_obj );
}
/* parse Transports { tport : s, type : t, route : { obj } } */
int
ConfigDB::parse_transports( MDMsg &msg, MDName &, MDReference &mref ) noexcept
{
  return this->parse_object_array( "transports", msg, mref, tports_obj );
}
/* parse Groups { group : g, users : [ array ] } */
int
ConfigDB::parse_groups( MDMsg &msg, MDName &, MDReference &mref ) noexcept
{
  return this->parse_object_array( "groups", msg, mref, grps_obj );
}
/* parse Parameters : { parm list } */
int
ConfigDB::parse_parameters( MDMsg &msg,  MDName &name, MDReference &mref ) noexcept
{
  return this->parse_object_list( "parameters", msg, name, mref, this->cfg.parameters );
}
/* parse Startup : { parm list } */
int
ConfigDB::parse_startup( MDMsg &msg,  MDName &name, MDReference &mref ) noexcept
{
  return this->parse_object_list( "startup", msg, name, mref, this->cfg.startup );
}
/* parse Hosts : { parm list } */
int
ConfigDB::parse_hosts( MDMsg &msg,  MDName &name, MDReference &mref ) noexcept
{
  return this->parse_object_list( "hosts", msg, name, mref, this->cfg.hosts );
}
/* parse Route parameters { field : value, ... } */
int
ConfigDB::parse_pairs( const char *where,  MDMsg &msg,
                       ConfigTree::PairList &list ) noexcept
{
  MDFieldIter * iter;
  MDName        name;
  MDReference   mref;
  int           status;

  if ( (status = msg.get_field_iter( iter )) != 0 )
    return status;
  if ( (status = iter->first()) != 0 ) {
    if ( status == Err::NOT_FOUND )
      return 0;
    return status;
  }
  do {
    if ( iter->get_name( name ) != 0 ) {
      fprintf( stderr, "Expecting a field in \"%s\"\n", where );
      continue;
    }
    if ( iter->get_reference( mref ) != 0 ) {
      fprintf( stderr, "Expecting a field value in \"%s\"\n", where );
      continue;
    }
    if ( mref.ftype == MD_ARRAY ) {
      if ( (status = this->config_array( where, msg, name, mref, list )) != 0 )
        break;
    }
    else {
      if ( (status = this->config_pair( where, msg, name, mref, list )) != 0 )
        break;
    }
  } while ( (status = iter->next()) == 0 );
  if ( status == Err::NOT_FOUND )
    return 0;
  return status;
}
/* create a string ref for a StringPair, field : value */
int
ConfigDB::config_pair( const char *where,  MDMsg &msg,  const MDName &name,
                       MDReference &mref,  ConfigTree::PairList &list ) noexcept
{
  char * buf;
  size_t len;
  int    status;

  if ( mref.ftype == MD_NODATA ) /* ignore null values */
    return 0;
  ConfigTree::StringPair *pair = this->make<ConfigTree::StringPair>();
  list.push_tl( pair );

  if ( (status = msg.get_string( mref, buf, len )) == 0 ) {
    this->str.ref_string( name.fname, name.fnamelen - 1, pair->name );
    this->str.ref_string( buf, len, pair->value );
  }
  else {
    fprintf( stderr, "Config %s in %s, status %d/%s\n",
             name.fname, where, status, Err::err( status )->descr );
  }
  return status;
}

/* create a string ref for a StringPair, field : value */
int
ConfigDB::config_array( const char *where,  MDMsg &msg,  const MDName &name,
                        MDReference &mref,  ConfigTree::PairList &list ) noexcept
{
  int    status = 0;
  size_t i, num_entries = mref.fsize;
  MDReference aref;
  if ( mref.fentrysz > 0 )
    num_entries /= mref.fentrysz;
  if ( num_entries > 0 ) {
    if ( mref.fentrysz != 0 ) {
      aref.zero();
      aref.ftype   = mref.fentrytp;
      aref.fsize   = mref.fentrysz;
      aref.fendian = mref.fendian;
      for ( i = 0; i < num_entries; i++ ) {
        aref.fptr = &mref.fptr[ i * (size_t) mref.fentrysz ];
        status = this->config_pair( where, msg, name, aref, list );
        if ( status != 0 )
          break;
      }
    }
    else {
      for ( i = 0; i < num_entries; i++ ) {
        msg.get_array_ref( mref, i, aref );
        status = this->config_pair( where, msg, name, aref, list );
        if ( status != 0 )
          break;
      }
    }
  }
  return status;
}

/* parse Route */
int
ConfigDB::parse_transports_route( MDMsg &msg, MDName &name,
                                  MDReference &mref ) noexcept
{
  const char where[] = "transports.route";
  MDMsg * rmsg;
  int     status;
  if ( mref.ftype != MD_MESSAGE )
    status = this->config_pair( where, msg, name, mref, this->t->route );
  else {
    status = msg.get_sub_msg( mref, rmsg );
    if ( status == 0 )
      status = this->parse_pairs( where, *rmsg, this->t->route );
  }
  if ( status != 0 )
    fprintf( stderr, "Expecting an object in %s\n", where );
  return status;
}
/* parse user : name */
int ConfigDB::parse_users_user( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "user.user", msg, mref, this->u->user );
}
/* parse svc : name */
int ConfigDB::parse_users_svc( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "user.svc", msg, mref, this->u->svc );
}
/* parse create : value */
int ConfigDB::parse_users_create( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "user.create", msg, mref, this->u->create );
}
/* parse expires : value */
int ConfigDB::parse_users_expires( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "user.expires", msg, mref, this->u->expires );
}
/* parse revoke : value */
int ConfigDB::parse_users_revoke( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "user.revoke", msg, mref, this->u->revoke );
}
/* parse pri : prikey */
int ConfigDB::parse_users_pri( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "user.pri", msg, mref, this->u->pri );
}
/* parse pri : pubkey */
int ConfigDB::parse_users_pub( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "user.pub", msg, mref, this->u->pub );
}
/* parse svc : name */
int ConfigDB::parse_services_svc( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "service.svc", msg, mref, this->s->svc );
}
int ConfigDB::parse_services_create( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "service.create", msg, mref, this->s->create );
}
int ConfigDB::parse_services_pri( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "service.pri", msg, mref, this->s->pri );
}
int ConfigDB::parse_services_pub( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "service.pub", msg, mref, this->s->pub );
}
int
ConfigDB::parse_services_users( MDMsg &msg, MDName &,
                                MDReference &mref ) noexcept
{
  MDMsg *rmsg;
  if ( mref.ftype != MD_MESSAGE ||
       msg.get_sub_msg( mref, rmsg ) != 0 ||
       this->parse_pairs( "service.users", *rmsg, this->s->users ) != 0 ) {
    fprintf( stderr, "Expecting an object in service.users\n" );
    return Err::BAD_SUB_MSG;
  }
  return 0;
}
int
ConfigDB::parse_services_revoke( MDMsg &msg, MDName &,
                                 MDReference &mref ) noexcept
{
  MDMsg *rmsg;
  if ( mref.ftype != MD_MESSAGE ||
       msg.get_sub_msg( mref, rmsg ) != 0 ||
       this->parse_pairs( "service.revoke", *rmsg, this->s->revoke ) != 0 ) {
    fprintf( stderr, "Expecting an object in service.revoke\n" );
    return Err::BAD_SUB_MSG;
  }
  return 0;
}
/* parse tport : name */
int ConfigDB::parse_transports_tport( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "transport.tport", msg, mref, this->t->tport );
}
/* parse type : name */
int ConfigDB::parse_transports_type( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "transport.type", msg, mref, this->t->type );
}
/* parse group : name */
int ConfigDB::parse_groups_group( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_string( "group.group", msg, mref, this->g->group );
}
/* parse uesrs : [ array ] */
int ConfigDB::parse_groups_users( MDMsg &msg, MDName &, MDReference &mref ) noexcept {
  return this->config_array( "group.users", msg, mref, this->g->users );
}

uint32_t
StringTab::ref_string( const char *str,  size_t len,  StringVal &sv ) noexcept
{
  StringCollision * col = NULL;
  StringArray     * ptr;
  char            * s;
  size_t            pos,
                    id_pos;
  uint32_t          val,
                    str_h,
                    str_id,
                    id_h,
                    id_val;

  while ( len > 0 && ( str[ len - 1 ] == ' ' || str[ len - 1 ] == '\t' ) )
    len--;
  if ( str == NULL || len == 0 ) {
    sv.zero();
    return 0;
  }
  str_h = kv_crc_c( str, len, 0 );
  if ( this->id->find( str_h, pos, val ) ) {
    /* check if str equals str[ id ] in skip list */
    for ( ptr = this->str.hd; ptr != NULL; ptr = ptr->next ) {
      if ( val >= ptr->first && val < ptr->last ) {
        if ( (sv.val = ptr->str[ val - ptr->first ]) != NULL &&
             ::memcmp( str, sv.val, len ) == 0 && sv.val[ len ] == '\0' ) {
          sv.id  = val;
          sv.len = (uint32_t) len;
          return val;
        }
        break; /* seg range is unique */
      }
    }
    /* if collision, check that */
    for ( col = this->str_col; col != NULL; col = col->next ) {
      if ( ::memcmp( str, col->str, len ) == 0 && col->str[ len ] == '\0' ) {
        sv.val = col->str;
        sv.id  = col->id;
        sv.len = (uint32_t) len;
        return col->id;
      }
    }
    /* not stored, is a collision */
    col = new ( this->mem.make( sizeof( StringCollision ) ) )
          StringCollision();
  }
  if ( len <= 31 ) {
    uint32_t sz = align<uint32_t>( (uint32_t) ( len + 1 ), sizeof( char * ) );
    if ( this->small_left < sz ) {
      this->small_str  = (char *) this->mem.make( 256 );
      this->small_left = 256;
    }
    s = this->small_str;
    this->small_str   = &this->small_str[ sz ];
    this->small_left -= sz;
  }
  else {
    s = (char *) this->mem.make( len + 1 );
  }
  ::memcpy( s, str, len );
  s[ len ] = '\0';
  do {
    str_id = this->next_id++; /* make sure hash( id ) is unique */
  } while ( this->uid->find( id_h = kv_hash_uint( str_id ), id_pos, id_val ) );
  this->uid->set( id_h, id_pos, str_id );
  if ( this->uid->need_resize() )
    this->uid = kv::UIntHashTab::resize( this->uid );
  /* fill collision */
  if ( col != NULL ) {
    col->id   = str_id;
    col->str  = s;
    col->next = this->str_col;
    this->str_col = col;
  }
  else {
    /* add skip list if necessary */
    ptr = this->str.tl;
    if ( ptr == NULL || str_id >= ptr->last ) {
      ptr = new ( this->mem.make( sizeof( StringArray ) ) )
            StringArray( str_id );
      this->str.push_tl( ptr );
    }
    /* add new string */
    ptr->str[ str_id - ptr->first ] = s;
    this->id->set( str_h, pos, str_id );
    if ( this->id->need_resize() )
      this->id = kv::UIntHashTab::resize( this->id );
  }
  sv.val = s;
  sv.id  = str_id;
  sv.len = (uint32_t) len;
  return str_id;
}

bool
StringTab::get_string( uint32_t val,  StringVal &sv ) noexcept
{
  StringCollision * col;
  StringArray     * ptr;
  /* find val in skip list */
  for ( ptr = this->str.hd; ptr != NULL; ptr = ptr->next ) {
    if ( val >= ptr->first && val < ptr->last ) {
      if ( (sv.val = ptr->str[ val - ptr->first ]) != NULL ) {
        sv.id  = val;
        sv.len = (uint32_t) ::strlen( sv.val );
        return true;
      }
      break; /* seg range is unique */
    }
  }
  /* if has collisions, check that */
  for ( col = this->str_col; col != NULL; col = col->next ) {
    if ( col->id == val ) {
      sv.val = col->str;
      sv.id  = val;
      sv.len = (uint32_t) ::strlen( col->str );
      return true;
    }
  }
  sv.val = "????";
  sv.id  = 0;
  sv.len = 4;
  return false;
}

void *
StringTab::make_obj( size_t sz ) noexcept
{
  size_t min_size = this->mem.align_size( sizeof( FreeObj ) ),
         size     = this->mem.align_size( sz );
  if ( size >= min_size ) {
    uint64_t bit = (uint64_t) 1ULL << ( ( size - min_size ) & 63 );
    if ( ( this->free_bits & bit ) != 0 ) {
      for ( FreeObj *o = this->free_list.hd; o != NULL; o = o->next ) {
        if ( o->size == size ) {
          this->free_list.pop( o );
          return (void *) o;
        }
      }
      /* woudld mask out large sizes (>512 bytes), but don't have those yet */
      this->free_bits &= ~bit;
    }
  }
  return this->mem.make( sz );
}

void
StringTab::free_obj( size_t sz,  void *p ) noexcept
{
  size_t min_size = this->mem.align_size( sizeof( FreeObj ) ),
         size     = this->mem.align_size( sz );
  if ( size >= min_size ) {
    uint64_t bit = (uint64_t) 1ULL << ( ( size - min_size ) & 63 );
    this->free_bits |= bit;
    FreeObj *o = (FreeObj *) p;
    o->size = size;
    this->free_list.push_hd( o );
  }
}

void
ConfigDB::check_null( ConfigTree::StrList &list ) noexcept
{
  if ( list.is_empty() ) {
    list.push_tl( this->make<ConfigTree::StringList>() );
  }
}

void
ConfigDB::check_null( ConfigTree::PairList &list ) noexcept
{
  if ( list.is_empty() ) {
    list.push_tl( this->make<ConfigTree::StringPair>() );
  }
}

int
ConfigErrPrinter::printf( const char *fmt,  ... ) noexcept
{
  va_list args;
  va_start( args, fmt );
  int n = ::vfprintf( stderr, fmt, args );
  va_end( args );
  return n;
}

int
ConfigErrPrinter::puts( const char *s ) noexcept
{
  if ( s != NULL ) {
    int n = fputs( s, stderr );
    if ( n > 0 )
      return (int) ::strlen( s );
  }
  return 0;
}

bool
ConfigDB::check_strings( MDOutput &p ) noexcept
{
  BitSpace                 bits;
  ConfigTree::User       * u;
  ConfigTree::Service    * s;
  ConfigTree::Transport  * t;
  ConfigTree::Group      * g;
  ConfigTree::Parameters * pa;
  bool                     b = true;

  for ( u = this->cfg.users.hd; u != NULL; u = u->next ) {
    b &= this->check_strings( *u, this->str, p );
    if ( u->user.id != 0 && bits.test_set( u->user.id ) )
      fprintf( stderr, "User %s redefined, second instance ignored\n", u->user.val );
  }
  bits.zero();
  for ( s = this->cfg.services.hd; s != NULL; s = s->next ) {
    b &= this->check_strings( *s, this->str, p );
    if ( s->svc.id != 0 && bits.test_set( s->svc.id ) )
      fprintf( stderr, "Service %s redefined, second instance ignored\n", s->svc.val );
  }
  bits.zero();
  for ( t = this->cfg.transports.hd; t != NULL; t = t->next ) {
    this->check_null( t->route );
    b &= this->check_strings( *t, this->str, p );
    if ( t->tport.id != 0 && bits.test_set( t->tport.id ) )
      fprintf( stderr, "Transport %s redefined, second instance ignored\n", t->tport.val );
  }
  bits.zero();
  for ( g = this->cfg.groups.hd; g != NULL; g = g->next ) {
    this->check_null( g->users );
    b &= this->check_strings( *g, this->str, p );
    if ( g->group.id != 0 && bits.test_set( g->group.id ) )
      fprintf( stderr, "Group %s redefined, second instance ignored\n", g->group.val );
  }
  for ( pa = this->cfg.parameters.hd; pa != NULL; pa = pa->next )
    b &= this->check_strings( *pa, this->str, p );

  return b;
}

bool
ConfigDB::check_string( StringVal &s,  StringTab &str,
                        const char *where,  MDOutput &p ) noexcept
{
  StringVal ref;
  if ( s.id != 0 )
    return true;
  bool b = str.get_string( s.id, ref );
  s.val = ref.val;
  s.len = ref.len;
  if ( ! b ) {
    if ( where != NULL )
      p.printf( "Err: missing value at %s\n", where );
    return false;
  }
  return true;
}

bool
ConfigDB::check_strings( ConfigTree::User &u,  StringTab &str,
                         MDOutput &p ) noexcept
{
  bool b = true;
  b &= this->check_string( u.user, str, "user.user", p );
  b &= this->check_string( u.svc, str, "user.svc", p );
  b &= this->check_string( u.create, str, "user.create", p );
  if ( ! this->check_string( u.expires, str, NULL, p ) ) {
    u.expires.val = NULL;
    u.expires.len = 0;
  }
  if ( ! this->check_string( u.revoke, str, NULL, p ) ) {
    u.revoke.val = NULL;
    u.revoke.len = 0;
  }
  if ( ! this->check_string( u.pri, str, NULL, p ) ) {
    u.pri.val = NULL;
    u.pri.len = 0;
  }
  b &= this->check_string( u.pub, str, "user.pub", p );
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::StringPair &pa,  StringTab &str,
                         const char *where,  MDOutput &p ) noexcept
{
  bool b = true;
  b &= this->check_string( pa.name, str, where, p );
  b &= this->check_string( pa.value, str, where, p );
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::StringList &l,  StringTab &str,
                         const char *where,  MDOutput &p ) noexcept
{
  return this->check_string( l.val, str, where, p );
}

bool
ConfigDB::check_strings( ConfigTree::Service &svc,
                         StringTab &str,  MDOutput &p ) noexcept
{
  bool b = true;
  b &= this->check_string( svc.svc, str, "service.svc", p );
  b &= this->check_string( svc.create, str, "service.create", p );
  if ( ! this->check_string( svc.pri, str, NULL, p ) ) {
    svc.pri.val = NULL;
    svc.pri.len = 0;
  }
  b &= this->check_string( svc.pub, str, "service.pub", p );
  ConfigTree::StringPair *sp;
  for ( sp = svc.users.hd; sp != NULL; sp = sp->next )
    b &= this->check_strings( *sp, str, "service.users", p );
  for ( sp = svc.revoke.hd; sp != NULL; sp = sp->next )
    b &= this->check_strings( *sp, str, "service.revoke", p );
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::Transport &tport,
                         StringTab &str,  MDOutput &p ) noexcept
{
  bool b = true;
  b &= this->check_string( tport.tport, str, "transport.tport", p );
  b &= this->check_string( tport.type, str, "transport.type", p );
  for ( ConfigTree::StringPair *sp = tport.route.hd; sp != NULL; sp = sp->next )
    b &= this->check_strings( *sp, str, "transport.route", p );
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::Group &grp,  StringTab &str,
                         MDOutput &p ) noexcept
{
  bool b = true;
  b &= this->check_string( grp.group, str, "group.group", p );
  for ( ConfigTree::StringList *sl = grp.users.hd; sl != NULL; sl = sl->next )
    b &= this->check_strings( *sl, str, "group.user", p );
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::Parameters &pa,  StringTab &str,
                         MDOutput &p ) noexcept
{
  bool b = true;
  for ( ConfigTree::StringPair *sp = pa.list.hd; sp != NULL; sp = sp->next )
    b &= this->check_strings( *sp, str, "parameters.parm", p );
  return b;
}

void
ConfigTree::Transport::print_y( MDOutput &p ) const noexcept
{
  ConfigJson cfg;
  JsonValue * val = cfg.copy( *this );
  if ( val != NULL )
    val->print_json( &p );
}

void
ConfigTree::print_js( MDOutput &p,  int which,  const StringVal *filter,
                     const ConfigTree::TransportArray *listen,
                     const ConfigTree::TransportArray *connect ) const noexcept
{
  ConfigJson cfg;
  JsonValue * val = cfg.copy( this, which, filter, listen, connect );
  if ( val != NULL )
    val->print_json( &p );
}

void
ConfigTree::print_y( MDOutput &p,  int which,  const StringVal *filter,
                     const ConfigTree::TransportArray *listen,
                     const ConfigTree::TransportArray *connect ) const noexcept
{
  ConfigJson cfg;
  JsonValue * val = cfg.copy( this, which, filter, listen, connect );
  if ( val != NULL )
    val->print_yaml( &p );
}

int
ConfigTree::Transport::get_host_port( const char *&hostp,  char *host,
                                  size_t &len, ParametersList &hosts ) noexcept
{
  int port = 0, first = 0;
  size_t avail = len;
  if ( hostp == NULL ) {
    len = 0;
    return 0;
  }
repeat_process:;
  size_t i, hlen = ::strlen( hostp );
  if ( len <= hlen ) {
    len = hlen;
    return 0;
  }
  ::memcpy( host, hostp, hlen );
  host[ hlen ] = '\0';
  hostp = host;
  len   = hlen;

  if ( hlen > 3 ) {
    for ( i = 0; i < hlen; i++ ) {
      if ( host[ i ] == ':' ) {
        /* strip x:// */
        if ( hlen > i + 3 && host[ i + 1 ] == '/' && host[ i + 2 ] == '/' ) {
          hlen -= i + 3;
          ::memmove( host, &host[ i + 3 ], hlen );
          host[ hlen ] = '\0';
        }
        break;
      }
      if ( ! isalpha( host[ i ] ) )
        break;
    }
  }
  for ( i = hlen; ; ) {
    if ( i == 0 ) {
      port = atoi( host ); /* only digits */
      len = 0;
      break;
    }
    if ( i < len && host[ i - 1 ] == ':' ) {
      port = atoi( &host[ i ] );
      len  = i - 1;
      break;
    }
    if ( ! isdigit( host[ --i ] ) )
      break;
  }
  /* ipv6 style [addr]:port */
  if ( len > 2 && host[ 0 ] == '[' && host[ len - 1 ] == ']' ) {
    if ( ::strchr( &host[ 1 ], '[' ) == NULL ) { /* if not [addr];[addr]:port */
      ::memmove( host, &host[ 1 ], len - 2 );
      len -= 2;
    }
  }

  host[ len ] = '\0';
  if ( first++ == 0 && hosts.find( host, hostp, host ) ) {
    len = avail;
    goto repeat_process;
  }
  return port;
}

bool
ConfigTree::Transport::is_wildcard( const char *host ) noexcept
{
  return host == NULL || host[ 0 ] == '\0' ||
         ( host[ 0 ] == '*' && host[ 1 ] == '\0' ) ||
         ( host[ 0 ] == '0' && host[ 1 ] == '\0' );
}

void
ConfigTree::Transport::get_route_pairs( const char *name,
                                        StringPairArray &el ) noexcept
{
  size_t i, name_len = ::strlen( name );
  ConfigTree::StringPair * sp, * sp2;

  sp = this->route.get_pair( name, name_len );
  if ( sp != NULL ) {
    el.push( sp );
    for ( i = 1; ; i++ ) {
      char nbuf[ 64 ]; /* try connect2, connect3, ... */
      size_t d = uint64_digits( i + 1 );
      if ( d + name_len + 1 > sizeof( nbuf ) )
        break;
      CatPtr p( nbuf );
      p.x( name, name_len ).u( i + 1, d ).end();
      sp2 = this->route.get_pair( nbuf, p.len() );
      if ( sp2 == NULL )
        break;
      el.push( sp2 );
    }
  }
  /* parse config that uses array of cost */
  if ( sp != NULL ) {
    while ( (sp = sp->next) != NULL ) {
      if ( ! sp->name.equals( name, name_len ) )
        break;
      el.push( sp );
    }
  }
}

void
ConfigTree::set_route_str( ConfigTree::Transport &t,  StringTab &st,
                           const char *name,  const char *value,
                           size_t value_len ) noexcept
{
  ConfigTree::StringPair * sp;
  size_t name_len = ::strlen( name );
  if ( (sp = t.route.get_pair( name, name_len )) == NULL ) {
    sp = st.make<ConfigTree::StringPair>();
    st.ref_string( name, name_len, sp->name );
    t.route.push_tl( sp );
  }
  st.ref_string( value, value_len, sp->value );
}
#if 0
void
ConfigTree::Transport::set_route_int( StringTab &st,  const char *name,
                                      int value ) noexcept
{
  char buf[ 16 ];
  int n = int32_to_string( value, buf );
  return this->set_route_str( st, name, buf, n );
}
#endif

ConfigTree::StringPair *
ConfigTree::ParametersList::find_sp( const char *name,
                                     size_t name_len ) noexcept
{
  for ( Parameters *p = this->hd; p != NULL; p = p->next ) {
    for ( StringPair *sp = p->list.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( name, name_len ) )
        return sp;
    }
  }
  return NULL;
}

bool
ConfigTree::ParametersList::find( const char *name,  const char *&value,
                                  const char *def_value ) noexcept
{
  StringPair * sp = this->find_sp( name, ::strlen( name ) );
  if ( sp != NULL )
    value = sp->value.val;
  else
    value = def_value;
  return sp != NULL;
}

void
ConfigTree::ParametersList::set( StringTab &st,  const char *name,
                                 const char *value ) noexcept
{
  size_t name_len = ::strlen( name );
  StringPair * sp = this->find_sp( name, name_len );
  Parameters * p;
  if ( sp == NULL ) {
    if ( (p = this->tl) == NULL ) {
      p = st.make<ConfigTree::Parameters>();
      this->push_tl( p );
    }
    sp = st.make<ConfigTree::StringPair>();
    p->list.push_tl( sp );
    st.ref_string( name, name_len, sp->name );
  }
  st.ref_string( value, ::strlen( value ), sp->value );
}

bool
ConfigTree::ParametersList::remove( StringTab &st,  const char *name ) noexcept
{
  size_t name_len = ::strlen( name );
  for ( Parameters *p = this->hd; p != NULL; p = p->next ) {
    StringPair *last = NULL;
    for ( StringPair *sp = p->list.hd; sp != NULL; ) {
      if ( sp->name.equals( name, name_len ) ) {
        if ( last == NULL ) {
          p->list.hd = sp->next;
          if ( p->list.hd == NULL )
            p->list.tl = NULL;
        }
        else {
          last->next = sp->next;
          if ( p->list.tl == sp )
            p->list.tl = last;
        }
        st.release( sp );
        return true;
      }
      last = sp;
      sp = sp->next;
    }
  }
  return false;
}

static bool
int_prefix( const char *s,  MDDecimal &dec,  size_t &off ) noexcept
{
  size_t i, j, len = ::strlen( s );
  if ( len == 0 )
    return false;

  for ( i = 0; i < len; i++ )
    if ( ! isspace( s[ i ] ) )
      break;
  if ( i == len )
    return false;
  s = &s[ i ];
  len -= i;
  if ( len > 2 && s[ 0 ] == '0' && ( s[ 1 ] == 'x' || s[ 1 ] == 'X' ) ) {
    for ( j = 2; j < len; j++ ) {
      if ( ! ( ( s[ j ] >= '0' && s[ j ] <= '9' ) ||
               ( s[ j ] >= 'a' && s[ j ] <= 'f' ) ||
               ( s[ j ] >= 'A' && s[ j ] <= 'F' ) ) )
        break;
    }
    dec.ival = string_to_uint64( s, j );
    dec.hint = MD_DEC_INTEGER;
  }
  else {
    for ( j = len; ; ) {
      if ( isdigit( s[ j - 1 ] ) || s[ j - 1 ] == '.' )
        break;
      if ( --j == 0 )
        return false;
    }

    const char * d1 = NULL, * d2 = NULL, * d3 = NULL;
    bool is_ip4 = false;
    d1 = (const char *) ::memchr( s, '.', j );
    if ( d1 != NULL )
      d2 = (const char *) ::memchr( d1+1, '.', &s[ j ] - &d1[ 1 ] );
    if ( d2 != NULL )
      d3 = (const char *) ::memchr( d2+1, '.', &s[ j ] - &d2[ 1 ] );
    if ( d1 != NULL && d2 != NULL && d3 != NULL ) {
      uint64_t a = 0, b = 0, c = 0, d = 0;
      if ( d1 > s )
        a = string_to_uint64( s, d1 - s );
      if ( d2 > &d1[ 1 ] )
        b = string_to_uint64( d1+1, d2 - &d1[ 1 ] );
      if ( d3 > &d2[ 1 ] )
        c = string_to_uint64( d2+1, d3 - &d2[ 1 ] );
      if ( &s[ j ] > &d3[ 1 ] )
        d = string_to_uint64( d3+1, &s[ j ] - &d3[ 1 ] );
      if ( ( a | b | c | d ) <= 0xff ) {
        dec.ival = ( a << 24 ) | ( b << 16 ) | ( c << 8 ) | d;
        dec.hint = MD_DEC_INTEGER;
        is_ip4 = true;
      }
    }
    if ( ! is_ip4 ) {
      if ( dec.parse( &s[ 0 ], j ) != 0 )
        return false;
    }
  }
  while ( j < len && isspace( s[ j ] ) )
    j++;
  off = i + j;
  return true;
}


bool
ConfigTree::string_to_uint( const char *s,  uint64_t &ival ) noexcept
{
  MDDecimal dec;
  double val;
  size_t off;
  if ( ! int_prefix( s, dec, off ) )
    return false;
  if ( dec.hint == MD_DEC_INTEGER ) {
    ival = (uint64_t) dec.ival;
    return true;
  }
  if ( dec.get_real( val ) != 0 )
    return false;
  ival = (uint64_t) val;
  return true;
}

bool
ConfigTree::string_to_bytes( const char *s,  uint64_t &bytes ) noexcept
{
  MDDecimal dec;
  double val;
  size_t off;
  if ( ! int_prefix( s, dec, off ) )
    return false;
  if ( dec.get_real( val ) != 0 )
    return false;
  switch ( s[ off ] ) {
    case '\0': case 'b': case 'B': break;
    case 'k': case 'K': val *= 1024.0; break;
    case 'm': case 'M': val *= 1024.0 * 1024; break;
    case 'g': case 'G': val *= 1024.0 * 1024 * 1024; break;
    default: return false;
  }
  bytes = (uint64_t) val;
  return true;
}

bool
ConfigTree::string_to_secs( const char *s,  uint64_t &secs ) noexcept
{
  MDStamp stamp;
  if( stamp.parse( s, ::strlen( s ), true ) != 0 )
    return false;
  secs = stamp.seconds();
  return true;
}

bool
ConfigTree::string_to_nanos( const char *s,  uint64_t &nanos ) noexcept
{
  MDStamp stamp;
  if( stamp.parse( s, ::strlen( s ), true ) != 0 )
    return false;
  nanos = stamp.nanos();
  return true;
}

bool
ConfigTree::string_to_bool( const char *s,  bool &b ) noexcept
{
  b = false;
  switch ( s[ 0 ] ) {
    case '1': case 't': case 'T': case 'y': case 'Y':
      b = true;
      return true;
    case '0': case 'f': case 'F': case 'n': case 'N':
      b = false;
      return true;
    default:
      break;
  }
  return false;
}

