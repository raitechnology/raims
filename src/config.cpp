#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raikv/util.h>
#include <raikv/os_file.h>
#ifndef _MSC_VER
#include <glob.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <raimd/json_msg.h>
#include <raikv/key_hash.h>
#include <raims/parse_config.h>
#include <raims/gen_config.h>

using namespace rai;
using namespace md;
using namespace kv;
using namespace ms;
#define ASZ( ar ) ( sizeof( ar ) / sizeof( ar[ 0 ] ) )

static struct ArrayParse top_level[] = {
  { "users",      &ConfigDB::parse_users,      MD_ARRAY },
  { "services",   &ConfigDB::parse_services,   MD_ARRAY },
  { "transports", &ConfigDB::parse_transports, MD_ARRAY },
  { "groups",     &ConfigDB::parse_groups,     MD_ARRAY },
  { "include",    &ConfigDB::parse_include,    MD_STRING },
  { "parameters", &ConfigDB::parse_parameters, MD_MESSAGE }
};
static ObjectParse top_obj = {
  top_level, ASZ( top_level ), NULL
};

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

static struct ArrayParse tports_fields[] = {
  { "tport", &ConfigDB::parse_transports_tport, MD_STRING },
  { "type",  &ConfigDB::parse_transports_type,  MD_STRING },
  { "route", &ConfigDB::parse_transports_route, MD_MESSAGE }
};
static struct ObjectParse tports_obj = {
  tports_fields, ASZ( tports_fields ), &ConfigDB::create_transport
};

static struct ArrayParse grps_fields[] = {
  { "group", &ConfigDB::parse_groups_group, MD_STRING },
  { "users", &ConfigDB::parse_groups_users, MD_NODATA }
};
static struct ObjectParse grps_obj = {
  grps_fields , ASZ( grps_fields ), &ConfigDB::create_group
};

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
ConfigDB::parse_dir( const char *dir_name,  StringTab &st,
                     ConfigPrinter &err ) noexcept
{
  char path[ 1024 ];
  int  n;
  n = ::snprintf( path, sizeof( path ), "%s/config.yaml", dir_name );
  if ( n > 0 && (size_t) n < sizeof( path ) ) {
    ConfigTree *tree = parse_jsfile( path, st, err );
    if ( tree != NULL )
      st.ref_string( dir_name, ::strlen( dir_name ), tree->dir_name );
    return tree;
  }
  fprintf( stderr, "dir_name too long\n" );
  return NULL;
}

ConfigTree *
ConfigDB::parse_jsfile( const char *fn,  StringTab &st,
                        ConfigPrinter &err ) noexcept
{
  ConfigTree * tree = new ( st.mem.make( sizeof( ConfigTree ) ) ) ConfigTree();
  InodeStack   ino;
  ConfigDB     db( *tree, st.mem, &ino, st );
  StringVal    ref;

  db.filename = fn;

  if ( db.parse_glob( fn ) != 0 || ! db.check_strings( err ) ) {
    fprintf( stderr, "Parse failed \"%s\"\n", fn );
    return NULL;
  }
  return tree;
}

#ifndef _MSC_VER
struct Glob {
  glob_t g;
  size_t i;
  int    status;
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
  
  Glob( const char *spec ) {
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
    char * slash;
    if ( this->dir == NULL )
      return this->fileinfo.name;
    ::snprintf( this->buf, sizeof( this->buf ), "%.*s/%s",
                this->dirlen, this->dir, this->fileinfo.name );
    slash = buf;
    while ( (slash = ::strchr( slash, '\\' )) != NULL )
      *slash++ = '/';
    return this->buf;
  }
  const char *first( void ) {
    if ( this->ptr == -1 )
      return NULL;
    return this->get_path();
  }
  const char *next( void ) {
    if ( this->ptr == -1 )
      return NULL;
    if ( _findnext( this->ptr, &this->fileinfo ) != 0 )
      return NULL;
    return this->get_path();
  }
};
#endif

int
ConfigDB::parse_glob( const char *fn ) noexcept
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
      this->filename = inc_file;
      status = this->parse_glob( inc_file );
      this->filename = old;
    }
    else {
      fprintf( stderr, "include file too long\n" );
      status = -1;
    }
  }
  return status;
}

struct FilePrinter : public ConfigPrinter {
  const StringVal & dir_name;
  FILE * fp;
  FilePrinter( const StringVal &d ) : dir_name( d ), fp( 0 ) {}
  ~FilePrinter() {
    if ( this->fp != NULL )
      fclose( this->fp );
  }
  int open( const char *kind,  const StringVal &sv ) noexcept;
  virtual int printf( const char *fmt,  ... ) noexcept;
};

int
FilePrinter::open( const char *kind,  const StringVal &sv ) noexcept
{
  const char * sep = "/";
  char path[ 1024 ];
  if ( this->dir_name.len == 0 )
    sep = "";
  int n = ::snprintf( path, sizeof( path ), "%.*s%s%s%.*s.yaml.new",
                      (int) this->dir_name.len, this->dir_name.val, sep,
                      kind, (int) sv.len, sv.val );
  if ( n > 0 && (size_t) n < sizeof( path ) ) {
    this->fp = fopen( path, "w" );
    if ( this->fp == NULL ) {
      fprintf( stderr, "unable to write %s: %d/%s\n", path, errno,
               strerror( errno ) );
      return -1;
    }
    return 0;
  }
  fprintf( stderr, "path name too long\n" );
  return -1;
}

int
FilePrinter::printf( const char *fmt,  ... ) noexcept
{
  va_list args;
  va_start( args, fmt );
  int n = ::vfprintf( this->fp, fmt, args );
  va_end( args );
  return n;
}

int
ConfigTree::save_tport( const ConfigTree::Transport &tport ) const noexcept
{
  FilePrinter out( this->dir_name );
  if ( out.open( "tport_", tport.tport ) != 0 )
    return -1;
  tport.print_y( out, 0 );
  return 0;
}

int
ConfigTree::save_parameters( const TransportArray &listen,
                             const TransportArray &connect ) const noexcept
{
  FilePrinter    out( this->dir_name ),
                 out2( this->dir_name );
  StringVal      mt;
  TransportArray mta;
  int            which;
  if ( out.open( "param", mt ) != 0 )
    return -1;
  which = PRINT_PARAMETERS | PRINT_HDR;
  this->print_parameters( out, which, NULL, 0, mta, mta );

  if ( out2.open( "startup", mt ) != 0 )
    return -1;
  which = PRINT_STARTUP | PRINT_HDR;
  this->print_parameters( out2, which, NULL, 0, listen, connect );
  return 0;
}

void
ConfigTree::print_parameters( ConfigPrinter &p, int which,
                              const char *name,  size_t namelen,
                              const TransportArray &listen,
                              const TransportArray &connect ) const noexcept
{
  size_t n;
  int i = ( ( which & PRINT_HDR ) != 0 ? 2 : 0 );
  int did_which;
  this->print_y( p, did_which, which & ~PRINT_STARTUP, name, namelen );
  if ( ( did_which & PRINT_PARAMETERS ) == 0 ) {
    if ( listen.count > 0 || connect.count > 0 )
      p.printf( "parameters:\n" );
  }
  if ( listen.count > 0 ) {
    if ( namelen == 0 ||
         ( namelen == 6 && ::memcmp( name, "listen", 6 ) == 0 ) ) {
      p.printf( "%*slisten:\n", i, "" );
      for ( n = 0; n < listen.count; n++ ) {
        p.printf( "  %*s- ", i, "" );
        listen.ptr[ n ]->tport.print_y( p );
        p.printf( "\n" );
      }
    }
  }
  if ( connect.count > 0 ) {
    if ( namelen == 0 ||
         ( namelen == 7 && ::memcmp( name, "connect", 7 ) == 0 ) ) {
      p.printf( "%*sconnect:\n", i, "" );
      for ( n = 0; n < connect.count; n++ ) {
        p.printf( "  %*s- ", i, "" );
        connect.ptr[ n ]->tport.print_y( p );
        p.printf( "\n" );
      }
    }
  }
}

bool
ConfigTree::save_new( void ) const noexcept
{
  const char * sep = "/";
  char path_new[ 1024 ];
  GenFileList ops;

  if ( this->dir_name.len == 0 )
    sep = "";
  int n = ::snprintf( path_new, sizeof( path_new ), "%.*s%s*.yaml.new",
                      (int) this->dir_name.len, this->dir_name.val, sep );
  if ( n < 0 || (size_t) n >= sizeof( path_new ) ) {
    fprintf( stderr, "dir path too big\n" );
    return false;
  }

  Glob g( path_new );
  const char *path;
  if ( (path = g.first() ) == NULL )
    return false;

  do {
    static const char run_file[] = "startup.yaml.new";
    static const char param_file[] = "param.yaml.new";
    static size_t run_file_size = sizeof( run_file ) - 1;
    static size_t param_file_size = sizeof( param_file ) - 1;
    const char * descr;
    GenFileTrans * t = GenFileTrans::create_file_path( GEN_CREATE_FILE, path );
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

  ops.print_files();
  if ( ops.commit_phase1() ) {
    ops.commit_phase2();
    return true;
  }
  ops.abort();
  return false;
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
      u_len = ::strlen( us );
    }
  }
  svc  = this->find_service( sv, s_len );
  usrp = NULL;
  if ( svc != NULL )
    usrp = this->find_user( *svc, us, u_len );
  if ( svc != NULL && usrp != NULL )
    return true;
  if ( svc == NULL )
    fprintf( stderr, "No service %.*s configured\n", (int) s_len, sv );
  else if ( usrp == NULL )
    fprintf( stderr, "No user %.*s configured\n", (int) u_len, us );
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
ConfigDB::parse_parameters( MDMsg &msg,  MDName &name,
                            MDReference &mref ) noexcept
{
  const char where[] = "parameters";
  MDMsg * smsg;
  int     status;
  ConfigTree::Parameters * p = this->make<ConfigTree::Parameters>();
  if ( mref.ftype == MD_ARRAY )
    status = this->config_array( where, msg, name, mref, p->parms );
  else if ( mref.ftype != MD_MESSAGE )
    status = this->config_pair( where, msg, name, mref, p->parms );
  else {
    status = msg.get_sub_msg( mref, smsg );
    if ( status == 0 )
      status = this->parse_pairs( where, *smsg, p->parms );
  }
  if ( status != 0 )
    fprintf( stderr, "Expecting an object in %s\n", where );
  this->cfg.parameters.push_tl( p );
  return status;
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

  if ( str == NULL ) {
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
ConfigPrinter::printf( const char *fmt,  ... ) noexcept
{
  va_list args;
  va_start( args, fmt );
  int n = ::vprintf( fmt, args );
  va_end( args );
  return n;
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

bool
ConfigDB::check_strings( ConfigPrinter &p ) noexcept
{
  bool b = true;

  for ( ConfigTree::User *u = this->cfg.users.hd; u != NULL; u = u->next )
    b &= this->check_strings( *u, this->str, p );

  for ( ConfigTree::Service *s = this->cfg.services.hd; s != NULL; s = s->next )
    b &= this->check_strings( *s, this->str, p );

  for ( ConfigTree::Transport *t = this->cfg.transports.hd; t != NULL;
        t = t->next ) {
    this->check_null( t->route );
    b &= this->check_strings( *t, this->str, p );
  }
  for ( ConfigTree::Group *g = this->cfg.groups.hd; g != NULL; g = g->next ) {
    this->check_null( g->users );
    b &= this->check_strings( *g, this->str, p );
  }
  for ( ConfigTree::Parameters *pa = this->cfg.parameters.hd; pa != NULL;
        pa = pa->next )
    b &= this->check_strings( *pa, this->str, p );

  return b;
}

bool
ConfigDB::check_string( StringVal &s,  StringTab &str,
                        const char *where,  ConfigPrinter &p ) noexcept
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
                         ConfigPrinter &p ) noexcept
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
  if ( ! b ) {
    p.printf( "  \"users\" : [ {\n" );
    u.print_js( p, 4 );
    p.printf( "  } ]\n" );
  }
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::StringPair &pa,  StringTab &str,
                         const char *where,  ConfigPrinter &p ) noexcept
{
  bool b = true;
  b &= this->check_string( pa.name, str, where, p );
  b &= this->check_string( pa.value, str, where, p );
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::StringList &l,  StringTab &str,
                         const char *where,  ConfigPrinter &p ) noexcept
{
  return this->check_string( l.val, str, where, p );
}

bool
ConfigDB::check_strings( ConfigTree::Service &svc,
                         StringTab &str,  ConfigPrinter &p ) noexcept
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
  if ( ! b ) {
    p.printf( "  \"services\" : [ {\n" );
    svc.print_js( p, 4 );
    p.printf( "  } ]\n" );
  }
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::Transport &tport,
                         StringTab &str,  ConfigPrinter &p ) noexcept
{
  bool b = true;
  b &= this->check_string( tport.tport, str, "transport.tport", p );
  b &= this->check_string( tport.type, str, "transport.type", p );
  for ( ConfigTree::StringPair *sp = tport.route.hd; sp != NULL; sp = sp->next )
    b &= this->check_strings( *sp, str, "transport.route", p );
  if ( ! b ) {
    p.printf( "  \"transports\" : [ {\n" );
    tport.print_js( p, 4 );
    p.printf( "  } ]\n" );
  }
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::Group &grp,  StringTab &str,
                         ConfigPrinter &p ) noexcept
{
  bool b = true;
  b &= this->check_string( grp.group, str, "group.group", p );
  for ( ConfigTree::StringList *sl = grp.users.hd; sl != NULL; sl = sl->next )
    b &= this->check_strings( *sl, str, "group.user", p );
  if ( ! b ) {
    p.printf( "  \"groups\" : [ {\n" );
    grp.print_js( p, 4 );
    p.printf( "  } ]\n" );
  }
  return b;
}

bool
ConfigDB::check_strings( ConfigTree::Parameters &pa,  StringTab &str,
                         ConfigPrinter &p ) noexcept
{
  bool b = true;
  for ( ConfigTree::StringPair *sp = pa.parms.hd; sp != NULL; sp = sp->next )
    b &= this->check_strings( *sp, str, "parameters.parm", p );
  if ( ! b ) {
    pa.print_js( p, 4 );
  }
  return b;
}

void
ConfigTree::print_js( ConfigPrinter &p ) const noexcept
{
  int which;
  this->print_js( p, which, PRINT_NORMAL, NULL, 0 );
}

void
ConfigTree::print_js( ConfigPrinter &p,  int &did_which,  int which,
                      const char *name,  size_t namelen ) const noexcept
{
  const char * nl = "";
  p.printf( "{\n" );
  int x = 0;
  if ( ( which & PRINT_USERS ) != 0 ) {
    const User *u = this->users.hd;
    if ( u != NULL ) {
      x |= PRINT_USERS;
      p.printf( "  \"users\" : [ {\n" );
      u->print_js( p, 6 );
      for ( u = u->next; u != NULL; u = u->next ) {
        if ( namelen == 0 || u->user.equals( name, namelen ) ) {
          p.printf( "    }, {\n" );
          u->print_js( p, 6 );
        }
      }
      p.printf( "    }\n  ]" );
      nl = ",\n";
    }
  }
  if ( ( which & PRINT_SERVICES ) != 0 ) {
    const Service *s = this->services.hd;
    if ( s != NULL ) {
      x |= PRINT_SERVICES;
      p.printf( "%s  \"services\" : [ {\n", nl );
      s->print_js( p, 6 );
      for ( s = s->next; s != NULL; s = s->next ) {
        if ( namelen == 0 || s->svc.equals( name, namelen ) ) {
          p.printf( "    }, {\n" );
          s->print_js( p, 6 );
        }
      }
      p.printf( "    }\n  ]" );
      nl = ",\n";
    }
  }
  if ( ( which & PRINT_TRANSPORTS ) != 0 ) {
    const Transport *t = this->transports.hd;
    if ( t != NULL ) {
      x |= PRINT_TRANSPORTS;
      p.printf( "%s  \"transports\" : [ {\n", nl );
      t->print_js( p, 6 );
      for ( t = t->next; t != NULL; t = t->next ) {
        if ( namelen == 0 || t->tport.equals( name, namelen ) ) {
          if ( ! t->route.is_empty() ) {
            p.printf( "    }, {\n" );
            t->print_js( p, 6 );
          }
        }
      }
      p.printf( "    }\n  ]" );
      nl = ",\n";
    }
  }
  if ( ( which & PRINT_GROUPS ) != 0 ) {
    const Group *g = this->groups.hd;
    if ( g != NULL ) {
      x |= PRINT_GROUPS;
      p.printf( "%s  \"groups\" : [ {\n", nl );
      g->print_js( p, 6 );
      for ( g = g->next; g != NULL; g = g->next ) {
        if ( namelen == 0 || g->group.equals( name, namelen ) ) {
          p.printf( "    }, {\n" );
          g->print_js( p, 6 );
        }
      }
      p.printf( "    }\n  ]" );
      nl = ",\n";
    }
  }
  if ( ( which & PRINT_PARAMETERS ) != 0 ) {
    const Parameters *pa = this->parameters.hd;
    if ( pa != NULL ) {
      x |= PRINT_PARAMETERS;
      p.printf( "%s", nl );
      for ( ; pa != NULL; pa = pa->next ) {
        pa->print_js( p, 2, pa->next == NULL ? 0 : ',' );
      }
    }
    else {
      p.printf( "\n" );
    }
  }
  p.printf( "}\n" );
  did_which = x;
}

void
ConfigTree::print_y( ConfigPrinter &p,  int &did_which,  int which,
                     const char *name,  size_t namelen ) const noexcept
{
  int x = 0;
  if ( ( which & PRINT_USERS ) != 0 ) {
    const User *u = this->users.hd;
    if ( u != NULL || ( which & PRINT_HDR ) ) {
      p.printf( "users:\n" );
      x |= PRINT_USERS;
      for ( ; u != NULL; u = u->next )
        if ( namelen == 0 || u->user.equals( name, namelen ) )
          u->print_y( p, 4 );
    }
  }
  if ( ( which & PRINT_SERVICES ) != 0 ) {
    const Service *s = this->services.hd;
    if ( s != NULL || ( which & PRINT_HDR ) ) {
      p.printf( "services:\n" );
      x |= PRINT_SERVICES;
      for ( ; s != NULL; s = s->next )
        if ( namelen == 0 || s->svc.equals( name, namelen ) )
          s->print_y( p, 4 );
    }
  }
  if ( ( which & PRINT_TRANSPORTS ) != 0 ) {
    const Transport *t = this->transports.hd;
    if ( t != NULL || ( which & PRINT_HDR ) ) {
      p.printf( "transports:\n" );
      x |= PRINT_TRANSPORTS;
      for ( ; t != NULL; t = t->next ) {
        if ( namelen == 0 || t->tport.equals( name, namelen ) ) {
          if ( ! t->route.is_empty() )
            t->print_y( p, 4 );
        }
      }
    }
  }
  if ( ( which & PRINT_GROUPS ) != 0 ) {
    const Group *g = this->groups.hd;
    if ( g != NULL || ( which & PRINT_HDR ) ) {
      p.printf( "groups:\n" );
      x |= PRINT_GROUPS;
      for ( ; g != NULL; g = g->next )
        if ( namelen == 0 || g->group.equals( name, namelen ) )
          g->print_y( p, 4 );
    }
  }
  if ( ( which & ( PRINT_PARAMETERS | PRINT_STARTUP ) ) != 0 ) {
    const Parameters *pa = this->parameters.hd;
    if ( pa != NULL || ( which & PRINT_HDR ) ) {
      p.printf( "parameters:\n" );
      x |= PRINT_PARAMETERS;
      for ( ; pa != NULL; pa = pa->next ) {
        const StringPair *sp = pa->parms.hd;
        for ( ; sp != NULL; ) {
          bool matched = false;
          if ( namelen == 0 || sp->name.equals( name, namelen ) ) {
            bool is_startup = ( sp->name.equals( "listen" ) ||
                                sp->name.equals( "connect" ) );
            if ( which & PRINT_STARTUP )
              matched = is_startup;
            else
              matched = ! is_startup;
          }
          if ( matched )
            sp = sp->print_ylist( p, 2 );
          else
            sp = sp->next;
        }
      }
    }
  }
  did_which = x;
}

static const char *
find_escape_chars( const char *s,  size_t len )
{
  for ( size_t i = 0; i < len; i++ ) {
    switch ( s[ i ] ) {
      case '\"':
      case '\\': return &s[ i ];
      default: break;
    }
  }
  return NULL;
}

void
StringVal::print_js( ConfigPrinter &p ) const noexcept
{
  const char *v = this->val,
             *s = find_escape_chars( v, this->len );
  if ( s == NULL )
    p.printf( "\"%*s\"", (int) this->len, v );
  else {
    const char *e = &this->val[ this->len ];
    p.printf( "\"%.*s", (int) ( s - v ), v );
    do {
      if ( *s == '\\' )
        p.printf( "\\\\" );
      else
        p.printf( "\\\"" );
      v = &s[ 1 ];
      s = find_escape_chars( v, e - v );
      if ( s == NULL ) s = e;
      p.printf( "%.*s", (int) ( s - v ), v );
    } while ( s < e );
    p.printf( "\"" );
  }
}

void
StringVal::print_y( ConfigPrinter &p ) const noexcept
{
  bool quote = ( this->len == 0 );
  if ( ! quote && this->len == 1 ) {
    switch ( this->val[ 0 ] ) {
      case 'Y': case 'y': case 'N': case 'n':
      /*case '0': case '1': case '2': case '3':
      case '4': case '5': case '6': case '7':
      case '8': case '9':*/
        quote = true;
        break;
    }
  }
  if ( ! quote ) {
    if ( ispunct( this->val[ 0 ] ) ) {
      switch ( this->val[ 0 ] ) {
        case '^': case '(': case ')': case '<': case '.': case ';':
          break;
        default:
          quote = true;
          break;
      }
    }
    if ( ! quote ) {
      if ( ::memchr( this->val, '\'', this->len ) != NULL ||
                ::memchr( this->val, '\"', this->len ) != NULL ||
                ::memchr( this->val, '\\', this->len ) != NULL )
        quote = true;
      /*else if ( ! isalpha( this->val[ 0 ] ) ) {
        char *end = (char *) this->val;
        ::strtod( this->val, &end );
        if ( end == &this->val[ this->len ] )
          quote = true;
      }*/
      else if ( ( this->len == 4 &&
                  ::strncasecmp( this->val, "true", 4 ) == 0 ) ||
                ( this->len == 4 &&
                  ::strncasecmp( this->val, "null", 4 ) == 0 ) ||
                ( this->len == 5 &&
                  ::strncasecmp( this->val, "false", 5 ) == 0 ) )
        quote = true;
      else if ( this->val[ this->len - 1 ] == ':' )
        quote = true;
    }
  }
  if ( quote )
    this->print_js( p );
  else
    p.printf( "%*s", (int) this->len, this->val );
}

void
ConfigTree::User::print_js( ConfigPrinter &p,  int i,  char c ) const noexcept
{
  p.printf( "%*s\"user\" : ", i, "" ); this->user.print_js( p ); p.printf( ",\n" );
  p.printf( "%*s\"svc\" : ", i, "" ); this->svc.print_js( p ); p.printf( ",\n" );
  p.printf( "%*s\"create\" : ", i, "" ); this->create.print_js( p ); p.printf( ",\n" );
  if ( ! this->expires.is_null() ) {
    p.printf( "%*s\"expires\" : ", i, "" ); this->expires.print_js( p );
    p.printf( ",\n" );
  }
  if ( ! this->revoke.is_null() ) {
    p.printf( "%*s\"revoke\" : ", i, "" ); this->revoke.print_js( p );
    p.printf( ",\n" );
  }
  if ( ! this->pri.is_null() ) {
    p.printf( "%*s\"pri\" : ", i, "" ); this->pri.print_js( p );
    p.printf( ",\n" );
  }
  p.printf( "%*s\"pub\" : ", i, "" ); this->pub.print_js( p );
  if ( c != 0 ) p.printf( "%c", c );
  p.printf( "\n" );
}

void
ConfigTree::User::print_y( ConfigPrinter &p,  int i ) const noexcept
{
  if ( i > 0 )
    p.printf( "%*s- user: ", i - 2, "" );
  else
    p.printf( "user: " );
  this->user.print_y( p ); p.printf( "\n" );
  p.printf( "%*ssvc: ", i, "" ); this->svc.print_y( p ); p.printf( "\n" );
  p.printf( "%*screate: ", i, "" ); this->create.print_y( p ); p.printf( "\n" );
  if ( ! this->expires.is_null() ) {
    p.printf( "%*sexpires: ", i, "" ); this->expires.print_y( p );
    p.printf( "\n" );
  }
  if ( ! this->revoke.is_null() ) {
    p.printf( "%*srevoke: ", i, "" ); this->revoke.print_y( p );
    p.printf( "\n" );
  }
  if ( ! this->pri.is_null() ) {
    p.printf( "%*spri: ", i, "" ); this->pri.print_y( p );
    p.printf( "\n" );
  }
  p.printf( "%*spub: ", i, "" ); this->pub.print_y( p );
  p.printf( "\n" );
}

void
ConfigTree::StringPair::print_js( ConfigPrinter &p ) const noexcept
{
  this->name.print_js( p ); p.printf( " : " ); this->value.print_js( p );
}

const ConfigTree::StringPair *
ConfigTree::StringPair::print_ylist( ConfigPrinter &p,  int i ) const noexcept
{
  const StringPair * end = this;
  for ( ; ; end = end->next ) {
    if ( end->next == NULL ||
         ! end->next->name.equals( this->name ) )
      break;
  }
  if ( this == end ) {
    p.printf( "%*s", i, "" );
    this->print_y( p );
    p.printf( "\n" );
  }
  else {
    p.printf( "%*s", i, "" );
    this->name.print_y( p );
    p.printf( ":\n" );
    for ( const StringPair *sp = this; ; sp = sp->next ) {
      p.printf( "%*s- ", i+2, "" );
      sp->value.print_y( p );
      p.printf( "\n" );
      if ( sp == end )
        break;
    }
  }
  return end->next;
}

void
ConfigTree::StringPair::print_y( ConfigPrinter &p ) const noexcept
{
  this->name.print_y( p ); p.printf( ": " ); this->value.print_y( p );
}

void
ConfigTree::StringList::print_js( ConfigPrinter &p ) const noexcept
{
  return this->val.print_js( p );
}

void
ConfigTree::StringList::print_y( ConfigPrinter &p ) const noexcept
{
  return this->val.print_y( p );
}

void
ConfigTree::Service::print_js( ConfigPrinter &p,  int i ) const noexcept
{
  p.printf( "%*s\"svc\" : ", i, "" ); this->svc.print_js( p ); p.printf( ",\n" );
  p.printf( "%*s\"create\" : ", i, "" ); this->create.print_js( p ); p.printf( ",\n" );
  if ( ! this->pri.is_null() ) {
    p.printf( "%*s\"pri\" : ", i, "" ); this->pri.print_js( p ); p.printf( ",\n" );
  }
  p.printf( "%*s\"pub\" : ", i, "" ); this->pub.print_js( p ); p.printf( ",\n" );
  StringPair *sp = this->users.hd;
  if ( sp != NULL ) {
    p.printf( "%*s\"users\" : {\n%*s  ", i, "", i, "" );
    sp->print_js( p );
    for ( sp = sp->next; sp != NULL; sp = sp->next ) {
      p.printf( ",\n%*s  ", i, "" );
      sp->print_js( p );
    }
    p.printf( "\n%*s}\n", i, "" );
  }
  sp = this->revoke.hd;
  if ( sp != NULL ) {
    p.printf( "%*s\"revoke\" : {\n%*s  ", i, "", i, "" );
    sp->print_js( p );
    for ( sp = sp->next; sp != NULL; sp = sp->next ) {
      p.printf( ",\n%*s  ", i, "" );
      sp->print_js( p );
    }
    p.printf( "\n%*s}\n", i, "" );
  }
}

void
ConfigTree::Service::print_y( ConfigPrinter &p,  int i ) const noexcept
{
  if ( i > 0 )
    p.printf( "%*s- svc: ", i - 2, "" );
  else
    p.printf( "svc: " );
  this->svc.print_y( p ); p.printf( "\n" );
  p.printf( "%*screate: ", i, "" ); this->create.print_y( p ); p.printf( "\n" );
  if ( ! this->pri.is_null() ) {
    p.printf( "%*spri: ", i, "" ); this->pri.print_y( p ); p.printf( "\n" );
  }
  p.printf( "%*spub: ", i, "" ); this->pub.print_y( p ); p.printf( "\n" );
  StringPair *sp = this->users.hd;
  if ( sp != NULL ) {
    p.printf( "%*susers:\n", i, "" );
    for ( ; sp != NULL; sp = sp->next ) {
      p.printf( "%*s  ", i, "" );
      sp->print_y( p );
      p.printf( "\n" );
    }
  }
  sp = this->revoke.hd;
  if ( sp != NULL ) {
    p.printf( "%*srevoke:\n", i, "" );
    for ( ; sp != NULL; sp = sp->next ) {
      p.printf( "%*s  ", i, "" );
      sp->print_y( p );
      p.printf( "\n" );
    }
  }
}

void
ConfigTree::Transport::print_js( ConfigPrinter &p,  int i ) const noexcept
{
  p.printf( "%*s\"tport\" : ", i, "" ); this->tport.print_js( p ); p.printf( ",\n" );
  p.printf( "%*s\"type\" : ", i, "" ); this->type.print_js( p );
  StringPair *sp = this->route.hd;
  p.printf( "%s\n", sp == NULL ? "" : "," );
  if ( sp != NULL ) {
    p.printf( "%*s\"route\" : {\n%*s  ", i, "", i, "" );
    sp->print_js( p );
    for ( sp = sp->next; sp != NULL; sp = sp->next ) {
      p.printf( ",\n%*s  ", i, "" );
      sp->print_js( p );
    }
    p.printf( "\n%*s}\n", i, "" );
  }
}

void
ConfigTree::Transport::print_y( ConfigPrinter &p,  int i ) const noexcept
{
  if ( i > 0 )
    p.printf( "%*s- tport: ", i - 2, "" );
  else
    p.printf( "tport: " );
  this->tport.print_y( p ); p.printf( "\n" );
  p.printf( "%*stype: ", i, "" ); this->type.print_y( p ); p.printf( "\n" );
  StringPair *sp = this->route.hd;
  if ( sp != NULL ) {
    p.printf( "%*sroute:\n", i, "" );
    for ( ; sp != NULL; sp = sp->next ) {
      p.printf( "%*s  ", i, "" );
      sp->print_y( p );
      p.printf( "\n" );
    }
  }
}

void
ConfigTree::Group::print_js( ConfigPrinter &p,  int i ) const noexcept
{
  p.printf( "%*s\"group\" : ", i, "" ); this->group.print_js( p ); p.printf( ",\n" );
  StringList *sl = this->users.hd;
  if ( sl != NULL ) {
    p.printf( "%*s\"users\" : [ ", i, "" );
    sl->print_js( p );
    for ( sl = sl->next; sl != NULL; sl = sl->next ) {
      p.printf( ", " );
      sl->print_js( p );
    }
    p.printf( " ]\n" );
  }
}

void
ConfigTree::Group::print_y( ConfigPrinter &p,  int i ) const noexcept
{
  if ( i > 0 )
    p.printf( "%*s- group: ", i - 2, "" );
  else
    p.printf( "group: " );
  this->group.print_y( p ); p.printf( "\n" );
  StringList *sl = this->users.hd;
  if ( sl != NULL ) {
    p.printf( "%*susers:\n", i, "" );
    for ( ; sl != NULL; sl = sl->next ) {
      p.printf( "%*s  ", i, "" );
      sl->print_y( p );
      p.printf( "\n" );
    }
  }
}

void
ConfigTree::Parameters::print_js( ConfigPrinter &p,  int i,
                                  char c ) const noexcept
{
  p.printf( "%*s\"parameters\" : {\n%*s  ", i, "", i, "" );
  StringPair *sp = this->parms.hd;
  if ( sp != NULL ) {
    sp->print_js( p );
    for ( sp = sp->next; sp != NULL; sp = sp->next ) {
      p.printf( ",\n%*s  ", i, "" );
      sp->print_js( p );
    }
  }
  p.printf( "\n%*s}", i, "" );
  if ( c != 0 ) p.printf( "%c", c );
  p.printf( "\n" );
}

void
ConfigTree::Parameters::print_y( ConfigPrinter &p,  int i ) const noexcept
{
  /*p.printf( "%*sparameters:\n", i, "" );*/
  StringPair *sp = this->parms.hd;
  if ( sp != NULL ) {
    for ( ; sp != NULL; sp = sp->next ) {
      p.printf( "%*s", i, "" );
      sp->print_y( p );
      p.printf( "\n" );
    }
  }
}

int
ConfigTree::Transport::get_host_port( const char *&hostp,  char *host,
                                      size_t &len ) noexcept
{
  int port = 0;
  if ( hostp == NULL ) {
    len = 0;
    return 0;
  }
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
  return port;
}

bool
ConfigTree::Transport::is_wildcard( const char *host ) noexcept
{
  return host == NULL || host[ 0 ] == '\0' ||
         ( host[ 0 ] == '*' && host[ 1 ] == '\0' ) ||
         ( host[ 0 ] == '0' && host[ 1 ] == '\0' );
}

bool
ConfigTree::find_parameter( const char *name,  const char *&value,
                            const char *def_value ) noexcept
{
  for ( Parameters *p = this->parameters.hd; p != NULL; p = p->next ) {
    for ( StringPair *sp = p->parms.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( name ) ) {
        value = sp->value.val;
        return true;
      }
    }
  }
  value = def_value;
  return false;
}

