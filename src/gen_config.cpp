#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <raikv/util.h>
#include <raikv/key_hash.h>
#include <raims/gen_config.h>

using namespace rai;
using namespace ms;
using namespace md;
using namespace kv;

bool
rai::ms::make_path( char *path,  size_t path_len,
                    const char *fmt, ... ) noexcept
{
  va_list args;
  va_start( args, fmt );
  int n = ::vsnprintf( path, path_len, fmt, args );
  va_end( args );
  if ( n >= 0 && (size_t) n < path_len )
    return true;
  fprintf( stderr, "Path has too many characters\n" );
  return false;
}

static const void *
map_file( const char *fn,  size_t &sz ) noexcept
{
  int    fd  = ::open( fn, O_RDONLY );
  void * map = MAP_FAILED;
  struct stat st;

  sz = 0;
  if ( fd < 0 ) {
    ::perror( fn );
    return NULL;
  }
  if ( ::fstat( fd, &st ) == 0 ) {
    if ( st.st_size > 0 )
      map = ::mmap( 0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0 );
    else
      map = NULL;
  }
  else {
    ::perror( fn );
  }
  if ( map == MAP_FAILED ) {
    ::perror( fn );
    ::close( fd );
    return NULL;
  }
  ::close( fd );
  sz = st.st_size;
  return map;
}


static void
unmap_file( const void *m,  size_t len ) noexcept
{
  if ( m != NULL && m != MAP_FAILED && len > 0 )
    ::munmap( (void *) m, len );
}

static int
cat_file( const void *text,  size_t len,  const char *path,
          bool add_nl = false,  int mode = 0666 ) noexcept
{
  int  fd = ::open( path, O_WRONLY | O_CREAT | O_EXCL, mode ),
       n  = 0;
  bool b  = false;

  if ( fd >= 0 ) {
    b = ( (size_t) ::write( fd, text, len ) == len );
    if ( b && add_nl )
      b &= ( ::write( fd, "\n", 1 ) == 1 );
    ::close( fd );
  }
  if ( ! b ) {
    ::perror( path );
    n = -1;
  }
  return n;
}

GenFileTrans *
GenFileTrans::create_file_path( GenFileOp op,  const char *path,
                                size_t n ) noexcept
{
  size_t len = ( n == 0 ? ::strlen( path ) : n );
  void * p = ::malloc( sizeof( GenFileTrans ) + len + 1 );
  GenFileTrans * t = new ( p ) GenFileTrans( op, path, len );
  return t;
}

GenFileTrans *
GenFileTrans::create_file_fmt( GenFileOp op,  const char *fmt, ... ) noexcept
{
  char path[ GEN_PATH_MAX ];
  va_list args;

  va_start( args, fmt );
  int n = ::vsnprintf( path, sizeof( path ), fmt, args );
  va_end( args );
  if ( n >= 0 && (size_t) n < sizeof( path ) )
    return GenFileTrans::create_file_path( op, path, n );
  fprintf( stderr, "Path has too many characters\n" );
  return NULL;
}

GenFileTrans::GenFileTrans( GenFileOp o,  const char *p,  size_t n ) noexcept
            : next( 0 ), back( 0 )
{
  this->op    = o;
  this->phase = 0;
  this->descr = NULL;
  this->len   = n;
  ::memcpy( this->path, p, n );
  this->path[ n ] = '\0';
}

const char *
GenFileTrans::op_str( void ) const noexcept
{
  switch ( this->op ) {
    case GEN_CREATE_FILE:    return "create file";
    case GEN_REMOVE_FILE:    return "remove file";
    case GEN_OVERWRITE_FILE: return "update file";
    case GEN_MK_DIR:         return "create dir ";
    case GEN_RM_DIR:         return "remove dir ";
    default:                 return "bad op";
  }
}

int
GenFileTrans::check_if_changed( void ) noexcept
{
  char path_tmp[ GEN_PATH_MAX ];
  if ( ::access( this->orig_path( path_tmp ), F_OK ) == 0 ) {
    size_t       from_size, to_size;
    const void * p1 = map_file( this->path, from_size ),
               * p2 = map_file( path_tmp, to_size );
    int          n  = cmp_bytes( p1, from_size, p2, to_size );
    unmap_file( p1, from_size );
    unmap_file( p2, to_size );
    if ( p1 == NULL || p2 == NULL )
      return -1;
    if ( n == 0 )
      return 0;
    this->op = GEN_OVERWRITE_FILE;
    return 1;
  }
  return 1;
}

int
GenFileTrans::remove_if_equal( void ) noexcept
{
  int n = this->check_if_changed();
  if ( n == 0 )
    return ::unlink( this->path );
  return n;
}

char *
GenFileTrans::orig_path( char *p ) noexcept
{
  if ( this->len > 4 &&
       ::memcmp( &this->path[ this->len - 4 ], ".new", 4 ) == 0 ) {
    ::memcpy( p, this->path, this->len - 4 );
    p[ len - 4 ] = '\0';
    return p;
  }
  else {
    ::memcpy( p, this->path, this->len );
    p[ this->len ] = '\0';
  }
  return this->path;
}

char *
GenFileTrans::tmp_path( char *p ) noexcept
{
  char tmp[ GEN_PATH_MAX ];
  if ( this->len > 4 &&
       ::memcmp( &this->path[ this->len - 4 ], ".new", 4 ) == 0 ) {
    ::memcpy( tmp, this->path, this->len - 4 );
    tmp[ len - 4 ] = '\0';
  }
  else {
    ::strcpy( tmp, this->path );
  }
  make_path( p, GEN_TEMP_MAX, "%s.old", tmp );
  return p;
}

int
GenFileTrans::commit_phase1( void ) noexcept
{
  if ( this->op == GEN_CREATE_FILE ) {
    char path_tmp[ GEN_PATH_MAX ];
    /* mv config.js.new config.js */
    if ( this->orig_path( path_tmp ) != this->path ) {
      if ( ::rename( this->path, path_tmp ) != 0 ) {
        ::perror( this->path );
        return -1;
      }
      this->phase = 1;
    }
  }
  /* mv config.js config.js.old
   * mv config.js.new config.js */
  else if ( this->op == GEN_OVERWRITE_FILE ) {
    char path_tmp1[ GEN_PATH_MAX ],
         path_tmp2[ GEN_TEMP_MAX ];
    if ( this->orig_path( path_tmp1 ) != this->path ) {
      if ( ::rename( path_tmp1, this->tmp_path( path_tmp2 ) ) != 0 ) {
        ::perror( path_tmp1 );
        return -1;
      }
      this->phase = 1;
      if ( ::rename( this->path, path_tmp1 ) != 0 ) {
        ::perror( this->path );
        return -1;
      }
    }
  }
  /* mv config.js config.js.old */
  else if ( this->op == GEN_REMOVE_FILE ) {
    char path_tmp2[ GEN_TEMP_MAX ];
    if ( ::rename( this->path, this->tmp_path( path_tmp2 ) ) != 0 ) {
      ::perror( path_tmp2 );
      return -1;
    }
  }
  return 0;
}

int
GenFileTrans::commit_phase2( void ) noexcept
{
  int status = 0;
  /* rm config.js.old */
  if ( this->op == GEN_OVERWRITE_FILE || this->op == GEN_REMOVE_FILE ) {
    char path_tmp2[ GEN_TEMP_MAX ];
    if ( ::unlink( this->tmp_path( path_tmp2 ) ) != 0 ) {
      status = -1;
      ::perror( path_tmp2 );
    }
  }
  return status;
}

void
GenFileTrans::abort( void ) noexcept
{
  if ( this->op == GEN_CREATE_FILE ) {
    char path_tmp[ GEN_PATH_MAX ];
    /* rm config.js.new */
    if ( this->phase == 0 ) {
      if ( ::unlink( this->path ) != 0 )
        ::perror( this->path );
    }
    else { /* rm config.js */
      if ( ::unlink( this->orig_path( path_tmp ) ) != 0 )
        ::perror( path_tmp );
    }
  }
  else if ( this->op == GEN_OVERWRITE_FILE ) {
    char path_tmp1[ GEN_PATH_MAX ],
         path_tmp2[ GEN_TEMP_MAX ];
    /* rm config.js.new */
    if ( this->phase == 0 ) {
      if ( this->orig_path( path_tmp1 ) != this->path ) {
        if ( ::unlink( this->path ) != 0 )
          ::perror( this->path );
      }
    }
    /* mv config.js.old config.js
     * rm config.js.new */
    else {
      if ( this->orig_path( path_tmp1 ) != this->path ) {
        this->tmp_path( path_tmp2 );
        if ( ::unlink( this->path ) != 0 )
          ::perror( this->path );
        if ( ::rename( path_tmp2, this->path ) != 0 )
          ::perror( path_tmp2 );
        if ( ::unlink( path_tmp1 ) != 0 )
          ::perror( path_tmp1 );
      }
    }
  }
  /* rmdir config */
  else if ( this->op == GEN_MK_DIR ) {
    if ( ::rmdir( this->path ) != 0 )
      ::perror( this->path );
  }
}

bool
GenUserSet::is_member( const char *user,  size_t user_len ) noexcept
{
  uint32_t h = kv_crc_c( user, user_len, 0 ) & ( USER_SET_SIZE - 1 );
  return this->BitSpace::is_member( h );
}

void
GenUserSet::add_member( const char *user,  size_t user_len ) noexcept
{
  uint32_t h = kv_crc_c( user, user_len, 0 ) & ( USER_SET_SIZE - 1 );
  return this->add( h );
}

int
GenCfg::check_dir( const char *dir_name,  bool create,
                   const char *descr ) noexcept
{
  if ( ::access( dir_name, W_OK ) != 0 ) {
    if ( ! create ) {
      fprintf( stderr, "Directory \"%s\" does not exist\n", dir_name );
      return -1;
    }
    if ( ::mkdir( dir_name, 0700 ) != 0 ) {
      perror( dir_name );
      fprintf( stderr, "Unable to create directory\n" );
      return -1;
    }
    GenFileTrans *t = GenFileTrans::create_file_path( GEN_MK_DIR, dir_name,
                                                      ::strlen( dir_name ) );
    t->descr = descr;
    this->list.push_tl( t );
    return 1;
  }
  return 0;
}

bool
GenCfg::init_pass( const char *dir_name,  CryptPass &pass,
                   const char *pass_file,  bool create_it ) noexcept
{
  char   path[ GEN_PATH_MAX ];
  void * mem;
  size_t mem_sz;
  bool   pass_exists = false;

  if ( pass_file == NULL )
    pass_file = ".pass";
  if ( ! make_path( path, sizeof( path ), "%s/%s", dir_name, pass_file ) )
    return false;
  if ( ::access( path, R_OK ) == 0 ) {
    if ( ! load_secure_file( path, mem, mem_sz ) ) {
      fprintf( stderr, "Unable to load passwd: \"%s\"\n", path );
      return false;
    }
    pass.pass     = (char *) mem;
    pass.pass_len = mem_sz;
    pass_exists = true;
  }

  if ( ! create_it && ! pass_exists )
    return false;

  if ( ! pass_exists ) {
    GenFileTrans *t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE,
                                                     "%s/%s.new",
                                                     dir_name, pass_file );
    if ( t == NULL )
      return false;
    if ( ! pass.gen_pass() )
      return false;
    if ( cat_file( pass.pass, pass.pass_len, t->path, true, 0400 ) < 0 )
      return false;
    this->list.push_tl( t );
    t->descr = "generated a new password";
    if ( t->check_if_changed() < 0 )
      return false;
  }
  return true;
}

bool
GenCfg::init_pass_salt( const char *dir_name,  CryptPass &pass,
                        const char *pass_file,  const char *salt_file,
                        bool create_it ) noexcept
{
  char   path[ GEN_PATH_MAX ];
  void * mem;
  size_t mem_sz;
  bool   salt_exists = false;

  if ( salt_file == NULL )
    salt_file = ".salt";
  if ( ! make_path( path, sizeof( path ), "%s/%s", dir_name, salt_file ) )
    return false;
  if ( ::access( path, R_OK ) == 0 ) {
    if ( ! load_secure_file( path, mem, mem_sz ) ) {
      fprintf( stderr, "Unable to load passwd: \"%s\"\n", path );
      return false;
    }
    init_kdf( mem, mem_sz );
    if ( mem != NULL )
      free_secure_mem( mem, mem_sz );
    salt_exists = true;
  }
  this->salt_path = ::strdup( path );

  if ( ! create_it && ! salt_exists )
    return false;

  if ( ! salt_exists ) {
    GenFileTrans *t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE, "%s.new",
                                                     this->salt_path );
    if ( t == NULL )
      return false;
    size_t salt_len;
    void *salt = pass.gen_salt( salt_len );
    if ( salt == NULL )
      return false;
    if ( cat_file( salt, salt_len, t->path, true, 0400 ) < 0 )
      return false;
    this->list.push_tl( t );
    t->descr = "generate new salt";
    init_kdf( salt, salt_len );
    free_secure_mem( salt, salt_len );
    if ( t->check_if_changed() < 0 )
      return false;
  }
  return this->init_pass( dir_name, pass, pass_file, create_it );
}

bool
GenCfg::copy_salt( const char *dir_name ) noexcept
{
  size_t       salt_len;
  const void * salt = map_file( this->salt_path, salt_len );

  if ( salt == NULL ) {
    ::perror( this->salt_path );
    return false;
  }
  bool b = true;
  GenFileTrans *t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE,
                                                   "%s/.salt.new", dir_name );
  if ( t == NULL || cat_file( salt, salt_len, t->path, false, 0400 ) < 0 )
    b = false;
  unmap_file( salt, salt_len );

  if ( b ) {
    int n;
    if ( (n = t->remove_if_equal()) < 0 )
      b = false;
    else if ( n != 0 ) {
      t->descr = "a copy of salt";
      this->list.push_tl( t );
      t = NULL;
    }
  }
  if ( t != NULL )
    delete t;
  return b;
}

bool
GenCfg::copy_param( const char *orig_dir,  const char *dir_name ) noexcept
{
  char   path[ GEN_PATH_MAX ];
  size_t pfile_len;

  if ( ! make_path( path, sizeof( path ), "%s/%s", orig_dir, "param.yaml" ) )
    return false;
  const void * pfile = map_file( path, pfile_len );
  if ( pfile == NULL ) {
    ::perror( path );
    return false;
  }

  bool b = true;
  GenFileTrans *t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE,
                                                "%s/param.yaml.new", dir_name );
  if ( t == NULL || cat_file( pfile, pfile_len, t->path, true, 0666 ) < 0 )
    b = false;

  unmap_file( pfile, pfile_len );

  if ( b ) {
    int n;
    if ( (n = t->remove_if_equal()) < 0 )
      b = false;
    else if ( n != 0 ) {
      t->descr = "a copy of param";
      this->list.push_tl( t );
      t = NULL;
    }
  }
  if ( t != NULL )
    delete t;
  return b;
}

void
GenCfg::add_user( const char *user,  size_t user_len,
                  const char *expire,  size_t expire_len,
                  CryptPass &pass ) noexcept
{
  UserBuf u;
  this->user_set.add_member( user, user_len );
  u.gen_key( user, user_len, this->svc.service, this->svc.service_len,
             expire, expire_len, pass );
  this->svc.add_user( u );
}

bool
GenFileTrans::cat_trans( GenFileTrans *t,  const void *text,  size_t len,
                         const char *descr,  GenFileList &list ) noexcept
{
  int n;
  if ( t == NULL )
    return false;
  bool b = true;
  if ( cat_file( text, len, t->path ) < 0 )
    b = false;
  else if ( (n = t->remove_if_equal()) < 0 )
    b = false;
  else if ( n > 0 ) {
    list.push_tl( t );
    t->descr = descr;
    t = NULL;
  }
  if ( t != NULL )
    delete t;
  return b;
}

bool
GenCfg::populate_example_transports( const char *dir_name ) noexcept
{
  char hostname[ 256 ];
  if ( gethostname( hostname, sizeof( hostname ) ) != 0 )
    ::strcpy( hostname, "localhost" );

  const char *tports[ 3 ][ 6 ] = {
    { "localhost","tcp","127.0.0.1","127.0.0.1","17550", "\n" },
    { "tcp","tcp","*",hostname,"7550", "\n" },
    { "pgm","pgm",";225.5.5.5",";225.5.5.5","7555",
      "\n  mcast_loop: \"2\"\n" }
  };
#if 0
  const char tport_fmt[] = 
    "{\n"
    "  \"tport\" : \"%s\",\n"
    "  \"type\" : \"%s\",\n"
    "  \"route\" : {\n"
    "    \"listen\" : \"%s\",\n"
    "    \"connect\" : \"%s\",\n"
    "    \"port\" : \"%s\"%s"
    "  }\n"
    "}\n";
#endif
  const char tport_fmt[] = 
    "tport: \"%s\"\n"
    "type: \"%s\"\n"
    "route:\n"
    "  listen: \"%s\"\n"
    "  connect: \"%s\"\n"
    "  port: \"%s\"%s";
  for ( size_t i = 0; i < 3; i++ ) {
    char buf[ 2 * GEN_PATH_MAX ];
    int n = ::snprintf( buf, sizeof( buf ), tport_fmt, tports[ i ][ 0 ],
                tports[ i ][ 1 ], tports[ i ][ 2 ], tports[ i ][ 3 ],
                tports[ i ][ 4 ], tports[ i ][ 5 ] );
    GenFileTrans *t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE,
                                                   "%s/tport_%s.yaml.new",
                                                   dir_name, tports[ i ][ 0 ] );
    if ( ! GenFileTrans::cat_trans( t, buf, n, "an example transport",
                                    this->list ) )
      return false;
  }
  return true;
}

bool
GenCfg::populate_directory( const char *dir_name,
                            bool want_transports,
                            bool want_param ) noexcept
{
#if 0
  const char base[] =
    "{\n"
    "  \"parameters\" : {\n"
    "    \"pass\" : \".pass\",\n"
    "    \"salt\" : \".salt\"\n"
    "  },\n"
    "  \"include\" : \"*.js\"\n"
    "}\n";
#endif
  GenFileTrans *t;
  const char base[] =
    "include: \"*.yaml\"\n";
  t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE, "%s/config.yaml.new",
                                     dir_name );
  if ( ! GenFileTrans::cat_trans( t, base, sizeof( base ) - 1,
                                 "base include file", this->list ) )
    return false;
  if ( want_param ) {
    const char run[] =
      "parameters:\n"
      "  pass: .pass\n"
      "  salt: .salt\n";
    t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE, "%s/param.yaml.new",
                                       dir_name );
    if ( ! GenFileTrans::cat_trans( t, run, sizeof( run ) - 1,
                                    "parameters file",
                                    this->list ) )
      return false;
  }
  if ( want_transports )
    if ( ! this->populate_example_transports( dir_name ) )
      return 1;
  return true;
}

bool
GenFileTrans::trans_if_neq( GenFileTrans *t,  const char *descr,
                            GenFileList &list ) noexcept
{
  int n;
  if ( (n = t->remove_if_equal()) <= 0 ) {
    delete t;
    return n < 0;
  }
  list.push_tl( t );
  t->descr = descr;
  return true;
}

bool
GenCfg::populate_service2( const char *dir_name,  ServiceBuf &svc2,
                           bool include_pri ) noexcept
{
  GenFileTrans * t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE,
                                     "%s/svc_%.*s.yaml.new",
                                     dir_name, (int) svc2.service_len,
                                     svc2.service );
  if ( t == NULL )
    return false;
  if ( ! svc2.print_yaml( 0, t->path, include_pri ) ) {
    ::perror( t->path );
    return false;
  }
  return GenFileTrans::trans_if_neq( t, "defines the service and signs users",
                                     this->list );
}

bool
GenCfg::populate_service( const char *dir_name,  bool include_pri ) noexcept
{
  return this->populate_service2( dir_name, this->svc, include_pri );
}

bool
GenCfg::populate_user( const char *dir_name,  UserElem *&u,
                       bool include_pri ) noexcept
{
  UserElem  * v = u;
  GenFileTrans * t = GenFileTrans::create_file_fmt( GEN_CREATE_FILE,
                    "%s/user_%.*s_svc_%.*s.yaml.new", dir_name,
                    (int) v->user.user_len, v->user.user,
                    (int) this->svc.service_len, this->svc.service );
  if ( t == NULL )
    return false;

  size_t count = 1;
  for ( UserElem *eq = v->next; eq != NULL; eq = eq->next ) {
    if ( UserBuf::cmp_user( v->user, eq->user ) != 0 )
      break;
    u = eq;
    count++;
  }
  if ( ! v->print_yaml_count( t->path, include_pri, count ) ) {
    ::perror( t->path );
    return false;
  }
  return GenFileTrans::trans_if_neq( t, "defines the user", this->list );
}

bool
GenCfg::populate_user_set( const char *dir_name ) noexcept
{
  for ( UserElem *u = this->svc.users.hd; u != NULL; u = u->next ) {
    if ( this->user_set.is_member( u->user.user, u->user.user_len ) ) {
      if ( ! this->populate_user( dir_name, u, true ) )
        return false;
    }
  }
  return true;
}

bool
GenCfg::export_users( const char *dir_name,  ServiceBuf &svc2,
                      UserElem *for_u ) noexcept
{
  for ( UserElem *u = svc2.users.hd; u != NULL; u = u->next ) {
    bool include_pri = ( for_u == NULL ||
                         UserBuf::cmp_user( u->user, for_u->user ) == 0 );
    if ( ! this->populate_user( dir_name, u, include_pri ) )
      return false;
  }
  return true;
}

bool
GenCfg::export_user_svc( const char *orig_dir,  CryptPass &pass,
                         const char *user,  size_t user_len,
                         bool want_transports ) noexcept
{
  UserElem * v;
  CryptPass  pass2;
  ServiceBuf svc2;
  char       path[ GEN_PATH_MAX ];
  bool       populate_dir = false;

  for ( UserElem *u = this->svc.users.hd; u != NULL; u = v ) {
    v = u->next;
    if ( cmp_bytes( u->user.user, u->user.user_len, user, user_len ) == 0 ) {
      /* user needs a private key to authenticate ECDH exchanges */
      if ( u->user.pri_len == 0 ) {
        fprintf( stderr, "User \"%.*s\" is not configured with a private key\n",
                 (int) user_len, user );
        return false;
      }
      if ( ! make_path( path, sizeof( path ), "%s", user ) )
        return false;
      switch ( this->check_dir( path, true, "exported configure directory" ) ) {
        case -1: return 1;
        case 0:  break;
        case 1:  populate_dir = true; break;
      }
      pass2.clear_pass();
      if ( ! this->copy_salt( path ) )
        return false;
      if ( populate_dir ) {
        if ( ! this->init_pass( path, pass2, NULL, true ) )
          return false;
        bool want_param = ! this->copy_param( orig_dir, path );
        if ( ! this->populate_directory( path, want_transports, want_param ) )
          return false;
      }
      else {
        if ( ! this->init_pass( path, pass2, NULL, false ) )
          return false;
      }
      svc2.release();
      svc2.copy( this->svc );
      if ( ! svc2.change_pass( pass, pass2 ) ||
           ! this->populate_service2( path, svc2, false ) ||
           ! this->export_users( path, svc2, u ) )
        return false;
    }
    while ( v != NULL && UserBuf::cmp_user( u->user, v->user ) == 0 )
      v = v->next;
  }
  return true;
}

bool
GenCfg::revoke_user( const char *user,  size_t user_len ) noexcept
{
  this->user_set.add_member( user, user_len );
  if ( ! this->svc.revoke_user( user, user_len ) ) {
    fprintf( stderr, "User \"%.*s\" not found\n", (int) user_len, user );
    return false;
  }
  return true;
}

bool
GenCfg::remove_user( const char *dir_name,  const char *user,
                     size_t user_len ) noexcept
{
  if ( ! this->svc.remove_user( user, user_len ) ) {
    fprintf( stderr, "User \"%.*s\" not found\n", (int) user_len, user );
    return false;
  }
  GenFileTrans *t = GenFileTrans::create_file_fmt( GEN_REMOVE_FILE,
       "%s/user_%.*s_svc_%.*s.js", dir_name, (int) user_len, user,
       (int) this->svc.service_len, this->svc.service );
  if ( t == NULL )
    return false;
  t->descr = "remove the user";
  this->list.push_tl( t );
  return true;
}

void
GenFileList::print_files( void ) noexcept
{
  GenFileTrans *t;
  size_t len = 3;
  for ( t = this->hd; t != NULL; t = t->next ) {
    len = max<size_t>( len, t->len + 3 );
  }
  for ( t = this->hd; t != NULL; t = t->next ) {
    char path_tmp[ GEN_PATH_MAX ];
    const char *opath = t->orig_path( path_tmp );
    if ( t->descr == NULL )
      printf( "%s %s\n", t->op_str(), opath );
    else
      printf( "%s %s %*s%s\n", t->op_str(), opath,
              (int)( len - ::strlen( opath ) ), "-- ", t->descr );
  }
}

bool
GenFileList::commit_phase1( void ) noexcept
{
  for ( GenFileTrans *t = this->hd; t != NULL; t = t->next )
    if ( t->commit_phase1() != 0 )
      return false;
  return true;
}

bool
GenFileList::commit_phase2( void ) noexcept
{
  int status = 0;
  for ( GenFileTrans *t = this->hd; t != NULL; t = t->next )
    if ( t->commit_phase2() != 0 )
      status = -1;
  return ( status == 0 );
}

void
GenFileList::abort( void ) noexcept
{
  GenFileTrans *t;
  for ( t = this->hd; t != NULL; t = t->next ) {
    if ( t->op != GEN_MK_DIR )
      t->abort();
  }
  for ( t = this->hd; t != NULL; t = t->next ) {
    if ( t->op == GEN_MK_DIR )
      t->abort();
  }
}

void
GenCfg::ask_commit( bool auto_yes ) noexcept
{
  bool abort = false;
  this->list.print_files();
  if ( ! auto_yes ) {
    char yn[ 80 ];
    printf( "OK? " ); fflush( stdout );
    abort = ( fgets( yn, sizeof( yn ), stdin ) == NULL );
    if ( ! abort )
      abort = ! ( yn[ 0 ] == 'y' || yn[ 0 ] == 'Y' );
  }
  if ( ! abort ) {
    if ( this->list.commit_phase1() ) {
      this->list.commit_phase2();
      printf( "done\n" );
    }
    else {
      abort = true;
    }
  }
  else {
    abort = true;
  }
  if ( abort ) {
    fprintf( stderr, "aborting\n" );
    this->list.abort();
  }
}

