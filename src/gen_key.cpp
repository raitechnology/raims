#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <raims/parse_config.h>
#include <raims/gen_config.h>

using namespace rai;
using namespace ms;
using namespace md;
using namespace kv;

static const char *
get_arg( int argc, char *argv[], int b, const char *f,
         const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ )
    if ( ::strcmp( f, argv[ i ] ) == 0 ) /* -p port */
      return argv[ i + b ];
  return def; /* default value */
}

static void
print_users( ServiceBuf &svc ) noexcept
{
  UserElem * el;
  size_t     len = 0;
  for ( el = svc.users.hd; el != NULL; el = el->next )
    len = max_int<size_t>( el->user.user_len, len );
  if ( len > 0 ) {
    if ( len < 5 )
      len = 5;
    printf( "Users %*s Expires\n", (int) ( len - 5 ), "" );
    for ( el = svc.users.hd; el != NULL; el = el->next ) {
      printf( "%.*s %*s ", (int) el->user.user_len, el->user.user,
              (int) ( len - el->user.user_len ), "" );
      uint64_t ns;
      char     buf[ 64 ];
      ns = el->user.get_revoke();
      if ( ns != 0 ) {
        printf( "%s (revoke)\n", timestamp( ns, 0, buf, sizeof( buf ) ) );
      }
      else {
        ns = el->user.get_expires();
        if ( ns != 0 )
          printf( "%s\n", timestamp( ns, 0, buf, sizeof( buf ) ) );
        else
          printf( "none\n" );
      }
    }
  }
}

int
main( int argc, char *argv[] )
{
  const char * dir_name = get_arg( argc, argv, 1, "-d", "config" ),
             * out_file = get_arg( argc, argv, 1, "-o", NULL ),
             * new_user = get_arg( argc, argv, 1, "-u", NULL ),
             * rev_user = get_arg( argc, argv, 1, "-k", NULL ),
             * exp_user = get_arg( argc, argv, 1, "-x", NULL ),
             * del_user = get_arg( argc, argv, 1, "-r", NULL ),
             * svc_name = get_arg( argc, argv, 1, "-s", NULL ),
             * expires  = get_arg( argc, argv, 1, "-e", NULL ),
             * examples = get_arg( argc, argv, 0, "-t", NULL ),
             * auto_yes = get_arg( argc, argv, 0, "-y", NULL ),
             * force    = get_arg( argc, argv, 0, "-f", NULL ),
             * help     = get_arg( argc, argv, 0, "-h", NULL );
  if ( help != NULL ) {
    printf(
    "%s [-d dir] [-o file ] [-u|-r|-x user1 [user2 ...]] [-s svc] [-e expires] "
       "[-t] [-y] [-f] [-p]\n"
            "   -d dir     : config dir name (default: config)\n"
            "   -o file    : output config in dir to a single file\n"
            "   -u user    : add user name(s)\n"
            "   -k user    : revoke user name(s)\n"
            "   -x user    : export user name(s)\n"
            "   -r user    : delete user name(s)\n"
            "   -s svc     : service name(s)\n"
            "   -e expires : when user expires\n"
            "   -t         : add example transports\n"
            "   -y         : don't ask for confirmation\n"
            "   -f         : force overwrite of existing config\n"
            "Without options, print the current users and services\n"
            "With a user or a new service, generate key pair(s) for user(s) "
            "and a service, encrypted with passwd\n",
            argv[ 0 ] );
    return 0;
  }

  ConfigTree * tree = NULL;
  MDMsgMem     mem;
  StringTab    st( mem );
  const char * pass_file        = NULL,
             * salt_file        = NULL;
  GenCfg       cfg;
  bool         populate_dir     = false,
               has_user         = ( new_user != NULL ||
                                    del_user != NULL ||
                                    exp_user != NULL ||
                                    rev_user != NULL ),
               has_new_users    = ( new_user != NULL ),
               has_delete_users = ( del_user != NULL ),
               has_revoke_users = ( rev_user != NULL ),
               want_transports  = ( examples != NULL ),
               has_export_users = ( exp_user != NULL );
  size_t       i;
  bool         ok = true;

  if ( svc_name != NULL ) {
    switch ( cfg.check_dir( dir_name, true/*has_new_users*/,
                            "the configure directory" ) ) {
      case -1: return 1;
      case 0:
        if ( force != NULL )
          populate_dir = true;
        break;
      case 1:
        populate_dir = true;
        break;
    }
  }
  CryptPass pass, pass2;
  if ( populate_dir ) {
    if ( ! cfg.init_pass_salt( dir_name, pass, NULL, NULL, true ) )
      return 1;
    if ( ! cfg.populate_directory( dir_name, want_transports, true ) )
      return 1;
  }
  else {
    ConfigErrPrinter err;
    tree = ConfigDB::parse_dir( dir_name, st, err );
    if ( tree == NULL )
      return 1;

    tree->parameters.find( "pass", pass_file );
    tree->parameters.find( "salt", salt_file );
    if ( ! cfg.init_pass_salt( dir_name, pass, pass_file, salt_file, false ) ) {
      fprintf( stderr, "Config exists in \"%s\", but pass/salt do not exist or "
                       "are unreadable, use -f to force\n", dir_name );
      return 1;
    }
    ConfigTree::Service *s;
    if ( svc_name != NULL ) {
      if ( (s = tree->find_service( svc_name,
                                    ::strlen( svc_name ) )) != NULL ) {
        printf( "- Loading service \"%.*s\"\n", (int) s->svc.len, s->svc.val );
        cfg.load_svc( *tree, *s );
        if ( ! cfg.svc.check_signatures( pass ) )
          return 1;
        printf( "- Signatures ok\n" );
        if ( ! has_user ) {
          print_users( cfg.svc );
          goto done;
        }
      }
      /*else if ( ! has_new_users ) {
        fprintf( stderr, "Service \"%s\" not found\n", svc_name );
        return 1;
      }*/
    }
    else {
      i = 0;
      for ( s = tree->services.hd; s != NULL; s = s->next ) {
        printf( "- Loading Service \"%.*s\"\n", (int) s->svc.len, s->svc.val );
        cfg.svc.load_service( *tree, *s );
        if ( cfg.svc.check_signatures( pass ) ) {
          printf( "- Signatures ok\n" );
          print_users( cfg.svc );
        }
      }
      goto done;
    }
  }
  /* if no keys, generate */
  if ( cfg.svc.pub_len == 0 )
    ok = cfg.svc.gen_key( svc_name, ::strlen( svc_name ), pass );
  /* add new users */
  if ( ok && has_new_users ) {
    size_t expires_len = ( expires != NULL ? ::strlen( expires ) : 0 );
    for ( i = 2; ; i++ ) {
      size_t user_len = ::strlen( new_user );
      cfg.add_user( new_user, user_len, expires, expires_len, pass );
      new_user = get_arg( argc, argv, (int) i, "-u", NULL );
      if ( new_user == NULL || new_user[ 0 ] == '-' )
        break;
    }
  }
  /* delete users */
  if ( ok && has_delete_users ) {
    for ( i = 2; ; i++ ) {
      ok = cfg.remove_user( dir_name, del_user, ::strlen( del_user ) );
      if ( ! ok )
        break;
      del_user = get_arg( argc, argv, (int) i, "-r", NULL );
      if ( del_user == NULL || del_user[ 0 ] == '-' )
        break;
    }
  }
  /* revoke users */
  if ( ok && has_revoke_users ) {
    for ( i = 2; ; i++ ) {
      ok = cfg.revoke_user( rev_user, ::strlen( rev_user ) );
      if ( ! ok )
        break;
      rev_user = get_arg( argc, argv, (int) i, "-k", NULL );
      if ( rev_user == NULL || rev_user[ 0 ] == '-' )
        break;
    }
  }
  /* generate new configs */
  if ( ok ) {
    if ( has_new_users || has_delete_users || has_revoke_users ) {
      ok = cfg.svc.sign_users( NULL, pass ) &&
           cfg.populate_service( dir_name, true );
      if ( ok && ( has_new_users || has_revoke_users ) )
        ok = cfg.populate_user_set( dir_name );
    }
    else {
      ok = cfg.populate_service( dir_name, true );
    }
  }

  if ( ok && has_export_users ) {
    for ( i = 2; ; i++ ) {
      ok = cfg.export_user_svc( dir_name, pass, exp_user, ::strlen( exp_user ),
                                want_transports );
      if ( ! ok )
        break;
      exp_user = get_arg( argc, argv, (int) i, "-x", NULL );
      if ( exp_user == NULL || exp_user[ 0 ] == '-' )
        break;
    }
  }
  if ( ok )
    cfg.ask_commit( auto_yes != NULL );
  else {
    cfg.abort();
    return 1;
  }
done:;
  if ( out_file != NULL ) {
    ConfigErrPrinter err;
    tree = ConfigDB::parse_dir( dir_name, st, err );
    if ( tree == NULL )
      return 1;
    const char * salt_file = NULL,
               * pass_file = NULL;
    char salt_path[ 1024 ], pass_path[ 1024 ];
    char * salt_data = NULL, * pass_data = NULL;
    size_t salt_size = 0, pass_size = 0;

    tree->parameters.find( "salt", salt_file, ".salt" );
    tree->parameters.find( "pass", pass_file, ".pass" );
    ::snprintf( salt_path, sizeof( salt_path ), "%s/%s", dir_name, salt_file );
    ::snprintf( pass_path, sizeof( pass_path ), "%s/%s", dir_name, pass_file );
    if ( load_secure_string( salt_path, salt_data, salt_size ) ) {
      tree->parameters.set( st, "salt_data", salt_data );
      tree->parameters.remove( st, "salt" );
    }
    if ( load_secure_string( pass_path, pass_data, pass_size ) ) {
      tree->parameters.set( st, "pass_data", pass_data );
      tree->parameters.remove( st, "pass" );
    }
    printf( "- Output config to \"%s\"\n", out_file );
    ConfigFilePrinter p;
    if ( p.open( out_file ) != 0 )
      return 1;
    tree->print_y( p, PRINT_NORMAL );
    p.close();
  }
  return 0;
}

