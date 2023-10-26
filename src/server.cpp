#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <errno.h>
#if defined( _MSC_VER ) || defined( __MINGW32__ )
#include <raikv/win.h>
#endif
#include <raikv/logger.h>
#include <raims/parse_config.h>
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>
#include <raims/ev_telnet.h>
#include <raids/ev_client.h>
#include <raims/console.h>
#include <linecook/ttycook.h>
#include <linecook/linecook.h>
#include <raikv/os_file.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;
using namespace ds;

struct MySessionMgr;
struct TermCallback : public EvCallback, public ConsoleOutput {
  MySessionMgr * mgr;
  EvTerminal   * term;
  Console      * console;
  TermCallback() : mgr( 0 ), term( 0 ), console( 0 ) {}
  virtual bool on_data( char *buf,  size_t &buflen ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
  virtual void on_prompt( const char *prompt ) noexcept;
  virtual void on_quit( void) noexcept;
  virtual void on_close( void ) noexcept;
};

struct MySessionMgr : public SessionMgr, public SubOnMsg {
  EvTerminal * term;
  MySessionMgr( EvPoll &p,  Logger &l,  ConfigTree &c,
                ConfigTree::User &u,  ConfigTree::Service &s,
                StringTab &st,  ConfigStartup &sup )
    : SessionMgr( p, l, c, u, s, st, sup ), term( 0 ) {}
};

bool
TermCallback::on_data( char *buf,  size_t &buflen ) noexcept
{
  if ( this->console != NULL )
    return this->console->on_input( this, buf, buflen );
  return true;
}

void
TermCallback::on_quit( void ) noexcept
{
  if ( this->mgr->is_running() )
    this->mgr->stop();
  this->mgr->poll.quit = 1; /* quit */
}

bool
TermCallback::on_output( const char *buf,  size_t buflen ) noexcept
{
  if ( this->term != NULL )
    this->term->output( buf, buflen );
  return true;
}

void
TermCallback::on_prompt( const char *prompt ) noexcept
{
  if ( this->term != NULL )
    lc_tty_set_prompt( this->term->term.tty, TTYP_PROMPT1, prompt );
}

void
TermCallback::on_close( void ) noexcept
{
}

static const char *
get_arg( int argc, const char *argv[], int b, const char *f,
         const char *g, const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ ) {
    if ( ( f != NULL && ::strcmp( f, argv[ i ] ) == 0 ) ||
         ( g != NULL && ::strcmp( g, argv[ i ] ) == 0 ) )
      return argv[ i + b ];
  }
  return def; /* default value */
}

int
main( int argc, const char *argv[] )
{
  const char * cfg         = NULL,
             * rv_file     = NULL,
             * user        = NULL,
             * tports      = NULL,
             * nets        = NULL,
             * log_file    = NULL,
             * log_rotate  = NULL,
             * log_max_rot = NULL,
             * no_perm     = NULL,
             * foreground  = NULL,
             * background  = NULL,
             * no_msg_loss = NULL,
             * listen      = NULL,
             * no_http     = NULL,
             * http        = NULL,
             * no_mcast    = NULL,
             * debug       = NULL,
             * ipc_name    = NULL,
             * map_file    = NULL,
             * db_num      = NULL,
             * use_console = NULL,
             * pid_file    = NULL,
             * hostid      = NULL,
             * reliability = NULL,
             * get_help    = NULL;
  bool         log_hdr     = true;
  static const char cfg_dir[] = "config";
  const char *program = ::strrchr( argv[ 0 ], '/' );
  program = ( program != NULL ? program + 1 : argv[ 0 ] );
  bool is_rvd = ::strcmp( program, "rvd" ) == 0;
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
  char path[ 1024 ];
  ssize_t n = ::readlink( "/proc/self/exe", path, sizeof( path ) );
  path[ sizeof( path ) - 1 ] = '\0';
  if ( n > 0 && (size_t) n < sizeof( path ) - 1 ) {
    char * slash = ::strrchr( path, '/' );
    if ( slash != NULL && &slash[ 9 ] <= &path[ 1024 ] ) {
      ::memcpy( slash+1, "rv.yaml", 8 );
      rv_file = path;
    }
  }
  if ( rv_file == NULL ) {
    fprintf( stderr, "exe path length bad: %ld\n", n );
    return 1;
  }
#endif
  if ( ! is_rvd ) {
    for ( int i = 1; i < argc; i++ ) {
      if ( argv[ i ][ 0 ] == '-' && ::strlen( argv[ i ] ) > 2 ) {
        is_rvd = true;
        break;
      }
    }
  }

  #define RVD_HELP \
  "\n" \
  "   -cfg               : config dir/file (default: exe_path/rv.yaml)\n" \
  "   -reliability       : seconds of reliability (default: 15)\n" \
  "   -user user.svc     : user name (default: hostname)\n" \
  "   -log               : log file\n" \
  "   -log-rotate        : rotate file size limit\n" \
  "   -log-max-rotations : max log file rotations\n" \
  "   -no-permanent      : exit when no clients\n" \
  "   -foreground        : run in foreground\n" \
  "   -listen            : rv listen port\n" \
  "   -no-http           : no http service\n" \
  "   -http              : port for http service (default: listen + 80)\n" \
  "   -no-multicast      : no multicast\n" \
  "   -no-msg-loss       : no msg loss errors\n" \
  "   -console           : run with console\n" \
  "   -pidfile           : write daemon pid to file\n" \
  "   -hostid            : host identity\n" \
  "   -debug             : debug flags\n"

  #define MS_SERVER_HELP \
  "[-d file/dir] -u user.svc -t tport.listen [...]\n" \
  "   -d dir         : config dir/file (default: config)\n" \
  "   -u user.svc    : user name (default: hostname)\n" \
  "   -t tport.list  : transport name + listen or connect\n" \
  "   -n svc.network : service name + network spec\n" \
  "   -l file        : log to file\n" \
  "   -f flags       : debug flags to set\n" \
  "   -i name        : connect with ipc name\n" \
  "   -m map         : attach to kv shm map\n" \
  "   -D dbnum       : default db num\n" \
  "   -x hostid      : host identity\n" \
  "   -c             : run with console\n" \
  "   -b             : fork and detach from terminal\n" \
  "   -e             : no message loss errors\n"

  get_help    = get_arg( argc, argv, 0, "-h", "-help", NULL );
  if ( get_help == NULL )
    get_help = get_arg( argc, argv, 0, "-v", "-version", NULL );
  if ( get_help != NULL ) {
    if ( is_rvd )
      printf( "%s " RVD_HELP "RaiMS version %s\n",
              argv[ 0 ], ms_get_version() );
    else
      printf( "%s " MS_SERVER_HELP "RaiMS version %s\n",
              argv[ 0 ], ms_get_version() );
    return 0;
  }

  cfg         = get_arg( argc, argv, 1, "-d", "-cfg", is_rvd ? rv_file : cfg_dir );
  reliability = get_arg( argc, argv, 1, NULL, "-reliability", NULL );
  user        = get_arg( argc, argv, 1, "-u", "-user", NULL );
  log_file    = get_arg( argc, argv, 1, "-l", "-log", NULL );
  if ( log_file == NULL )
    log_file  = get_arg( argc, argv, 1, NULL, "-logfile", NULL );
  log_rotate  = get_arg( argc, argv, 1, NULL, "-log-rotate", NULL );
  if ( log_rotate == NULL )
    log_rotate = get_arg( argc, argv, 1, NULL, "-log-max-size", NULL );
  log_max_rot = get_arg( argc, argv, 1, NULL, "-log-max-rotations", NULL );
  no_perm     = get_arg( argc, argv, 0, NULL, "-no-permanent", NULL );
  foreground  = get_arg( argc, argv, 0, NULL, "-foreground", NULL );
  listen      = get_arg( argc, argv, 1, NULL, "-listen", is_rvd ? "7500" : NULL );
  no_http     = get_arg( argc, argv, 0, NULL, "-no-http", NULL );
  http        = get_arg( argc, argv, 1, NULL, "-http", NULL );
  no_mcast    = get_arg( argc, argv, 0, NULL, "-no-multicast", NULL );
  if ( no_mcast == NULL )
    no_mcast  = get_arg( argc, argv, 0, NULL, "-no-mcast", NULL );
  use_console = get_arg( argc, argv, 0, "-c", "-console", NULL );
  pid_file    = get_arg( argc, argv, 1, NULL, "-pidfile", NULL );
  hostid      = get_arg( argc, argv, 1, "-x", "-hostid", NULL );
  debug       = get_arg( argc, argv, 1, "-f", "-debug", NULL );
  tports      = get_arg( argc, argv, 1, "-t", NULL, NULL );
  nets        = get_arg( argc, argv, 1, "-n", NULL, NULL );
  ipc_name    = get_arg( argc, argv, 1, "-i", NULL, NULL );
  map_file    = get_arg( argc, argv, 1, "-m", NULL, NULL );
  db_num      = get_arg( argc, argv, 1, "-D", NULL, NULL );
  background  = get_arg( argc, argv, 0, "-b", NULL, NULL );
  no_msg_loss = get_arg( argc, argv, 0, "-e", "-no-msg-loss", NULL );

  if ( use_console != NULL )
    background = NULL;
  if ( use_console != NULL )
    foreground = use_console;

#if defined( _MSC_VER ) || defined( __MINGW32__ )
  ws_global_init(); /* gethostname() needs WSAStartup() */
#endif
  int err_fd = os_dup( STDERR_FILENO );

  if ( log_file != NULL ) {
    if ( ::freopen( log_file, "a", stderr ) == NULL ) {
      const char *err = ::strerror( errno );
      os_write( err_fd, log_file, ::strlen( log_file ) );
      os_write( err_fd, ": ", 2 );
      os_write( err_fd, err, ::strlen( err ) );
      os_write( err_fd, "\n", 1 );
      return 1;
    }
    ::setvbuf( stderr, NULL, _IOLBF, 1024 );
    Console::log_header( STDERR_FILENO );
    log_hdr = false;
  }
  if ( debug != NULL ) {
    int dbg_dist = 0, check_bl = 0; /* dummy arg, can't set this yet */
    Console::parse_debug_flags( debug, ::strlen( debug ), dbg_dist, check_bl );
  }
  MDMsgMem         mem;
  StringTab        st( mem );
  ConfigStartup    startup( st );
  ConfigErrPrinter err;
  ConfigTree     * tree;
  CryptPass        pwd;
  bool             conn;

  tree = ConfigDB::parse_tree( cfg, st, err );
  if ( tree != NULL )
    startup.copy( *tree );
  if ( tree == NULL || ! init_pass( tree, pwd, cfg ) )
    return 1;

  if ( log_file != NULL )
    tree->parameters.set( st, P_LOG_FILE, log_file );
  else
    tree->parameters.find( P_LOG_FILE, log_file, NULL );
  if ( map_file != NULL )
    tree->parameters.set( st, P_MAP_FILE, map_file );
  if ( db_num != NULL )
    tree->parameters.set( st, P_DB_NUM, db_num );
  if ( ipc_name != NULL )
    tree->parameters.set( st, P_IPC_NAME, ipc_name );
  if ( reliability != NULL )
    tree->parameters.set( st, P_RELIABILITY, reliability );
  if ( pid_file != NULL )
    tree->parameters.set( st, P_PID_FILE, pid_file );
  if ( hostid != NULL )
    tree->parameters.set( st, P_HOST_ID, hostid );
  if ( no_msg_loss != NULL )
    tree->parameters.set( st, P_MSG_LOSS_ERRORS, false );

  ConfigTree::User      * usr   = NULL;
  ConfigTree::Service   * svc   = NULL;
  ConfigTree::Transport * tport = NULL;
  char host[ 256 ];
  int stdin_fd = STDIN_FILENO;
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
  /* if parse_config read from stdin, it will be closed */
  if ( use_console != NULL ) {
    if ( cfg == NULL || ::strcmp( cfg, "-" ) == 0 ) {
      stdin_fd = os_open( "/dev/tty", O_RDONLY, 0 );
      if ( stdin_fd < 0 )
        use_console = NULL;
    }
  }
#endif
  /* make a user with the hostname */
  if ( user == NULL )
    if ( ::gethostname( host, sizeof( host ) ) == 0 )
      user = host;

  if ( ! tree->resolve( user, usr, svc ) ) {
    if ( svc == NULL )
      return 1;
    UserBuf user_buf;
    const char * rv_port_num = NULL;
    char tmp_port[ 16 ];
    if ( listen != NULL ) {
      if ( (rv_port_num = ::strrchr( listen, ':' )) != NULL )
        rv_port_num++;
      else
        rv_port_num = listen;
    }
    if ( is_rvd ) {
      int port = 0;
      ConfigTree::Transport * rvd = tree->find_transport( "rvd", 3 );
      if ( rvd != NULL ) {
        port = EvTcpTransportParameters::get_listen_port( *rvd );
        if ( port > 0 && ( rv_port_num == NULL ||
                           port != atoi( rv_port_num ) ) ) {
          uint32_to_string( (uint32_t) port, tmp_port );
          rv_port_num = tmp_port;
        }
      }
    }
    if ( ! user_buf.gen_tmp_key( user, rv_port_num, *tree, *svc, pwd ) ) {
      fprintf( stderr, "Unable to generate user\n" );
      return 1;
    }
    bool is_new = false;
    if ( (usr = tree->find_user( NULL, user, ::strlen( user ) )) == NULL ) {
      usr = st.make<ConfigTree::User>();
      is_new = true;
    }
    st.ref_string( user_buf.user, user_buf.user_len, usr->user );
    st.ref_string( user_buf.service, user_buf.service_len, usr->svc );
    st.ref_string( user_buf.create, user_buf.create_len, usr->create );
    st.ref_string( user_buf.pri, user_buf.pri_len, usr->pri );
    st.ref_string( user_buf.pub, user_buf.pub_len, usr->pub );
    usr->is_temp = true;
    if ( is_new ) {
      usr->user_id = tree->user_cnt;
      tree->users.push_tl( usr );
    }
  }
  else {
    if ( ! UserBuf::test_user( pwd, *usr ) )
      return 1;
  }

  EvPoll poll;
  EvShm  shm( "ms_server" );
  SignalHandler sighndl;
  Logger & log = *Logger::create();
  sighndl.install();
  poll.init( 1024, false );
  poll.sub_route.init_shm( shm );

  TermCallback cb;
  MySessionMgr sess( poll, log, *tree, *usr, *svc, st, startup );
  EvTerminal   term( poll, cb );

  if ( log_file != NULL ) {
    sess.console.open_log( log_file, log_hdr );
    if ( log_rotate != NULL )
      sess.console.log_max_size = strtol( log_rotate, NULL, 0 );
    if ( log_max_rot != NULL )
      sess.console.log_max_rotate = atoi( log_max_rot );

    if ( err_fd >= 0 ) { /* errs go to log */
      ::close( err_fd );
      err_fd = -1;
    }
  }
  if ( use_console != NULL ) {
    sess.console.term_list.push_tl( &cb );
    term.term.prompt = ""; /* no prompt until after init */
    cb.mgr     = &sess;
    cb.term    = &term;
    cb.console = &sess.console;
    sess.term  = &term;
    term.stdin_fd = stdin_fd;
    term.stdout_fd = os_dup( STDOUT_FILENO );
    log.start_ev( poll );
    term.start();
    term.term.lc->complete_cb  = console_complete;
    term.term.lc->complete_arg = &sess.console;
    term.term.help_cb = console_help;
    term.term.closure = &sess.console;
    static char iec[] = "-iec", question[] = "?", show_help[] = "&show-help";
    static char *recipe[] = { iec, question, show_help };
    lc_bindkey( term.term.lc, recipe, 3 );
    lc_tty_set_prompt( term.term.tty, TTYP_PROMPT1, "" );

    if ( err_fd >= 0 ) { /* errs go to console */
      ::close( err_fd );
      err_fd = -1;
    }
  }
  else {
    term.stdin_fd = -1;
    term.stdout_fd = -1;
    /*tel.listen( NULL, 6500, DEFAULT_TCP_LISTEN_OPTS, "telnet_listen" );
    tel.console = &sess.console;*/
    log.start_ev( poll );
  }
  int status = 0;
  if ( ! sess.load_parameters() || ! sess.add_ipc_transport() )
    status = -1;
  if ( status == 0 && nets != NULL ) {
    const char * n     = ::strchr( nets, '.' ),
               * s     = nets;
    size_t       s_len = ::strlen( nets ),
                 n_len = 0;
    if ( n != NULL ) {
      s_len = n++ - nets;
      n_len = ::strlen( n );
    }
    for ( int i = 2; status == 0; i++ ) {
      if ( ! sess.add_network( n, n_len, s, s_len, false ) )
        status = -1;
      nets = get_arg( argc, argv, i, "-n", NULL, NULL );
      if ( nets == NULL || nets[ 0 ] == '-' )
        break;
      n     = ::strchr( s = nets, '.' );
      s_len = ::strlen( s );
      n_len = 0;
      if ( n != NULL ) {
        s_len = n++ - nets;
        n_len = ::strlen( n );
      }
    }
  }
  if ( status == 0 && tports != NULL ) {
    tport = tree->find_transport( tports, ::strlen( tports ), &conn );
    if ( tport == NULL ) {
      fprintf( stderr, "Transport %s not found\n", tports );
      status = -1;
    }
    for ( int i = 2; status == 0; i++ ) {
      if ( ! sess.add_transport( *tport, ! conn ) ) {
        fprintf( stderr, "Transport %s failed to start\n", tports );
        status = -1;
        break;
      }
      tports = get_arg( argc, argv, i, "-t", NULL, NULL );
      if ( tports == NULL || tports[ 0 ] == '-' )
        break;
      tport = tree->find_transport( tports, ::strlen( tports ), &conn );
      if ( tport == NULL ) {
        fprintf( stderr, "Transport %s not found\n", tports );
        status = -1;
      }
    }
  }
  if ( status == 0 ) {
    if ( ! sess.add_startup_transports() ) {
      fprintf( stderr, "Startup transports failed to start\n" );
      status = -1;
    }
    if ( is_rvd && status == 0 ) {
      int flags = ( no_perm ? RV_NO_PERMANENT : 0 ) |
                  ( no_http ? RV_NO_HTTP : 0 ) |
                  ( no_mcast ? RV_NO_MCAST : 0 );
      if ( ! sess.add_rvd_transports( listen, http, flags ) ) {
        fprintf( stderr, "Rvd transports failed to start\n" );
        status = -1;
      }
    }
  }
  if ( status == 0 ) {
    status = sess.init_session( pwd );
    if ( status != 0 )
      fprintf( stderr, "Init session status %d\n", status );
  }
  pwd.clear_pass(); /* no longer need pass */
  if ( status == 0 ) {
    if ( use_console != NULL ) {
      lc_tty_set_prompt( term.term.tty, TTYP_PROMPT1, sess.console.prompt );
    }
    else {
      bool is_fork_daemon =
        ( ( is_rvd && foreground == NULL ) || background != NULL );
      if ( is_fork_daemon ) {
        const char *wkdir = NULL;
        tree->parameters.find( P_WORKING_DIRECTORY, wkdir, NULL );
        sess.fork_daemon( err_fd, wkdir );
      }
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
      /* detach terminal, but keep fd used so that it isn't allocated again */
      int fd = ::open( "/dev/null", O_RDONLY );
      ::dup2( fd, STDIN_FILENO );
      ::close( fd );
#endif
    }
    sess.start();
    uint32_t idle = 0;
    while ( sess.loop( idle ) ) {
      if ( sighndl.signaled ) {
        if ( poll.quit == 0 ) {
          if ( sess.is_running() )
            sess.stop();
          poll.quit = 1;
        }
      }
    }
  }
  else {
    uint64_t timeout_ns = current_monotonic_time_ns() + sec_to_ns( 1 );
    while ( poll.quit < 5 ) {
      poll.dispatch();
      poll.wait( 10 );
      /* wait for log message */
      if ( sighndl.signaled || current_monotonic_time_ns() > timeout_ns ||
           sess.console.on_log( sess.log ) ) {
        if ( poll.quit == 0 )
          poll.quit = 1;
      }
    }
  }
  sess.console.flush_log( log );
  if ( use_console != NULL )
    term.finish();
  else if ( log_file == NULL || is_rvd ) {
    if ( status != 0 && sess.console.log_index > 0 && err_fd >= 0 )
      os_write( err_fd, sess.console.log.ptr, sess.console.log_index );
  }
  log.shutdown();
  /*if ( log_fp != NULL )
    fclose( log_fp );*/
  /*term.printf( "stdout: %.*s\n", (int) log.out_sz, log.out_buf );
  term.printf( "stderr: %.*s\n", (int) log.err_sz, log.err_buf );*/

  return status == 0 ? 0 : 1;
}

