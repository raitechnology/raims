#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <raikv/os_file.h>
#include <raikv/logger.h>
#include <raims/parse_config.h>
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>
#include <raims/ev_telnet.h>
#include <raids/ev_client.h>
#include <raims/console.h>
#include <linecook/ttycook.h>
#include <linecook/linecook.h>

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
                StringTab &st )
    : SessionMgr( p, l, c, u, s, st ), term( 0 ) {}
};

static const char *
get_arg( int argc, char *argv[], int b, const char *f,
         const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ )
    if ( ::strcmp( f, argv[ i ] ) == 0 ) /* -p port */
      return argv[ i + b ];
  return def; /* default value */
}

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

int
main( int argc, char *argv[] )
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
             * listen      = NULL,
             * no_http     = NULL,
             * http        = NULL,
             * no_mcast    = NULL,
             * debug       = NULL,
             * ipc_name    = NULL,
             * map_file    = NULL,
             * db_num      = NULL,
             * use_console = NULL,
             * reliability = NULL,
             * get_help    = NULL;
  static const char cfg_dir[] = "config";
  const char *program = ::strrchr( argv[ 0 ], '/' );
  program = ( program != NULL ? program + 1 : argv[ 0 ] );
  bool is_rvd = ::strcmp( program, "rvd" ) == 0;
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
  if ( ! is_rvd ) {
    for ( int i = 1; i < argc; i++ ) {
      if ( argv[ i ][ 0 ] == '-' && ::strlen( argv[ i ] ) > 2 ) {
        is_rvd = true;
        break;
      }
    }
  }

  if ( is_rvd ) {
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
  "   -no-mcast          : no multicast\n" \
  "   -console           : run with console\n"
    cfg         = get_arg( argc, argv, 1, "-cfg", rv_file );
    reliability = get_arg( argc, argv, 1, "-reliability", NULL );
    user        = get_arg( argc, argv, 1, "-user", NULL );
    log_file    = get_arg( argc, argv, 1, "-log", NULL );
    if ( log_file == NULL )
      log_file = get_arg( argc, argv, 1, "-logfile", NULL );
    log_rotate  = get_arg( argc, argv, 1, "-log-rotate", NULL );
    if ( log_rotate == NULL )
      log_rotate = get_arg( argc, argv, 1, "-log-max-size", NULL );
    log_max_rot = get_arg( argc, argv, 1, "-log-max-rotations", NULL );
    no_perm     = get_arg( argc, argv, 0, "-no-permanent", NULL );
    foreground  = get_arg( argc, argv, 0, "-foreground", NULL );
    listen      = get_arg( argc, argv, 1, "-listen", "7500" );
    no_http     = get_arg( argc, argv, 0, "-no-http", NULL );
    http        = get_arg( argc, argv, 1, "-http", NULL );
    no_mcast    = get_arg( argc, argv, 0, "-no-multicast", NULL );
    use_console = get_arg( argc, argv, 0, "-console", NULL );
    if ( use_console != NULL )
      foreground = use_console;
    get_help    = get_arg( argc, argv, 0, "-help", NULL );
  }
  else {
  #define MS_SERVER_HELP \
  "[-d dir] [-a file] -u user.svc -t tport.listen [...]\n" \
  "   -d dir         : config dir/file (default: config)\n" \
  "   -u user.svc    : user name (default: hostname)\n" \
  "   -t tport.list  : transport name + listen or connect\n" \
  "   -n svc.network : service name + network spec\n" \
  "   -l file        : log to file\n" \
  "   -f flags       : debug flags to set\n" \
  "   -i name        : connect with ipc name\n" \
  "   -m map         : attach to kv shm map\n" \
  "   -D dbnum       : default db num\n" \
  "   -c             : run with console\n"

    cfg         = get_arg( argc, argv, 1, "-d", cfg_dir );
    user        = get_arg( argc, argv, 1, "-u", NULL );
    tports      = get_arg( argc, argv, 1, "-t", NULL );
    nets        = get_arg( argc, argv, 1, "-n", NULL );
    log_file    = get_arg( argc, argv, 1, "-l", NULL );
    debug       = get_arg( argc, argv, 1, "-f", NULL );
    ipc_name    = get_arg( argc, argv, 1, "-i", NULL );
    map_file    = get_arg( argc, argv, 1, "-m", NULL );
    db_num      = get_arg( argc, argv, 1, "-D", NULL );
    use_console = get_arg( argc, argv, 0, "-c", NULL );
    get_help    = get_arg( argc, argv, 0, "-h", NULL );
  }
  if ( get_help != NULL ) {
    if ( is_rvd )
      printf( "%s " RVD_HELP "RaiMS version %s\n",
              argv[ 0 ], ms_get_version() );
    else
      printf( "%s " MS_SERVER_HELP "RaiMS version %s\n",
              argv[ 0 ], ms_get_version() );
    return 0;
  }
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
  }
  if ( debug != NULL ) {
    int dbg_dist = 0; /* dummy arg, can't set this yet */
    Console::parse_debug_flags( debug, ::strlen( debug ), dbg_dist );
  }
  MDMsgMem         mem;
  StringTab        st( mem );
  ConfigErrPrinter err;
  ConfigTree     * tree;
  CryptPass        pwd;
  os_stat          stbuf;
  bool             conn;

  if ( os_fstat( cfg, &stbuf ) < 0 || ( stbuf.st_mode & S_IFDIR ) == 0 )
    tree = ConfigDB::parse_jsfile( cfg, st, err );
  else
    tree = ConfigDB::parse_dir( cfg, st, err );
  if ( tree == NULL || ! init_pass( tree, pwd, cfg ) )
    return 1;

  if ( map_file != NULL )
    tree->set_parameter( st, P_MAP_FILE, map_file );
  if ( db_num != NULL )
    tree->set_parameter( st, P_DB_NUM, db_num );
  if ( ipc_name != NULL )
    tree->set_parameter( st, P_IPC_NAME, ipc_name );
  if ( reliability != NULL )
    tree->set_parameter( st, P_RELIABILITY, reliability );

  ConfigTree::User      * usr   = NULL;
  ConfigTree::Service   * svc   = NULL;
  ConfigTree::Transport * tport = NULL;
  char host[ 256 ];

  /* make a user with the hostname */
  if ( user == NULL )
    if ( ::gethostname( host, sizeof( host ) ) == 0 )
      user = host;

  if ( ! tree->resolve( user, usr, svc ) ) {
    if ( svc == NULL )
      return 1;
    UserBuf user_buf;
    const char * rv_port_num = NULL;
    if ( listen != NULL ) {
      if ( (rv_port_num = ::strrchr( listen, ':' )) != NULL )
        rv_port_num++;
      else
        rv_port_num = listen;
    }
    if ( ! user_buf.gen_tmp_key( user, rv_port_num, *svc, pwd ) ) {
      fprintf( stderr, "Unable to generate user\n" );
      return 1;
    }
    usr = st.make<ConfigTree::User>();
    st.ref_string( user_buf.user, user_buf.user_len, usr->user );
    st.ref_string( user_buf.service, user_buf.service_len, usr->svc );
    st.ref_string( user_buf.create, user_buf.create_len, usr->create );
    st.ref_string( user_buf.pri, user_buf.pri_len, usr->pri );
    st.ref_string( user_buf.pub, user_buf.pub_len, usr->pub );
    usr->user_id = tree->user_cnt;
    tree->users.push_tl( usr );
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
  MySessionMgr sess( poll, log, *tree, *usr, *svc, st );
  EvTerminal   term( poll, cb );

  if ( log_file != NULL ) {
    sess.console.open_log( log_file, false );
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
    term.stdin_fd  = 0;
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
  if ( ! sess.init_param() || ! sess.add_ipc_transport() )
    status = -1;
  if ( status == 0 && nets != NULL ) {
    const char * p = ::strchr( nets, '.' );
    if ( p == NULL ) {
      fprintf( stderr, "expecting svc.network (%s)\n", nets );
      status = -1;
    }
    for ( int i = 2; status == 0; i++ ) {
      if ( ! sess.add_network( p+1, ::strlen( p ) - 1, nets, p - nets ) )
        status = -1;
      nets = get_arg( argc, argv, i, "-n", NULL );
      if ( nets == NULL || nets[ 0 ] == '-' )
        break;
      p = ::strchr( nets, '.' );
      if ( p == NULL ) {
        fprintf( stderr, "expecting svc.network (%s)\n", nets );
        status = -1;
      }
    }
  }
  if ( status == 0 && tports != NULL ) {
    tport = tree->find_transport( tports, ::strlen( tports ), &conn );
    if ( tport == NULL ) {
      fprintf( stderr, "transport %s not found\n", tports );
      status = -1;
    }
    for ( int i = 2; status == 0; i++ ) {
      if ( ! sess.add_transport( *tport, ! conn ) ) {
        status = -1;
        break;
      }
      tports = get_arg( argc, argv, i, "-t", NULL );
      if ( tports == NULL || tports[ 0 ] == '-' )
        break;
      tport = tree->find_transport( tports, ::strlen( tports ), &conn );
      if ( tport == NULL ) {
        fprintf( stderr, "transport %s not found\n", tports );
        status = -1;
      }
    }
  }
  if ( status == 0 ) {
    if ( ! sess.add_startup_transports() )
      status = -1;
    if ( is_rvd && status == 0 ) {
      int flags = ( no_perm ? RV_NO_PERMANENT : 0 ) |
                  ( no_http ? RV_NO_HTTP : 0 ) |
                  ( no_mcast ? RV_NO_MCAST : 0 );
      if ( ! sess.add_rvd_transports( listen, http, flags ) )
        status = -1;
    }
  }
  if ( status == 0 )
    status = sess.init_session( pwd );
  pwd.clear_pass(); /* no longer need pass */
  if ( status == 0 ) {
    if ( use_console != NULL ) {
      lc_tty_set_prompt( term.term.tty, TTYP_PROMPT1, sess.console.prompt );
    }
    else if ( is_rvd && foreground == NULL ) {
      sess.fork_daemon( err_fd );
    }
    sess.start();
    while ( sess.loop() ) {
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
    while ( sess.loop() ) {
      if ( sighndl.signaled || current_monotonic_time_ns() > timeout_ns ) {
        if ( poll.quit == 0 )
          poll.quit = 1;
      }
      /* wait for log message */
      if ( sess.console.on_log( sess.log ) )
        if ( poll.quit == 0 )
          poll.quit = 1;
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

