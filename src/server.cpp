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
/*#ifndef _MSC_VER*/
  static const char cfg_dir[] = "config";
/*#else
  static const char cfg_dir[] = "/Users/gchri/rai/build/raims/config";
#endif*/
  const char * di = get_arg( argc, argv, 1, "-d", cfg_dir ),
             * us = get_arg( argc, argv, 1, "-u", NULL ),
             * ti = get_arg( argc, argv, 1, "-t", NULL ),
             * lo = get_arg( argc, argv, 1, "-l", NULL ),
             * fl = get_arg( argc, argv, 1, "-f", NULL ),
             * ip = get_arg( argc, argv, 1, "-i", NULL ),
             * ma = get_arg( argc, argv, 1, "-m", NULL ),
             * db = get_arg( argc, argv, 1, "-D", NULL ),
             * co = get_arg( argc, argv, 0, "-c", NULL ),
             * he = get_arg( argc, argv, 0, "-h", NULL );
  if ( he != NULL ) {
    printf( "%s [-d dir] -u user.svc -t tport.listen [...]\n"
            "   -d dir        : config dir (default: config)\n"
            "   -u user.svc   : user + service name\n"
            "   -t tport.list : transport name + listen or connect\n"
            "   -l file       : log to file\n"
            "   -f flags      : debug flags to set\n"
            "   -i name       : connect with ipc name\n"
            "   -m map        : attach to kv shm map\n"
            "   -D dbnum      : default db num\n"
            "   -c            : run with console\n"
            "Connect or listen user to service on transports\n"
            "RaiMS version %s\n",
            argv[ 0 ], ms_get_version() );
    return 0;
  }
  int err_fd = os_dup( STDERR_FILENO );

  if ( lo != NULL ) {
    if ( ::freopen( lo, "a", stderr ) == NULL ) {
      const char *err = ::strerror( errno );
      os_write( err_fd, lo, ::strlen( lo ) );
      os_write( err_fd, ": ", 2 );
      os_write( err_fd, err, ::strlen( err ) );
      os_write( err_fd, "\n", 1 );
      return 1;
    }
    ::setvbuf( stderr, NULL, _IOLBF, 1024 );
    Console::log_header( STDERR_FILENO );
  }
  if ( fl != NULL )
    dbg_flags = (int) string_to_uint64( fl, ::strlen( fl ) );
  MDMsgMem         mem;
  StringTab        st( mem );
  ConfigErrPrinter err;
  ConfigTree     * tree = ConfigDB::parse_dir( di, st, err );
  CryptPass        pwd;
  bool             conn;

  if ( tree == NULL || ! init_pass( tree, pwd, di ) )
    return 1;

  ConfigTree::User      * usr   = NULL;
  ConfigTree::Service   * svc   = NULL;
  ConfigTree::Transport * tport = NULL;

  if ( ! tree->resolve( us, usr, svc ) ) {
    if ( svc == NULL )
      return 1;
    UserBuf user_buf;
    if ( ! user_buf.gen_tmp_key( us, *svc, pwd ) ) {
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

  if ( lo != NULL ) {
    sess.console.open_log( lo, false );

    if ( err_fd >= 0 ) { /* errs go to log */
      ::close( err_fd );
      err_fd = -1;
    }
  }
  if ( co != NULL ) {
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
  if ( ! sess.init_param() ||
       ! sess.add_ipc_transport( *svc, ip, ma, db ? atoi( db ) : 0 ) )
    status = -1;
  if ( status == 0 && ti != NULL ) {
    tport = tree->find_transport( ti, ::strlen( ti ), &conn );
    if ( tport == NULL ) {
      fprintf( stderr, "transport %s not found\n", ti );
      status = -1;
    }
    for ( int i = 2; status == 0; i++ ) {
      if ( ! sess.add_transport( *svc, *tport, ! conn ) ) {
        status = -1;
        break;
      }
      ti = get_arg( argc, argv, i, "-t", NULL );
      if ( ti == NULL || ti[ 0 ] == '-' )
        break;
      tport = tree->find_transport( ti, ::strlen( ti ), &conn );
      if ( tport == NULL ) {
        fprintf( stderr, "transport %s not found\n", ti );
        status = -1;
      }
    }
  }
  if ( status == 0 ) {
    if ( ! sess.add_startup_transports( *svc ) )
      status = -1;
  }
  if ( status == 0 )
    status = sess.init_session( pwd );
  pwd.clear_pass(); /* no longer need pass */
  if ( status == 0 ) {
    if ( co != NULL ) {
      lc_tty_set_prompt( term.term.tty, TTYP_PROMPT1, sess.console.prompt );
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
  if ( co != NULL )
    term.finish();
  else if ( lo == NULL ) {
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

