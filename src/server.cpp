#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
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

#if 0
struct SubNotify : public RouteNotify {
  EvTerminal * term;
  SubNotify( EvTerminal *t ) : term( t ) {}
  void * operator new( size_t, void *ptr ) { return ptr; }

  virtual void on_sub( uint32_t h,  const char *sub,  size_t len,
                       uint32_t fd,  uint32_t rcnt,  char src_type,
                       const char *rep,  size_t rlen ) noexcept;
  virtual void on_unsub( uint32_t h,  const char *sub,  size_t len,
                         uint32_t fd,  uint32_t rcnt,
                         char src_type ) noexcept;
  virtual void on_psub( uint32_t h,  const char *pattern,  size_t len,
                        const char *prefix,  uint8_t prefix_len,
                        uint32_t fd,  uint32_t rcnt,
                        char src_type ) noexcept;
  virtual void on_punsub( uint32_t h,  const char *pattern,  size_t len,
                          const char *prefix,  uint8_t prefix_len,
                          uint32_t fd,  uint32_t rcnt,
                          char src_type ) noexcept;
  virtual void on_reassert( uint32_t fd,  RouteVec<RouteSub> &sub_db,
                            RouteVec<RouteSub> &pat_db ) noexcept;
};
void
SubNotify::on_sub( uint32_t ,  const char *sub,  size_t len,
                   uint32_t fd,  uint32_t rcnt,  char ,
                   const char *,  size_t ) noexcept
{
  this->term->printf( "%.*son_sub%.*s( %.*s, fd=%u, rcnt=%u )%.*s\n",
                      bz, bc, gz, gc, (int) len, sub, fd, rcnt, nz, nc );
}
void
SubNotify::on_unsub( uint32_t ,  const char *sub,  size_t len,
                  uint32_t fd,  uint32_t rcnt,  char ) noexcept
{
  this->term->printf( "%.*son_unsub%.*s( %.*s, fd=%u, rcnt=%u )%.*s\n",
                      bz, bc, gz, gc, (int) len, sub, fd, rcnt, nz, nc );
}
void
SubNotify::on_psub( uint32_t,  const char *pattern,  size_t len,
                 const char *prefix,  uint8_t prefix_len,
                 uint32_t fd,  uint32_t rcnt,  char ) noexcept
{
  this->term->printf( "%.*son_psub%.*s( %.*s, %.*s, fd=%u, rcnt=%u )%.*s\n",
                      bz, bc, gz, gc, (int) len, pattern,
                      (int) prefix_len, prefix, fd, rcnt, nz, nc );
}
void
SubNotify::on_punsub( uint32_t,  const char *pattern,  size_t len,
                   const char *prefix,  uint8_t prefix_len,
                   uint32_t fd,  uint32_t rcnt, char ) noexcept
{
  this->term->printf( "%.*son_punsub%.*s( %.*s, %.*s, fd=%u, rcnt=%u )%.*s\n",
                      bz, bc, gz, gc, (int) len, pattern, (int) prefix_len,
                      prefix, fd, rcnt, nz, nc );
}
void
SubNotify::on_reassert( uint32_t fd,  RouteVec<RouteSub> &,
                     RouteVec<RouteSub> & ) noexcept
{
  this->term->printf( "%.*son_reassert%.*s( %u )%.*s\n",
                      bz, bc, gz, gc, fd, nz, nc );
}
#endif

int
main( int argc, char *argv[] )
{
/*#ifndef _MSC_VER*/
  static const char cfg_dir[] = "config";
/*#else
  static const char cfg_dir[] = "/Users/gchri/rai/build/raims/config";
#endif*/
  const char * di = get_arg( argc, argv, 1, "-d", cfg_dir ),
             * us = get_arg( argc, argv, 1, "-u", "A.test" ),
             * ti = get_arg( argc, argv, 1, "-t", NULL ),
             * lo = get_arg( argc, argv, 1, "-l", NULL ),
             * fl = get_arg( argc, argv, 1, "-f", NULL ),
             * co = get_arg( argc, argv, 0, "-c", NULL ),
             * he = get_arg( argc, argv, 0, "-h", NULL );
  if ( he != NULL ) {
    printf( "%s [-d dir] -u user.svc -t tport.listen [...]\n"
            "   -d dir        : config dir (default: config)\n"
            "   -u user.svc   : user + service name\n"
            "   -t tport.list : transport name + listen or connect\n"
            "   -l file       : log to file\n"
            "   -f flags      : debug flags to set\n"
            "   -c            : run with console\n"
            "Connect or listen user to service on transports\n"
            "RaiMS version %s\n",
            argv[ 0 ], ms_get_version() );
    return 0;
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

  if ( ! tree->resolve( us, usr, svc ) )
    return 1;
  if ( ! UserBuf::test_user( pwd, *usr ) )
    return 1;

  EvPoll poll;
  EvShm  shm;
  SignalHandler sighndl;
  Logger & log = *Logger::create();
  /*HashTabGeom geom;*/
  /*TelnetListen tel( poll );*/
  sighndl.install();
  poll.init( 1024, false );
  /*geom.map_size         = sizeof( HashTab ) + 1024;
  geom.max_value_size   = 0;
  geom.hash_entry_size  = 64;
  geom.hash_value_ratio = 1;
  geom.cuckoo_buckets   = 0;
  geom.cuckoo_arity     = 0;*/
  /*shm.map    = HashTab::alloc_map( geom );
  shm.map->hdr.ht_read_only = 1;
  shm.ctx_id = 0;
  shm.dbx_id = 0;*/
  poll.sub_route.init_shm( shm );

  TermCallback cb;
  MySessionMgr sess( poll, log, *tree, *usr, *svc, st );
  EvTerminal   term( poll, cb );

  if ( lo != NULL )
    sess.console.open_log( lo );
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
  }
  else {
    term.stdin_fd = -1;
    term.stdout_fd = -1;
    /*tel.listen( NULL, 6500, DEFAULT_TCP_LISTEN_OPTS, "telnet_listen" );
    tel.console = &sess.console;*/
    log.start_ev( poll );
  }
  int status = 0;
  if ( ti != NULL ) {
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
  if ( ! sess.add_external_transport( *svc ) ||
       ! sess.add_startup_transports( *svc ) )
    status = -1;
#if 0
  size_t count = sess.user_db.transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * t = sess.user_db.transport_tab.ptr[ i ];
    SubNotify * n = new ( ::malloc( sizeof( SubNotify ) ) ) SubNotify( &term );
    t->sub_route.add_route_notify( *n );
  }
#endif
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
    while ( sess.loop() ) {
      if ( sighndl.signaled ) {
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
  log.shutdown();
  /*if ( log_fp != NULL )
    fclose( log_fp );*/
  /*term.printf( "stdout: %.*s\n", (int) log.out_sz, log.out_buf );
  term.printf( "stderr: %.*s\n", (int) log.err_sz, log.err_buf );*/

  return 0;
}

