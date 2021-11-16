#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <raims/parse_config.h>
#include <raims/session.h>
#include <linecook/linecook.h>
#include <raikv/logger.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

static const char *
get_arg( int argc, char *argv[], int b, const char *f,
         const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ )
    if ( ::strcmp( f, argv[ i ] ) == 0 ) /* -p port */
      return argv[ i + b ];
  return def; /* default value */
}

static const char *nc = ANSI_NORMAL;
static int         nz = ANSI_NORMAL_SIZE;
static const char *rc = ANSI_RED;
static int         rz = ANSI_RED_SIZE;
static const char *gc = ANSI_GREEN;
static int         gz = ANSI_GREEN_SIZE;

static double start_time;
FILE *std_out;
static void
output_flush( Logger &log ) noexcept
{
  char     out[ 8 * 1024 ];
  size_t   len;
  uint64_t stamp;

  for (;;) {
    len = sizeof( out );
    stamp = log.read_stdout( out, len );
    if ( stamp == 0 )
      break;
    fprintf( std_out, "%.6f %.*s%.*s%.*s",
                 (double) stamp / ( 1000 * 1000 * 1000.0 ) - start_time,
                 gz, gc, (int) len, out, nz, nc );

  }
  for (;;) {
    len = sizeof( out );
    stamp = log.read_stderr( out, len );
    if ( stamp == 0 )
      break;
    fprintf( std_out, "%.6f %.*s%.*s%.*s",
                 (double) stamp / ( 1000 * 1000 * 1000.0 ) - start_time,
                 rz, rc, (int) len, out, nz, nc );

  }
}

void
SessionMgr::on_data( const SubMsgData &val ) noexcept
{
  char xdata[ 8192 ];
  for ( size_t i = 0; i < sizeof( xdata ); ) {
    size_t len = sizeof( xdata ) - i;
    if ( len > val.datalen )
      len = val.datalen;
    ::memcpy( &xdata[ i ], val.data, len );
    i += len;
  }
  if ( val.reply != 0 ) {
    printf( "## subject %.*s reply %u\n", (int) val.pub.subject_len,
            val.pub.subject, val.reply );
    PubPtpData ptp( val.u_nonce, val.reply, xdata, sizeof( xdata ), MD_STRING );
    this->publish_to( ptp );
  }
  else {
    printf( "## subject %.*s\n", (int) val.pub.subject_len, val.pub.subject );
    PubMcastData mc( "TEST", 4, xdata, sizeof( xdata ), MD_STRING );
    this->publish( mc );
  }
}

struct Notify : public RouteNotify {
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
Notify::on_sub( uint32_t ,  const char *sub,  size_t len,
                uint32_t fd,  uint32_t rcnt,  char ,
                const char *,  size_t ) noexcept
{
  fprintf( std_out, "%.*son_sub( %.*s, fd=%u, rcnt=%u )%.*s\n",
       gz, gc, (int) len, sub, fd, rcnt, nz, nc );
}
void
Notify::on_unsub( uint32_t ,  const char *sub,  size_t len,
                  uint32_t fd,  uint32_t rcnt,  char ) noexcept
{
  fprintf( std_out, "%.*son_unsub( %.*s, fd=%u, rcnt=%u )%.*s\n",
       gz, gc, (int) len, sub, fd, rcnt, nz, nc );
}
void
Notify::on_psub( uint32_t,  const char *pattern,  size_t len,
                 const char *prefix,  uint8_t prefix_len,
                 uint32_t fd,  uint32_t rcnt,  char ) noexcept
{
  fprintf( std_out, "%.*son_psub( %.*s, %.*s, fd=%u, rcnt=%u )%.*s\n",
       gz, gc, (int) len, pattern, (int) prefix_len, prefix, fd, rcnt, nz, nc );
}
void
Notify::on_punsub( uint32_t,  const char *pattern,  size_t len,
                   const char *prefix,  uint8_t prefix_len,
                   uint32_t fd,  uint32_t rcnt, char ) noexcept
{
  fprintf( std_out, "%.*son_punsub( %.*s, %.*s, fd=%u, rcnt=%u )%.*s\n",
       gz, gc, (int) len, pattern, (int) prefix_len, prefix, fd, rcnt, nz, nc );
}
void
Notify::on_reassert( uint32_t fd,  RouteVec<RouteSub> &,
                     RouteVec<RouteSub> & ) noexcept
{
  fprintf( std_out, "%.*son_reassert( %u )%.*s\n",
       gz, gc, fd, nz, nc );
}

int
main( int argc, char *argv[] )
{
  const char * di = get_arg( argc, argv, 1, "-d", "config" ),
             * us = get_arg( argc, argv, 1, "-u", "sam.test" ),
             * ti = get_arg( argc, argv, 1, "-t", "localhost" ),
             * he = get_arg( argc, argv, 0, "-h", NULL );
  if ( he != NULL ) {
    printf( "%s [-d dir] [-u user.tport]\n"
            "   -d dir        : config dir (default: config)\n"
            "   -u user.tport : user + transport name\n"
            "   -t tport      : trasport name\n"
            "Start service svc with user\n",
            argv[ 0 ] );
    return 0;
  }
  MDMsgMem     mem;
  ConfigTree * tree = ConfigDB::parse_dir( mem, di );
  CryptPass    pwd; 
  bool         conn;
  
  if ( tree == NULL || ! init_pass( tree, pwd, di ) )
    return 1;

  ConfigTree::User      * usr   = NULL;
  ConfigTree::Service   * svc   = NULL;
  ConfigTree::Transport * tport = NULL;

  if ( ! tree->resolve( us, usr, svc ) ) {
    fprintf( stderr, "Failed to resolve %s\n", us );
    return 1;
  }
  if ( ! tree->find_transport( ti, tport, conn ) ) {
    fprintf( stderr, "Unable to find transport %s\n", ti );
    return 1;
  }
  if ( ! UserBuf::test_user( pwd, *usr ) ) {
    fprintf( stderr, "User test failed\n" );
    return 1;
  }
  EvPoll poll;
  SignalHandler sighndl;
  start_time = kv_current_realtime_s();
  std_out = ::fdopen( dup( 1 ), "a" );
  ::setlinebuf( std_out );
  Logger & log = *Logger::create();
  Notify n;
  sighndl.install();
  poll.init( 50, false );

  SessionMgr sess( poll, *tree, *usr, *svc );

  log.start();
  for ( int i = 2; ; i++ ) {
    if ( ! sess.add_transport( *svc, *tport, ! conn ) ) {
      fprintf( stderr, "Unable to start transport\n" );
      return 1;
    }
    ti = get_arg( argc, argv, i, "-t", NULL );
    if ( ti == NULL || ti[ 0 ] == '-' )
      break;
    if ( ! tree->find_transport( ti, tport, conn ) ) {
      fprintf( stderr, "Unable to find transport %s\n", ti );
      break;
    }
  }
  size_t count = sess.user_db.transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute * t = sess.user_db.transport_tab.ptr[ i ];
    t->sub_route.add_route_notify( n );
  }
  sess.init_session( pwd );
  pwd.clear_pass(); /* no longer need pass */

  sess.start();
  /*sess.sub_db.sub_start( "X.TEST", 6 );
  sess.sub_db.sub_start( "XYZ.AA", 6 );
  sess.sub_db.sub_start( "XYZ.AB", 6 );*/
  while ( sess.loop() ) {
    if ( sighndl.signaled ) {
      if ( poll.quit == 0 ) {
        sess.stop();
        poll.quit = 1;
      }
    }
    output_flush( log );
  }
  output_flush( log );
  log.shutdown();

  return 0;
}

