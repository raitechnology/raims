#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <raikv/logger.h>
#include <raids/term.h>
#define IMPORT_CONSOLE_CMDS
#define IMPORT_EVENT_DATA
#define IMPORT_DEBUG_STRINGS
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>
#include <raims/ev_telnet.h>
#include <linecook/linecook.h>
#include <linecook/ttycook.h>

namespace rai {
namespace kv {
extern uint32_t kv_debug;
}
namespace sassrv {
extern uint32_t rv_debug;
}
}

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;
using namespace ds;

Console::Console( SessionMgr &m ) noexcept
       : MDOutput( MD_OUTPUT_OPAQUE_TO_B64 ), mgr( m ), user_db( m.user_db ),
         sub_db( m.sub_db ), tree( m.tree ), string_tab( m.user_db.string_tab ),
         cfg_tport( 0 ), fname_fmt( ANSI_GREEN "%-18s" ANSI_NORMAL " : " ),
         type_fmt( ANSI_BLUE "%-10s %3d" ANSI_NORMAL " : " ),
         prompt( 0 ), max_log( 64 * 1024 ), log_index( 0 ), log_ptr( 0 ),
         inbox_num( 0 ), log_filename( 0 ), log_fd( -1 ), next_rotate( 1 ),
         log_status( 0 ), mute_log( false ), last_secs( 0 ), last_ms( 0 )
{
  time_t t = time( NULL ), t2;
  struct tm tm;
  localtime_r( &t, &tm );
  tm.tm_sec = 0;
  tm.tm_min = 0;
  tm.tm_hour = 0;
  t2 = mktime( &tm );
  t2 += 24 * 60 * 60;
  this->log_rotate_time = (uint64_t) t2 * 1000000000;
  this->make_prompt();
}

static const char *nc = ANSI_NORMAL;
static int         nz = ANSI_NORMAL_SIZE;
static const char *bc = ANSI_BLUE;
static int         bz = ANSI_BLUE_SIZE;
static const char *rc = ANSI_RED;
static int         rz = ANSI_RED_SIZE;
static const char *gc = ANSI_GREEN;
static int         gz = ANSI_GREEN_SIZE;
/*static const char *yc = ANSI_YELLOW;
static int         yz = ANSI_YELLOW_SIZE;*/
static const char *cc = ANSI_CYAN;
static int         cz = ANSI_CYAN_SIZE;

bool
Console::open_log( const char *fn ) noexcept
{
  this->log_fd = ::open( fn, O_APPEND | O_WRONLY | O_CREAT, 0666 );
  if ( this->log_fd < 0 ) {
    ::perror( fn );
    return false;
  }
  time_t now = ::time( NULL );
  struct tm local;
  char   line[ 128 ];
  size_t off = 0;
  localtime_r( &now, &local );
  int diff_hr = local.tm_hour - ( ( now / 3600 ) % 24 );
  int diff_mi = local.tm_min  - ( ( now / 60 ) % 60 );
  if ( diff_mi < 0 ) diff_mi = -diff_mi;

  ::strcpy( &line[ off ], "=--=--=--=\n" );  off = ::strlen( line );
  ::strcpy( &line[ off ], ::ctime( &now ) ); off = ::strlen( line );
  ::snprintf( &line[ off ], sizeof( line ) - off,
    "UTC offset: %d:%02d (%s)\n", diff_hr, diff_mi, tzname[ daylight ] );
  off = ::strlen( line );
  ::strcpy( &line[ off ], "=--=--=--=\n" );  off = ::strlen( line );
  if ( (size_t) ::write( this->log_fd, line, off ) != off ) {
    ::perror( fn );
    ::close( this->log_fd );
    this->log_fd = -1;
    return false;
  }
  if ( fn != this->log_filename ) {
    this->log_filename = (char *) ::malloc( ::strlen( fn ) * 2 + 24 );
    ::strcpy( this->log_filename, fn );
  }
  return true;
}

bool
Console::rotate_log( void ) noexcept
{
  uint64_t next = 24 * 60 * 60 * (uint64_t) 1000000000;
  this->log_rotate_time += next;
  if ( this->log_fd >= 0 ) {
    ::close( this->log_fd );
    this->log_fd = -1;

    size_t len = ::strlen( this->log_filename );
    char * newpath = &this->log_filename[ len + 1 ];
    ::memcpy( newpath, this->log_filename, len );
    newpath[ len ] = '.';
    for ( uint32_t i = this->next_rotate; ; i++ ) {
      size_t j = uint32_to_string( i, &newpath[ len + 1 ] );
      newpath[ len + 1 + j ] = '\0';
      if ( ::access( newpath, R_OK | W_OK ) != 0 ) {
        this->next_rotate = i + 1;
        break;
      }
    }
    if ( ::rename( this->log_filename, newpath ) != 0 ) {
      ::perror( newpath );
      return false;
    }
    return this->open_log( this->log_filename );
  }
  return true;
}

char *
cat_prompt( char *p,  char *e,  const char *s1,  const char *s2 = NULL,
            const char *s3 = NULL ) noexcept
{
  for ( ; *s1 != '\0'; s1++ ) if ( p < e ) *p++ = *s1;
  if ( s2 != NULL ) {
    for ( ; *s2 != '\0'; s2++ ) if ( p < e ) *p++ = *s2;
    if ( s2 != NULL ) {
      for ( ; *s3 != '\0'; s3++ ) if ( p < e ) *p++ = *s3;
    }
  }
  return p;
}

size_t
Console::make_prompt( const char *where,  size_t wsz ) noexcept
{
  char       * p, * e,
               blank[ NONCE_B64_LEN + 1 ];
  const char * us = this->user_db.user.user.val,
             * sv = this->user_db.svc.svc.val;
  size_t       off, boff;

  if ( this->prompt == NULL )
    this->prompt = (char *) ::malloc( 256 );
  p   = this->prompt;
  off = ( ANSI_NORMAL_SIZE + 2 );
  e   = &this->prompt[ 255 - off ];
  memset( blank, '_', NONCE_B64_LEN );
  blank[ NONCE_B64_LEN ] = '\0';
  p = cat_prompt( p, e, ANSI_CYAN, us, "." );
  p = cat_prompt( p, e, sv, ANSI_NORMAL "[", ANSI_GREEN );
  boff = p - this->prompt;
  p = cat_prompt( p, e,
                  blank,             ANSI_NORMAL "]@",
                  ANSI_MAGENTA "\\h" ANSI_NORMAL
                  ANSI_BLUE    "["   ANSI_NORMAL
                  ANSI_RED     "\\#" ANSI_NORMAL
                  ANSI_BLUE    "]"   );
  if ( where != NULL ) {
    p = cat_prompt( p, e, ANSI_YELLOW "(" );
    for ( size_t i = 0; i < wsz; i++ ) {
      if ( p < e )
        *p++ = where[ i ];
    }
    p = cat_prompt( p, e, ")" );
  }
  e = &e[ off ];
  p = cat_prompt( p, e, ANSI_NORMAL "> " );
  *p = '\0';
  return boff;
}

void
Console::update_prompt( const char *where,  size_t wsz ) noexcept
{
  size_t off = this->make_prompt( where, wsz );
  this->user_db.bridge_id.nonce.to_base64( &this->prompt[ off ] );
}

bool
ConsoleOutput::on_output( const char *,  size_t ) noexcept
{
  return true; /* virtual override by terminal class */
}

void
ConsoleOutput::on_prompt( const char * ) noexcept
{
}

void
ConsoleOutput::on_quit( void ) noexcept
{
}

void
Console::log_output( int stream,  uint64_t stamp,  size_t len,
                     const char *buf ) noexcept
{
  uint64_t secs, ms;

  secs = stamp / (uint64_t) ( 1000 * 1000 * 1000.0 );
  if ( secs != this->last_secs ) {
    uint32_t ar[ 3 ], j = 0;
    ar[ 2 ] = secs % 60,
    ar[ 1 ] = ( secs / 60 ) % 60;
    ar[ 0 ] = ( secs / 3600 ) % 24;
    for ( int i = 0; i < 3; i++ ) {
      this->ts[ j++ ] = ( ar[ i ] / 10 ) + '0';
      this->ts[ j++ ] = ( ar[ i ] % 10 ) + '0';
      this->ts[ j++ ] = ( i == 2 ? '.' : ':' );
    }
    this->last_secs = secs;
  }
  ms = stamp / (uint64_t) ( 1000 * 1000 );
  if ( ms != this->last_ms ) {
    this->ts[ TS_LEN+1 ] = ( ( ms / 100 ) % 10 ) + '0';
    this->ts[ TS_LEN+2 ] = ( ( ms / 10 ) % 10 ) + '0';
    this->ts[ TS_LEN+3 ] = ( ms % 10 ) + '0';
    this->last_ms = ms;
  }

  size_t sz = len + TSHDR_LEN;
  char * p  = this->log.make( this->log.count + sz );
  p = &p[ this->log.count ];
  this->log.count += sz;
  ::memcpy( p, this->ts, TSERR_OFF );
  p = &p[ TSERR_OFF ];
  *p++ = ( stream == 1 ? ' ' : '!' );
  *p++ = ' ';
  ::memcpy( p, buf, len );
}

bool
Console::colorize_log( const char *buf,  size_t len ) noexcept
{
  const char * end = &buf[ len ];
  bool b = true;

  while ( buf < end ) {
    const char *ptr = (const char *) ::memchr( buf, '\n', end - buf );
    if ( ptr == NULL ) {
      ptr = &buf[ len ];
    }
    else {
      if ( ptr > buf && *( ptr - 1 ) == '\r' )
        ptr--;
    }
    if ( &buf[ TSHDR_LEN ] < ptr ) {
      const char * color    = gc;
      size_t       color_sz = gz;

      if ( buf[ TSERR_OFF ] != ' ' ) {
        color    = rc;
        color_sz = rz;
      }
      size_t off  = 0,
             sz   = ptr - &buf[ TSHDR_LEN ];
      char * line = this->tmp.make( TSHDR_LEN + color_sz + sz + nz + 1 );

      ::memcpy( line, buf, TSHDR_LEN );                off += TSHDR_LEN;
      ::memcpy( &line[ off ], color, color_sz );       off += color_sz;
      ::memcpy( &line[ off ], &buf[ TSHDR_LEN ], sz ); off += sz;
      ::memcpy( &line[ off ], nc, nz );                off += nz;
      line[ off++ ] = '\n';

      for ( ConsoleOutput *o = this->term_list.hd; o!= NULL; o = o->next ) {
        b &= o->on_output( line, off );
      }
    }
    buf = ptr;
    if ( buf < end && buf[ 0 ] == '\r' )
      buf++;
    if ( buf < end && buf[ 0 ] == '\n' )
      buf++;
  }
  return b;
}

bool
Console::flush_output( void ) noexcept
{
  bool b = true;
  if ( this->out.count > 0 ) {
    size_t len = this->out.count;
    for ( ConsoleOutput *o = this->term_list.hd; o != NULL; o = o->next ) {
      b &= o->on_output( this->out.ptr, len );
    }
    this->out.count = 0;
  }
  if ( this->log_index < this->log.count ) {
    const char * lptr = &this->log.ptr[ this->log_index ];
    size_t       lsz  = this->log.count - this->log_index;
    if ( this->log_fd >= 0 ) {
      if ( (size_t) ::write( this->log_fd, lptr, lsz ) != lsz )
        this->log_status = errno;
      else
        this->log_status = 0;
    }
    if ( ! this->mute_log )
      b &= this->colorize_log( lptr, lsz );
    if ( this->log_ptr == 0 && this->log_index >= this->max_log )
      this->log_ptr = this->log_index;
    this->log_index = this->log.count;
    if ( this->log_index >= this->max_log * 2 ) {
      ::memmove( this->log.ptr, &this->log.ptr[ this->log_ptr ],
                 this->log_index - this->log_ptr );
      this->log_index -= this->log_ptr;
      this->log.count  = this->log_index;
      this->log_ptr = 0;
    }
  }
  return b;
}

bool
Console::on_log( Logger &log ) noexcept
{
  char     out[ 4 * 1024 ],
           err[ 4 * 1024 ];
  size_t   out_len   = sizeof( out ),
           err_len   = sizeof( err );
  uint64_t out_stamp = 0,
           err_stamp = 0;
  bool     out_done  = false,
           err_done  = false,
           b         = false;

  if ( ! log.avail() )
    return false;
  while ( ! out_done || ! err_done ) {
    if ( ! out_done && out_stamp == 0 ) {
      out_stamp = log.read_stdout( out, out_len );
      if ( out_stamp == 0 )
        out_done = true;
    }
    if ( ! err_done && err_stamp == 0 ) {
      err_stamp = log.read_stderr( err, err_len );
      if ( err_stamp == 0 )
        err_done = true;
    }
    bool do_out = ! out_done, do_err = ! err_done;
    if ( do_out && do_err ) {
      if ( out_stamp < err_stamp )
        do_err = false;
      else
        do_out = false;
    }
    if ( do_out ) {
      if ( out_len > 1 || out[ 0 ] != '\n' )
        this->log_output( 1, out_stamp, out_len, out );
      out_stamp = 0; out_len = sizeof( out );
      b = true;
    }
    if ( do_err ) {
      if ( err_len > 1 || err[ 0 ] != '\n' )
        this->log_output( 2, err_stamp, err_len, err );
      err_stamp = 0; err_len = sizeof( err );
      b = true;
    }
  }
  if ( b )
    this->flush_output();
  return b;
}

void
Console::flush_log( Logger &log ) noexcept
{
  log.flush();
  usleep( 50 );
  while ( this->on_log( log ) )
    usleep( 10 );
}
#if 0
static size_t
scan_arg( const char *buf,  const char *end,  const char *&sub ) noexcept
{
  while ( buf < end && *buf == ' ' )
    buf++;
  const char * s = (const char *) ::memchr( buf, ' ', end - buf );
  if ( s == NULL ) {
    sub = NULL;
    return 0;
  }
  while ( s < end && *s == ' ' )
    s++;
  sub = s;
  const char *e = (const char *) ::memchr( s, ' ', end - s );
  if ( e == NULL )
    e = end;
  return e - s;
}
#endif
static size_t
scan_args( const char *buf,  const char *end,  const char **args,
           size_t *arglen,  size_t maxargs ) noexcept
{
  size_t argc = 0;
  for (;;) {
    while ( buf < end && *buf <= ' ' )
      buf++;
    if ( buf == end || argc == maxargs )
      break;
    args[ argc ] = buf;
    while ( buf < end && *buf > ' ' )
      buf++;
    arglen[ argc ] = buf - args[ argc ];
    argc++;
  }
  return argc;
}

static void
make_valid( ValidCmds &valid,
            const ConsoleCmdString *cmd,  size_t ncmds,
            const ConsoleCmdString *help,  size_t nhelps ) noexcept
{
  ConsoleCmdString * x = (ConsoleCmdString *)
                         ::malloc( sizeof( cmd[ 0 ] ) * valid.nvalid * 2 ),
                   * y = &x[ valid.nvalid ];
  size_t             xcnt = 0,
                     ycnt = 0,
                     j, k;
  for ( j = 0; j < valid.nvalid; j++ ) {
    for ( k = 0; k < ncmds; k++ ) {
      if ( cmd[ k ].cmd == valid.valid[ j ] ) {
        x[ xcnt++ ] = cmd[ k ];
        break;
      }
    }
    for ( k = 0; k < nhelps; k++ ) {
      if ( help[ k ].cmd == valid.valid[ j ] ) {
        y[ ycnt++ ] = help[ k ];
        break;
      }
    }
  }
  valid.cmd    = x;
  valid.ncmds  = xcnt;
  valid.help   = y;
  valid.nhelps = ycnt;
}

void
Console::get_valid_cmds( const ConsoleCmdString *&cmds,
                         size_t &ncmds ) noexcept
{
  if ( this->cfg_tport == NULL ) {
    cmds  = console_cmd;
    ncmds = num_console_cmds;
  }
  else {
    for ( size_t i = 0; i < num_valid_cmds; i++ ) {
      if ( this->cfg_tport->type.equals( valid_cmd[ i ].type ) ) {
        ValidCmds &valid = valid_cmd[ i ];
        if ( valid.ncmds == 0 )
          make_valid( valid, tport_cmd, num_tport_cmds, tport_help_cmd,
                      num_tport_help_cmds );
        cmds  = valid.cmd;
        ncmds = valid.ncmds;
        return;
      }
    }
    cmds  = tport_cmd;
    ncmds = num_tport_cmds;
  }
}

void
Console::get_valid_help_cmds( const ConsoleCmdString *&cmds,
                              size_t &ncmds ) noexcept
{
  if ( this->cfg_tport == NULL ) {
    cmds  = help_cmd;
    ncmds = num_help_cmds;
  }
  else {
    for ( size_t i = 0; i < num_valid_cmds; i++ ) {
      if ( this->cfg_tport->type.equals( valid_cmd[ i ].type ) ) {
        ValidCmds &valid = valid_cmd[ i ];
        if ( valid.nhelps == 0 )
          make_valid( valid, tport_cmd, num_tport_cmds, tport_help_cmd,
                      num_tport_help_cmds );
        cmds  = valid.help;
        ncmds = valid.nhelps;
        return;
      }
    }
    cmds  = tport_help_cmd;
    ncmds = num_tport_help_cmds;
  }
}

static const size_t MAXARGS = 8;
int
Console::parse_command( const char *buf,  const char *end,
                        const char *&arg,  size_t &len,
                        const char **args,  size_t *arglen,
                        size_t &argcount ) noexcept
{
  const ConsoleCmdString * cmds;
  size_t     ncmds;
  int        argc = scan_args( buf, end, args, arglen, MAXARGS ),
             j    = 0;
  ConsoleCmd cmd;

  this->get_valid_cmds( cmds, ncmds );
  argcount = (size_t) argc;
  arg = NULL;
  len = 0;

  if ( argc == 0 )
    return CMD_EMPTY;
  cmd = which_cmd( cmds, ncmds, args[ 0 ], arglen[ 0 ], NULL );

  if ( cmd == CMD_BAD && cmds == console_cmd ) {
    ConsoleCmd cmd2 = which_show( args[ 0 ], arglen[ 0 ] );
    if ( cmd2 != CMD_BAD ) {
      cmd = cmd2;
      j   = -1; /* show optional */
      goto skip_parse_show;
    }
    return CMD_BAD;
  }
  switch ( cmd ) {
    default:
      if ( argc > 1 ) {
        arg = args[ 1 ];
        len = arglen[ 1 ];
      }
      break;
    case CMD_CONFIGURE: /* configure ... */
      if ( argc > 1 ) {
        cmd = which_config( args[ 1 ], arglen[ 1 ] );
        if ( cmd != CMD_BAD && argc > 2 ) {
          arg = args[ 2 ];
          len = arglen[ 2 ];
        }
      }
      break;
    case CMD_SHOW: /* show ... */
      if ( argc > 1 ) {
        cmd = which_show( args[ 1 ], arglen[ 1 ] );
      skip_parse_show:;
        /* show run ... */
        if ( cmd == CMD_SHOW_RUN ) {
          if ( argc > j+2 ) {
            cmd = which_run( args[ j+2 ], arglen[ j+2 ] );
            if ( cmd != CMD_BAD && j+3 < argc ) {
              arg = args[ j+3 ];
              len = arglen[ j+3 ];
            }
          }
        }
        else {
          if ( cmd != CMD_BAD && j+2 < argc ) {
            arg = args[ j+2 ];
            len = arglen[ j+2 ];
          }
        }
      }
      break;
  }
  return cmd;
}

int
console_complete( struct LineCook_s *state,  const char *buf,  size_t off,
                  size_t len ) noexcept
{
  const ConsoleCmdString * cmds;
  size_t         ncmds;
  const char *   args[ MAXARGS ];
  size_t         arglen[ MAXARGS ];
  int            argc,
                 arg_complete,
                 j = 0;
  CmdMask        mask;
  ConsoleArgType type = NO_ARG;
  char           trail = 0;
  ConsoleCmd     cmd  = CMD_EMPTY;
  Console      * cons = (Console *) ((Term *) state->closure)->closure;

  argc = scan_args( buf, &buf[ off + len ], args, arglen, MAXARGS );
  arg_complete = argc;
  cons->get_valid_cmds( cmds, ncmds );

  if ( off + len > 0 ) {
    trail = buf[ off + len - 1 ];
    if ( trail == ' ' )
      arg_complete++;
  }
  if ( argc > 0 ) {
    cmd = which_cmd( cmds, ncmds, args[ 0 ], arglen[ 0 ], &mask );

    if ( cmd == CMD_BAD && mask.count() == 0 && cmds == console_cmd ) {
      ConsoleCmd cmd2 = which_show( args[ 0 ], arglen[ 0 ] );
      if ( cmd2 != CMD_BAD ) {
        cmds  = show_cmd;
        ncmds = num_show_cmds;
        cmd   = cmd2;
        j     = -1; /* show optional */
        goto skip_parse_show;
      }
    }
    if ( ( argc == 1 && trail == ' ' ) ||
         ( argc == 2 && trail != ' ' ) )
      type = console_command_type( cmd );

    if ( cmd == CMD_SHOW && arg_complete > 1 ) {
      cmds  = show_cmd;
      ncmds = num_show_cmds;
      if ( argc > 1 ) {
        cmd = which_show( args[ 1 ], arglen[ 1 ] );
      skip_parse_show:;
        if ( ( argc == j+2 && trail == ' ' ) ||
             ( argc == j+3 && trail != ' ' ) )
          type = console_command_type( cmd );

        if ( cmd == CMD_SHOW_RUN && arg_complete > j+2 ) {
          cmds  = run_cmd;
          ncmds = num_run_cmds;

          if ( argc > j+2 ) {
            cmd = which_run( args[ j+2 ], arglen[ j+2 ] );

            if ( ( argc == j+3 && trail == ' ' ) ||
                 ( argc == j+4 && trail != ' ' ) )
              type = console_command_type( cmd );
          }
        }
      }
    }
    else if ( cmd == CMD_CONFIGURE && arg_complete > 1 ) {
      cmds  = config_cmd;
      ncmds = num_config_cmds;
      if ( argc > 1 ) {
        cmd = which_config( args[ 1 ], arglen[ 1 ] );
        if ( ( argc == 2 && trail == ' ' ) ||
             ( argc == 3 && trail != ' ' ) )
          type = console_command_type( cmd );
      }
    }
  }

  if ( type == NO_ARG ) {
    for ( size_t k = 0; k < ncmds; k++ )
      lc_add_completion( state, cmds[ k ].str, ::strlen( cmds[ k ].str ) );
  }
  else if ( type == TPORT_ARG || type == PEER_ARG || type == USER_ARG ||
            type == PARM_ARG || type == SVC_ARG ) {
    if ( type == PEER_ARG ) {
      for ( uint32_t uid = 0; uid < cons->user_db.next_uid; uid++ ) {
        UserBridge * n = cons->user_db.bridge_tab[ uid ];
        if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) {
          lc_add_completion( state, n->peer.user.val, n->peer.user.len );
        }
      }
    }
    else if ( type == USER_ARG ) {
      for ( ConfigTree::User * user = cons->tree.users.hd;
            user != NULL; user = user->next )
        lc_add_completion( state, user->user.val, user->user.len );
    }
    else if ( type == TPORT_ARG ) {
      for ( ConfigTree::Transport * tport = cons->tree.transports.hd;
            tport != NULL; tport = tport->next )
        lc_add_completion( state, tport->tport.val, tport->tport.len );
    }
    else if ( type == SVC_ARG ) {
      for ( ConfigTree::Service * svc = cons->tree.services.hd;
            svc != NULL; svc = svc->next )
        lc_add_completion( state, svc->svc.val, svc->svc.len );
    }
    else if ( type == PARM_ARG ) {
      for ( ConfigTree::Parameters *p = cons->tree.parameters.hd;
            p != NULL; p = p->next ) {
        for ( ConfigTree::StringPair *sp = p->parms.hd; sp != NULL;
              sp = sp->next ) {
          lc_add_completion( state, sp->name.val, sp->name.len );
        }
      }
    }
  }
  return 0;
}

void
console_help( struct Term_s *t ) noexcept
{
  const ConsoleCmdString * cmds, * help;
  size_t ncmds, nhelp;
  Term * term = (Term *) t;
  int    arg_num,   /* which arg is completed, 0 = first */
         arg_count, /* how many args */
         arg_off[ 32 ],  /* offset of args */
         arg_len[ 32 ];  /* length of args */
  char   buf[ 1024 ];
  CmdMask cmd_mask;
  Console * cons = (Console *) term->closure;

  int n = lc_tty_get_completion_cmd( term->tty, buf, sizeof( buf ),
                                     &arg_num, &arg_count, arg_off,
                                     arg_len, 32 );
  if ( n < 0 )
    return;
  cons->get_valid_cmds( cmds, ncmds );
  if ( arg_count > 0 && arg_len[ 0 ] > 0 ) {
    ConsoleCmd cmd;
    cmd = which_cmd( cmds, ncmds, &buf[ arg_off[ 0 ] ], arg_len[ 0 ],
                     &cmd_mask );
    if ( cmd == CMD_SHOW ) {
      if ( arg_count > 1 )
        cmd = which_show( &buf[ arg_off[ 1 ] ], arg_len[ 1 ], &cmd_mask );
      if ( cmd == CMD_SHOW || cmd_mask.count() == 0 ) {
        cmd_mask.zero();
        for ( size_t i = 0; i < num_show_cmds; i++ )
          cmd_mask.add( show_cmd[ i ].cmd );
      }
    }
    else if ( cmd == CMD_CONFIGURE ) {
      if ( arg_count > 1 )
        cmd = which_config( &buf[ arg_off[ 1 ] ], arg_len[ 1 ], &cmd_mask );
    }
  }
  /*Console * cons = (Console *) term->closure;*/
  cons->get_valid_help_cmds( help, nhelp );
  for ( size_t i = 0; i < nhelp; i++ ) {
    if ( cmd_mask.count() == 0 || cmd_mask.is_member( help[ i ].cmd ) ) {
      const char * s = help[ i ].str;
      for (;;) {
        const char * e = (const char *) ::memchr( s, '\n', ::strlen( s ) );
        if ( e != NULL ) {
          lc_add_completion( term->lc, s, ( e - s ) );
          s = &e[ 1 ];
        }
        else {
          lc_add_completion( term->lc, s, ::strlen( s ) );
          break;
        }
      }
    }
  }
}

void
Console::output_help( int c ) noexcept
{
  const ConsoleCmdString * help;
  size_t nhelp;
  size_t i = 0;
  this->get_valid_help_cmds( help, nhelp );
  for ( ; i < nhelp && c != help[ i ].cmd; i++ )
    ;
  if ( i < num_help_cmds ) {
    const char * s = help[ i ].str;
    for (;;) {
      const char * e = (const char *) ::memchr( s, '\n', ::strlen( s ) );
      if ( e != NULL ) {
        this->printf( "%.*s\n", (int) ( e - s ), s );
        s = &e[ 1 ];
      }
      else {
        this->printf( "%s\n", s );
        break;
      }
    }
  }
}

void
Console::tab_connection( const char *proto,  const char *remote,  uint32_t rsz,  
                         const char *local,  uint32_t lsz,
                         const UserBridge &n,  TabPrint &pr ) noexcept
{
  size_t psz = ::strlen( proto ),
         dig = uint32_digits( n.uid ),
         nsz = n.peer.user.len,
         sz  = psz + rsz + lsz + dig + nsz + 7, i = 0;
  char * str = this->tmp.make( this->tmp.count + sz );
  str = &str[ this->tmp.count ];
  this->tmp.count += sz;

  ::memcpy( str, proto, psz );                 i += psz;
  ::memcpy( &str[ i ], local, lsz );           i += lsz;
  ::memcpy( &str[ i ], " -> ", 4 );            i += 4;
  ::memcpy( &str[ i ], n.peer.user.val, nsz ); i += nsz;
  str[ i++ ] = '.';
  uint32_to_string( n.uid, &str[ i ], dig );   i += dig;
  str[ i++ ] = '@';
  ::memcpy( &str[ i ], remote, rsz );          i += rsz;
  str[ i ] = '\0';
  pr.set( str, i );
}

void
Console::tab_url( const char *proto, const char *addr, uint32_t addrlen,
                  TabPrint &pr ) noexcept
{
  size_t psz = ::strlen( proto ),
         sz  = psz + addrlen + 4, i = 0;
  char * str = this->tmp.make( this->tmp.count + sz );
  str = &str[ this->tmp.count ];
  this->tmp.count += sz;

  ::memcpy( str, proto, psz );          i += psz;
  ::memcpy( &str[ i ], "://", 3 );      i += 3;
  ::memcpy( &str[ i ], addr, addrlen ); i += addrlen;
  str[ i ] = '\0';
  pr.set( str, i );
}

void
Console::tab_user_id( uint32_t uid,  TabPrint &pr ) noexcept
{
  if ( uid == 0 ) {
    pr.set( this->user_db.user.user, PRINT_SELF );
  }
  else {
    UserBridge *n = NULL;
    if ( uid < this->user_db.next_uid )
      n = this->user_db.bridge_tab[ uid ];
    if ( n != NULL )
      pr.set( n->peer.user, uid, PRINT_ID );
    else
      pr.set_null();
  }
}

void
Console::tab_concat( const char *s,  size_t sz1,  const char *s2,
                     TabPrint &pr ) noexcept
{
  size_t sz2 = ::strlen( s2 ),
         sz  = sz1 + sz2 + 4;
  char * str = this->tmp.make( this->tmp.count + sz );
  str = &str[ this->tmp.count ];
  this->tmp.count += sz;
  str[ 0 ] = '(';
  ::memcpy( &str[ 1 ], s2, sz2 );
  str[ sz2 + 1 ] = ')';
  str[ sz2 + 2 ] = ' ';
  ::memcpy( &str[ sz2 + 3 ], s, sz1 );
  str[ sz1 + sz2 + 3 ] = '\0';
  pr.set( str, sz1 + sz2 + 3 );
}

void
Console::tab_concat( const char *s,  const char *s2,  TabPrint &pr ) noexcept
{
  return this->tab_concat( s, ::strlen( s ), s2, pr );
}

void
Console::tab_string( const char *buf,  TabPrint &pr ) noexcept
{
  size_t len = ::strlen( buf );
  char * str = this->tmp.make( this->tmp.count + len + 1 );
  str = &str[ this->tmp.count ];
  this->tmp.count += len + 1;
  ::memcpy( str, buf, len );
  str[ len ] = '\0';
  pr.set( str, len );
}

void
Console::tab_nonce( const Nonce &nonce,  TabPrint &pr ) noexcept
{
  char * str = this->tmp.make( this->tmp.count + NONCE_B64_LEN + 1 );
  str = &str[ this->tmp.count ];
  this->tmp.count += NONCE_B64_LEN + 1;
  nonce.to_base64_str( str );
  pr.set( str, NONCE_B64_LEN );
}

uint32_t
TabPrint::width( UserDB &user_db,  char *buf ) noexcept
{
  UserRoute * u_ptr;
  size_t sz = 0;
  switch ( this->type() ) {
    case PRINT_STRING:
      return min<uint32_t>( this->len, 79 );

    case PRINT_SELF:
      return min<uint32_t>( this->len + 2, 79 );

    case PRINT_ID:
      return min<uint32_t>( ::strlen( this->val ) + 1 +
                            uint32_digits( this->len ), 79 );

    case PRINT_USER:
      return min<uint32_t>( this->n->peer.user.len + 1 +
                            uint32_digits( this->n->uid ), 79 );
    case PRINT_ADDR:
    case PRINT_UADDR:
      if ( this->len == 0 )
        return 0;
      if ( this->type() == PRINT_UADDR ) {
        sz = this->n->peer.user.len + uint32_digits( this->n->uid ) + 2;
      }
      if ( this->pre != NULL )
        sz += ::strlen( this->pre ) + 3;
      sz += this->len;
      return min<uint32_t>( sz, 79 );
    case PRINT_TPORT:
      if ( this->len == 0 )
        return 0;
      sz += this->len;
      if ( this->pre != NULL )
        sz += ::strlen( this->pre ) + 1;
      return min<uint32_t>( sz, 79 );
    case PRINT_LATENCY: {
      if ( this->ival == 0 )
        return 0;
      uint64_t lat = this->ival;
      while ( lat > 1000000 )
        lat /= 1000;
      return ::snprintf( buf, 80, "%.3gxs", (double) lat / 1000.0 );
    }
    case PRINT_NONCE:
      if ( this->n == NULL )
        return 0;
      return NONCE_B64_LEN;

    case PRINT_DIST:
      if ( this->n == NULL )
        return 0;
      u_ptr = n->primary( user_db );
      this->len = user_db.peer_dist.calc_transport_cache( this->n->uid,
                                                          u_ptr->rte.tport_id,
                                                          u_ptr->rte );
      /* fall through */
    case PRINT_INT:
      return uint32_digits( this->len );
    case PRINT_SHORT_HEX:
      return 4 + 2;
    case PRINT_LONG_HEX:
      if ( this->ival <= (uint64_t) 0xffffffffU ) {
        if ( this->ival <= (uint64_t) 0xffffU ) {
          if ( this->ival == 0 )
            return 1;
          return 4 + 2;
        }
        return 8 + 2;
      }
      return 8 + 8 + 2;
    case PRINT_STATE: {
      char buf[ 5 * 10 + 1 ];
      return ::strlen( user_state_abrev( this->len &
                                     ( INBOX_ROUTE_STATE |
                                       UCAST_URL_STATE |
                                       UCAST_URL_SRC_STATE |
                                       MESH_URL_STATE |
                                       HAS_HB_STATE ), buf ) );
    }
    case PRINT_LONG:
      return uint64_digits( this->ival );
    case PRINT_STAMP:
      if ( this->ival == 0 )
        return 0;
      return Console::TS_LEN + Console::TSFRACTION_LEN + 1;
    case PRINT_TSTATE:
      return __builtin_popcount( this->len );
    default:
      return 0;
  }
}

static inline size_t
cat80( char *buf,  size_t off,  const char *s,  size_t len )
{
  len = min<uint32_t>( off + len, 79 );
  const char * end = &buf[ len ];
  buf = &buf[ off ];
  while ( buf < end )
    *buf++ = *s++;
  return len;
}

static inline size_t
cat80( char *buf,  size_t off,  const char *s )
{
  return cat80( buf, off, s, ::strlen( s ) );
}

static inline size_t
cat80( char *buf,  size_t off,  uint32_t i )
{
  char str[ 16 ];
  size_t sz = uint32_to_string( i, str );
  return cat80( buf, off, str, sz );
}

const char *
TabPrint::string( char *buf ) noexcept
{
  size_t sz = 0;
  switch ( this->type() ) {
    case PRINT_STRING:
      if ( this->len == 0 )
        return "";
      if ( this->len > 79 ) {
        sz = cat80( buf, 0, this->val, this->len );
        buf[ sz ] = '\0';
        return buf;
      }
      return this->val;
    case PRINT_SELF:
      sz = cat80( buf, 0, this->val, this->len );
      sz = cat80( buf, sz, ".*" );
      buf[ sz ] = '\0';
      return buf;
    case PRINT_ID:
      sz = cat80( buf, 0, this->val, ::strlen( this->val ) );
      sz = cat80( buf, sz, "." );
      sz = cat80( buf, sz, this->len );
      buf[ sz ] = '\0';
      return buf;
    case PRINT_USER:
      sz = cat80( buf, 0, this->n->peer.user.val );
      sz = cat80( buf, sz, "." );
      sz = cat80( buf, sz, this->n->uid );
      buf[ sz ] = '\0';
      return buf;
    case PRINT_ADDR:
    case PRINT_UADDR:
      if ( this->len == 0 )
        return "";
      if ( this->type() == PRINT_UADDR ) {
        sz = cat80( buf, 0, this->n->peer.user.val );
        sz = cat80( buf, sz, "." );
        sz = cat80( buf, sz, this->n->uid );
        sz = cat80( buf, sz, "@" );
      }
      if ( this->pre != NULL ) {
        sz = cat80( buf, sz, this->pre );
        sz = cat80( buf, sz, "://" );
      }
      sz = cat80( buf, sz, this->val, this->len );
      buf[ sz ] = '\0';
      return buf;
    case PRINT_TPORT:
      if ( this->len == 0 )
        return "";
      sz = cat80( buf, sz, this->val, this->len );
      if ( this->pre != NULL ) {
        sz = cat80( buf, sz, "." );
        sz = cat80( buf, sz, this->pre );
      }
      buf[ sz ] = '\0';
      return buf;
    case PRINT_LATENCY: {
      if ( this->ival == 0 )
        return "";
      uint64_t lat = this->ival;
      const char * units = "us";
      while ( lat > 1000000 ) {
        lat /= 1000;
        if ( units[ 0 ] == 'u' )
          units = "ms";
        else {
          units = "se";
          break;
        }
      }
      ::snprintf( buf, 80, "%.3g%s", (double) lat / 1000.0, units );
      return buf;
    }
    case PRINT_NONCE:
      if ( this->n == NULL )
        return "";
      this->n->bridge_id.nonce.to_base64_str( buf );
      return buf;
    case PRINT_DIST:
      if ( this->n == NULL )
        return "";
      /* fall through */
    case PRINT_INT:
      sz = uint32_to_string( this->len, buf );
      buf[ sz ] = '\0';
      return buf;
    case PRINT_SHORT_HEX:
      buf[ 0 ] = '0';
      buf[ 1 ] = 'x';
      hexstr16( this->len, &buf[ 2 ] );
      buf[ 2 + 4 ] = '\0';
      return buf;
    case PRINT_LONG_HEX:
      buf[ 0 ] = '0';
      buf[ 1 ] = 'x';
      if ( this->ival <= (uint64_t) 0xffffffffU ) {
        if ( this->ival <= (uint64_t) 0xffffU ) {
          if ( this->ival == 0 ) {
            buf[ 1 ] = '\0';
            return buf;
          }
          hexstr16( (uint16_t) this->ival, &buf[ 2 ] );
          buf[ 4 + 2 ] = '\0';
          return buf;
        }
        hexstr32( (uint32_t) this->ival, &buf[ 2 ] );
        buf[ 8 + 2 ] = '\0';
        return buf;
      }
      hexstr64( this->ival, &buf[ 2 ] );
      buf[ 2 + 8 + 8 ] = '\0';
      return buf;
    case PRINT_STATE:
      return user_state_abrev( this->len &
                               ( INBOX_ROUTE_STATE |
                                 UCAST_URL_STATE |
                                 UCAST_URL_SRC_STATE |
                                 MESH_URL_STATE |
                                 HAS_HB_STATE ), buf );
    case PRINT_LONG:
      sz = uint64_to_string( this->ival, buf );
      buf[ sz ] = '\0';
      return buf;
    case PRINT_STAMP: {
      if ( this->ival == 0 )
        return "";
      uint64_t secs = this->ival / (uint64_t) ( 1000 * 1000 * 1000.0 );
      uint32_t ar[ 3 ], j = 0;
      ar[ 2 ] = secs % 60,
      ar[ 1 ] = ( secs / 60 ) % 60;
      ar[ 0 ] = ( secs / 3600 ) % 24;
      for ( int i = 0; i < 3; i++ ) {
        buf[ j++ ] = ( ar[ i ] / 10 ) + '0';
        buf[ j++ ] = ( ar[ i ] % 10 ) + '0';
        buf[ j++ ] = ( i == 2 ? '.' : ':' );
      }
      uint64_t ms = this->ival / (uint64_t) ( 1000 * 1000 );
      buf[ Console::TS_LEN+1 ] = ( ( ms / 100 ) % 10 ) + '0';
      buf[ Console::TS_LEN+2 ] = ( ( ms / 10 ) % 10 ) + '0';
      buf[ Console::TS_LEN+3 ] = ( ms % 10 ) + '0';
      buf[ Console::TS_LEN+4 ] = '\0';
      return buf;
    }
    case PRINT_TSTATE: {
      uint32_t j = 0;
      if ( this->len & TPORT_IS_SVC      ) buf[ j++ ] = 'S';
      if ( this->len & TPORT_IS_LISTEN   ) buf[ j++ ] = 'L';
      if ( this->len & TPORT_IS_MCAST    ) buf[ j++ ] = 'M';
      if ( this->len & TPORT_IS_MESH     ) buf[ j++ ] = 'X';
      if ( this->len & TPORT_IS_CONNECT  ) buf[ j++ ] = 'C';
      if ( this->len & TPORT_IS_SHUTDOWN ) buf[ j++ ] = '-';
      buf[ j ] = '\0';
      return buf;
    }
    default:
      return "";
  }
}

void
Console::print_dashes( const uint32_t *width,  uint32_t ncols ) noexcept
{
  for ( uint32_t j = 0; j < ncols; j++ ) {
    char dashes[ 84 ];
    ::memset( dashes, '-', width[ j ] + 3 );
    if ( j < ncols - 1 ) {
      dashes[ width[ j ] + 1 ] = '+';
      dashes[ width[ j ] + 3 ] = '\0';
    }
    else {
      dashes[ width[ j ] + 0 ] = '\n';
      dashes[ width[ j ] + 1 ] = '\0';
    }
    this->puts( dashes );
  }
}

void
Console::print_table( const char **hdr,  uint32_t ncols ) noexcept
{
  uint32_t     i, j,
               tabsz = this->table.count;
  TabPrint   * tab   = this->table.ptr;
  UserDB     & u     = this->user_db;
  uint32_t     width[ 64 ];
  char         buf[ 80 ];
  const char * v, * fmt;

  for ( j = 0; j < ncols; j++ ) {
    width[ j ] = ::strlen( hdr[ j ] );
  }
  for ( i = 0; i < tabsz; i += ncols ) {
    for ( j = 0; j < ncols; j++ ) {
      uint32_t w = tab[ i + j ].width( u, buf );
      width[ j ] = max( width[ j ], w );
    }
  }
  for ( j = 0; j < ncols; j++ ) {
    uint32_t len = ::strlen( hdr[ j ] );
    if ( width[ j ] > len ) {
      uint32_t back = len / 2,        front = len - back,
               wb   = width[ j ] / 2, wf    = width[ j ] - wb;
      front += wf;
      this->printf( "%*s%*s", front, hdr[ j ], width[ j ] - front, "" );
    }
    else {
      this->puts( hdr[ j ] );
    }
    this->puts( ( j < ncols - 1 ) ? " | " : "\n" );
  }
  this->print_dashes( width, ncols );

  for ( i = 0; i < tabsz; i += ncols ) {
    bool overflow = false;
    for ( j = 0; j < ncols; j++ ) {
      v   = tab[ i + j ].string( buf );
      fmt = ( tab[ i + j ].left() ? "%-*s%s" : "%*s%s" );
      this->printf( fmt, width[ j ], v,
                    ( j < ncols - 1 ) ? " | " : "\n" );
      if ( tab[ i + j ].type() == PRINT_STRING &&
           tab[ i + j ].len > width[ j ] )
        overflow = true;
    }
    if ( overflow ) {
      uint32_t n = 1;
      do {
        overflow = false;
        for ( j = 0; j < ncols; j++ ) {
          v = "";
          if ( tab[ i + j ].type() == PRINT_STRING &&
               tab[ i + j ].len > n * width[ j ] ) {
            v = &tab[ i + j ].val[ n * width[ j ] ];
            if ( tab[ i + j ].len > ( n + 1 ) * width[ j ] ) {
              overflow = true;
              ::memcpy( buf, v, width[ j ] );
              buf[ width[ j ] ] = '\0';
              v = buf;
            }
          }
          fmt = ( tab[ i + j ].left() ? "%-*s%s" : "%*s%s" );
          this->printf( fmt, width[ j ], v,
                        ( j < ncols - 1 ) ? " | " : "\n" );
        }
        n++;
      } while ( overflow );
    }
    if ( tab[ i + ncols - 1 ].separator() )
      this->print_dashes( width, ncols );
  }
}

UserBridge *
Console::find_user( const char *name,  size_t len ) noexcept
{
  if ( len > 0 ) {
    for ( uint32_t uid = 0; uid < this->user_db.next_uid; uid++ ) {
      UserBridge * n = this->user_db.bridge_tab[ uid ];
      if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) {
        if ( n->peer.user.equals( name, len ) )
          return n;
      }
    }
  }
  return NULL;
}

bool
Console::on_input( ConsoleOutput *p,  const char *buf,
                   size_t buflen ) noexcept
{
  ConsoleCmd cmd = CMD_BAD;
  if ( 0 ) {
  help:;
    if ( cmd != CMD_BAD ) {
      this->output_help( cmd );
    }
    else {
      for ( size_t i = 0; i < num_help_cmds; i++ )
        this->output_help( help_cmd[ i ].cmd );
    }
    return this->flush_output();
  }
  const char * args[ MAXARGS ]; /* all args */
  size_t       arglen[ MAXARGS ], argc;
  const char * arg;   /* arg after command */
  size_t       len;   /* len of arg */
  cmd = (ConsoleCmd)
    this->parse_command( buf, &buf[ buflen ], arg, len, args, arglen, argc );
  /* empty line, skip it */
  if ( cmd == CMD_EMPTY )
    return this->flush_output();

  switch ( cmd ) {
    default:
      goto help;

    case CMD_QUIT: {
      bool b = this->flush_output();
      p->on_quit();
      return b;
    }
    case CMD_CONNECT:  this->connect( arg, len ); break;
    case CMD_LISTEN:   this->listen( arg, len ); break;
    case CMD_SHUTDOWN: this->shutdown( arg, len ); break;
      break;
    case CMD_CONFIGURE_TPORT:
      if ( len == 0 || argc < 3 )
        goto help;
      this->config_tport( arg, len, &args[ 3 ], &arglen[ 3 ], argc - 3 );
      break;
    case CMD_SAVE:
      this->config_save();
      break;
    case CMD_TPORT_NAME:
      if ( argc < 1 )
        goto help;
      this->string_tab.reref_string( args[ 1 ], arglen[ 1 ],
                                     this->cfg_tport->tport );
      break;
    case CMD_TPORT_TYPE:
      if ( argc < 1 )
        goto help;
      this->string_tab.reref_string( args[ 1 ], arglen[ 1 ],
                                     this->cfg_tport->type );
      break;
    case CMD_TPORT_LISTEN:
    case CMD_TPORT_CONNECT:
    case CMD_TPORT_PORT:
    case CMD_TPORT_TIMEOUT:
    case CMD_TPORT_MTU:
    case CMD_TPORT_TXW_SQNS:
    case CMD_TPORT_RXW_SQNS:
    case CMD_TPORT_MCAST_LOOP:
    case CMD_TPORT_EDGE:
      if ( argc < 1 )
        goto help;
      this->config_tport_route( args[ 0 ], arglen[ 0 ],
                                args[ 1 ], arglen[ 1 ] );
      break;
    case CMD_TPORT_SHOW:
      this->cfg_tport->print_y( *this, 0 );
      break;
    case CMD_TPORT_QUIT:
      this->changes.add( this->cfg_tport );
      this->cfg_tport = NULL;
      this->change_prompt( NULL, 0 );
      break;

    case CMD_CONFIGURE_PARAM:
      if ( len == 0 || argc < 3 )
        goto help;
      if ( argc == 3 ) {
        args[ 3 ] = NULL;
        arglen[ 3 ] = 0;
      }
      this->config_param( arg, len, args[ 3 ], arglen[ 3 ] );
      break;
    case CMD_MUTE_LOG:
      this->mute_log = true;
      break;
    case CMD_UNMUTE_LOG:
      this->mute_log = false;
      break;

    case CMD_SHOW_PEERS:     this->show_peers();     break;
    case CMD_SHOW_PORTS:     this->show_ports( arg, len ); break;
    case CMD_SHOW_STATUS:    this->show_status( arg, len ); break;
    case CMD_SHOW_ADJACENCY: this->show_adjacency(); break;
    case CMD_SHOW_ROUTES:    this->show_routes();    break;
    case CMD_SHOW_URLS:      this->show_urls();      break;
    case CMD_SHOW_TPORTS:    this->show_tports( arg, len ); break;
    case CMD_SHOW_USERS:     this->show_users();     break;
    case CMD_SHOW_EVENTS:    this->show_events();    break;
    case CMD_SHOW_UNKNOWN:   this->show_unknown();   break;
    case CMD_SHOW_LOG:
      this->colorize_log( this->log.ptr, this->log_index );
      break;
    case CMD_SHOW_COUNTERS:  this->show_counters();  break;
    case CMD_SHOW_REACHABLE: this->show_reachable(); break;
    case CMD_SHOW_TREE:
      this->show_tree( this->find_user( arg, len ) );
      break;
    case CMD_SHOW_PRIMARY:   this->show_primary();   break;
    case CMD_SHOW_FDS:       this->show_fds();       break;
    case CMD_SHOW_BLOOMS:    this->show_blooms();    break;
    case CMD_SHOW_RUN:
      this->show_running( PRINT_NORMAL, arg, len ); break;
    case CMD_SHOW_RUN_TPORTS:
      this->show_running( PRINT_TRANSPORTS | PRINT_HDR, arg, len ); break;
    case CMD_SHOW_RUN_SVCS:
      this->show_running( PRINT_SERVICES | PRINT_HDR, arg, len ); break;
    case CMD_SHOW_RUN_USERS:
      this->show_running( PRINT_USERS | PRINT_HDR, arg, len ); break;
    case CMD_SHOW_RUN_GROUPS:
      this->show_running( PRINT_GROUPS | PRINT_HDR, arg, len ); break;
    case CMD_SHOW_RUN_PARAM:
      this->show_running( PRINT_PARAMETERS | PRINT_HDR, arg, len ); break;

    case CMD_DEBUG:
      if ( len == 0 )
        goto help;
      if ( len >= 4 && ::memcmp( arg, "dist", 4 ) == 0 ) {
        this->user_db.peer_dist.invalidate( INVALID_NONE );
        this->printf( "recalculate peer dist\n" );
      }
      else if ( len >= 2 && ::memcmp( arg, "kv", 2 ) == 0 ) {
        kv_debug = ! kv_debug;
        this->printf( "kv debug %s\n", kv_debug ? "on" : "off" );
      }
      else if ( len >= 2 && ::memcmp( arg, "rv", 2 ) == 0 ) {
        sassrv::rv_debug = ! sassrv::rv_debug;
        this->printf( "rv debug %s\n", sassrv::rv_debug ? "on" : "off" );
      }
      else {
        dbg_flags = string_to_uint64( arg, len );
        char buf[ 80 ];
        size_t sz = 0;
        for ( size_t i = 0; i < debug_str_count; i++ ) {
          if ( ( dbg_flags & ( 1 << i ) ) != 0 ) {
            if ( sz > 0 )
              sz = cat80( buf, sz, "," );
            sz = cat80( buf, sz, debug_str[ i ] );
          }
        }
        if ( sz > 0 ) {
          buf[ sz ] = '\0';
          this->printf( "debug flags set to 0x%x (%s)\n", dbg_flags, buf );
        }
        else {
          this->printf( "debug flags cleared\n" );
        }
      }
      break;

    case CMD_CANCEL:
      for ( ConsoleRPC *rpc = this->rpc_list.hd; rpc != NULL; rpc = rpc->next ){
        if ( ! rpc->complete ) {
          if ( rpc->type == PING_RPC ) {
            rpc->complete = true;
            this->on_ping( *(ConsolePing *) rpc );
          }
          else if ( rpc->type == SUBS_RPC ) {
            rpc->complete = true;
            this->on_subs( *(ConsoleSubs *) rpc );
          }
        }
      }
      break;

    case CMD_SHOW_SUBS: this->show_subs( arg, len ); break;
    case CMD_PING:      this->ping_peer( arg, len ); break;
    case CMD_MPING:     this->mcast_ping();             break;

    case CMD_SUB_START: /* sub */
      if ( len == 0 )
        goto help;
      this->printf( "start(%.*s) seqno = %lu\n", (int) len, arg,
        this->sub_db.internal_sub_start( arg, len, this ) );
      break;
    case CMD_SUB_STOP: /* unsub */
      if ( len == 0 )
        goto help;
      this->printf( "stop(%.*s) seqno = %lu\n", 
        (int) len, arg, this->sub_db.internal_sub_stop( arg, len ) );
      break;
    case CMD_PSUB_START: /* psub */
      if ( len == 0 )
        goto help;
      this->printf( "pstart(%.*s) seqno = %lu\n", 
        (int) len, arg,
        this->sub_db.internal_psub_start( arg, len, RV_PATTERN_FMT, this ) );
      break;
    case CMD_PSUB_STOP: /* pstop */
      if ( len == 0 )
        goto help;
      this->printf( "pstop(%.*s) seqno = %lu\n", 
        (int) len, arg,
        this->sub_db.internal_psub_stop( arg, len, RV_PATTERN_FMT ) );
      break;
    case CMD_GSUB_START: /* gsub */
      if ( len == 0 )
        goto help;
      this->printf( "gstart(%.*s) seqno = %lu\n", 
        (int) len, arg,
        this->sub_db.internal_psub_start( arg, len, GLOB_PATTERN_FMT, this ) );
      break;
    case CMD_GSUB_STOP: /* gstop */
      if ( len == 0 )
        goto help;
      this->printf( "gstop(%.*s) seqno = %lu\n", 
        (int) len, arg,
        this->sub_db.internal_psub_stop( arg, len, GLOB_PATTERN_FMT ) );
      break;

    case CMD_RPC:
    case CMD_ANY:
    case CMD_PUBLISH:
    case CMD_TRACE:
    case CMD_PUB_ACK: { /* pub */
      if ( len == 0 )
        goto help;
      const char * data = &arg[ len ];
      size_t datalen    = &buf[ buflen ] - data;
      while ( datalen > 0 && *data == ' ' ) {
        data++;
        datalen--;
      }
      while ( datalen > 0 && data[ datalen - 1 ] <= ' ' )
        datalen--;
      if ( datalen == 0 )
        goto help;
      this->printf( "pub(%.*s) \"%.*s\"\n", 
        (int) len, arg, (int) datalen, data );

      PubMcastData mc( arg, len, data, datalen, MD_STRING );
      if ( cmd != CMD_PUBLISH ) {
        if ( this->inbox_num == 0 )
          this->inbox_num = this->sub_db.inbox_start( 0, this );
        mc.reply = this->inbox_num;
        if ( cmd == CMD_TRACE )
          mc.option = CABA_OPT_TRACE;
        else if ( cmd == CMD_PUB_ACK )
          mc.option = CABA_OPT_ACK;
        else if ( cmd == CMD_ANY )
          mc.option = CABA_OPT_ANY;
        if ( cmd == CMD_TRACE || cmd == CMD_PUB_ACK )
          mc.time  = current_realtime_ns();
      }
      this->mgr.publish( mc );
      break;
    }
  }
  return this->flush_output();
}

enum {
  T_NO_EXIST   = 0,
  T_CFG_EXISTS = 1,
  T_IS_RUNNING = 2,
  T_IS_DOWN    = 3
};

int
Console::find_tport( const char *name,  uint32_t len,
                     ConfigTree::Transport *&tree_idx,
                     uint32_t &tport_id ) noexcept
{
  if ( len > 0 ) {
    ConfigTree::Transport * tport = this->tree.find_transport( name, len );
    TransportRoute * rte = this->user_db.transport_tab.find_transport( tport );
    if ( rte != NULL ) {
      tree_idx = tport;
      tport_id = rte->tport_id;
      if ( rte->is_set( TPORT_IS_SHUTDOWN ) )
        return T_IS_DOWN;
      this->printf( "transport \"%.*s\" is running tport %u\n",
                    (int) len, name, tport_id );
      return T_IS_RUNNING;
    }
    tree_idx = tport;
    tport_id = this->user_db.transport_tab.count;
    return T_CFG_EXISTS;
  }
  this->printf( "transport \"%.*s\" not found\n", (int) len, name );
  return T_NO_EXIST;
}

void
Console::connect( const char *name,  uint32_t len ) noexcept
{
  ConfigTree::Transport * tree_idx = NULL;
  uint32_t tport_id;
  int res = this->find_tport( name, len, tree_idx, tport_id );
  bool b;
  if ( res == T_NO_EXIST || res == T_IS_RUNNING ) {
    if ( res == T_IS_RUNNING ) {
      TransportRoute *rte = this->user_db.transport_tab[ tport_id ];
      if ( rte->transport.type.equals( "mesh" ) )
        b = this->mgr.start_transport( *rte, false );
    }
    return;
  }
  if ( res == T_IS_DOWN ) {
    TransportRoute *rte = this->user_db.transport_tab[ tport_id ];
    b = this->mgr.start_transport( *rte, false );
  }
  else {
    b = this->mgr.add_transport( this->mgr.svc, *tree_idx, false );
  }
  if ( b )
    this->printf( "transport \"%.*s\" started connecting\n", (int) len, name );
  else
    this->printf( "transport \"%.*s\" connect failed\n", (int) len, name );
}

void
Console::listen( const char *name,  uint32_t len ) noexcept
{
  ConfigTree::Transport * tree_idx = NULL;
  uint32_t tport_id;
  int res = this->find_tport( name, len, tree_idx, tport_id );
  bool b;
  if ( res == T_NO_EXIST || res == T_IS_RUNNING )
    return;
  if ( res == T_IS_DOWN ) {
    TransportRoute *rte = this->user_db.transport_tab[ tport_id ];
    b = this->mgr.start_transport( *rte, true );
  }
  else {
    b = this->mgr.add_transport( this->mgr.svc, *tree_idx, true );
  }
  if ( b )
    this->printf( "transport \"%.*s\" started listening\n", (int) len, name );
  else
    this->printf( "transport \"%.*s\" listen failed\n", (int) len, name );
}

void
Console::shutdown( const char *name,  uint32_t len ) noexcept
{
  ConfigTree::Transport * tree_idx = NULL;
  uint32_t tport_id;
  int res = this->find_tport( name, len, tree_idx, tport_id );
  if ( res == T_NO_EXIST )
    return;
  /*if ( res != T_IS_RUNNING ) {
    this->printf( "transport \"%.*s\" not running\n", (int) len, name );
    return;
  }*/
  uint32_t count = this->mgr.shutdown_transport( this->mgr.svc, *tree_idx );
  if ( count > 0 )
    this->printf( "transport \"%.*s\" shutdown (%u instances down)\n",
                  (int) len, name, count );
  else
    this->printf( "no transport \"%.*s\" running\n", (int) len, name );
}

void
Console::get_active_tports( ConfigTree::TransportArray &listen,
                            ConfigTree::TransportArray &connect ) noexcept
{
  ConfigTree::Transport * tport;
  for ( tport = this->tree.transports.hd; tport != NULL; tport = tport->next ) {
    uint32_t count = this->user_db.transport_tab.count;
    for ( uint32_t t = 0; t < count; t++ ) {
      TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];
      if ( &rte->transport == tport ) {
        if ( ! rte->is_set( TPORT_IS_SHUTDOWN ) ) {
          if ( rte->is_set( TPORT_IS_LISTEN ) )
            listen.push( tport );
          else
            connect.push( tport );
        }
        break;
      }
    }
  }
  if ( this->mgr.telnet != NULL &&
       this->mgr.telnet->in_list( IN_ACTIVE_LIST ) ) {
    listen.push( this->mgr.telnet_tport );
  }
}

void
Console::config_save( void ) noexcept
{
  ConfigChange * c;
  ConfigTree::TransportArray listen, connect;

  for ( c = this->changes.hd; c != NULL; c = c->next ) {
    if ( c->tport != NULL )
      if ( this->tree.save_tport( *c->tport ) != 0 )
        return;
  }
  this->get_active_tports( listen, connect );
  if ( this->tree.save_parameters( listen, connect ) != 0 )
    return;
  if ( this->tree.save_new() ) {
    this->changes.release();
    this->printf( "config saved\n" );
  }
  else {
    this->printf( "failed to save config updates\n" );
  }
}

void
Console::config_param( const char *param, size_t plen,
                       const char *value, size_t vlen ) noexcept
{
  ConfigTree::Parameters *p;
  ConfigTree::StringPair *sp;
  for ( p = this->tree.parameters.hd; p != NULL; p = p->next ) {
    sp = p->parms.get_pair( param, plen );
    if ( sp != NULL ) {
      if ( vlen > 0 )
        this->string_tab.reref_string( value, vlen, sp->value );
      else {
        p->parms.unlink( sp );
        this->free_pairs.push_tl( sp );
      }
      return;
    }
  }
  if ( vlen == 0 ) {
    this->printf( "notfound: %.*s\n", (int) plen, param );
  }
  else {
    p = this->string_tab.make<ConfigTree::Parameters>();
    if ( this->free_pairs.is_empty() )
      sp = this->string_tab.make<ConfigTree::StringPair>();
    else
      sp = this->free_pairs.pop_hd();
    this->string_tab.ref_string( param, plen, sp->name );
    this->string_tab.ref_string( value, vlen, sp->value );
    p->parms.push_tl( sp );
    this->tree.parameters.push_tl( p );
  }
}

void
Console::change_prompt( const char *param,  size_t plen ) noexcept
{
  this->update_prompt( param, plen );
  for ( ConsoleOutput *o = this->term_list.hd; o!= NULL; o = o->next )
    o->on_prompt( this->prompt );
}

void
Console::config_tport( const char *param,  size_t plen,
                       const char **,  size_t *,
                       size_t ) noexcept
{
  this->change_prompt( param, plen );
  this->cfg_tport = this->tree.find_transport( param, plen );
  if ( this->cfg_tport == NULL ) {
    this->cfg_tport = this->string_tab.make<ConfigTree::Transport>();
    this->string_tab.ref_string( param, plen, this->cfg_tport->tport );
    this->cfg_tport->tport_id = this->tree.transport_cnt++;
    this->tree.transports.push_tl( this->cfg_tport );
  }
}

void
Console::config_tport_route( const char *param, size_t plen,
                             const char *value, size_t vlen ) noexcept
{
  ConfigTree::StringPair *sp = this->cfg_tport->route.get_pair( param, plen );
  if ( sp == NULL ) {
    if ( this->free_pairs.is_empty() )
      sp = this->string_tab.make<ConfigTree::StringPair>();
    else
      sp = this->free_pairs.pop_hd();
    this->string_tab.ref_string( param, plen, sp->name );
    this->cfg_tport->route.push_tl( sp );
  }
  this->string_tab.reref_string( value, vlen, sp->value );
}

void
Console::show_subs( const char *arg,  uint32_t arglen ) noexcept
{
  UserBridge  * n;
  char          isub[ UserDB::INBOX_BASE_SIZE + sizeof( _SUBS ) ];
  uint32_t      len;
  ConsoleSubs * rpc = this->create_rpc<ConsoleSubs>( SUBS_RPC );

  for ( uint32_t uid = 0; uid < this->user_db.next_uid; uid++ ) {
    n = this->user_db.bridge_tab[ uid ];
    if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) {
      if ( arglen != 0 ) {
        if ( ! n->peer.user.equals( arg, arglen ) )
          continue;
      }
      if ( n->sub_seqno > 0 ) { /* must have subs seqno */
        len = n->make_inbox_subject( isub, _SUBS );

        PubMcastData mc( isub, len, NULL, 0, MD_NODATA );
        mc.reply = rpc->inbox_num;
        mc.time  = current_realtime_ns();
        mc.token = rpc->token;
        this->mgr.publish( mc );
        rpc->count++;
      }
    }
  }
  if ( rpc->count == 0 ) {
    rpc->complete = true;
    this->on_subs( *(ConsoleSubs *) rpc );
  }
}

void
Console::ping_peer( const char *arg,  uint32_t arglen ) noexcept
{
  UserBridge  * n;
  char          isub[ UserDB::INBOX_BASE_SIZE + sizeof( _PING ) ];
  uint32_t      len;
  ConsolePing * rpc = this->create_rpc<ConsolePing>( PING_RPC );

  for ( uint32_t uid = 0; uid < this->user_db.next_uid; uid++ ) {
    n = this->user_db.bridge_tab[ uid ];
    if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) {
      if ( arglen != 0 ) {
        if ( ! n->peer.user.equals( arg, arglen ) )
          continue;
      }
      len = n->make_inbox_subject( isub, _PING );

      PubMcastData mc( isub, len, NULL, 0, MD_NODATA );
      mc.reply = rpc->inbox_num;
      mc.time  = current_realtime_ns();
      mc.token = rpc->token;
      this->mgr.publish( mc );
      rpc->count++;
    }
  }
  if ( rpc->count == 0 ) {
    rpc->complete = true;
    if ( arglen > 0 )
      this->printf( "no users matched \"%.*s\"\n", (int) arglen, arg );
    else
      this->printf( "no users\n" );
  }
  else {
    rpc->reply.zero();
    rpc->reply.make( rpc->count, true );
  }
}

void
Console::mcast_ping( void ) noexcept
{
  ConsolePing * rpc = this->create_rpc<ConsolePing>( PING_RPC );

  rpc->count = this->user_db.uid_auth_count;
  if ( rpc->count == 0 ) {
    rpc->complete = true;
    this->printf( "no users\n" );
  }
  else {
    static const char m_ping[] = _MCAST "." _PING;
    PubMcastData mc( m_ping, sizeof( m_ping ) - 1, NULL, 0, MD_NODATA );
    mc.reply = rpc->inbox_num;
    mc.time  = current_realtime_ns();
    mc.token = rpc->token;
    this->mgr.publish( mc );
    rpc->reply.zero();
    rpc->reply.make( rpc->count, true );
  }
}

void
Console::on_ping( ConsolePing &ping ) noexcept
{
  static const uint32_t ncols = 4;
  uint32_t p, i = 0;
  this->table.count = ping.count * ncols;
  TabPrint * tab = this->table.make( this->table.count );
  for ( p = 0; p < ping.count; p++ ) {
    PingReply & reply = ping.reply.ptr[ p ];
    bool no_route = true;
    if ( reply.uid < this->user_db.bridge_tab.count ) {
      UserBridge * n = this->user_db.bridge_tab[ reply.uid ];
      if ( n != NULL ) {
        tab[ i++ ].set( n->peer.user, reply.uid, PRINT_ID );
        tab[ i++ ].set( n, PRINT_DIST );
        no_route = false;
      }
    }
    if ( no_route ) {
      tab[ i++ ].set_null();
      tab[ i++ ].set_null();
    }
    tab[ i++ ].set_long( reply.recv_time - reply.sent_time, PRINT_LATENCY );

    if ( reply.tid < this->user_db.transport_tab.count ) {
      TransportRoute *rte = this->user_db.transport_tab.ptr[ reply.tid ];
      tab[ i++ ].set( rte->transport.tport, reply.tid, PRINT_ID );
    }
    else
      tab[ i++ ].set_null();
  }
  this->table.count = i;
  static const char *hdr[ ncols ] = { "user", "dist", "lat", "tport" };
  this->print_table( hdr, ncols );
  this->flush_output();
}

void
Console::on_subs( ConsoleSubs &subs ) noexcept
{
  static const uint32_t ncols = 2;
  uint32_t s, i = 0, uid;
  BitSpace users;
  this->table.count = subs.reply.count * ncols;
  SubListIter iter( this->sub_db.sub_list, 0, this->sub_db.sub_seqno );
  this->table.count += iter.count();

  TabPrint * tab = this->table.make( this->table.count );
  for ( bool ok = iter.first(); ok; ok = iter.next() ) {
    if ( i == 0 )
      tab[ i++ ].set( this->user_db.user.user, PRINT_SELF ); /* user */
    else
      tab[ i++ ].set_null();
    if ( iter.action == ACTION_SUB_JOIN ) {
      SubRoute * sub;
      sub = this->sub_db.sub_tab.find_sub( iter.hash, iter.seqno );
      if ( sub != NULL ) {
        tab[ i++ ].set( sub->value, sub->len );
      }
    }
    else {
      PatRoute * pat;
      pat = this->sub_db.pat_tab.find_sub( iter.hash, iter.seqno );
      if ( pat != NULL ) {
        this->tab_concat( pat->value, pat->len, "p", tab[ i++ ] );
      }
    }
  }
  for ( s = 0; s < subs.reply.count; s++ ) {
    SubsReply & reply = subs.reply.ptr[ s ];
    users.add( reply.uid );
  }
  for ( bool ok = users.first( uid ); ok; ok = users.next( uid ) ) {
    uint32_t last_uid = 0;
    for ( s = 0; s < subs.reply.count; s++ ) {
      SubsReply & reply = subs.reply.ptr[ s ];
      if ( reply.uid != uid )
        continue;
      bool no_user = true;
      if ( last_uid == 0 && reply.uid < this->user_db.bridge_tab.count ) {
        UserBridge * n = this->user_db.bridge_tab[ reply.uid ];
        if ( n != NULL ) {
          if ( i > 0 )
            tab[ i - 1 ].typ |= PRINT_SEP;
          tab[ i++ ].set( n->peer.user, reply.uid, PRINT_ID );
          no_user = false;
        }
        last_uid = reply.uid;
      }
      if ( no_user )
        tab[ i++ ].set_null();
      const char *str = &subs.strings.ptr[ reply.sub_off ];
      if ( ! reply.is_pattern )
        tab[ i++ ].set( str, reply.sub_len );
      else
        this->tab_concat( str, "p", tab[ i++ ] );
    }
  }

  this->table.count = i;
  static const char *hdr[ ncols ] = { "user", "sub" };
  this->print_table( hdr, ncols );
  this->flush_output();
}

void
Console::show_users( void ) noexcept
{
  uint32_t i = 0;
  static const uint32_t ncols = 5;
  this->table.count = this->tree.user_cnt * ncols;
  TabPrint * tab = this->table.make( this->table.count );
  for ( ConfigTree::User *user = this->tree.users.hd; user != NULL;
        user = user->next ) {
    UserBridge * n = this->find_user( user->user.val, user->user.len );
    if ( n == NULL )
      tab[ i++ ].set_null();
    else
      tab[ i++ ].set_int( n->uid );
    tab[ i++ ].set( user->user );
    tab[ i++ ].set( user->svc );
    tab[ i++ ].set( user->create );
    tab[ i++ ].set( user->expires );
  }
  static const char *hdr[ ncols ] = { "uid", "user", "svc", "create",
                                      "expires" };
  this->print_table( hdr, ncols );
}

void
Console::show_events( void ) noexcept
{
  const EventRec * ev;
  uint32_t n, i = 0, tid, uid;
  const char * s, * s2;
  char buf[ 32 ];
  static const uint32_t ncols = 6;
  this->table.count = this->mgr.events.num_events() * ncols;
  TabPrint * tab = this->table.make( this->table.count );
  for ( ev = this->mgr.events.first( n ); ev != NULL;
        ev = this->mgr.events.next( n ) ) {

    tab[ i++ ].set_time( ev->stamp ); /* stamp */
    if ( ev->has_tport( tid ) &&
         tid < this->user_db.transport_tab.count ) { /* tport */
      TransportRoute *rte = this->user_db.transport_tab.ptr[ tid ];
      tab[ i++ ].set( rte->transport.tport, tid, PRINT_ID );
    }
    else if ( ev->is_flood() )
      tab[ i++ ].set( "(mcast)", 7 );
    else
      tab[ i++ ].set_null();

    this->tab_user_id( ev->source_uid, tab[ i++ ] ); /* user */

    if ( ev->has_peer( uid ) ) /* source */
      this->tab_user_id( uid, tab[ i++ ] ); /* peer */
    else if ( ev->is_ecdh() )
      tab[ i++ ].set( "(ecdh)", 6 );
    else 
      tab[ i++ ].set_null();

    tab[ i++ ].set( event_strings[ ev->event_type() ].val,
                    event_strings[ ev->event_type() ].len ); /* event */
    if ( (s = ev->data_tag( this->string_tab, buf )) != NULL ) { /* data */
      if ( (s2 = ev->reason_str()) != NULL )
        this->tab_concat( s, s2, tab[ i++ ] );
      else
        tab[ i++ ].set( s );
    }
    else if ( (s = ev->reason_str()) != NULL )
      tab[ i++ ].set( s );
    else
      tab[ i++ ].set_null();
  }
  static const char *hdr[ ncols ] = { "stamp", "tport", "user", "peer", "event",
                                      "data" };
  this->print_table( hdr, ncols );
}

void
Console::show_unknown( void ) noexcept
{
  const AdjPending * u;
  uint32_t i = 0, count = 0;
  for ( u = this->user_db.adjacency_unknown.hd; u != NULL; u = u->next )
    count++;
  if ( count == 0 ) {
    this->printf( "empty\n" );
    return;
  }
  static const uint32_t ncols = 6;
  this->table.count = count * ncols;
  TabPrint * tab = this->table.make( this->table.count );
  for ( u = this->user_db.adjacency_unknown.hd; u != NULL; u = u->next ) {
    tab[ i++ ].set( u->rte.transport.tport, u->rte.tport_id ); /* tport */
    this->tab_nonce( u->nonce, tab[ i++ ] ); /* bridge */
    if ( u->uid != 0 )
      this->tab_user_id( u->uid, tab[ i++ ] ); /* source */
    else
      tab[ i++ ].set_null();
    tab[ i++ ].set( u->tport_sv ); /* adj_tp */
    tab[ i++ ].set( u->user_sv );  /* unknown user */
    tab[ i++ ].set( peer_sync_reason_string( u->reason ) ); /* reason */
    tab[ i-1 ].typ |= PRINT_LEFT;
  }
  static const char *hdr[ ncols ] = { "tport", "bridge", "source",
                                      "adj_tp", "user", "reason" };
  this->print_table( hdr, ncols );
}

PortOutput::PortOutput( Console &c,  uint32_t t,  uint32_t nc ) noexcept :
    console( c ), mgr( c.mgr ), user_db( c.user_db ),
    tport_id( t ), ncols( nc ) {}

void
PortOutput::init( TransportRoute *rte,  int fl,  int fd,
                  UserBridge *user ) noexcept
{
  this->stats.zero(); 
  this->rte   = rte;
  this->type  = &rte->transport.type;
  this->tport = &rte->transport.tport;
  this->state = rte->state;
  this->n     = user;
  this->fd    = fd;
  this->flags = fl;
  this->local.zero();
  this->remote.zero();
}

void
PortOutput::init( TransportRoute *rte,  ExtRte *ext ) noexcept
{
  this->stats.zero(); 
  this->rte   = rte;
  this->type  = &ext->transport.type;
  this->tport = &ext->transport.tport;
  this->state = rte->state;
  this->n     = NULL;
  this->fd    = ext->listener->fd;
  this->flags = P_IS_LOCAL;
  this->local.zero();
  this->remote.zero();
}

uint32_t
PortOutput::output( void ( PortOutput::*put )( void ) ) noexcept
{
  uint32_t mcast_fd, ucast_fd;
  EvPoll & poll = this->mgr.poll;

  TransportRoute *rte = this->user_db.transport_tab.ptr[ this->tport_id ];
  if ( rte->is_set( TPORT_IS_SHUTDOWN ) ) {
    this->init( rte, P_IS_DOWN, -1 );
    (this->*put)();
  }
  else if ( rte->is_set( TPORT_IS_EXTERNAL ) ) {
    for ( ExtRte * ext = rte->ext->list.hd; ext != NULL; ext = ext->next ) {
      this->init( rte, ext );
      ext->listener->client_stats( this->stats );
      this->local_addr( ext->listener->peer_address.buf );
      (this->*put)();
    }
  }
  else if ( rte->listener != NULL ) {
    this->init( rte, P_IS_LOCAL, rte->listener->fd );
    rte->listener->client_stats( this->stats );
    this->local_addr( rte->listener->peer_address.buf );
    (this->*put)();
  }
  else if ( rte->is_mcast() ) {
    mcast_fd = rte->mcast_fd;
    ucast_fd = rte->inbox_fd;
    this->init( rte, P_IS_LOCAL, mcast_fd );

    if ( mcast_fd < poll.maxfd && poll.sock[ mcast_fd ] != NULL ) {
      this->local_addr( poll.sock[ mcast_fd ]->peer_address.buf );
      poll.sock[ mcast_fd ]->client_stats( this->stats );
    }
    (this->*put)();
    this->init( rte, P_IS_LOCAL | P_IS_INBOX, ucast_fd );
    if ( ucast_fd < poll.maxfd && poll.sock[ ucast_fd ] != NULL ) {
      this->local_addr( poll.sock[ ucast_fd ]->peer_address.buf );
      poll.sock[ ucast_fd ]->client_stats( this->stats );
    }
    (this->*put)();
  }

  uint32_t uid;
  for ( bool ok = rte->uid_connected.first( uid ); ok;
        ok = rte->uid_connected.next( uid ) ) {
    UserBridge * n = this->user_db.bridge_tab[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;
    UserRoute * u_ptr = n->user_route_ptr( this->user_db, this->tport_id );
    if ( rte->is_mcast() ) {
      ucast_fd = u_ptr->inbox_fd;
      this->init( rte, P_IS_REMOTE | P_IS_INBOX, ucast_fd, n );
      this->stats.bytes_sent = u_ptr->bytes_sent;
      this->stats.msgs_sent  = u_ptr->msgs_sent;
      if ( u_ptr->is_set( UCAST_URL_STATE ) ) {
        const char *addr = u_ptr->ucast_url;
        uint32_t    len  = u_ptr->ucast_url_len;
        if ( len > sizeof( "inbox://" ) &&
             ::memcmp( "inbox://", addr, 8 ) == 0 ) {
          len -= 8; addr += 8;
        }
        this->remote_addr( addr, len );
      }
      (this->*put)();
    }
    else {
      mcast_fd = u_ptr->mcast_fd;
      this->init( rte, P_IS_REMOTE, mcast_fd, n );
      if ( mcast_fd < poll.maxfd && poll.sock[ mcast_fd ] != NULL ) {
        this->remote_addr( poll.sock[ mcast_fd ]->peer_address.buf );
        poll.sock[ mcast_fd ]->client_stats( this->stats );
      }
      (this->*put)();
    }
  }
  return this->console.table.count;
}

void
PortOutput::put_show_ports( void ) noexcept
{
  TabPrint *tab =
    this->console.table.make( this->console.table.count + this->ncols );
  uint32_t i = this->console.table.count;
  const char * type = this->type->val;
  if ( ( this->flags & P_IS_INBOX ) != 0 )
    type = "inbox";
  this->console.table.count += this->ncols;
  tab[ i++ ].set( *this->tport, this->tport_id, PRINT_ID );
  tab[ i++ ].set( type ); /* type */
  if ( ( this->flags & P_IS_DOWN ) == 0 )
    tab[ i++ ].set_int( this->fd ); /* fd */
  else
    tab[ i++ ].set_null();
  if ( this->stats.bytes_sent != 0 )
    tab[ i++ ].set_long( this->stats.bytes_sent ); /* bs */
  else
    tab[ i++ ].set_null();
  if ( this->stats.bytes_recv != 0 )
    tab[ i++ ].set_long( this->stats.bytes_recv ); /* br */
  else
    tab[ i++ ].set_null();
  if ( this->stats.msgs_sent != 0 )
    tab[ i++ ].set_long( this->stats.msgs_sent ); /* ms */
  else
    tab[ i++ ].set_null();
  if ( this->stats.msgs_recv != 0 )
    tab[ i++ ].set_long( this->stats.msgs_recv ); /* mr */
  else
    tab[ i++ ].set_null();
  if ( this->n != NULL && this->n->round_trip_time != 0 )
    tab[ i++ ].set_long( this->n->round_trip_time, PRINT_LATENCY ); /* lat */
  else
    tab[ i++ ].set_null();

  tab[ i++ ].set_int( this->state, PRINT_TSTATE );

  if ( ( this->flags & P_IS_DOWN ) != 0 ) {
    tab[ i++ ].set_null();
  }
  else if ( ( this->flags & P_IS_LOCAL ) != 0 ) { /* address */
    if ( ! this->local.is_null() )
      tab[ i++ ].set_url( type, this->local );
    else
      tab[ i++ ].set_null();
  }
  else {
    if ( ! this->remote.is_null() && this->n != NULL )
      tab[ i++ ].set_url_dest( this->n, type, this->remote );
    else
      tab[ i++ ].set_null();
  }
}

void
Console::show_ports( const char *name,  size_t len ) noexcept
{
  static const uint32_t ncols = 10;
  uint32_t count = this->user_db.transport_tab.count;

  if ( len == 3 && ::memcmp( name, "all", 3 ) == 0 )
    len = 0;
  this->table.count = 0;
  this->tmp.count = 0;
  for ( uint32_t t = 0; t < count; t++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];

    if ( len != 0 ) {
      if ( len != rte->transport.tport.len )
        continue;
      if ( ::memcmp( name, rte->transport.tport.val, len ) != 0 )
        continue;
    }
    PortOutput out( *this, t, ncols );
    out.output( &PortOutput::put_show_ports );
  }
  static const char *hdr[ ncols ] = { "tport", "type", "fd", "bs", "br", "ms",
                                      "mr", "lat", "fl", "address" };
  this->print_table( hdr, ncols );
}

void
PortOutput::put_status( void ) noexcept
{
  TabPrint *tab =
    this->console.table.make( this->console.table.count + this->ncols );
  uint32_t i = this->console.table.count;
  const char * type = this->type->val;
  if ( ( this->flags & P_IS_INBOX ) != 0 )
    type = "inbox";
  this->console.table.count += this->ncols;
  tab[ i++ ].set( *this->tport, this->tport_id, PRINT_ID );
  tab[ i++ ].set( type ); /* type */
  if ( ( this->flags & P_IS_DOWN ) == 0 )
    tab[ i++ ].set_int( this->fd ); /* fd */
  else
    tab[ i++ ].set_null();

  tab[ i++ ].set_int( this->state, PRINT_TSTATE );

  if ( ( this->flags & P_IS_DOWN ) != 0 ) {
    char status_buf[ 256 ];
    size_t len = this->rte->port_status( status_buf, sizeof( status_buf ) );
    if ( len != 0 )
      this->console.tab_string( status_buf, tab[ i++ ] );
    else
      tab[ i++ ].set_null();
  }
  else if ( ( this->flags & P_IS_LOCAL ) != 0 ) { /* address */
    if ( ! this->local.is_null() )
      tab[ i++ ].set_url( type, this->local );
    else
      tab[ i++ ].set_null();
  }
  else {
    if ( ! this->remote.is_null() && this->n != NULL )
      tab[ i++ ].set_url_dest( this->n, type, this->remote );
    else
      tab[ i++ ].set_null();
  }
  tab[ i-1 ].typ |= PRINT_LEFT;
}

void
Console::show_status( const char *name,  size_t len ) noexcept
{
  static const uint32_t ncols = 5;
  uint32_t count = this->user_db.transport_tab.count;

  if ( len == 3 && ::memcmp( name, "all", 3 ) == 0 )
    len = 0;
  this->table.count = 0;
  this->tmp.count = 0;
  for ( uint32_t t = 0; t < count; t++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];

    if ( len != 0 ) {
      if ( len != rte->transport.tport.len )
        continue;
      if ( ::memcmp( name, rte->transport.tport.val, len ) != 0 )
        continue;
    }
    PortOutput out( *this, t, ncols );
    out.output( &PortOutput::put_status );
  }
  static const char *hdr[ ncols ] = { "tport", "type", "fd", "fl", "status" };
  this->print_table( hdr, ncols );
}

void
Console::show_tports( const char *name,  size_t len ) noexcept
{
  static const uint32_t ncols = 5;
  uint32_t         i = 0, t, count = this->user_db.transport_tab.count;
  TabPrint       * tab;
  TransportRoute * rte;

  if ( len == 3 && ::memcmp( name, "all", 3 ) == 0 )
    len = 0;

  this->table.count = 0;
  this->tmp.count = 0;

  for ( ConfigTree::Transport * tport = this->tree.transports.hd;
        tport != NULL; tport = tport->next ) {
    if ( len != 0 ) {
      if ( len != tport->tport.len )
        continue;
      if ( ::memcmp( name, tport->tport.val, len ) != 0 )
        continue;
    }
    for ( t = 0; t < count; t++ ) {
      rte = this->user_db.transport_tab.ptr[ t ];
      if ( &rte->transport == tport )
        break;
    }
    if ( t == count )
      rte = NULL;

    const char * listen,
               * connect;
    int          port;
    tport->get_route_int( "port", port );
    tport->get_route_str( "listen", listen );
    tport->get_route_str( "connect", connect );

    char   buf[ 80 ];
    size_t len = sizeof( buf );
    bool   is_accepting = false;

    tab = this->table.make( this->table.count + ncols );
    this->table.count += ncols;
    tab[ i++ ].set( tport->tport ); /* tport */
    tab[ i++ ].set( tport->type );  /* type */

    if ( rte != NULL ) {
      is_accepting = ( rte->listener != NULL );
    }
    else if ( this->mgr.external_tport != NULL ) {
      for ( ExtRte *ext = this->mgr.external_tport->ext->list.hd; ext != NULL;
            ext = ext->next ) {
        if ( tport == &ext->transport ) {
          rte = this->mgr.external_tport;
          is_accepting = true;
          break;
        }
      }
    }
    if ( rte == NULL )
      tab[ i++ ].set( "-" ); /* state */
    else if ( rte->is_set( TPORT_IS_SHUTDOWN ) )
      tab[ i++ ].set( "shutdown" );
    else if ( is_accepting )
      tab[ i++ ].set( "accepting" );
    else if ( rte->is_set( TPORT_IS_EXTERNAL ) )
      tab[ i++ ].set( "external" );
    else if ( rte->is_mcast() )
      tab[ i++ ].set( "joined" );
    else
      tab[ i++ ].set( "connected" );

    if ( listen != NULL ) {
      size_t off = ::snprintf( buf, len, "%s://%s", tport->type.val, listen );
      if ( port != 0 )
        ::snprintf( &buf[ off ], len - off, ":%u", port );
      this->tab_string( buf, tab[ i++ ] ); /* listen */
    }
    else {
      tab[ i++ ].set_null();
    }
    if ( connect != NULL ) {
      size_t off = ::snprintf( buf, len, "%s://%s", tport->type.val, connect );
      if ( port != 0 )
        ::snprintf( &buf[ off ], len - off, ":%u", port );
      this->tab_string( buf, tab[ i++ ] ); /* connect */
    }
    else {
      tab[ i++ ].set_null();
    }
  }
  static const char *hdr[ ncols ] = { "tport", "type", "state", "listen",
                                      "connect" };
  this->print_table( hdr, ncols );
}

void
Console::show_peers( void ) noexcept
{
  static const uint32_t ncols = 8;
  uint32_t     i = 0;
  TabPrint   * tab;
  const char * address;
  uint32_t     addr_len, ucast_fd;
  EvPoll     & poll = this->mgr.poll;
  char         nonce[ NONCE_B64_LEN + 1 ];

  this->table.count = 0;
  this->tmp.count = 0;

  tab = this->table.make( this->table.count + ncols );
  this->table.count += ncols;

  tab[ i++ ].set( this->user_db.user.user, PRINT_SELF ); /* user */
  this->user_db.bridge_id.nonce.to_base64_str( nonce );
  tab[ i++ ].set( nonce ); /* bridge */
  tab[ i++ ].set_long( this->sub_db.sub_seqno ); /* sub */
  tab[ i++ ].set_long( this->user_db.link_state_seqno ); /* link */
  tab[ i++ ].set_null(); /* lat */
  tab[ i++ ].set_null(); /* tport */
  tab[ i++ ].set_null(); /* dist */
  tab[ i++ ].set_null(); /* ptp */

  for ( uint32_t uid = 0; uid < this->user_db.next_uid; uid++ ) {
    UserBridge * n = this->user_db.bridge_tab[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;
    tab = this->table.make( this->table.count + ncols );
    this->table.count += ncols;

    tab[ i++ ].set( n, PRINT_USER ); /* user */
    tab[ i++ ].set( n, PRINT_NONCE ); /* bridge */
    tab[ i++ ].set_long( n->sub_seqno ); /* sub */
    tab[ i++ ].set_long( n->link_state_seqno ); /* link */
    tab[ i++ ].set_long( n->round_trip_time, PRINT_LATENCY ); /* lat */

    UserRoute *u_ptr = n->primary( this->user_db );
    if ( ! u_ptr->is_valid() ) {
      tab[ i++ ].set_null(); /* tport */
      tab[ i++ ].set_null(); /* dist */
      tab[ i++ ].set_null(); /* address */
    }
    else {
      const char * url_type = u_ptr->rte.transport.type.val;
      tab[ i++ ].set( u_ptr->rte.transport.tport, u_ptr->rte.tport_id,
                      PRINT_ID ); /* tport */
      tab[ i++ ].set( n, PRINT_DIST ); /* dist */
      switch ( u_ptr->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE |
                              MESH_URL_STATE ) ) {
        default: { /* normal tcp */
          ucast_fd = u_ptr->inbox_fd;
          if ( ucast_fd < poll.maxfd && poll.sock[ ucast_fd ] != NULL ) {
            uint32_t uid2;
            bool found = false;
            address  = poll.sock[ ucast_fd ]->peer_address.buf;
            addr_len = get_strlen64( address );
            if ( u_ptr->rte.uid_connected.first( uid2 ) ) {
              if ( uid2 != uid ) { /* if routing through another uid */
                UserBridge * n = this->user_db.bridge_tab[ uid2 ];
                if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) { /* ptp */
                  tab[ i++ ].set_url_dest( n, url_type, address, addr_len );
                  found = true;
                }
              }
            }
            if ( ! found )
              tab[ i++ ].set_url( url_type, address, addr_len ); /* ptp */
          }
          else {
            tab[ i++ ].set_null();
          }
          break;
        }
        case UCAST_URL_STATE:
          tab[ i++ ].set( u_ptr->ucast_url, u_ptr->ucast_url_len ); /* ptp */
          break;
        case UCAST_URL_SRC_STATE: {
          const UserRoute & u_src = *u_ptr->ucast_src;
          tab[ i++ ].set_url_dest( &u_src.n, NULL, /* address */
                          u_src.ucast_url, u_src.ucast_url_len, PRINT_UADDR );
          break;
        }
        case MESH_URL_STATE:
          tab[ i++ ].set( u_ptr->mesh_url, u_ptr->mesh_url_len ); /* ptp */
          break;
      }
    }
  }
  static const char *hdr[ ncols ] = { "user", "bridge", "sub", "link", "lat",
                                      "tport", "dist", "address" };
  this->print_table( hdr, ncols );
}

void
Console::show_adjacency( void ) noexcept
{
  static const size_t cols = 3;
  TabPrint * tab = NULL;
  uint32_t   count, i = 0, sep, uid,
             last_user, last_tport;

  this->table.count = 0;
  this->tmp.count = 0;
  count = this->user_db.transport_tab.count;
  last_user = last_tport = -1;
  for ( uint32_t t = 0; t < count; t++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];
    /* print users on the tport */
    for ( bool ok = rte->uid_connected.first( uid ); ok;
          ok = rte->uid_connected.next( uid ) ) {
      UserBridge * n = this->user_db.bridge_tab[ uid ];
      if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
        continue;

      tab = this->table.make( this->table.count + cols );
      this->table.count += cols;
      if ( last_user != 0 )
        tab[ i++ ].set( this->user_db.user.user, PRINT_SELF ); /* user */
      else
        tab[ i++ ].set_null();
      tab[ i++ ].set( n, PRINT_USER );
      if ( last_tport != t )
        tab[ i++ ].set( rte->transport.tport, t, PRINT_ID );
      else
        tab[ i++ ].set_null();
      last_user  = 0;
      last_tport = t;
    }
    /* print empty tports */
    if ( last_tport != t ) {
      tab = this->table.make( this->table.count + cols );
      this->table.count += cols;
      if ( last_user != 0 )
        tab[ i++ ].set( this->user_db.user.user, PRINT_SELF ); /* user */
      else
        tab[ i++ ].set_null();
      tab[ i++ ].set_null();
      tab[ i++ ].set( rte->transport.tport, t, PRINT_ID );
      last_user  = 0;
      last_tport = t;
    }
  }
  if ( i > 0 )
    tab[ i - 1 ].typ |= PRINT_SEP;
  sep = i;
  last_user = last_tport = -1;
  /* print each users port */
  for ( uid = 0; uid < this->user_db.next_uid; uid++ ) {
    UserBridge * n = this->user_db.bridge_tab[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;
    count = n->adjacency.count;
    last_tport = -1;
    /* for each tport populated */
    for ( uint32_t j = 0; j < count; j++ ) {
      AdjacencySpace *set = n->adjacency[ j ];
      uint32_t b;
      if ( set == NULL )
        continue;
      /* for each user on the port */
      for ( bool ok = set->first( b ); ok; ok = set->next( b ) ) {
        UserBridge * n2 = NULL;
        if ( b != 0 )
          n2 = this->user_db.bridge_tab[ b ];
        if ( b == 0 || n2 != NULL ) {
          tab = this->table.make( this->table.count + cols );
          this->table.count += cols;
          if ( last_user != uid )
            tab[ i++ ].set( n, PRINT_USER );
          else
            tab[ i++ ].set_null();
          if ( n2 != NULL )
            tab[ i++ ].set( n2, PRINT_USER );
          else
            tab[ i++ ].set( this->user_db.user.user, PRINT_SELF );
          if ( last_tport != j ) {
            if ( set->tport.len > 0 )
              tab[ i++ ].set( set->tport, j, PRINT_ID );
            else
              tab[ i++ ].set_int( j );
          }
          else
            tab[ i++ ].set_null();
          last_user  = uid;
          last_tport = j;
        }
      }
    }
    if ( i > sep ) {
      tab[ i - 1 ].typ |= PRINT_SEP;
      sep = i;
    }
  }
  const char *hdr[ cols ] = { "user", "adj", "tport" };
  this->print_table( hdr, cols );

  this->printf( "consistent: %s\n",
    this->user_db.peer_dist.is_consistent() ? "true" : "false" );
  UserBridge * from, * to;
  while ( this->user_db.peer_dist.find_inconsistent2( from, to ) ) {
    if ( from != NULL ) {
      if ( to != NULL ) {
        this->printf( "find_inconsistent2 from %s.%u to %s.%u\n",
          from->peer.user.val, from->uid, to->peer.user.val, to->uid );
      }
      else {
        this->printf( "find_inconsistent2 from %s.%u orphaned\n",
          from->peer.user.val, from->uid );
      }
    }
  }
}

void
Console::show_routes( void ) noexcept
{
  static const uint32_t ncols = 6;
  uint32_t     i = 0;
  TabPrint   * tab;
  const char * address;
  uint32_t     addr_len, ucast_fd, mcast_fd;
  EvPoll     & poll = this->mgr.poll;
  bool         first_tport;

  this->table.count = 0;
  this->tmp.count = 0;
  for ( uint32_t uid = 0; uid < this->user_db.next_uid; uid++ ) {
    UserBridge * n = this->user_db.bridge_tab[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;

    tab = this->table.make( this->table.count + ncols );
    this->table.count += ncols;

    if ( i > 0 )
      tab[ i - 1 ].typ |= PRINT_SEP;
    tab[ i++ ].set( n, PRINT_USER ); /* user */

    uint32_t count = this->user_db.transport_tab.count;
    first_tport = true;
    for ( uint32_t t = 0; t < count; t++ ) {
      UserRoute *u_ptr = n->user_route_ptr( this->user_db, t );
      if ( ! u_ptr->is_valid() )
        continue;

      if ( ! first_tport ) {
        tab = this->table.make( this->table.count + ncols );
        this->table.count += ncols;
        tab[ i++ ].set_null(); /* user */
      }
      else {
        first_tport = false;
      }
      TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];
      uint32_t dist =
        this->user_db.peer_dist.calc_transport_cache( uid, t, *rte );
      tab[ i++ ].set( rte->transport.tport, t, PRINT_ID );
      tab[ i++ ].set_int( u_ptr->state, PRINT_STATE ); /* state */

      tab[ i++ ].set_int( dist );  /* dist */
      if ( n->primary_route == t )
        tab[ i++ ].set_long( n->round_trip_time, PRINT_LATENCY ); /* lat */
      else
        tab[ i++ ].set_null();
      const char * url_type = u_ptr->rte.transport.type.val;
      switch ( u_ptr->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE |
                              MESH_URL_STATE ) ) {
        case MESH_URL_STATE:
          if ( dist == 0 ) {
            tab[ i++ ].set( u_ptr->mesh_url, u_ptr->mesh_url_len ); /* ptp */
            break;
          }
          /* fall through */
        default: {
          ucast_fd = u_ptr->inbox_fd;
          if ( ucast_fd < poll.maxfd && poll.sock[ ucast_fd ] != NULL ) {
            uint32_t uid2;
            bool found = false;
            address  = poll.sock[ ucast_fd ]->peer_address.buf;
            addr_len = get_strlen64( address );
            if ( dist > 0 && u_ptr->rte.uid_connected.first( uid2 ) ) {
              UserBridge * n = this->user_db.bridge_tab[ uid2 ];
              if ( n != NULL && n->is_set( AUTHENTICATED_STATE ) ) { /* ptp */
                tab[ i++ ].set_url_dest( n, url_type, address, addr_len );
                found = true;
              }
            }
            if ( ! found )
              tab[ i++ ].set_url( url_type, address, addr_len ); /* ptp */
          }
          else {
            tab[ i++ ].set_null();
          }
          break;
        }
        case UCAST_URL_STATE:
          tab[ i++ ].set( u_ptr->ucast_url, u_ptr->ucast_url_len ); /* ptp */
          tab = this->table.make( this->table.count + ncols );
          this->table.count += ncols;

          mcast_fd = rte->mcast_fd;
          if ( mcast_fd < poll.maxfd && poll.sock[ mcast_fd ] != NULL ) {
            for ( uint32_t k = 0; k < ncols - 1; k++ ) {
              tab[ i++ ].set_null();
            }
            address  = poll.sock[ mcast_fd ]->peer_address.buf;
            addr_len = get_strlen64( address );
            tab[ i++ ].set_url( url_type, address, addr_len );
          }
          break;
        case UCAST_URL_SRC_STATE: {
          const UserRoute & u_src = *u_ptr->ucast_src;
          tab[ i++ ].set_url_dest( &u_src.n, NULL, /* ptp */
                          u_src.ucast_url, u_src.ucast_url_len, PRINT_UADDR );
          break;
        }
      }
    }
  }
  static const char *hdr[ ncols ] = { "user", "tport", "state",
                                      "dist", "lat", "route" };
  this->print_table( hdr, ncols );
}

void
Console::show_urls( void ) noexcept
{
  static const uint32_t ncols = 8;
  uint32_t     i = 0;
  TabPrint   * tab;
  EvPoll     & poll = this->mgr.poll;
  bool         first_tport;

  this->table.count = 0;
  this->tmp.count = 0;
  for ( uint32_t uid = 0; uid < this->user_db.next_uid; uid++ ) {
    UserBridge * n = this->user_db.bridge_tab[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;

    tab = this->table.make( this->table.count + ncols );
    this->table.count += ncols;

    if ( i > 0 )
      tab[ i - 1 ].typ |= PRINT_SEP;
    tab[ i++ ].set( n, PRINT_USER ); /* user */

    uint32_t count = this->user_db.transport_tab.count;
    first_tport = true;
    for ( uint32_t t = 0; t < count; t++ ) {
      UserRoute *u_ptr = n->user_route_ptr( this->user_db, t );
      if ( ! u_ptr->is_valid() )
        continue;

      if ( ! first_tport ) {
        tab = this->table.make( this->table.count + ncols );
        this->table.count += ncols;
        tab[ i++ ].set_null(); /* user */
      }
      else {
        first_tport = false;
      }
      TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];
      uint32_t dist =
        this->user_db.peer_dist.calc_transport_cache( uid, t, *rte );
      tab[ i++ ].set( rte->transport.tport, t, PRINT_ID );
      tab[ i++ ].set_int( u_ptr->state, PRINT_STATE ); /* state */

      tab[ i++ ].set_int( dist );  /* dist */
      if ( rte->mesh_id == NULL )
        tab[ i++ ].set_null();
      else
        tab[ i++ ].set( rte->mesh_id->transport.tport );
      const char * url_type = u_ptr->rte.transport.type.val,
                 * address;
      uint32_t     ucast_fd,
                   addr_len;
      switch ( u_ptr->is_set( UCAST_URL_STATE | UCAST_URL_SRC_STATE |
                              MESH_URL_STATE ) ) {
        case MESH_URL_STATE:
        default:
          if ( u_ptr->is_set( MESH_URL_STATE ) )
            tab[ i++ ].set( u_ptr->mesh_url, u_ptr->mesh_url_len ); /* ptp */
          else
            tab[ i++ ].set_null();
          ucast_fd = u_ptr->inbox_fd;
          if ( ucast_fd < poll.maxfd && poll.sock[ ucast_fd ] != NULL ) {
            PeerAddrStr paddr;
            paddr.set_sock_addr( ucast_fd );
            this->tab_url( url_type, paddr.buf, get_strlen64( paddr.buf ),
                           tab[ i++ ] ); /* local */
            address  = poll.sock[ ucast_fd ]->peer_address.buf;
            addr_len = get_strlen64( address );
            tab[ i++ ].set_url( url_type, address, addr_len ); /* remote */
          }
          else {
            tab[ i++ ].set_null();
            tab[ i++ ].set_null();
          }
          break;

        case UCAST_URL_STATE:
          tab[ i++ ].set( u_ptr->ucast_url, u_ptr->ucast_url_len ); /* ptp */
          /* fallthru */
          if ( 0 ) {
        case UCAST_URL_SRC_STATE:
            const UserRoute & u_src = *u_ptr->ucast_src;
            tab[ i++ ].set_url_dest( &u_src.n, NULL, /* ptp */
                           u_src.ucast_url, u_src.ucast_url_len, PRINT_UADDR );
          }
          ucast_fd = u_ptr->inbox_fd;
          if ( ucast_fd < poll.maxfd && poll.sock[ ucast_fd ] != NULL ) {
            address  = poll.sock[ ucast_fd ]->peer_address.buf;
            addr_len = get_strlen64( address );
            tab[ i++ ].set_url( "inbox", address, addr_len ); /* local */
          }
          else {
            tab[ i++ ].set_null();
          }
          tab[ i++ ].set_null();
          break;
      }
    }
  }
  static const char *hdr[ ncols ] = { "user", "tport", "state",
                                      "dist", "mesh", "url",
                                      "local", "remote" };
  this->print_table( hdr, ncols );
}

void
Console::show_counters( void ) noexcept
{
  static const uint32_t ncols = 14;
  uint32_t     i = 0;
  TabPrint   * tab;

  this->table.count = 0;
  this->tmp.count = 0;
  tab = this->table.make( this->table.count + ncols );
  this->table.count += ncols;

  tab[ i++ ].set( this->user_db.user.user, PRINT_SELF ); /* user */
  tab[ i++ ].set_time( this->user_db.start_time );       /* start */
  while ( i < ncols )
    tab[ i++ ].set_null();

  for ( uint32_t uid = 0; uid < this->user_db.next_uid; uid++ ) {
    UserBridge * n = this->user_db.bridge_tab[ uid ];
    if ( n == NULL || ! n->is_set( AUTHENTICATED_STATE ) )
      continue;

    tab = this->table.make( this->table.count + ncols );
    this->table.count += ncols;

    tab[ i++ ].set( n, PRINT_USER );            /* user */
    tab[ i++ ].set_time( n->start_time );       /* start */
    tab[ i++ ].set_long( n->hb_seqno );         /* hb */
    tab[ i++ ].set_time( n->hb_time );          /* hb_time */
    tab[ i++ ].set_long( n->send_inbox_seqno ); /* isnd */
    tab[ i++ ].set_long( n->recv_inbox_seqno ); /* ircv */
    tab[ i++ ].set_long( n->ping_send_count );  /* pisnd */
    tab[ i++ ].set_time( n->ping_send_time );   /* ping_stime */
    tab[ i++ ].set_long( n->pong_recv_count );  /* porcv */
    tab[ i++ ].set_time( n->pong_recv_time );   /* pong_rtime */
    tab[ i++ ].set_long( n->ping_recv_count );  /* pircv */
    tab[ i++ ].set_time( n->ping_recv_time );   /* ping_rtime */
    tab[ i++ ].set_int( n->seqno_repeat );
    tab[ i++ ].set_int( n->seqno_not_subscr );
  }
  static const char *hdr[ ncols ] =
    { "user", "start", "hb", "hb_time", "isnd", "ircv",
      "pisnd", "ping_stime", "porcv", "pong_rtime",
      "pircv", "ping_rtime", "repeat", "not_subscr" };
  this->print_table( hdr, ncols );
}

void
Console::show_reachable( void ) noexcept
{
  static const uint32_t ncols = 2;
  uint32_t     i = 0, t, count = this->user_db.transport_tab.count;
  char         buf[ 80 ];
  TabPrint   * tab;

  this->table.count = 0;
  this->tmp.count = 0;
  tab = this->table.make( count * ncols );
  this->table.count += count * ncols;

  for ( t = 0; t < count; t++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];
    if ( rte->is_set( TPORT_IS_MESH ) && rte->listener != NULL ) {
      tab[ i++ ].set_tport( rte->transport.tport, "mesh" );
      this->user_db.uid_names( *rte->uid_in_mesh, buf, sizeof( buf ) );
      this->tab_string( buf, tab[ i++ ] );
    }
    else {
      tab[ i++ ].set( rte->transport.tport, t, PRINT_ID );
      rte->reachable_names( buf, sizeof( buf ) );
      this->tab_string( buf, tab[ i++ ] );
    }
  }

  static const char *hdr[ ncols ] =
    { "tport", "reachable" };
  this->print_table( hdr, ncols );
}

void
Console::show_tree( const UserBridge *src ) noexcept
{
  static const uint32_t ncols = 4;
  AdjDistance & peer_dist = this->user_db.peer_dist;
  TabPrint    * tab;
  char          buf[ 80 ];
  uint32_t      i = 0,
                src_uid;
  this->table.count = 0;
  this->tmp.count = 0;
  if ( src != NULL )
    src_uid = src->uid;
  else
    src_uid = 0;

  for ( uint32_t dist = 0; ; dist++ ) {
    if ( peer_dist.calc_dist_peers( src_uid, dist ) == 0 )
      break;
    uint32_t count = peer_dist.uid_next.idx;
    tab = this->table.make( count * ncols );
    this->table.count += count * ncols;
    for ( uint32_t k = 0; k < count; k++ ) {
      PeerUidSet * rec = peer_dist.uid_next.ptr[ k ];
      uint32_t uid = rec->src_uid;
      tab[ i++ ].set_int( dist ); /* dist */
      if ( uid == UserDB::MY_UID ) {
        TransportRoute *rte =
          this->user_db.transport_tab.ptr[ rec->tport_id ];
        tab[ i++ ].set( this->user_db.user.user, PRINT_SELF ); /* user */
        tab[ i++ ].set( rte->transport.tport, rec->tport_id, PRINT_ID );
      }
      else {
        UserBridge * n = this->user_db.bridge_tab.ptr[ uid ];
        tab[ i++ ].set( n, PRINT_USER ); /* user */
        AdjacencySpace *set = n->adjacency[ rec->tport_id ];
        if ( set->tport.len > 0 )
          tab[ i++ ].set( set->tport, rec->tport_id, PRINT_ID );
        else
          tab[ i++ ].set_int( rec->tport_id );
      }
      peer_dist.uid_set_names( *rec, buf, sizeof( buf ) );
      this->tab_string( buf, tab[ i++ ] ); /* dest */
    }
  }

  static const char *hdr[ ncols ] =
    { "dist", "source", "tport", "dest" };
  this->print_table( hdr, ncols );
}

void
Console::show_primary( void ) noexcept
{
  static const uint32_t ncols = 3;
  AdjDistance & peer_dist = this->user_db.peer_dist;
  TabPrint    * tab;
  char          buf[ 80 ];
  uint32_t      i = 0;
  this->table.count = 0;
  this->tmp.count = 0;
  peer_dist.calc_primary();

  uint32_t count = peer_dist.uid_primary.idx;
  tab = this->table.make( count * ncols );
  this->table.count += count * ncols;
  for ( uint32_t k = 0; k < count; k++ ) {
    PeerUidSet * rec = peer_dist.uid_primary.ptr[ k ];
    uint32_t uid = rec->src_uid;
    if ( uid == UserDB::MY_UID ) {
      TransportRoute *rte =
        this->user_db.transport_tab.ptr[ rec->tport_id ];
      tab[ i++ ].set( this->user_db.user.user, PRINT_SELF ); /* user */
      tab[ i++ ].set( rte->transport.tport, rec->tport_id, PRINT_ID );
    }
    else {
      UserBridge * n = this->user_db.bridge_tab.ptr[ uid ];
      tab[ i++ ].set( n, PRINT_USER ); /* user */
      AdjacencySpace *set = n->adjacency[ rec->tport_id ];
      if ( set->tport.len > 0 )
        tab[ i++ ].set( set->tport, rec->tport_id, PRINT_ID );
      else
        tab[ i++ ].set_int( rec->tport_id );
    }
    peer_dist.uid_set_names( *rec, buf, sizeof( buf ) );
    this->tab_string( buf, tab[ i++ ] ); /* dest */
  }

  static const char *hdr[ ncols ] =
    { "source", "tport", "dest" };
  this->print_table( hdr, ncols );
}

void
Console::show_fds( void ) noexcept
{
  static const uint32_t ncols = 5;
  EvPoll     & poll = this->mgr.poll;
  TabPrint   * tab;
  const char * address;
  uint32_t     addr_len, i = 0;

  this->table.count = 0;
  this->tmp.count = 0;
  for ( size_t fd = 0; fd < poll.maxfd; fd++ ) {
    if ( fd < poll.maxfd && poll.sock[ fd ] != NULL ) {
      tab = this->table.make( this->table.count + ncols );
      this->table.count += ncols;
      tab[ i++ ].set_int( fd );
      tab[ i++ ].set( poll.sock[ fd ]->type_string() );
      tab[ i++ ].set( poll.sock[ fd ]->kind );
      tab[ i++ ].set( poll.sock[ fd ]->name );
      address  = poll.sock[ fd ]->peer_address.buf;
      addr_len = get_strlen64( address );

      bool has_ptp_link = false;
      if ( ! this->user_db.route_list.is_empty( fd ) ) {
        UserRoute * u_ptr = this->user_db.route_list[ fd ].hd;
        if ( ! u_ptr->rte.is_mcast() ) {
          tab[ i++ ].set_url_dest( &u_ptr->n, NULL, address, addr_len,
                                   PRINT_UADDR );
          has_ptp_link = true;
        }
      }
      if ( ! has_ptp_link )
        tab[ i++ ].set( address, addr_len );
    }
  }

  static const char *hdr[ ncols ] =
    { "fd", "type", "kind", "name", "address" };
  this->print_table( hdr, ncols );
}

void
Console::show_blooms( void ) noexcept
{
  static const uint32_t ncols = 8;
  TabPrint   * tab;
  uint32_t     uid, i = 0,
               count = this->user_db.transport_tab.count;

  this->table.count = 0;
  this->tmp.count = 0;
  for ( uint32_t t = 0; t < count; t++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ t ];
    if ( i > 0 )
      tab[ i - 1 ].typ |= PRINT_SEP;
    for ( BloomRoute *p = rte->sub_route.bloom_list.hd; p != NULL;
          p = p->next ) {
      size_t sz = 0;
      char   buf[ 80 ];
      tab = this->table.make( this->table.count + ncols );
      this->table.count += ncols;
      tab[ i++ ].set_int( p->r );
      if ( p->r == (uint32_t) this->mgr.fd )
        tab[ i++ ].set( "session" );
      else if ( p->r == (uint32_t) rte->fd )
        tab[ i++ ].set( rte->transport.tport, rte->tport_id );
      else {
        if ( ! this->user_db.route_list.is_empty( p->r ) ) {
          UserRoute * u_ptr = this->user_db.route_list[ p->r ].hd;
          if ( ! u_ptr->rte.is_mcast() ) {
            tab[ i++ ].set( u_ptr->n.peer.user, u_ptr->n.uid );
          }
          else {
            tab[ i++ ].set( "(mcast)" );
          }
        }
        else {
          tab[ i++ ].set_null();
        }
      }
      tab[ i++ ].set( rte->transport.tport, rte->tport_id, PRINT_ID );
      uint64_t pref_mask = 0, detail_mask = 0;
      uint32_t subs = 0, total = 0;
      for ( uint32_t j = 0; j < p->nblooms; j++ ) {
        static const char rtr_str[] = "rtr";
        BloomRef   * ref = p->bloom[ j ];
        const char * s  = NULL;
        pref_mask |= ref->pref_mask;
        detail_mask |= ref->detail_mask;
        total += ref->bits->count;
        subs  += ref->pref_count[ SUB_RTE ];
        if ( ref == &this->sub_db.bloom )
          s = "sub";
        else if ( ref == &this->sub_db.internal )
          s = "int";
        else if ( ref == &this->sub_db.external )
          s = "ext";
        else if ( ref == &this->mgr.sys_bloom )
          s = "sys";
        else if ( ref == &this->user_db.auth_bloom )
          s = "auth";
        else if ( ref == &this->mgr.router_bloom )
          s = rtr_str; /* emtpy */
        else {
          for ( uid = 0; uid < this->user_db.next_uid; uid++ ) {
            UserBridge * n = this->user_db.bridge_tab[ uid ];
            if ( n == NULL )
              continue;
            if ( ref == &n->bloom ) {
              s = n->peer.user.val;
              break;
            }
          }
        }
        if ( s != rtr_str ) {
          if ( s == NULL )
            s = "??";
          sz = cat80( buf, sz, s );
          sz = cat80( buf, sz, ", " );
        }
      }
      if ( sz > 1 ) sz -= 2; /* strip , */
      buf[ sz ] = '\0';
      this->tab_string( buf, tab[ i++ ] );
      tab[ i++ ].set_long( pref_mask, PRINT_LONG_HEX );
      tab[ i++ ].set_long( detail_mask, PRINT_LONG_HEX );
      tab[ i++ ].set_int( subs );
      tab[ i++ ].set_int( total );
    }
  }
  static const char *hdr[ ncols ] =
    { "fd", "dest", "tport", "bloom", "prefix", "detail", "subs", "total" };
  this->print_table( hdr, ncols );
}

void
Console::show_running( int which,  const char *name,  size_t namelen ) noexcept
{
  if ( ( which & PRINT_PARAMETERS ) != 0 ) {
    ConfigTree::TransportArray listen, connect;
    this->get_active_tports( listen, connect );
    this->tree.print_parameters( *this, which, name, namelen, listen, connect );
  }
  else {
    this->tree.print_y( *this, which, name, namelen );
  }
}

int
Console::puts( const char *s ) noexcept
{
  size_t n = ::strlen( s );
  char * p = this->out.make( this->out.count + n );
  ::memcpy( &p[ this->out.count ], s, n );
  this->out.count += n;
  return (int) n;
}

int
Console::printf( const char *fmt, ... ) noexcept
{
  va_list args;
  va_start( args, fmt );
  int n, len = 1024;

  for (;;) {
    char * p = this->out.make( this->out.count + len );
    n = ::vsnprintf( &p[ this->out.count ], len, fmt, args );
    if ( n < len ) {
      this->out.count += n;
      break;
    }
    len += 1024;
  }
  va_end( args );
  return n;
}

void
Console::print_msg( MDMsg &msg ) noexcept
{
  MDFieldIter * f;

  if ( msg.get_field_iter( f ) == 0 ) {
    if ( f->first() == 0 ) {
      do {
        f->print( this, 1, this->fname_fmt, this->type_fmt );
      } while ( f->next() == 0 );
    }
  }
  else {
    msg.print( this );
  }
}

void
ConsoleRPC::on_data( const SubMsgData &val ) noexcept
{
  this->console.on_data( val );
}

void
ConsolePing::on_data( const SubMsgData &val ) noexcept
{
  if ( this->complete || val.token != this->token )
    return;
  uint32_t i = this->total_recv++;
  PingReply &reply = this->reply[ i ];
  if ( this->total_recv >= this->count )
    this->complete = true;

  reply.uid       = val.src_bridge.uid;
  reply.tid       = val.pub.rte.tport_id;
  reply.sent_time = val.time;
  reply.recv_time = current_realtime_ns();

  if ( this->complete )
    this->console.on_ping( *this );
}

void
ConsoleSubs::on_data( const SubMsgData &val ) noexcept
{
  if ( this->complete || val.token != this->token )
    return;
  const MsgHdrDecoder & dec = val.pub.dec;
  const char * str = NULL;
  size_t       len = 0;
  bool         is_pattern = false;

  if ( dec.test( FID_SUBJECT ) ) {
    len = dec.mref[ FID_SUBJECT ].fsize;
    str = (const char *) dec.mref[ FID_SUBJECT ].fptr;
  }
  else if ( dec.test( FID_PATTERN ) ) {
    len = dec.mref[ FID_PATTERN ].fsize;
    str = (const char *) dec.mref[ FID_PATTERN ].fptr;
    is_pattern = true;
  }
  if ( dec.test( FID_END ) ) {
    uint64_t end = 0;
    cvt_number<uint64_t>( dec.mref[ FID_END ], end );
    if ( end >= val.src_bridge.sub_seqno ) {
      if ( ++this->total_recv >= this->count )
        this->complete = true;
    }
  }
  if ( len > 0 ) {
    size_t i   = this->reply.count,
           off = this->strings.count;
    SubsReply & reply = this->reply[ i ];
    char      * sub   = this->strings.make( off + len + 1 );
    sub = &sub[ off ];
    ::memcpy( sub, str, len );
    sub[ len ] = '\0';
    this->strings.count += len + 1;

    reply.uid        = val.src_bridge.uid;
    reply.sub_off    = off;
    reply.sub_len    = len;
    reply.is_pattern = is_pattern;
  }
  if ( this->complete )
    this->console.on_subs( *this );
}

void
Console::on_data( const SubMsgData &val ) noexcept
{
  size_t       sublen = val.pub.subject_len;
  const char * sub    = val.pub.subject;
  if ( val.time != 0 ) {
    uint64_t delta = current_realtime_ns() - val.time;
    this->printf( "%.*sdelta %.1f usecs%.*s\n",
                  rz, rc, (double) delta / 1000.0, nz, nc );
  }
  char src_nonce[ NONCE_B64_LEN + 1 ];
  val.src_bridge.bridge_id.nonce.to_base64_str( src_nonce );
  if ( val.datalen > 0 ) {
    if ( val.fmt != 0 ) {
      MDMsgMem mem;
      MDMsg * m = MDMsg::unpack( (void *) val.data, 0, val.datalen, val.fmt,
                                 MsgFrameDecoder::msg_dict, &mem );
      
      this->printf( "%.*s%.*s%.*s n=%lu (%s @ %s via %s)\n",
              bz, bc, (int) sublen, sub, nz, nc, val.seqno,
              val.src_bridge.peer.user.val, src_nonce, val.pub.rte.name );
      if ( m != NULL )
        this->print_msg( *m );
    }
    else {
      this->printf( "%.*s%.*s%.*s n=%lu (%s @ %s via %s) : %.*s%.*s%.*s\n",
              bz, bc, (int) sublen, sub, nz, nc, val.seqno,
              val.src_bridge.peer.user.val, src_nonce, val.pub.rte.name, cz, cc,
              (int) val.datalen, (char *) val.data, nz, nc );
    }
  }
  else {
    this->printf( "%.*s%.*s%.*s n=%lu (%s @ %s via %s)\n",
            bz, bc, (int) sublen, sub, nz, nc, val.seqno,
            val.src_bridge.peer.user.val, src_nonce, val.pub.rte.name );

    this->print_msg( *val.pub.dec.msg );
  }
  this->flush_output();
}

