#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define TELCMDS
#define TELOPTS
#include <arpa/telnet.h>
#include <raims/ev_telnet.h>
#include <raims/debug.h>
#include <linecook/linecook.h>
#include <linecook/ttycook.h>
#include <raimd/md_types.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

static const char *
code_to_str( uint32_t code ) noexcept
{
  /* code == WILL, WONT, DO, DONT */
  if ( code >= xEOF && code <= IAC )
    return telcmds[ code - xEOF ];
  return "?cmd?";
}

static const char *
opt_to_str( uint32_t opt ) noexcept
{
  /* opt BINARY, ECHO, SGA, NAWS, ... */
  if ( opt < NTELOPTS )
    return telopts[ opt ];
  return "?opt?";
}

static uint32_t
cat_bits( char *buf,  uint32_t i,  const char *s )
{
  if ( i > 0 )
    buf[ i++ ] = '|';
  while ( *s != '\0' )
    buf[ i++ ] = *s++;
  return i;
}

static const uint32_t MAX_BITS_BUF = 12 * 8;
static const char *
state_bits_to_str( uint8_t bits,  char *buf ) noexcept
{
  uint32_t i = 0;

  if ( bits & TelnetService::WILL_SENT )
    i = cat_bits( buf, i, "WILL_SENT" );
  if ( bits & TelnetService::WILL_RECV )
    i = cat_bits( buf, i, "WILL_RECV" );

  if ( bits & TelnetService::WONT_SENT )
    i = cat_bits( buf, i, "WONT_SENT" );
  if ( bits & TelnetService::WONT_RECV )
    i = cat_bits( buf, i, "WONT_RECV" );

  if ( bits & TelnetService::DO_SENT )
    i = cat_bits( buf, i, "DO_SENT" );
  if ( bits & TelnetService::DO_RECV )
    i = cat_bits( buf, i, "DO_RECV" );

  if ( bits & TelnetService::DONT_SENT )
    i = cat_bits( buf, i, "DONT_SENT" );
  if ( bits & TelnetService::DONT_RECV )
    i = cat_bits( buf, i, "DONT_RECV" );
  buf[ i ] = '\0';
  return buf;
}

bool
TelnetListen::accept( void ) noexcept
{
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof( addr );
  int sock = ::accept( this->fd, (struct sockaddr *) &addr, &addrlen );
  if ( sock < 0 ) {
    if ( errno != EINTR ) {
      if ( errno != EAGAIN )
        perror( "accept" );
      this->pop3( EV_READ, EV_READ_LO, EV_READ_HI );
    }
    return false;
  }
  TelnetService *c =
    this->poll.get_free_list<TelnetService>( this->accept_sock_type );
  if ( c == NULL ) {
    perror( "accept: no memory" );
    ::close( sock );
    return false;
  }
  EvTcpListen::set_sock_opts( this->poll, sock, this->sock_opts );
  ::fcntl( sock, F_SETFL, O_NONBLOCK | ::fcntl( sock, F_GETFL ) );

  c->PeerData::init_peer( sock, (struct sockaddr *) &addr, "telnet" );
  c->init_state();
  c->console = this->console;
  this->console->term_list.push_tl( c );
  if ( this->poll.add_sock( c ) < 0 ) {
    ::close( sock );
    this->poll.push_free_list( c );
    return false;
  }
  c->start();
  return true;
}

TelnetService::TelnetService( EvPoll &p,  uint8_t t ) noexcept
             : kv::EvConnection( p, t )
{
}

void
TelnetService::init_state( void ) noexcept
{
  static const uint8_t VAL_FLIO = SLC_VALUE | SLC_FLUSHIN | SLC_FLUSHOUT,
                       VAL_FLI  = SLC_VALUE | SLC_FLUSHIN;
  ::memset( this->slc, 0, sizeof( this->slc ) );
  ::memset( this->opt_state, 0, sizeof( this->opt_state ) );
  this->console      = NULL;
  this->line_buf     = NULL;
  this->line_buflen  = 0;
  this->neg_state    = 0;
  this->term_int     = 0;
  this->naws_cols    = 80;
  this->naws_lines   = 24;
  this->term_started = false;
  this->set_slc_func( SLC_SYNCH , SLC_DEFAULT, 0 );
  this->set_slc_func( SLC_IP    , VAL_FLIO   , 3 );   /* ctrl-c */
  this->set_slc_func( SLC_AO    , SLC_VALUE  , 15 );  /* ctrl-o (abort output)*/
  this->set_slc_func( SLC_AYT   , SLC_DEFAULT, 0 );
  this->set_slc_func( SLC_ABORT , VAL_FLIO   , 28 );  /* break? */
  this->set_slc_func( SLC_EOF   , SLC_VALUE  , 4 );   /* ctrl-d */
  this->set_slc_func( SLC_SUSP  , VAL_FLI    , 26 );  /* ctrl-z */
  this->set_slc_func( SLC_EC    , SLC_VALUE  , 127 ); /* backspace */
  this->set_slc_func( SLC_EL    , SLC_VALUE  , 21 );  /* ctrl-u */
  this->set_slc_func( SLC_EW    , SLC_VALUE  , 23 );  /* ctrl-w */
  this->set_slc_func( SLC_RP    , SLC_VALUE  , 18 );  /* ctrl-r */
  this->set_slc_func( SLC_LNEXT , SLC_VALUE  , 22 );  /* ctrl-v */
  this->set_slc_func( SLC_XON   , SLC_VALUE  , 17 );  /* ctrl-q */
  this->set_slc_func( SLC_XOFF  , SLC_VALUE  , 19 );  /* ctrl-s */
  this->term.zero();
}

void
TelnetService::set_slc_func( uint8_t func,  uint8_t level,
                             uint8_t value ) noexcept
{
  if ( func < MAX_SLC ) {
    TelnetSLC &f = this->slc[ func ];
    f.level = level;
    f.value = value;
  }
}

void
TelnetService::send_opt( uint8_t cmd,  uint8_t opt ) noexcept
{
  char * buf = this->alloc( 3 );
  buf[ 0 ] = IAC;
  buf[ 1 ] = cmd;
  buf[ 2 ] = opt;
  this->sz += 3;
}

void
TelnetService::add_state( uint8_t opt,  uint8_t state ) noexcept
{
  if ( opt >= MAX_OPT || state > 128 )
    return;

  char buf1[ MAX_BITS_BUF ], buf2[ MAX_BITS_BUF ];
  d_tel( "add_state[ %s ] %s |= %s\n", opt_to_str( opt ),
         state_bits_to_str( this->opt_state[ opt ], buf1 ),
         state_bits_to_str( state, buf2 ) ); 

  uint8_t & opt_st = this->opt_state[ opt ];
  opt_st |= state;
  if ( state < 16 ) /* sent opts */
    return;

  if ( state == DO_RECV && opt == TELOPT_TM ) {
    this->send_opt( WILL, TELOPT_TM );
    return;
  }
  if ( opt == TELOPT_LINEMODE ) {
    if ( opt_st == ( DO_SENT | WILL_RECV ) ||
         opt_st == ( WILL_SENT | DO_RECV ) ) {
      char * buf = this->alloc( 7 );
      /* IAC SB LINEMODE LM_MODE MODE_TRAPSIG IAC SE */
      buf[ 0 ] = IAC;
      buf[ 1 ] = SB;
      buf[ 2 ] = TELOPT_LINEMODE;
      buf[ 3 ] = LM_MODE;
      buf[ 4 ] = MODE_TRAPSIG; /* we want signals */
      buf[ 5 ] = IAC;
      buf[ 6 ] = SE;
      this->sz += 7;
      if ( ! this->term_started )
        this->start_term();
    }
  }
  uint8_t add = 0;
  switch ( state ) {
    case WILL_RECV:
      if ( ( opt_st & ( DO_SENT | DONT_SENT ) ) == 0 ) {
        this->send_opt( DO, opt );
        add = DO_SENT;
      }
      this->neg_state |= (uint64_t) 1 << opt; /* WILL DO */
      break;
    case WONT_RECV:
      if ( ( opt_st & ( DO_SENT | DONT_SENT ) ) == 0 ) {
        this->send_opt( DONT, opt );
        add = DONT_SENT;
      }
      this->neg_state &= ~(uint64_t) 1 << opt; /* WONT DONT */
      break;
    case DO_RECV:
      if ( ( opt_st & ( WILL_SENT | WONT_SENT ) ) == 0 ) {
        this->send_opt( WILL, opt );
        add = WILL_SENT;
      }
      this->neg_state |= (uint64_t) 1 << opt; /* WILL DO */
      break;
    case DONT_RECV:
      if ( ( opt_st & ( WILL_SENT | WONT_SENT ) ) == 0 ) {
        this->send_opt( WONT, opt );
        add = WONT_SENT;
      }
      this->neg_state &= ~(uint64_t) 1 << opt; /* WONT DONT */
      break;
  }
  if ( add != 0 ) {
    d_tel( "neg_state[ %s ] %s\n", opt_to_str( opt ),
            state_bits_to_str( add, buf1 ) );
    opt_st |= add;
  }
  if ( opt_st == ( DO_SENT   | WILL_RECV ) ||
       opt_st == ( WILL_SENT | DO_RECV   ) ||
       opt_st == ( DONT_SENT | WONT_RECV ) ||
       opt_st == ( WONT_SENT | DONT_RECV ) )
    opt_st = 0; /* success negotiation */
  else {
    if ( opt_st == ( DO_SENT   | WONT_RECV ) ||
         opt_st == ( WILL_SENT | DONT_RECV ) ||
         opt_st == ( DONT_SENT | DO_RECV   ) ||
         opt_st == ( WONT_SENT | WILL_RECV ) ) {
      d_tel( "failed neg %s = %s\n", opt_to_str( opt ),
              state_bits_to_str( opt_st, buf1 ) );
    }
    else {
      printf( "unknown neg %s = %s\n", opt_to_str( opt ),
              state_bits_to_str( opt_st, buf1 ) );
    }
    opt_st = 0; /* failed negotiation */
  }
}

void
TelnetService::start( void ) noexcept
{
  this->send_opt( DO, TELOPT_SGA );
  this->send_opt( DO, TELOPT_NAWS );
  this->send_opt( DO, TELOPT_LINEMODE );
  this->send_opt( WILL, TELOPT_ECHO );

  this->add_state( TELOPT_SGA, DO_SENT );
  this->add_state( TELOPT_NAWS, DO_SENT );
  this->add_state( TELOPT_LINEMODE, DO_SENT );
  this->add_state( TELOPT_ECHO, WILL_SENT );

  this->idle_push( EV_WRITE_HI );
}

void
TelnetService::start_term( void ) noexcept
{
  /*if ( this->console->log_index > 0 )
    this->term.tty_write( this->console->log.ptr, this->console->log_index );*/
  this->term_started = true;

  this->term.tty_init();
  this->term.closure = this->console;
  this->term.lc->complete_cb = console_complete;
  this->term.help_cb = console_help;
  static char iec[] = "-iec", question[] = "?", show_help[] = "&show-help";
  static char *recipe[] = { iec, question, show_help };
  lc_bindkey( term.lc, recipe, 3 );
  linecook::TTY *tty = static_cast<linecook::TTY *>( this->term.tty );
  tty->cols  = this->naws_cols;
  tty->lines = this->naws_lines;
  lc_tty_set_prompt( tty, TTYP_PROMPT1, this->console->prompt );
  lc_set_geom( this->term.lc, tty->cols, tty->lines );
  this->term.tty_prompt();
  this->flush_term();
  this->idle_push( EV_WRITE );
}

void
TelnetService::on_prompt( const char *prompt ) noexcept
{
  if ( this->term_started ) {
    linecook::TTY *tty = static_cast<linecook::TTY *>( this->term.tty );
    lc_tty_set_prompt( tty, TTYP_PROMPT1, prompt );
    this->flush_term();
    this->idle_push( EV_WRITE );
  }
}

bool
TelnetService::on_output( const char *buf,  size_t buflen ) noexcept
{
  if ( this->term_started ) {
    lc_tty_clear_line( this->term.tty );
    this->flush_term();
    this->term.tty_write( buf, buflen );
    this->term.tty_prompt();
    this->flush_term();
  }
  else {
    this->flush_buf( buf, buflen );
  }
  this->idle_push( EV_WRITE );
  return true;
}

void
TelnetService::on_quit( void ) noexcept
{
  this->idle_push( EV_SHUTDOWN );
}

void
TelnetService::process_shutdown( void ) noexcept
{
  ::shutdown( this->fd, SHUT_WR );
}

void
TelnetService::flush_term( void ) noexcept
{
  this->flush_buf( this->term.out_buf, this->term.out_len );
  this->term.tty_out_reset();
}

void
TelnetService::flush_buf( const char *out_buf,  size_t out_len ) noexcept
{
  for ( size_t i = 0; ; ) {
    if ( i == out_len )
      return;
    size_t       left = out_len - i;
    const char * ptr  = &out_buf[ i ];
    const char * eol;
    bool         need_cr = false;
    if ( (eol = (const char *) ::memchr( ptr, '\n', left )) != NULL ) {
      if ( eol > ptr ) {
        if ( *( eol - 1 ) == '\r' ) {
          eol++;
        }
        else {
          need_cr = true;
        }
      }
      left = eol - ptr;
    }
    this->append( ptr, left );
    i += left;
    if ( need_cr ) {
      this->append( "\r\n", 2 );
      i++;
    }
  }
}

void
TelnetService::process( void ) noexcept
{
  while ( this->off < this->len ) {
    size_t       buflen = this->len - this->off;
    const char * ptr    = &this->recv[ this->off ];
    const char * tel    = (const char *) ::memchr( ptr, IAC, buflen );
    bool         consumed = false;

    if ( tel != NULL ) {
      if ( buflen == 1 ) /* need more to check if telnet protocol */
        break;
      if ( (uint8_t) tel[ 1 ] >= xEOF ) { /* 236 -> 255 valid */
        if ( tel > ptr ) {
          size_t prefix = tel - ptr;
          this->output( ptr, prefix );
          this->off += prefix;
          ptr       += prefix;
          buflen    -= prefix;
        }
        if ( ! this->process_iac( ptr, buflen ) )
          break;
        this->off += buflen;
        consumed = true;
      }
    }
    if ( ! consumed ) {
      this->output( ptr, buflen );
      this->off += buflen;
    }
  }
  if ( this->process_console() ||
       this->term_int != this->term.interrupt + this->term.suspend ) {
    this->term_int = this->term.interrupt + this->term.suspend;
    if ( this->term_started )
      this->term.tty_prompt();
  }
  if ( this->term_started )
    this->flush_term();
  this->pop( EV_PROCESS );
  this->push_write();
}

void
TelnetService::output( const char *ptr,  size_t buflen ) noexcept
{
  const char * end = &ptr[ buflen ];
  char * lbuf = NULL;
  size_t off  = 0;
  if ( ! this->term_started ) {
    lbuf = (char *) ::realloc( this->line_buf, this->line_buflen + buflen + 1 );
    this->line_buf = lbuf;
    off = this->line_buflen;
  }
  while ( ptr < end ) {
    size_t       len = end - ptr;
    const char * eos = (const char *) ::memchr( ptr, '\0', len );
    if ( eos == NULL ) {
      if ( this->term_started )
        this->term.tty_input( ptr, len );
      else {
        ::memcpy( &lbuf[ off ], ptr, len );
        off += len;
      }
      ptr = end;
    }
    else if ( eos > ptr ) {
      if ( this->term_started )
        this->term.tty_input( ptr, eos - ptr );
      else {
        ::memcpy( &lbuf[ off ], ptr, eos - ptr );
        off += eos - ptr;
      }
      ptr = &eos[ 1 ];
    }
  }
  if ( off > 0 ) {
    lbuf[ off ] = '\0';
    this->line_buflen = off;
  }
}

bool
TelnetService::process_console( void ) noexcept
{
  size_t linecnt = 0;
  if ( ! this->term_started ) {
    char * lbuf = this->line_buf;
    size_t off = 0;
    for (;;) {
      char * eol = (char *)
        ::memchr( &lbuf[ off ], '\n', this->line_buflen - off );
      if ( eol == NULL ) {
        if ( off > 0 ) {
          this->line_buflen -= off;
          ::memmove( lbuf, &lbuf[ off ], this->line_buflen );
        }
        break;
      }
      eol++;
      this->console->on_input( this, &lbuf[ off ], eol - &lbuf[ off ] );
      linecnt++;
      off += eol - &lbuf[ off ];
    }
  }
  else {
    size_t buflen;

    for (;;) {
      buflen = this->term.line_len - this->term.line_off;
      if ( buflen == 0 )
        break;
      char * buf = &this->term.line_buf[ this->term.line_off ];
      this->console->on_input( this, buf, buflen );
      this->term.line_off += buflen;
      linecnt++;
    }
  }
  return linecnt > 0;
}

bool
TelnetService::process_subneg( const char *ptr,  size_t &buflen ) noexcept
{
  const char * se  = ptr,
             * end = &ptr[ buflen ];
  for (;;) {
    size_t len = end - se;
    se = (const char *) ::memchr( se, SE, len );
    if ( se == NULL )
      return false;
    if ( se > ptr && (uint8_t) *(se - 1) == IAC ) { /* IAC SE ends the record */
      buflen = ( se - ptr ) + 1;
      break;
    }
    if ( ++se == end ) /* IAC not found, go to next char */
      return false;
  }
  switch ( (uint8_t) *ptr ) {
    case TELOPT_NAWS:
      this->process_naws( ptr, buflen );
      return true;
    case TELOPT_LINEMODE:
      this->process_linemode( ptr, buflen );
      return true;
    default: {
      MDOutput mout;
      d_tel( "subneg\n" );
      mout.print_hex( ptr, buflen );
      break;
    }
  }
  return true;
}

void
TelnetService::process_linemode( const char *ptr,  size_t buflen ) noexcept
{
  if ( buflen < 3 )
    return;
  if ( ptr[ 1 ] == LM_SLC ) {
    for ( size_t i = 2; i + 2 < buflen; i += 3 ) {
      uint8_t func  = (uint8_t) ptr[ i ],
              bits  = (uint8_t) ptr[ i + 1 ],
              value = (uint8_t) ptr[ i + 2 ];
      /* XXX should reply if ACK bit is set */
      /* maybe disable XONN/XOFF */
      this->set_slc_func( func, bits, value );
    }
  }
#if 0
  else if ( ptr[ 1 ] == LM_MODE ) {
    if ( buflen == 5 && ( ptr[ 2 ] & MODE_ACK ) != 0 &&
         (uint8_t) ptr[ 3 ] == IAC &&
         (uint8_t) ptr[ 4 ] == SE ) {
      if ( ( ptr[ 2 ] & MODE_EDIT ) != 0 )
        printf( "mode edit\n" );
      if ( ( ptr[ 2 ] & MODE_TRAPSIG ) != 0 )
        printf( "mode trapsig\n" );
      if ( ( ptr[ 2 ] & MODE_SOFT_TAB ) != 0 )
        printf( "mode soft tab\n" );
      if ( ( ptr[ 2 ] & MODE_LIT_ECHO ) != 0 )
        printf( "mode lit echo\n" );
    }
  }
#endif
}

void
TelnetService::process_naws( const char *ptr,  size_t buflen ) noexcept
{
  if ( buflen == 7 ) {
    this->naws_cols  = (uint16_t) ( (uint8_t) ptr[ 1 ] << 8 ) |
                                    (uint8_t) ptr[ 2 ];
    this->naws_lines = (uint16_t) ( (uint8_t) ptr[ 3 ] << 8 ) |
                                    (uint8_t) ptr[ 4 ];
    if ( this->naws_cols < 6 || this->naws_cols > 1024 ||
         this->naws_lines < 3 || this->naws_lines > 1024 ) {
      printf( "invalid terminal size cols=%u lines=%u\n",
              this->naws_cols, this->naws_lines );
      this->naws_cols = 80;
      this->naws_cols = 24;
    }
    if ( this->term_started ) {
      linecook::TTY *tty = static_cast<linecook::TTY *>( this->term.tty );
      tty->cols  = this->naws_cols;
      tty->lines = this->naws_lines;
      lc_set_geom( this->term.lc, tty->cols, tty->lines );
      lc_clear_line( this->term.lc );
      this->term.tty_prompt();
    }
  }
}

bool
TelnetService::process_iac( const char *ptr,  size_t &buflen ) noexcept
{
  if ( buflen < 2 )
    return false;
  switch ( (uint8_t) ptr[ 1 ] ) {
    case IAC   : /* 255 (0xff) double IAC, I presume escapes IAC */
      this->output( &ptr[ 1 ], 1 );
      buflen = 2;
      return true; /* interpret as literal ff */

    case DONT  : /* 254 (0xfe) you are not to use option */
    case DO    : /* 253 (0xfd) please, you use option */
    case WONT  : /* 252 (0xfc) I won't use option */
    case WILL  : /* 251 (0xfb) I will use option */
      if ( buflen < 3 )
        return false;

      this->process_telopt( (uint8_t) ptr[ 1 ], (uint8_t) ptr[ 2 ] );
      buflen = 3;
      return true;

    case SB    : { /* 250 (0xfa) interpret as subnegotiation */
      size_t len = buflen - 2;
      if ( buflen < 3 )
        return false;
      if ( this->process_subneg( &ptr[ 2 ], len ) ) {
        buflen = len + 2;
        return true;
      }
      return false;
    }
    case GA    : /* 249 (0xf9) you may reverse the line */
      d_tel( "iac ga\n" );
      break;
    case EL    : /* 248 (0xf8) erase the current line */
      if ( this->term_started )
        this->term.tty_input( KEY_CTRL_U, 1 );
      break;
    case EC    : /* 247 (0xf7) erase the current character */
      this->term.tty_input( KEY_CTRL_D, 1 );
      break;
    case AYT   : /* 246 (0xf6) are you there */
      d_tel( "iac ayt\n" );
      break;
    case AO    : /* 245 (0xf5) abort output--but let prog finish */
      d_tel( "iac ad\n" );
      break;
    case IP    : /* 244 (0xf4) interrupt process--permanently */
      if ( this->term_started )
        this->term.tty_input( KEY_CTRL_C, 1 );
      break;
    case BREAK : /* 243 (0xf3) break */
      if ( this->term_started )
        this->term.tty_input( KEY_CTRL_C, 1 );
      break;
    case DM    : /* 242 (0xf2) data mark--for connect. cleaning */
      d_tel( "iac dm\n" );
      break;
    case NOP   : /* 241 (0xf1) nop */
      d_tel( "iac nop\n" );
      break;
    case SE    : /* 240 (0xf0) end sub negotiation */
      d_tel( "iac se\n" );
      break;
    case EOR   : /* 239 (0xef) end of record (transparent mode) */
      d_tel( "iac eor\n" );
      break;
    case ABORT : /* 238 (0xee) Abort process */
      if ( this->term_started )
        this->term.tty_input( KEY_CTRL_C, 1 );
      break;
    case SUSP  : /* 237 (0xed) Suspend process */
      if ( this->term_started )
        this->term.tty_input( KEY_CTRL_Z, 1 );
      break;
    case xEOF  : /* 236 (0xec) End of file: EOF is already used... */
      if ( this->term_started )
        this->term.tty_input( KEY_CTRL_D, 1 );
      break;
    default:
      d_tel( "iac %x\n", (uint8_t) ptr[ 1 ] );
      break;
  }
  buflen = 2;
  return true;
}

void
TelnetService::process_telopt( uint8_t code,  uint8_t opt ) noexcept
{
  uint8_t state = 0;

  d_tel( "process: %s %s\n", code_to_str( code ), opt_to_str( opt ) );
  switch ( code ) {
    case DONT: state = DONT_RECV; break;
    case DO:   state = DO_RECV; break;
    case WONT: state = WONT_RECV; break;
    case WILL: state = WILL_RECV; break;
    default: return;
  }
  this->add_state( opt, state );
}

void
TelnetService::release( void ) noexcept
{
  this->console->term_list.pop( this );
  if ( this->term_started )
    this->term.tty_release();
  if ( this->line_buf != NULL ) {
    ::free( this->line_buf );
    this->line_buf    = NULL;
    this->line_buflen = 0;
  }
  this->EvConnection::release_buffers();
  this->poll.push_free_list( this );
}

#if 0
  switch ( code ) {
    case DONT: s = "DONT"; state = DONT_RECV; break;
    case DO:   s = "DO";   state = DO_RECV;   break;
    case WONT: s = "WONT"; state = WONT_RECV; break;
    case WILL: s = "WILL"; state = WILL_RECV; break;
    default: return;
  }
  switch ( opt ) {
    case TELOPT_BINARY : o = "BIN"; break;    /* 0   8-bit data path */
    case TELOPT_ECHO   : o = "ECHO"; break;   /* 1   echo */
    case TELOPT_RCP    : o = "RCP"; break;    /* 2   prepare to reconnect */
    case TELOPT_SGA    : o = "SGA"; break;    /* 3   suppress go ahead */
    case TELOPT_NAMS   : o = "NAMS"; break;   /* 4   approximate message size */
    case TELOPT_STATUS : o = "STATUS"; break; /* 5   give status */
    case TELOPT_TM     : o = "TM"; break;     /* 6   timing mark */
    case TELOPT_RCTE   : o = "RCTE"; break;   /* 7   remote controlled transmission and echo */
    case TELOPT_NAOL   : o = "NAOL"; break;   /* 8   negotiate about output line width */
    case TELOPT_NAOP   : o = "NAOP"; break;   /* 9   negotiate about output page size */
    case TELOPT_NAOCRD : o = "NAOCRD"; break; /* 10  negotiate about CR disposition */
    case TELOPT_NAOHTS : o = "NAOHTS"; break; /* 11  negotiate about horizontal tabstops */
    case TELOPT_NAOHTD : o = "NAOHTD"; break; /* 12  negotiate about horizontal tab disposition */
    case TELOPT_NAOFFD : o = "NAOFFD"; break; /* 13  negotiate about formfeed disposition */
    case TELOPT_NAOVTS : o = "NAOVTS"; break; /* 14  negotiate about vertical tab stops */
    case TELOPT_NAOVTD : o = "NAOVTD"; break; /* 15  negotiate about vertical tab disposition */
    case TELOPT_NAOLFD : o = "NAOLFD"; break; /* 16  negotiate about output LF disposition */
    case TELOPT_XASCII : o = "XASCII"; break; /* 17  extended ascii character set */
    case TELOPT_LOGOUT : o = "LOGOUT"; break; /* 18  force logout */
    case TELOPT_BM     : o = "BM"; break;     /* 19  byte macro */
    case TELOPT_DET    : o = "DET"; break;    /* 20  data entry terminal */
    case TELOPT_SUPDUP : o = "SUPDUP"; break; /* 21  supdup protocol */
    case TELOPT_SUPDUPOUTPUT : o = "SUPDUPOUTPUT"; break; /* 22  supdup output */
    case TELOPT_SNDLOC : o = "SNDLOC"; break; /* 23  send location */
    case TELOPT_TTYPE  : o = "TTYPE"; break;  /* 24  terminal type */
    case TELOPT_EOR    : o = "EOR"; break;    /* 25  end or record */
    case TELOPT_TUID   : o = "TUID"; break;   /* 26  TACACS user identification */
    case TELOPT_OUTMRK : o = "OUTMRK"; break; /* 27  output marking */
    case TELOPT_TTYLOC : o = "TTYLOC"; break; /* 28  terminal location number */
    case TELOPT_3270REGIME : o = "3270REGIME"; break; /* 29  3270 regime */
    case TELOPT_X3PAD   : o = "X3PAD"; break; /* 30 X.3 PAD */
    case TELOPT_NAWS    : o = "NAWS"; break;  /* 31 window size */
    case TELOPT_TSPEED  : o = "TSPEED"; break;/* 32 terminal speed */
    case TELOPT_LFLOW   : o = "LFLOW"; break; /* 33 remote flow control */
    case TELOPT_LINEMODE: o = "LINEMODE"; break; /* 34 Linemode option */
    case TELOPT_XDISPLOC: o = "XDISPLOC"; break; /* 35 X Display Location */
    case TELOPT_OLD_ENVIRON    : o = "ENVIRON"; break; /* 36  Old - Environment variables */
    case TELOPT_AUTHENTICATION : o = "AUTHENTICATION"; break; /* 37  Authenticate */
    case TELOPT_ENCRYPT        : o = "ENCRYPT"; break; /* 38  Encryption option */
    case TELOPT_NEW_ENVIRON    : o = "ENVIRON"; break; /* 39  New - Environment variables */
    case TELOPT_EXOPL          : o = "EXOPL"; break;   /* 255 extended-options-list */
    default: return;
  }
  #endif
