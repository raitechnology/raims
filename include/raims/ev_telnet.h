#ifndef __rai_raims__ev_telnet_h__
#define __rai_raims__ev_telnet_h__

#include <raikv/ev_tcp.h>
#include <raids/term.h>
#include <raims/console.h>

namespace rai {
namespace ms {

struct TelnetListen : public kv::EvTcpListen {
  Console * console;
  void * operator new( size_t, void *ptr ) { return ptr; }
  TelnetListen( kv::EvPoll &p )
    : kv::EvTcpListen( p, "telnet_listen", "telnet_sock" ), console( 0 ) {}

  virtual bool accept( void ) noexcept;
};

/* linemode "set local chars" */
struct TelnetSLC {
  uint8_t level, value;
};

struct TelnetService : public kv::EvConnection, public ConsoleOutput {
  static const size_t MAX_SLC = 19,
                      MAX_OPT = 40;
  static const uint8_t WILL_SENT = 1, WILL_RECV = 16,
                       WONT_SENT = 2, WONT_RECV = 32,
                       DO_SENT   = 4, DO_RECV   = 64,
                       DONT_SENT = 8, DONT_RECV = 128;
  ds::Term  term;
  Console * console;
  TelnetSLC slc[ MAX_SLC ];
  uint8_t   opt_state[ MAX_OPT ]; /* WILL, DO transitions */
  uint64_t  neg_state;
  char    * line_buf;
  size_t    line_buflen;
  int       term_int;
  uint16_t  naws_cols,
            naws_lines;
  bool      term_started;
  void * operator new( size_t, void *ptr ) { return ptr; }

  TelnetService( kv::EvPoll &p,  uint8_t t ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
  virtual void on_prompt( const char *prompt ) noexcept;
  virtual void on_quit( void ) noexcept;
  void init_state( void ) noexcept;
  void set_slc_func( uint8_t func,  uint8_t level, uint8_t value ) noexcept;
  void start( void ) noexcept;
  void start_term( void ) noexcept;
  void flush_term( void ) noexcept;
  void flush_buf( const char *out_buf,  size_t out_len ) noexcept;
  void send_opt( uint8_t cmd,  uint8_t opt ) noexcept;
  void add_state( uint8_t opt,  uint8_t state ) noexcept;
  bool process_subneg( const char *ptr,  size_t &buflen ) noexcept;
  void process_linemode( const char *ptr,  size_t buflen ) noexcept;
  void process_naws( const char *ptr,  size_t buflen ) noexcept;
  bool process_iac( const char *ptr,  size_t &buflen ) noexcept;
  void process_telopt( uint8_t code,  uint8_t opt ) noexcept;
  void output( const char *ptr,  size_t buflen ) noexcept;
  bool process_console( void ) noexcept;
  virtual void process( void ) noexcept final; /* decode read buffer */
  virtual void release( void ) noexcept final; /* after shutdown release mem */
  virtual void process_shutdown( void ) noexcept final;
};

#if 0
static const uint8_t SE   = 240, /* 0xf0 end negotiation */
                     NOP  = 241, /* 0xf1 no op */
                     DM   = 242, /* 0xf2 data mark */
                     BRK  = 243, /* 0xf3 break */
                     IP   = 244, /* 0xf4 interrupt */
                     AO   = 245, /* 0xf5 abort output */
                     AYT  = 246, /* 0xf6 are you there */
                     EC   = 247, /* 0xf7 erase char */
                     EL   = 248, /* 0xf8 erase line */
                     GA   = 249, /* 0xf9 go ahead */
                     SB   = 250, /* 0xfa start negotiation */
                     WILL = 251, /* 0xfb will */
                     WONT = 252, /* 0xfc wont */
                     DO   = 253, /* 0xfd do */
                     DONT = 254, /* 0xfe dont */
                     IAC  = 255, /* 0xff interpret as command */

/* iana assigned options: */
                     BIN  =  0, /* binary transmission */
                     ECHO =  1, /* echo */
                     REC  =  2, /* reconnection */
                     SGA  =  3, /* supress go ahead*/
                     AMS  =  4, /* approx message size */
                     STA  =  5, /* status */
                     MARK =  6, /* timing mark */
                     RC   =  7, /* remote controlled trans, echo */
                     OLW  =  8, /* output line width */
                     OPS  =  9, /* output page size */
                     OCR  = 10, /* 0x0a output carriage return disposition */
                     TT   = 24, /* 0x18 terminal type */
                     NAWS = 31, /* 0x1f negotiate window size */
                     TTS  = 32, /* 0x20 terminal speed */
                     RFC  = 33, /* 0x21 remote flow control */
                     LM   = 34, /* 0x22 line mode */
                     XW   = 35, /* 0x23 x window location */
                     ENV  = 39; /* 0x27 environment */

SLC <func> <modifiers> <char>

  modifiers & SLC_LEVELBITS (0x03) = { SLC_NOSUPPORT (0), SLC_CANTCHANGE (1), SLC_VALUE (2), SLC_DEFAULT (3) }
  modifiers & 0xe0                 = { SLC_ACK (0x80), SLC_FLUSHIN (0x40), SLC_FLUSHOUT (0x20) }

                                     ff fa 22  03 01 00 00  03 62 03 04      "  "     b
                                                  |         |        |
  56:11.725     20   02 0f 05 00  00 07 62 1c  08 02 04 09  42 1a 0a 02        b     B
                           |         |         |        |         |
  56:11.725     30   7f 0b 02 15  0c 02 17 0d  02 12 0e 02  16 0f 02 11
                        |         |        |         |         |
  56:11.725     40   10 02 13 11  00 00 12 00  00
                     |        |         |
IAC LM 01 = LM_MODE = EDIT     0x01 (client side edit)
                      TRAPSIG  0x02 (client side trap, cvt to telnet proto)
                      FLOW     0x04 (flow control)
                      ECHO     0x10 (echo, client should not neg will echo )
                      SOFT_TAB 0x08 (use spaces instead of tab)
                      LIT_ECHO 0x10 (client will echo non-printable)
IAC LM 02 = LM_FORWARDMASK = do forwardmask, dont forwardmask, will forwardmask, wont forwardmask
                      32 octets       stop using        mask will be used, wont be used
IAC LM 03 = LM_SLC  = set local chars, define functions

01 = SYNCH, 00 = NOSUPPORT,  00 = mt
03 = IP,    62 = VALUE,      03 = ctrl-c, interrupt
04 = AO,    02 = VALUE,      0f = abort output
05 = AYT,   00 = NOSUPPORT,  00 = are you there
07 = ABORT, 62 = VALUE,      1c = interrupt process
08 = EOF,   42 = VALUE,      04 = ctrl-d, support kbd eof
09 = SUSP,  42 = VALUE,      1a = suspend process
0a = EC,    02 = VALUE,      7f = earse char
0b = EL,    02 = VALUE,      15 = earse line
0c = EW,    02 = VALUE,      17 = earse word
0d = RP,    02 = VALUE,      12 = reprint line
0e = LNEXT, 02 = VALUE,      16 = liternal next char, escapes telnet
0f = XON,   02 = VALUE,      11 = resume output
10 = XOFF,  02 = VALUE,      13 = stop output
11 = FORW1, 00 = NOSUPPORT,  00 = flush output
12 = FORW2, 00 = NOSUPPORT,  00 = same

SLC_ACK      = 0x80
SLC_FLUSHIN  = 0x40 when sent, send SYNCH
SLC_FLUSHOUT = 0x20 when sent, output flushed

#endif
/*
 * negotiate window size (rfc 1073):
 *
 * (server sends)  IAC DO NAWS
 * (client sends)  IAC WILL NAWS
 * (client sends)  IAC SB NAWS 0 80 0 24 IAC SE
 *
 * ctrl-c: (rfc 854)
 *
 * (client sends)  { IAC IP } { IAC DO MARK }
 *
 * telnet
 *
 * IAC DO SGA     do supress go ahead      (0x03)
 * IAC WILL TT    will terminal type       (0x18)
 * IAC WILL NAWS  will window size         (0x1f)
 * IAC WILL TTS   will terminal speed      (0x20)
 * IAC WILL RFC   will remote flow control (0x21)
 * IAC WILL LM    will line mode           (0x22)
 * IAC WILL ENV   will environment option  (0x27)
 * IAC DO STA     do status                (0x05)
 * IAC WILL XW    will display X location  (0x23)
 *
 * telnetd
 *
 * IAC DO TT
 * IAC DO TTS
 * IAC DO XW
 * IAC DO ENV
 * IAC WILL SGA
 * IAC DO NAWS
 * IAC DO RFC
 * IAC DONT LM
 * IAC WILL STA
 * IAC SB term speed IAC SE
 * IAC SB env option IAC SE
 * IAC SB term type IAC SE
 *
 * telnet
 *
 * IAC SB NAWS 00 137 00 98 IAC SE  window size 137, 98
 * IAC SB TTS ... IAC SE            terminal speed
 * IAC SB XW tracy.rai:0 IAC SE     display location
 * IAC SB TT XTERM-256COLOR IAC SE  terminal type
 *
 * telnetd
 *
 * IAC DO ECHO
 *
 * telnet
 *
 * IAC WONT ECHO
 *
 * telnetd
 *
 * IAC WILL ECHO
 * \r\n
 * Kernel ... on x86_64\r\n
 *
 * IAC DO ECHO
 *
 * tracy login:
 */

}
}
#endif
