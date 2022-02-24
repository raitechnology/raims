#ifndef __rai_raims__console_h__
#define __rai_raims__console_h__

#include <raikv/array_space.h>
#include <raikv/dlinklist.h>
#include <raikv/logger.h>
#include <raikv/ev_net.h>
#include <raimd/md_types.h>
#include <raims/sub.h>
#include <raims/string_tab.h>
#include <raims/config_tree.h>

extern "C" {
  struct LineCook_s;
  struct Term_s;
  int console_complete( struct LineCook_s *state,  const char *buf,  size_t off,
                        size_t len ) noexcept;
  void console_help( struct Term_s *term ) noexcept;
}

namespace rai {
namespace ms {

struct ConsoleOutput {
  ConsoleOutput *next, *back;
  ConsoleOutput() : next( 0 ), back( 0 ) {}
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
  virtual void on_prompt( const char *prompt ) noexcept;
  virtual void on_quit( void ) noexcept;
};

struct ConsoleOutputList : public kv::DLinkList< ConsoleOutput > {};

struct SessionMgr;
struct UserDB;
struct SubDB;
struct UserRoute;
struct TransportRoute;
struct ExtRte;
struct Nonce;
struct Console;

enum PortFlags {
  P_IS_LOCAL  = 1,
  P_IS_REMOTE = 2,
  P_IS_INBOX  = 4,
  P_IS_DOWN   = 8
};
struct PortOutput {
  Console        & console;
  SessionMgr     & mgr;
  UserDB         & user_db;
  uint32_t         tport_id,
                   ncols;
  UserBridge     * n;
  StringVal        local,
                   remote,
                 * tport,
                 * type;
  TransportRoute * rte;
  uint32_t         state;
  int              fd,
                   flags;
  kv::PeerStats    stats;

  PortOutput( Console &c,  uint32_t t,  uint32_t nc ) noexcept;

  void init( TransportRoute *rte,  int fl,  int fd,
             UserBridge *user = NULL ) noexcept;
  void init( TransportRoute *rte,  ExtRte *ext ) noexcept;

  void local_addr( const char *buf,  uint32_t len = 0 ) {
    this->local.val = buf;
    if ( len == 0 )
      this->local.len = kv::get_strlen64( buf );
    else
      this->local.len = len;
  }
  void remote_addr( const char *buf,  uint32_t len = 0 ) {
    this->remote.val = buf;
    if ( len == 0 )
      this->remote.len = kv::get_strlen64( buf );
    else
      this->remote.len = len;
  }
  void put_show_ports( void ) noexcept;

  void put_status( void ) noexcept;

  uint32_t output( void ( PortOutput::*put )( void ) ) noexcept;
};

enum PrintType {
  PRINT_NULL        = 0,
  PRINT_STRING      = 1,
  PRINT_SELF        = 2,
  PRINT_ID          = 3,
  PRINT_USER        = 4,
  PRINT_ADDR        = 5,
  PRINT_TPORT       = 6,
  PRINT_UADDR       = 7,
  PRINT_NONCE       = 8,
  PRINT_DIST        = 9,
  PRINT_LATENCY     = 10,
  PRINT_INT         = 11,
  PRINT_SHORT_HEX   = 12,
  PRINT_LONG_HEX    = 13,
  PRINT_STATE       = 14,
  PRINT_LONG        = 15,
  PRINT_STAMP       = 16,
  PRINT_TPORT_STATE = 17,
  PRINT_SOCK_STATE  = 18,
  PRINT_LEFT        = 0x40, /* left justify */
  PRINT_SEP         = 0x80, /* separator after row */
  PRINT_NULL_TERM   = 0x100,/* string null terminated */
  PRINT_STRING_NT   = PRINT_STRING | PRINT_NULL_TERM
};

struct TabPrint {
  const char * val, * pre;
  UserBridge * n;
  uint64_t     ival;
  uint32_t     len;
  uint16_t     typ;

  PrintType type( void ) const {
    return (PrintType) ( this->typ & 0x3f );
  }
  bool separator( void ) const {
    return ( this->typ & PRINT_SEP ) != 0;
  }
  bool left( void ) const {
    return ( this->typ & PRINT_LEFT ) != 0;
  }
  bool null_term( void ) const {
    return ( this->typ & PRINT_NULL_TERM ) != 0;
  }
  void set_null( void ) {
    this->typ = PRINT_NULL;
  }
  void set( const StringVal &s,  PrintType t = PRINT_STRING_NT ) {
    this->val = s.val;
    this->len = s.len;
    this->typ = t;
  }
  void set( const StringVal &s,  uint32_t i,  PrintType t = PRINT_ID ) {
    this->val = s.val;
    this->len = i;
    this->typ = t;
  }
  void set( const char *s,  uint32_t l,  PrintType t = PRINT_STRING ) {
    this->val = s;
    this->len = l;
    this->typ = t;
  }
  void set_tport( const StringVal &s,  const char *p ) {
    this->val = s.val;
    this->len = s.len;
    this->pre = p;
    this->typ = PRINT_TPORT;
  }
  void set_url( const char *p,  const StringVal &s ) {
    this->set_url( p, s.val, s.len );
  }
  void set_url_dest( UserBridge *n,  const char *p,  const StringVal &s ) {
    this->set_url_dest( n, p, s.val, s.len );
  }
  void set_url( const char *p,  const char *s,  uint32_t l,
                PrintType t = PRINT_ADDR ) {
    this->pre = p;
    this->val = s;
    this->len = l;
    this->typ = t;
  }
  void set_url_dest( UserBridge *n,  const char *p,  const char *s,  uint32_t l,
                     PrintType t = PRINT_UADDR ) {
    this->n   = n;
    this->pre = p;
    this->val = s;
    this->len = l;
    this->typ = t;
  }
  void set( const char *s ) {
    this->val = s;
    this->len = ( s != NULL ? ::strlen( s ) : 0 );
    this->typ = PRINT_STRING_NT;
  }
  void set( UserBridge *bridge,  PrintType t ) {
    this->n   = bridge;
    this->typ = t;
  }
  void set_long( uint64_t l,  PrintType t = PRINT_LONG ) {
    this->ival = l;
    this->typ  = t;
  }
  void set_time( uint64_t l ) {
    this->ival = l;
    this->typ  = PRINT_STAMP;
  }
  void set_int( uint32_t i,  PrintType t = PRINT_INT ) {
    this->len = i;
    this->typ = t;
  }
  uint32_t width( UserDB &user_db,  char *buf ) noexcept;
  const char * string( char *buf ) noexcept;
};

enum ConsRpcType {
  PING_RPC = 0,
  SUBS_RPC = 1
};

struct Console;
struct ConsoleRPC : public SubOnMsg {
  ConsoleRPC * next,
             * back;
  Console    & console;
  uint64_t     token;
  uint32_t     inbox_num,
               total_recv,
               count;
  ConsRpcType  type;
  bool         complete;
  ConsoleRPC( Console &c,  ConsRpcType t )
    : next( 0 ), back( 0 ), console( c ), token( 0 ), inbox_num( 0 ),
      total_recv( 0 ), count( 0 ), type( t ), complete( false ) {}
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->token++;
    this->total_recv = 0;
    this->count      = 0;
    this->complete   = false;
  }
};

struct PingReply {
  uint32_t uid, tid;
  uint64_t sent_time, recv_time;
};

struct ConsolePing : public ConsoleRPC {
  kv::ArrayCount< PingReply, 16 > reply;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ConsolePing( Console &c ) : ConsoleRPC( c, PING_RPC ) {}
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->ConsoleRPC::init();
    this->reply.count = 0;
  }
};

struct SubsReply {
  size_t   sub_off;
  uint32_t uid;
  uint16_t sub_len;
  bool     is_pattern;
};

struct ConsoleSubs : public ConsoleRPC {
  kv::ArrayCount< char, 8192 >      strings;
  kv::ArrayCount< SubsReply, 1024 > reply;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ConsoleSubs( Console &c ) : ConsoleRPC( c, SUBS_RPC ) {}
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->ConsoleRPC::init();
    this->strings.count = 0;
    this->reply.count   = 0;
  }
};

struct ConsoleRPCList : public kv::DLinkList< ConsoleRPC > {};

struct ConfigChange {
  ConfigChange * next,
               * back;
  ConfigTree::Transport  * tport;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ConfigChange( ConfigTree::Transport *t )
    : next( 0 ), back( 0 ), tport( t ) {}
};

struct ConfigChangeList : public kv::DLinkList< ConfigChange > {
  void add( ConfigTree::Transport *tport ) {
    for ( ConfigChange *p = this->hd; p != NULL; p = p->next ) {
      if ( p->tport == tport )
        return;
    }
    this->push_tl( new ( ::malloc( sizeof( ConfigChange ) ) )
                   ConfigChange( tport ) );
  }
  void release( void ) {
    while ( ! this->is_empty() )
      delete this->pop_hd();
  }
};

struct ConsoleCmdString;

struct Console : public md::MDOutput, public SubOnMsg, public ConfigPrinter {
  SessionMgr      & mgr;
  UserDB          & user_db;
  SubDB           & sub_db;
  ConfigTree      & tree;
  StringTab       & string_tab;
  ConfigTree::PairList    free_pairs;
  ConfigTree::Transport * cfg_tport;
  ConfigChangeList  changes;
  const char      * fname_fmt,
                  * type_fmt;
  char            * prompt;
  ConsoleOutputList term_list;
  ConsoleRPCList    rpc_list;
  kv::ArrayCount< char, 8192 > out;
  kv::ArrayCount< char, 8192 > log;
  kv::ArrayCount< char, 8192 > tmp;
  kv::ArrayCount< TabPrint, 64 > table;
  uint32_t          max_log,
                    log_index,
                    log_ptr,
                    inbox_num;
  uint64_t          log_rotate_time;
  char            * log_filename;
  int               log_fd;
  uint32_t          next_rotate;
  int               log_status;
  bool              mute_log;

  static const size_t TS_LEN         = 8, /* H:M:S */
                      TSFRACTION_LEN = 3, /* 123 */
                      TSERR_OFF      = TS_LEN + 1 + TSFRACTION_LEN,
                      TSHDR_LEN      = TS_LEN + 1 + TSFRACTION_LEN + 2;
  char ts[ TSERR_OFF ];
  uint64_t last_secs, last_ms;

  Console( SessionMgr &mgr ) noexcept;
  bool open_log( const char *fn ) noexcept;
  bool rotate_log( void ) noexcept;
  size_t make_prompt( const char *where = NULL,  size_t wsz = 0 ) noexcept;
  void update_prompt( const char *where = NULL,  size_t wsz = 0 ) noexcept;
  void change_prompt( const char *where = NULL,  size_t wsz = 0 ) noexcept;
  bool on_log( kv::Logger &log ) noexcept;
  void flush_log( kv::Logger &log ) noexcept;
  bool colorize_log( const char *buf,  size_t len ) noexcept;
  bool flush_output( void ) noexcept;
  void get_valid_cmds( const ConsoleCmdString *&cmds, size_t &ncmds ) noexcept;
  void get_valid_help_cmds( const ConsoleCmdString *&cmds,
                            size_t &ncmds ) noexcept;
  int parse_command( const char *buf,  const char *end,
                     const char *&arg,  size_t &len,
                     const char **args,  size_t *arglen,
                     size_t &argcount ) noexcept;
  void output_help( int c ) noexcept;
  void print_dashes( const uint32_t *width,  uint32_t ncols ) noexcept;
  void print_table( const char **hdr,  uint32_t ncols ) noexcept;
  void tab_connection( const char *proto,  const char *remote,  uint32_t rsz,
                       const char *local,  uint32_t lsz,
                       const UserBridge &n,  TabPrint &pr ) noexcept;
  void tab_url( const char *proto,  const char *addr,  uint32_t addrlen,
                TabPrint &pr ) noexcept;
  void tab_user_id( uint32_t uid,  TabPrint &pr ) noexcept;
  void tab_concat( const char *s,  size_t sz1,  const char *s2,
                   TabPrint &pr ) noexcept;
  void tab_string( const char *buf,  TabPrint &pr ) noexcept;
  void tab_concat( const char *s,  const char *s2,  TabPrint &pr ) noexcept;
  void tab_nonce( const Nonce &nonce,  TabPrint &pr ) noexcept;
  UserBridge * find_user( const char *name,  size_t len ) noexcept;
  virtual bool on_input( ConsoleOutput *p,  const char *buf,
                         size_t buflen ) noexcept;
  virtual void on_data( const SubMsgData &val ) noexcept;
  int find_tport( const char *name,  uint32_t len,
                  ConfigTree::Transport *&tree_idx,
                  uint32_t &tport_id ) noexcept;
  void connect( const char *arg,  uint32_t arglen ) noexcept;
  void listen( const char *arg,  uint32_t arglen ) noexcept;
  void shutdown( const char *arg,  uint32_t arglen ) noexcept;
  void get_active_tports( ConfigTree::TransportArray &listen, 
                          ConfigTree::TransportArray &connect ) noexcept;
  void config_save( void ) noexcept;
  void config_param( const char *param,  size_t plen,
                     const char *value,  size_t vlen ) noexcept;
  void config_tport( const char *param,  size_t plen,
                     const char **value,  size_t *vlen,
                     size_t nvals ) noexcept;
  void config_tport_route( const char *param,  size_t plen,
                           const char *value,  size_t vlen ) noexcept;
  void show_subs( const char *arg,  uint32_t arglen ) noexcept;
  void ping_peer( const char *arg,  uint32_t arglen ) noexcept;
  void mcast_ping( void ) noexcept;

  void on_ping( ConsolePing &ping ) noexcept;
  void on_subs( ConsoleSubs &subs ) noexcept;
  void print_msg( md::MDMsg &msg ) noexcept;
  void show_tports( const char *name,  size_t len ) noexcept;
  void show_users( void ) noexcept;
  void show_events( void ) noexcept;
  void show_unknown( void ) noexcept;
  void show_ports( const char *name,  size_t len ) noexcept;
  void show_status( const char *name,  size_t len ) noexcept;
  uint32_t show_port( uint32_t tport_id,  uint32_t ncols,
                      uint32_t i ) noexcept;
  void show_peers( void ) noexcept;
  void show_adjacency( void ) noexcept;
  void show_routes( void ) noexcept;
  void show_urls( void ) noexcept;
  void show_counters( void ) noexcept;
  void show_reachable( void ) noexcept;
  void show_tree( const UserBridge *src ) noexcept;
  void show_primary( void ) noexcept;
  void show_fds( void ) noexcept;
  void show_blooms( void ) noexcept;
  void show_running( int which,  const char *name,  size_t len ) noexcept;
  void config( const char *name,  size_t len ) noexcept;
  int puts( const char *s ) noexcept;
  virtual int printf( const char *fmt,  ... ) noexcept final __attribute__((format(printf,2,3)));
  void log_output( int stream,  uint64_t stamp,  size_t len,
                   const char *buf ) noexcept;

  template<class T>
  T * create_rpc( ConsRpcType type ) {
    ConsoleRPC * rpc;
    for ( rpc = this->rpc_list.hd; rpc != NULL; rpc = rpc->next ) {
      if ( rpc->complete && rpc->type == type )
        break;
    }
    if ( rpc == NULL ) {
      rpc = new ( ::malloc( sizeof( T ) ) ) T( *this );
      rpc->inbox_num = this->sub_db.inbox_start( 0, rpc );
      this->rpc_list.push_tl( rpc );
    }
    rpc->init();
    return (T *) rpc;
  }
};

#ifdef IMPORT_CONSOLE_CMDS
enum ConsoleCmd {
  CMD_EMPTY            = 0,
  CMD_PING             = 1,  /* ping [U]                   */
  CMD_MPING            = 2,  /* mping                      */
  CMD_SHOW             = 3,  /* show ... */
  CMD_SHOW_SUBS        = 4,  /* show subs [U]              */
  CMD_SHOW_ADJACENCY   = 5,  /* show adjacency             */
  CMD_SHOW_PEERS       = 6,  /* show peers                 */
  CMD_SHOW_PORTS       = 7,  /* show ports [T]             */
  CMD_SHOW_STATUS      = 8,  /* show status [T]            */
  CMD_SHOW_ROUTES      = 9,  /* show routes                */
  CMD_SHOW_URLS        = 10, /* show urls                  */
  CMD_SHOW_TPORTS      = 11, /* show tport [T]             */
  CMD_SHOW_USERS       = 12, /* show user [U]              */
  CMD_SHOW_EVENTS      = 13, /* show events                */
  CMD_SHOW_UNKNOWN     = 14, /* show unknown               */
  CMD_SHOW_LOG         = 15, /* show log                   */
  CMD_SHOW_COUNTERS    = 16, /* show counters              */
  CMD_SHOW_REACHABLE   = 17, /* show reachable             */
  CMD_SHOW_TREE        = 18, /* show tree [U]              */
  CMD_SHOW_PRIMARY     = 19, /* show primary               */
  CMD_SHOW_FDS         = 20, /* show fds                   */
  CMD_SHOW_BLOOMS      = 21, /* show blooms                */
  CMD_SHOW_RUN         = 22, /* show running               */
  CMD_SHOW_RUN_TPORTS  = 23, /* show running transport [T] */
  CMD_SHOW_RUN_SVCS    = 24, /* show running service [S]   */
  CMD_SHOW_RUN_USERS   = 25, /* show running user [U]      */
  CMD_SHOW_RUN_GROUPS  = 26, /* show running group [G]     */
  CMD_SHOW_RUN_PARAM   = 27, /* show running parameter [P] */
  CMD_CONNECT          = 28, /* connect [T]                */
  CMD_LISTEN           = 29, /* listen [T]                 */
  CMD_SHUTDOWN         = 30, /* shutdown [T]               */
  CMD_CONFIGURE        = 31, /* configure                  */
  CMD_CONFIGURE_TPORT  = 32, /* configure transport T      */
  CMD_CONFIGURE_PARAM  = 33, /* configure parameter P V    */
  CMD_SAVE             = 34, /* save                       */
  CMD_SUB_START        = 35, /* sub subject                */
  CMD_SUB_STOP         = 36, /* unsub subject              */
  CMD_PSUB_START       = 37, /* psub rv-wildcard           */
  CMD_PSUB_STOP        = 38, /* punsub rv-wildcard         */
  CMD_GSUB_START       = 39, /* gsub glob-wildcard         */
  CMD_GSUB_STOP        = 40, /* gunsub glob-wildcard       */
  CMD_PUBLISH          = 41, /* pub subject msg            */
  CMD_TRACE            = 42, /* trace subject msg          */
  CMD_PUB_ACK          = 43, /* ack subject msg            */
  CMD_RPC              = 44, /* rpc subject msg            */
  CMD_ANY              = 45, /* any subject msg            */
  CMD_DEBUG            = 47, /* debug ival                 */
  CMD_CANCEL           = 48, /* cancel                     */
  CMD_MUTE_LOG         = 49, /* mute                       */
  CMD_UNMUTE_LOG       = 50, /* unmute                     */
  CMD_QUIT             = 51, /* quit/exit                  */
  CMD_TPORT_NAME       = 52, /* tport N                    */
  CMD_TPORT_TYPE       = 53, /* type T                     */
  CMD_TPORT_LISTEN     = 54, /* listen A                   */
  CMD_TPORT_CONNECT    = 55, /* connect A                  */
  CMD_TPORT_PORT       = 56, /* port N                     */
  CMD_TPORT_TIMEOUT    = 57, /* timeout N                  */
  CMD_TPORT_MTU        = 58, /* mtu N                      */
  CMD_TPORT_TXW_SQNS   = 59, /* txw_sqns N                 */
  CMD_TPORT_RXW_SQNS   = 60, /* rxw_sqns N                 */
  CMD_TPORT_MCAST_LOOP = 61, /* mcast_loop N               */
  CMD_TPORT_EDGE       = 62, /* edge B                     */
  CMD_TPORT_SHOW       = 63, /* show                       */
  CMD_TPORT_QUIT       = 64, /* quit/exit                  */
  CMD_BAD              = 65
};

enum ConsoleArgType {
  NO_ARG    = 0,  /* arg type for completions */
  PEER_ARG  = 1,
  USER_ARG  = 2,
  SVC_ARG   = 3,
  PARM_ARG  = 4,
  GRP_ARG   = 5,
  TPORT_ARG = 6,
  SUB_ARG   = 7,
  PUB_ARG   = 8
};

struct ConsoleCmdString {
  ConsoleCmd   cmd; /* enum val */
  const char * str; /* command match string */
};

struct ConsoleCmdType {
  ConsoleCmd     cmd;  /* enum val */
  ConsoleArgType type; /* arg type */
};

static const ConsoleCmdType command_type[] = {
  { CMD_PING            , PEER_ARG   }, /* ping peers */
  { CMD_CONNECT         , TPORT_ARG  }, /* connect <tport> */
  { CMD_LISTEN          , TPORT_ARG  }, /* listen <tport> */
  { CMD_SHUTDOWN        , TPORT_ARG  }, /* shutdown <tport> */
  { CMD_CONFIGURE_TPORT , TPORT_ARG  }, /* configure transport <tport> */
  { CMD_CONFIGURE_PARAM , PARM_ARG   }, /* configure parameter <parm> */
  { CMD_SUB_START       , SUB_ARG    }, /* subscribe <subject> */
  { CMD_SUB_STOP        , SUB_ARG    }, /* unsubscribe <subject> */
  { CMD_PSUB_START      , SUB_ARG    }, /* psubscribe <rv-pattern> */
  { CMD_PSUB_STOP       , SUB_ARG    }, /* punsubscribe <rv-pattern> */
  { CMD_GSUB_START      , SUB_ARG    }, /* gsubscribe <glob-pattern> */
  { CMD_GSUB_STOP       , SUB_ARG    }, /* gunsubscribe <glob-pattern> */
  { CMD_PUBLISH         , PUB_ARG    }, /* pub <subject> message */
  { CMD_TRACE           , PUB_ARG    }, /* trace <subject> message */
  { CMD_PUB_ACK         , PUB_ARG    }, /* ack <subject> message */
  { CMD_RPC             , PUB_ARG    }, /* rpc <subject> message */
  { CMD_ANY             , PUB_ARG    }, /* any <subject> message */
  { CMD_SHOW_SUBS       , PEER_ARG   }, /* request sub tables */
  { CMD_SHOW_PORTS      , TPORT_ARG  }, /* show ports tport */
  { CMD_SHOW_STATUS     , TPORT_ARG  }, /* show status tport */
  { CMD_SHOW_TPORTS     , TPORT_ARG  }, /* show tport config */
  { CMD_SHOW_USERS      , PEER_ARG   }, /* show user concig */
  { CMD_SHOW_TREE       , PEER_ARG   }, /* show tree */
  { CMD_SHOW_RUN_TPORTS , TPORT_ARG  }, /* show running transport <tport> */
  { CMD_SHOW_RUN_SVCS   , SVC_ARG    }, /* show running service <svc> */
  { CMD_SHOW_RUN_USERS  , USER_ARG   }, /* show running user <user> */
  { CMD_SHOW_RUN_GROUPS , GRP_ARG    }, /* show running group <grp> */
  { CMD_SHOW_RUN_PARAM  , PARM_ARG   }  /* show running parameter <parm> */
};
#define ASZ( A ) ( sizeof( A ) / sizeof( A[ 0 ] ) )
static const size_t num_command_types = ASZ( command_type );

static inline ConsoleArgType console_command_type( ConsoleCmd cmd ) {
  for ( size_t i = 0; i < num_command_types; i++ )
    if ( cmd == command_type[ i ].cmd )
      return command_type[ i ].type;
  return NO_ARG;
}

static const ConsoleCmdString console_cmd[] = {
  { CMD_PING       , "ping"         }, /* ping peers */
  { CMD_MPING      , "mping"        }, /* multicast ping peers */
  { CMD_SHOW       , "show"         }, /* show <subcmd> */
  { CMD_CONNECT    , "connect"      }, /* connect <tport> */
  { CMD_LISTEN     , "listen"       }, /* listen <tport> */
  { CMD_SHUTDOWN   , "shutdown"     }, /* shutdown <tport> */
  { CMD_CONFIGURE  , "configure"    }, /* configure <subcmd> */
  { CMD_SAVE       , "save"         }, /* save config */
  { CMD_SUB_START  , "subscribe"    }, /* subscribe <subject> */
  { CMD_SUB_STOP   , "unsubscribe"  }, /* unsubscribe <subject> */
  { CMD_PSUB_START , "psubscribe"   }, /* psubscribe <rv-pattern> */
  { CMD_PSUB_STOP  , "punsubscribe" }, /* punsubscribe <rv-pattern> */
  { CMD_GSUB_START , "gsubscribe"   }, /* gsubscribe <glob-pattern> */
  { CMD_GSUB_STOP  , "gunsubscribe" }, /* gunsubscribe <glob-pattern> */
  { CMD_PUBLISH    , "publish"      }, /* pub <subject> message */
  { CMD_TRACE      , "trace"        }, /* trace <subject> message */
  { CMD_PUB_ACK    , "ack"          }, /* ack <subject> message */
  { CMD_RPC        , "rpc"          }, /* rpc <subject> message */
  { CMD_ANY        , "any"          }, /* any <subject> message */
  { CMD_DEBUG      , "debug"        }, /* debug <integer> */
  { CMD_CANCEL     , "cancel"       }, /* cancel incomplete rpc */
  { CMD_MUTE_LOG   , "mute"         }, /* mute log */
  { CMD_UNMUTE_LOG , "unmute"       }, /* unmute log */
  { CMD_QUIT       , "quit"         },
  { CMD_QUIT       , "exit"         }
};
static const size_t num_console_cmds = ASZ( console_cmd );

static const ConsoleCmdString show_cmd[] = {
  { CMD_SHOW_SUBS      , "subscriptions" }, /* request sub tables */
  { CMD_SHOW_ADJACENCY , "adjacency"     }, /* show adjacency */
  { CMD_SHOW_PEERS     , "peers"         }, /* show peers */
  { CMD_SHOW_PORTS     , "ports"         }, /* show ports tport */
  { CMD_SHOW_STATUS    , "status"        }, /* show status tport */
  { CMD_SHOW_ROUTES    , "routes"        }, /* show routes */
  { CMD_SHOW_URLS      , "urls"          }, /* show urls */
  { CMD_SHOW_TPORTS    , "tports"        }, /* show tport config */
  { CMD_SHOW_USERS     , "users"         }, /* show user concig */
  { CMD_SHOW_EVENTS    , "events"        }, /* show events */
  { CMD_SHOW_UNKNOWN   , "unknown"       }, /* show unknown */
  { CMD_SHOW_LOG       , "log"           }, /* show log */
  { CMD_SHOW_COUNTERS  , "counters"      }, /* show counters */
  { CMD_SHOW_REACHABLE , "reachable"     }, /* show reachable */
  { CMD_SHOW_TREE      , "tree"          }, /* show tree */
  { CMD_SHOW_PRIMARY   , "primary"       }, /* show primary */
  { CMD_SHOW_FDS       , "fds"           }, /* show fds */
  { CMD_SHOW_BLOOMS    , "blooms"        }, /* show blooms */
  { CMD_SHOW_RUN       , "running"       }  /* show running */
};
static const size_t num_show_cmds = ASZ( show_cmd );

static const ConsoleCmdString run_cmd[] = {
  { CMD_SHOW_RUN_TPORTS , "transports" }, /* config sections */
  { CMD_SHOW_RUN_SVCS   , "services"   },
  { CMD_SHOW_RUN_USERS  , "users"      },
  { CMD_SHOW_RUN_GROUPS , "groups"     },
  { CMD_SHOW_RUN_PARAM  , "parameters" }
};
static const size_t num_run_cmds = ASZ( run_cmd );

static const ConsoleCmdString config_cmd[] = {
  { CMD_CONFIGURE_TPORT , "transport" },
  { CMD_CONFIGURE_PARAM , "parameter" }
};
static const size_t num_config_cmds = ASZ( config_cmd );

static const ConsoleCmdString help_cmd[] = {
  { CMD_PING             , "ping [U]                   Ping peers, all peers or only U"                   },
  { CMD_MPING            , "mping                      Multicast ping all peers"                          },
  { CMD_CONNECT          , "connect [T]                Start tport connect"                               },
  { CMD_LISTEN           , "listen [T]                 Start tport listener"                              },
  { CMD_SHUTDOWN         , "shutdown [T]               Shutdown tport"                                    },
  { CMD_CONFIGURE        , "configure                  Configure ..."                                     },
  { CMD_CONFIGURE_TPORT  , "configure transport T      Configure tport T"                                 },
  { CMD_CONFIGURE_PARAM  , "configure parameter P V    Configure parameter P = V"                         },
  { CMD_SAVE             , "save                       Save current config as startup"                    },
  { CMD_SHOW_SUBS        , "show subs [U]              Get peers subscriptions, all peers or only U"      },
  { CMD_SHOW_ADJACENCY   , "show adjacency             Show peers adjacency"                              },
  { CMD_SHOW_PEERS       , "show peers                 Show peers"                                        },
  { CMD_SHOW_PORTS       , "show ports [T]             Show ports T or all"                               },
  { CMD_SHOW_STATUS      , "show status [T]            Show ports status T or all"                        },
  { CMD_SHOW_ROUTES      , "show routes                Show routes"                                       },
  { CMD_SHOW_URLS        , "show urls                  Show urls of peers"                                },
  { CMD_SHOW_TPORTS      , "show tport [T]             Show tports, or only T"                            },
  { CMD_SHOW_USERS       , "show user [U]              Show users, or only U"                             },
  { CMD_SHOW_EVENTS      , "show events                Show event recorder"                               },
  { CMD_SHOW_UNKNOWN     , "show unknown               Show the list of peers yet to be resolved"         },
  { CMD_SHOW_LOG         , "show log                   Show log buffer"                                   },
  { CMD_SHOW_COUNTERS    , "show counters              Show peers seqno and time values"                  },
  { CMD_SHOW_REACHABLE   , "show reachable             Show reachable peers through tports"               },
  { CMD_SHOW_TREE        , "show tree [U]              Show multicast tree from me or U"                  },
  { CMD_SHOW_PRIMARY     , "show primary               Show primary multicast tree"                       },
  { CMD_SHOW_FDS         , "show fds                   Show fd centric routes"                            },
  { CMD_SHOW_BLOOMS      , "show blooms                Show bloom centric routes"                         },
  { CMD_SHOW_RUN         , "show running               Show all config running"                           },
  { CMD_SHOW_RUN_TPORTS  , "show running transport [T] Show transports running, T or all"                 },
  { CMD_SHOW_RUN_SVCS    , "show running service [S]   Show services running config, S or all"            },
  { CMD_SHOW_RUN_USERS   , "show running user [U]      Show users running config, U or all"               },
  { CMD_SHOW_RUN_GROUPS  , "show running group [G]     Show groups running config, G or all"              },
  { CMD_SHOW_RUN_PARAM   , "show running parameter [P] Show parameters running config, P or all"          },
  { CMD_SUB_START        , "sub subject                Subscribe subject"                                 },
  { CMD_SUB_STOP         , "unsub subject              Unsubscribe subject"                               },
  { CMD_PSUB_START       , "psub wildcard              Subscribe rv-wildcard"                             },
  { CMD_PSUB_STOP        , "punsub wildcard            Unsubscribe rv-wildcard"                           },
  { CMD_GSUB_START       , "gsub wildcard              Subscribe glob-wildcard"                           },
  { CMD_GSUB_STOP        , "gunsub wildcard            Unsubscribe glob-wildcard"                         },
  { CMD_PUBLISH          , "pub subject msg            Publish msg string to subject"                     },
  { CMD_TRACE            , "trace subject msg          Publish msg string to subject, route will reply"   },
  { CMD_PUB_ACK          , "ack subject msg            Publish msg string to subject, recver will ack"    },
  { CMD_RPC              , "rpc subject msg            Publish msg string to subject, with return"        },
  { CMD_ANY              , "any subject msg            Publish msg string to any subject"                 },
  { CMD_CANCEL           , "cancel                     Cancel and show incomplete (ping, show subs)"      },
  { CMD_MUTE_LOG         , "mute                       Mute the log output"                               },
  { CMD_UNMUTE_LOG       , "unmute                     Unmute the log output"                             },
  { CMD_DEBUG            , "debug ival                 Set debug flags to ival, bit mask of:\n"
                           " 1=tcp,     2=pgm,      4=ibx,    8=tport,   0x10=usr,   0x20=link, 0x40=peer,\n"
                           " 0x80=auth, 0x100=sess, 0x200=hb, 0x400=sub, 0x800=mrcv, 0x1000=telnet"       },
  { CMD_QUIT             , "quit/exit                  Exit console"                                      }
};

static const size_t num_help_cmds = ASZ( help_cmd );

static const ConsoleCmdString tport_cmd[] = {
  { CMD_TPORT_NAME       , "tport"      },
  { CMD_TPORT_TYPE       , "type"       },
  { CMD_TPORT_LISTEN     , "listen"     },
  { CMD_TPORT_CONNECT    , "connect"    },
  { CMD_TPORT_PORT       , "port"       },
  { CMD_TPORT_TIMEOUT    , "timeout"    },
  { CMD_TPORT_MTU        , "mtu"        },
  { CMD_TPORT_TXW_SQNS   , "txw_sqns"   },
  { CMD_TPORT_RXW_SQNS   , "rxw_sqns"   },
  { CMD_TPORT_MCAST_LOOP , "mcast_loop" },
  { CMD_TPORT_EDGE       , "edge"       },
  { CMD_TPORT_SHOW       , "show"       },
  { CMD_TPORT_QUIT       , "quit"       },
  { CMD_TPORT_QUIT       , "exit"       }
};
static const size_t num_tport_cmds = ASZ( tport_cmd );

static const ConsoleCmd valid_tcp[] =
  { CMD_TPORT_NAME, CMD_TPORT_TYPE, CMD_TPORT_LISTEN, CMD_TPORT_CONNECT, CMD_TPORT_PORT,
    CMD_TPORT_TIMEOUT, CMD_TPORT_EDGE, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_mesh[] =
  { CMD_TPORT_NAME, CMD_TPORT_TYPE, CMD_TPORT_LISTEN, CMD_TPORT_CONNECT, CMD_TPORT_PORT,
    CMD_TPORT_TIMEOUT, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_pgm[] =
  { CMD_TPORT_NAME, CMD_TPORT_TYPE, CMD_TPORT_LISTEN, CMD_TPORT_CONNECT, CMD_TPORT_PORT,
    CMD_TPORT_MTU, CMD_TPORT_TXW_SQNS, CMD_TPORT_RXW_SQNS, CMD_TPORT_MCAST_LOOP,
    CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_rv[] =
  { CMD_TPORT_NAME, CMD_TPORT_TYPE, CMD_TPORT_LISTEN, CMD_TPORT_PORT,
    CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_nats[] =
  { CMD_TPORT_NAME, CMD_TPORT_TYPE, CMD_TPORT_LISTEN, CMD_TPORT_PORT,
    CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_redis[] =
  { CMD_TPORT_NAME, CMD_TPORT_TYPE, CMD_TPORT_LISTEN, CMD_TPORT_PORT,
    CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmdString tport_help_cmd[] = {
  { CMD_TPORT_NAME       , "tport N      Name of transport" },
  { CMD_TPORT_TYPE       , "type T       Type of transport (tcp,pgm,mesh,rv,nats,redis)" },
  { CMD_TPORT_LISTEN     , "listen A     Listen address for passive transport" },
  { CMD_TPORT_CONNECT    , "connect A    Connect address for active transport" },
  { CMD_TPORT_PORT       , "port N       Port for address" },
  { CMD_TPORT_TIMEOUT    , "timeout N    Timeout for connect or accept" },
  { CMD_TPORT_MTU        , "mtu N        MTU for pgm type transport, which is the UDP datagram size" },
  { CMD_TPORT_TXW_SQNS   , "txw_sqns N   Transmit window for pgm type transport, in datagram sequences" },
  { CMD_TPORT_RXW_SQNS   , "rxw_sqns N   Recieve window for pgm type transport, in datagram sequences" },
  { CMD_TPORT_MCAST_LOOP , "mcast_loop N Controls multicast loop: 0 - none, 2 - host loop and exclude sender" },
  { CMD_TPORT_EDGE       , "edge B       When true, don't create a adjaceny and use existing" },
  { CMD_TPORT_SHOW       , "show         Show tport config" },
  { CMD_TPORT_QUIT       , "quit/exit    Exit config" }
};
static const size_t num_tport_help_cmds = ASZ( tport_help_cmd );

struct ValidCmds {
  const char       * type;
  const ConsoleCmd * valid;
  size_t             nvalid;
  ConsoleCmdString * cmd;
  size_t             ncmds;
  ConsoleCmdString * help;
  size_t             nhelps;
} valid_cmd[] = {
  { "tcp",  valid_tcp,  ASZ( valid_tcp ),  NULL, 0, NULL, 0 },
  { "mesh", valid_mesh, ASZ( valid_mesh ), NULL, 0, NULL, 0 },
  { "pgm",  valid_pgm,  ASZ( valid_pgm ),  NULL, 0, NULL, 0 },
  { "rv",   valid_rv,   ASZ( valid_rv ),   NULL, 0, NULL, 0 },
  { "nats", valid_nats, ASZ( valid_nats ), NULL, 0, NULL, 0 },
  { "redis",valid_redis,ASZ( valid_redis ),NULL, 0, NULL, 0 }
};
static const size_t num_valid_cmds = ASZ( valid_cmd );
#undef ASZ

struct CmdMask {
  static const uint32_t max_bit = (uint32_t) CMD_BAD + 1;
  uint64_t bits[ ( max_bit + 63 ) / 64 ];
  CmdMask() { this->zero(); }
  void zero( void ) {
    kv::BitSetT<uint64_t> set( this->bits );
    set.zero( max_bit );
  }
  void mask( uint32_t nbits ) {
    kv::BitSetT<uint64_t> set( this->bits );
    set.zero( max_bit );
    for ( uint32_t b = 0; b < nbits; b++ )
      set.add( b );
  }
  bool is_member( uint32_t b ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.is_member( b );
  }
  void add( uint32_t b ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.add( b );
  }
  void remove( uint32_t b ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.remove( b );
  }
  uint32_t count( void ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.count( max_bit );
  }
};

static ConsoleCmd
which_cmd( const ConsoleCmdString *cmds,  size_t ncmds,
           const char *buf,  size_t buflen,  CmdMask *cmd_mask )
{
  CmdMask  match;
  size_t   off, last = 0;
  bool     matched = false;
  match.mask( ncmds );
  for ( off = 0; match.count() != 0; off++ ) {
    if ( off == buflen || buf[ off ] == ' ' ) {
      matched = true;
      break;
    }
    for ( size_t i = 0; i < ncmds; i++ ) {
      if ( match.is_member( i ) ) {
        if ( cmds[ i ].str[ off ] != buf[ off ] )
          match.remove( i );
        else
          last = i;
      }
    }
  }
  if ( cmd_mask != NULL ) {
    cmd_mask->zero();
    if ( match.count() != 0 ) {
      for ( size_t i = 0; i < ncmds; i++ ) {
        if ( match.is_member( i ) )
          cmd_mask->add( cmds[ i ].cmd );
      }
    }
  }
  if ( match.count() == 1 && matched )
    return cmds[ last ].cmd;
  return CMD_BAD;
}
#if 0
static ConsoleCmd
which_command( const char *buf,  size_t buflen,  uint64_t *cmd_mask = NULL )
{
  return which_cmd( console_cmd, num_console_cmds, buf, buflen, cmd_mask );
}
#endif
static ConsoleCmd
which_show( const char *buf,  size_t buflen,  CmdMask *cmd_mask = NULL )
{
  return which_cmd( show_cmd, num_show_cmds, buf, buflen, cmd_mask );
}

static ConsoleCmd
which_run( const char *buf,  size_t buflen,  CmdMask *cmd_mask = NULL )
{
  return which_cmd( run_cmd, num_run_cmds, buf, buflen, cmd_mask );
}

static ConsoleCmd
which_config( const char *buf,  size_t buflen,  CmdMask *cmd_mask = NULL )
{
  return which_cmd( config_cmd, num_config_cmds, buf, buflen, cmd_mask );
}

#endif

}
}

#endif
