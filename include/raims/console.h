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
#include <raims/config_const.h>

extern "C" {
  struct LineCook_s;
  struct Term_s;
  int console_complete( struct LineCook_s *state,  const char *buf,  size_t off,
                        size_t len,  void *me ) noexcept;
  void console_help( struct Term_s *term ) noexcept;
}

namespace rai {
namespace ms {

struct ConsoleRPC;
struct ConsoleOutput {
  ConsoleOutput *next, *back;
  ConsoleRPC * rpc;
  bool is_html, is_json, is_remote;
  ConsoleOutput( bool html = false,  bool json = false,  bool is_rem = false )
    : next( 0 ), back( 0 ), rpc( 0 ), is_html( html ), is_json( json ),
      is_remote( is_rem ) {}
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
  virtual void on_prompt( const char *prompt ) noexcept;
  virtual void on_quit( void ) noexcept;
  virtual void on_remove( void ) noexcept;
};

struct ConsoleOutputList : public kv::DLinkList< ConsoleOutput > {};
struct ConsoleOutArray   : public kv::ArrayCount< ConsoleOutput *, 2 > {
  ConsoleRPC * rpc;
  ConsoleOutArray( ConsoleRPC * r ) : rpc( r ) {}
  bool add( ConsoleOutput *p ) noexcept;
  bool replace( ConsoleOutput *p,  ConsoleOutput *p2 ) noexcept;
  bool remove( ConsoleOutput *p ) noexcept;
};

struct JsonFileOutput : public ConsoleOutput {
  char   * path;
  uint32_t pathlen;
  int      fd;
  void * operator new( size_t, void *ptr ) { return ptr; }
  JsonFileOutput( int fildes )
    : ConsoleOutput( false, true ), path( 0 ), pathlen( 0 ), fd( fildes ) {}
  static JsonFileOutput *create( const char *path,  size_t pathlen ) noexcept;
  bool open( void ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
  virtual void on_remove( void ) noexcept;
};

struct JsonOutArray : public kv::ArrayCount< JsonFileOutput *, 2 > {
  JsonOutArray() {}
  JsonFileOutput * open( const char *path,  size_t pathlen ) noexcept;
  JsonFileOutput * find( const char *path,  size_t pathlen ) noexcept;
};

struct JsonBufOutput : public ConsoleOutput {
  kv::ArrayOutput result;
  JsonBufOutput() : ConsoleOutput( false, true ) {}
  ~JsonBufOutput() { this->result.clear(); }
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
};

struct SessionMgr;
struct UserDB;
struct SubDB;
struct UserRoute;
struct TransportRoute;
struct IpcRte;
struct Nonce;
struct Console;
struct TabOut;
struct Unrouteable;

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
  TabOut         & out;
  uint32_t         tport_id,
                   state;
  uint64_t         cur_time;
  UserBridge     * n;
  StringVal        local,
                   remote,
                 * tport,
                 * type;
  TransportRoute * rte;
  int              fd,
                   flags;
  kv::PeerStats    stats;
  Unrouteable    * unrouteable;

  PortOutput( Console &c,  TabOut &o,  uint32_t t ) noexcept;
  PortOutput( Console &c,  TabOut &o,  Unrouteable *u ) noexcept;

  void init( TransportRoute *rte,  int fl,  int fd,
             UserBridge *user = NULL ) noexcept;
  void init( TransportRoute *rte,  IpcRte *ext ) noexcept;

  void init( ConfigTree::Transport &tport,  int fl,  int fd ) noexcept;

  void local_addr( const char *buf,  uint32_t len = 0 ) {
    this->local.val = buf;
    if ( len == 0 )
      this->local.len = (uint32_t) kv::get_strlen64( buf );
    else
      this->local.len = len;
  }
  void remote_addr( const char *buf,  uint32_t len = 0 ) {
    this->remote.val = buf;
    if ( len == 0 )
      this->remote.len = (uint32_t) kv::get_strlen64( buf );
    else
      this->remote.len = len;
  }
  void put_show_ports( void ) noexcept;
  void put_show_cost( void ) noexcept;
  void put_status( void ) noexcept;
  void output( void ( PortOutput::*put )( void ) ) noexcept;
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
  PRINT_SINT        = 12,
  PRINT_SHORT_HEX   = 13,
  PRINT_LONG_HEX    = 14,
  PRINT_STATE       = 15,
  PRINT_LONG        = 16,
  PRINT_SLONG       = 17,
  PRINT_STAMP       = 18,
  PRINT_TPORT_STATE = 19,
  PRINT_SOCK_STATE  = 20,
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
  TabPrint &set_null( void ) {
    this->typ = PRINT_NULL;
    return this[ 1 ];
  }
  TabPrint &set( const StringVal &s,  PrintType t = PRINT_STRING_NT ) {
    this->val = s.val;
    this->len = s.len;
    this->typ = t;
    return this[ 1 ];
  }
  TabPrint &set( const StringVal &s,  uint32_t i,  PrintType t = PRINT_ID ) {
    this->val = s.val;
    this->len = i;
    this->typ = t;
    return this[ 1 ];
  }
  TabPrint &set( const char *s,  uint32_t l,  PrintType t = PRINT_STRING ) {
    this->val = s;
    this->len = l;
    this->typ = t;
    return this[ 1 ];
  }
  TabPrint &set_tport( const StringVal &s,  const char *p ) {
    this->val = s.val;
    this->len = s.len;
    this->pre = p;
    this->typ = PRINT_TPORT;
    return this[ 1 ];
  }
  TabPrint &set_url( const char *p,  const StringVal &s ) {
    this->set_url( p, s.val, s.len );
    return this[ 1 ];
  }
  TabPrint &set_url_dest( UserBridge *n,  const char *p,  const StringVal &s ) {
    this->set_url_dest( n, p, s.val, s.len );
    return this[ 1 ];
  }
  TabPrint &set_url( const char *p,  const char *s,  uint32_t l,
                     PrintType t = PRINT_ADDR ) {
    this->pre = p;
    this->val = s;
    this->len = l;
    this->typ = t;
    return this[ 1 ];
  }
  TabPrint &set_url_dest( UserBridge *n,  const char *p,  const char *s,  uint32_t l,
                          PrintType t = PRINT_UADDR ) {
    this->n   = n;
    this->pre = p;
    this->val = s;
    this->len = l;
    this->typ = t;
    return this[ 1 ];
  }
  TabPrint &set( const char *s ) {
    this->val = s;
    this->len = (uint32_t) ( s != NULL ? ::strlen( s ) : 0 );
    this->typ = PRINT_STRING_NT;
    return this[ 1 ];
  }
  TabPrint &set( UserBridge *bridge,  PrintType t ) {
    this->n   = bridge;
    this->typ = t;
    return this[ 1 ];
  }
  TabPrint &set_long( uint64_t l,  PrintType t = PRINT_LONG ) {
    this->ival = l;
    this->typ  = t;
    return this[ 1 ];
  }
  TabPrint &set_time( uint64_t l ) {
    this->ival = l;
    this->typ  = PRINT_STAMP;
    return this[ 1 ];
  }
  TabPrint &set_int( uint32_t i,  PrintType t = PRINT_INT ) {
    this->len = i;
    this->typ = t;
    return this[ 1 ];
  }
  uint32_t width( Console &console,  char *buf ) noexcept;
  const char * string( Console &console,  char *buf ) noexcept;
};

enum ConsRpcType {
  PING_RPC   = 0,
  REMOTE_RPC = 1,
  SUBS_RPC   = 2,
  SUB_START  = 3,
  PSUB_START = 4
};

struct Console;
struct ConsoleRPC : public SubOnMsg {
  ConsoleRPC    * next,
                * back;
  Console       & console;
  ConsoleOutArray out;
  uint64_t        token;
  uint32_t        inbox_num,
                  total_recv,
                  count;
  ConsRpcType     type;
  bool            complete;
  ConsoleRPC( Console &c,  ConsRpcType t )
    : next( 0 ), back( 0 ), console( c ), out( this ), token( 0 ),
      inbox_num( 0 ), total_recv( 0 ), count( 0 ), type( t ),
      complete( false ) {}
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->token++;
    this->out.count  = 0;
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
  char * match;
  size_t match_len;
  bool   show_self;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ConsoleSubs( Console &c ) : ConsoleRPC( c, SUBS_RPC ),
    match( 0 ), match_len( 0 ), show_self( false ) {}
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->ConsoleRPC::init();
    this->strings.count = 0;
    this->reply.count   = 0;
    this->match_len     = 0;
    this->show_self     = false;
  }
  void set_match( const char *s,  size_t l ) {
    this->match = (char *) ::realloc( this->match, l + 1 );
    ::memcpy( this->match, s, l );
    this->match[ l ] = '\0';
    this->match_len = l;
  }
};

struct RemoteReply {
  size_t   data_off;
  uint32_t data_len,
           uid;
};

struct ConsoleRemote : public ConsoleRPC {
  kv::ArrayCount< char, 8192 >        strings;
  kv::ArrayCount< RemoteReply, 1024 > reply;
  uint32_t total_recv;
  char   * cmd;
  size_t   cmd_len;
  bool     show_self;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ConsoleRemote( Console &c ) : ConsoleRPC( c, REMOTE_RPC ), total_recv( 0 ),
    cmd( 0 ), cmd_len( 0 ), show_self( false ) {}
  void append_data( uint32_t uid,  const char *str,  size_t len ) noexcept;
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->ConsoleRPC::init();
    this->strings.count = 0;
    this->reply.count   = 0;
    this->total_recv    = 0;
    this->cmd_len       = 0;
    this->show_self     = false;
  }
  void set_command( const char *s,  size_t l ) {
    this->cmd = (char *) ::realloc( this->cmd, l + 1 );
    ::memcpy( this->cmd, s, l );
    this->cmd[ l ] = '\0';
    this->cmd_len = l;
  }
};

struct ConsoleSubStart : public ConsoleRPC {
  uint64_t start_seqno;
  char   * sub;
  size_t   sublen;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ConsoleSubStart( Console &c )
    : ConsoleRPC( c, SUB_START ), start_seqno( 0 ), sub( 0 ), sublen( 0 ) {}
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->ConsoleRPC::init();
    this->start_seqno = 0;
  }
  void set_sub( const char *s,  size_t l ) {
    this->sub = (char *) ::realloc( this->sub, l + 1 );
    ::memcpy( this->sub, s, l );
    this->sub[ l ] = '\0';
    this->sublen = l;
  }
  bool matches( const char *s,  size_t l ) {
    return this->sublen == l && ::memcmp( s, this->sub, l ) == 0;
  }
};

struct ConsolePSubStart : public ConsoleRPC {
  uint64_t start_seqno;
  char   * psub;
  size_t   psublen;
  kv::PatternFmt pat_fmt;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ConsolePSubStart( Console &c )
    : ConsoleRPC( c, PSUB_START ), start_seqno( 0 ),
      psub( 0 ), psublen( 0 ), pat_fmt( kv::RV_PATTERN_FMT ) {}
  virtual void on_data( const SubMsgData &val ) noexcept;
  virtual void init( void ) noexcept {
    this->ConsoleRPC::init();
    this->start_seqno = 0;
  }
  void set_psub( const char *s,  size_t l,  kv::PatternFmt fmt ) {
    this->psub = (char *) ::realloc( this->psub, l + 1 );
    ::memcpy( this->psub, s, l );
    this->psub[ l ] = '\0';
    this->psublen = l;
    this->pat_fmt = fmt;
  }
  bool matches( const char *s,  size_t l,  kv::PatternFmt fmt ) {
    return fmt == pat_fmt &&
      this->psublen == l && ::memcmp( s, this->psub, l ) == 0;
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

typedef kv::ArrayCount< TabPrint, 64 > TableArray;
struct ConsoleCmdString;
struct CmdMask;
struct ConsoleOutBuf : public kv::ArrayOutput {};

struct TabOut {
  TableArray   & table;
  md::MDMsgMem & tmp;
  size_t         ncols;
  TabOut( TableArray & t, md::MDMsgMem & b, size_t n )
      : table( t ), tmp( b ), ncols( n ) {
    t.count = 0;
    b.reuse();
  }
  TabPrint *make_row( void ) {
    TabPrint *tab = this->table.make( this->table.count + this->ncols, true );
    this->table.count += this->ncols;
    return tab;
  }
  TabPrint *add_row_p( void ) {
    size_t i = this->table.count;
    return &(this->make_row())[ i ];
  }
  TabPrint &add_row( void ) {
    return *this->add_row_p();
  }
  TabPrint &row( size_t i ) {
    i += this->table.count - this->ncols;
    return this->table.ptr[ i ];
  }
};

struct LastTimeStamp {
  static const size_t TS_MON_DAY_LEN  = 5,
                      TS_FRACTION_OFF = TS_MON_DAY_LEN + 8, /* md H:M:S */
                      TS_FRACTION_LEN = 3, /* 123 */
                      TS_LEN          = TS_FRACTION_OFF + 1 + TS_FRACTION_LEN;
  uint64_t last_secs, last_ms, last_day;
  char ts[ TS_LEN ];

  LastTimeStamp() : last_secs( 0 ), last_ms( 0 ), last_day( 0 ) {}
  void update( uint64_t stamp ) noexcept;
};

struct Console : public md::MDOutput, public SubOnMsg, public ConfigPrinter {
  SessionMgr      & mgr;
  UserDB          & user_db;
  SubDB           & sub_db;
  ConfigTree      & tree;
  StringTab       & string_tab;
  ConfigTree::Transport * cfg_tport;
  ConfigChangeList  changes;
  const char      * fname_fmt,
                  * type_fmt;
  char            * prompt;
  ConsoleOutputList term_list;
  ConsoleRPCList    rpc_list;
  ConsoleOutBuf     out;
  ConsoleOutBuf     log;
  md::MDMsgMem      tmp;
  TableArray        table;
  JsonOutArray      json_files;
  size_t            max_log,
                    log_index,
                    log_ptr;
  uint32_t          inbox_num,
                    log_max_rotate;
  uint64_t          log_rotate_time,
                    log_max_size;
  char            * log_filename;
  int               log_fd;
  uint32_t          next_rotate;
  int               log_status;
  uint32_t          last_log_hash,
                    last_log_repeat_count;
  bool              mute_log;
  LastTimeStamp     log_ts,
                    stamp_ts;

  static const size_t TS_ERR_OFF = LastTimeStamp::TS_LEN,
                      TS_HDR_LEN = LastTimeStamp::TS_LEN + 2;

  Console( SessionMgr &mgr ) noexcept;
  bool open_log( const char *fn,  bool add_hdr ) noexcept;
  static bool log_header( int fd ) noexcept;
  bool rotate_log( void ) noexcept;
  static void parse_debug_flags( const char *arg,  size_t len,
                                 int &dist_dbg ) noexcept;
  size_t make_prompt( const char *where = NULL,  size_t wsz = 0 ) noexcept;
  void update_prompt( const char *where = NULL,  size_t wsz = 0 ) noexcept;
  void change_prompt( const char *where = NULL,  size_t wsz = 0 ) noexcept;
  bool on_log( kv::Logger &log ) noexcept;
  void flush_log( kv::Logger &log ) noexcept;
  bool colorize_log( ConsoleOutput *p,  const char *buf,  size_t len ) noexcept;
  bool flush_output( ConsoleOutput *p ) noexcept;
  void get_valid_cmds( const ConsoleCmdString *&cmds, size_t &ncmds ) noexcept;
  void get_valid_help_cmds( const ConsoleCmdString *&cmds,
                            size_t &ncmds ) noexcept;
  static int which_cmd( const ConsoleCmdString *cmds,  size_t ncmds,
                   const char *buf, size_t buflen, CmdMask *cmd_mask ) noexcept;
  static const size_t MAXARGS = 64;
  int parse_command( const char *buf,  const char *end,
                     const char *&arg,  size_t &len,
                     const char **args,  size_t *arglen,
                     size_t &argcount ) noexcept;
  int shift_command( size_t shift,  const char **&args,  size_t *&arglen,
                     size_t &argcount ) noexcept;
  void output_help( ConsoleOutput *p,  int c ) noexcept;
  void print_dashes( const uint32_t *width,  uint32_t ncols ) noexcept;
  void print_table( ConsoleOutput *p,  const char **hdr,
                    uint32_t ncols ) noexcept;
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
  void print_data( ConsoleOutput *p,  const SubMsgData &val ) noexcept;
  void print_json_data( ConsoleOutput *p,  const SubMsgData &val ) noexcept;
  int find_tport( const char *name,  size_t len,
                  ConfigTree::Transport *&tree_idx,
                  uint32_t &tport_id ) noexcept;
  void connect( const char *arg,  size_t arglen ) noexcept;
  void listen( const char *arg,  size_t arglen ) noexcept;
  void shutdown( const char *arg,  size_t arglen ) noexcept;
  void get_active_tports( ConfigTree::TransportArray &listen, 
                          ConfigTree::TransportArray &connect ) noexcept;
  void config_save( void ) noexcept;
  void config_param( const char *param,  size_t plen,
                     const char *value,  size_t vlen ) noexcept;
  bool config_transport( const char *args[],  size_t *arglen,
                         size_t argc ) noexcept;
  bool config_transport_param( int cmd,  const char *args[],
                               size_t *arglen,  size_t argc ) noexcept;
  void config_transport_route( const char *param,  size_t plen,
                               const char *value,  size_t vlen ) noexcept;
  void show_subs( ConsoleOutput *p,  const char *arg,  size_t arglen,
                  const char *arg2,  size_t arglen2 ) noexcept;
  void ping_peer( ConsoleOutput *p,  const char *arg,  size_t arglen ) noexcept;
  void send_remote_request( ConsoleOutput *p,  const char *arg,  size_t arglen,
                            const char *cmd,  size_t cmdlen ) noexcept;
  bool recv_remote_request( const MsgFramePublish &pub,  UserBridge &n,
                            const MsgHdrDecoder &dec ) noexcept;
  void mcast_ping( ConsoleOutput *p ) noexcept;

  void on_ping( ConsolePing &ping ) noexcept;
  bool print_json_table( ConsoleOutput *p,  const void * data,
                         size_t datalen ) noexcept;
  void on_remote( ConsoleRemote &remote ) noexcept;
  void on_subs( ConsoleSubs &subs ) noexcept;
  void print_msg( md::MDMsg &msg ) noexcept;
  void print_json( md::MDMsg &msg ) noexcept;
  void show_tports( ConsoleOutput *p,  const char *name,  size_t len ) noexcept;
  void show_users( ConsoleOutput *p ) noexcept;
  void show_events( ConsoleOutput *p ) noexcept;
  void show_unknown( ConsoleOutput *p ) noexcept;
  void show_ports( ConsoleOutput *p,  const char *name,  size_t len ) noexcept;
  void show_cost( ConsoleOutput *p,  const char *name,  size_t len ) noexcept;
  void show_status( ConsoleOutput *p,  const char *name,  size_t len ) noexcept;
  void show_peers( ConsoleOutput *p ) noexcept;
  void show_adjacency( ConsoleOutput *p ) noexcept;
  void show_links( ConsoleOutput *p ) noexcept;
  void show_nodes( ConsoleOutput *p ) noexcept;
  void show_routes( ConsoleOutput *p ) noexcept;
  void show_urls( ConsoleOutput *p ) noexcept;
  void show_counters( ConsoleOutput *p ) noexcept;
  void show_inbox( ConsoleOutput *p,  const char *arg, size_t arglen ) noexcept;
  void show_loss( ConsoleOutput *p ) noexcept;
  void show_skew( ConsoleOutput *p ) noexcept;
  void show_reachable( ConsoleOutput *p ) noexcept;
  void show_tree( ConsoleOutput *p,  const UserBridge *src,
                  uint8_t path_select ) noexcept;
  void show_path( ConsoleOutput *p,  uint8_t path_select ) noexcept;
  void show_fds( ConsoleOutput *p ) noexcept;
  void show_buffers( ConsoleOutput *p ) noexcept;
  void show_windows( ConsoleOutput *p ) noexcept;
  void show_blooms( ConsoleOutput *p,  uint8_t path_select ) noexcept;
  void show_running( ConsoleOutput *p,  int which,  const char *name,
                     size_t len ) noexcept;
  void show_graph( ConsoleOutput *p ) noexcept;
  void tab_pub( Pub *pub,  TabOut &out ) noexcept;
  void tab_seqno( SubSeqno *sub,  TabOut &out ) noexcept;
  void show_seqno( ConsoleOutput *p, const char *arg,  size_t arglen ) noexcept;
  void config( const char *name,  size_t len ) noexcept;
  int puts( const char *s ) noexcept;
  void putchar( char c ) noexcept;
  virtual int printf( const char *fmt,  ... ) noexcept final __attribute__((format(printf,2,3)));
  void outf( ConsoleOutput *p,  const char *fmt,  ... ) noexcept __attribute__((format(printf,3,4)));
  void log_output( int stream,  uint64_t stamp,  size_t len,
                   const char *buf ) noexcept;
  void stop_rpc( ConsoleOutput *p,  ConsoleRPC *rpc ) noexcept;

  template<class T>
  T * create_rpc( ConsoleOutput *p,  ConsRpcType type ) {
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
    rpc->out.add( p );
    return (T *) rpc;
  }
  template<class T>
  T * find_rpc( T * sub,  ConsRpcType type ) {
    ConsoleRPC * rpc;
    if ( sub == NULL )
      rpc = this->rpc_list.hd;
    else
      rpc = sub->next;
    for ( ; rpc != NULL; rpc = rpc->next ) {
      if ( ! rpc->complete && rpc->type == type )
        return (T *) rpc;
    }
    return NULL;
  }
};

enum ConsoleCmd {
  CMD_BAD              = 0,
  CMD_EMPTY            = 1,
  CMD_PING             = 2,  /* ping [U]                   */
  CMD_MPING            = 3,  /* mping                      */
  CMD_REMOTE           = 4,  /* remote [U] cmd             */
  CMD_SHOW             = 5,  /* show ...                   */
  CMD_SHOW_SUBS        = 6,  /* show subs [U]              */
  CMD_SHOW_SEQNO       = 7,  /* show seqno                 */
  CMD_SHOW_ADJACENCY   = 8,  /* show adjacency             */
  CMD_SHOW_PEERS       = 9,  /* show peers                 */
  CMD_SHOW_PORTS       = 10, /* show ports [T]             */
  CMD_SHOW_COST        = 11, /* show ports [T]             */
  CMD_SHOW_STATUS      = 12, /* show status [T]            */
  CMD_SHOW_LINKS       = 13, /* show links                 */
  CMD_SHOW_NODES       = 14, /* show nodes                 */
  CMD_SHOW_ROUTES      = 15, /* show routes                */
  CMD_SHOW_URLS        = 16, /* show urls                  */
  CMD_SHOW_TPORTS      = 17, /* show tport [T]             */
  CMD_SHOW_USERS       = 18, /* show user [U]              */
  CMD_SHOW_EVENTS      = 19, /* show events                */
  CMD_SHOW_UNKNOWN     = 20, /* show unknown               */
  CMD_SHOW_LOGS        = 21, /* show logs                  */
  CMD_SHOW_COUNTERS    = 22, /* show counters              */
  CMD_SHOW_INBOX       = 23, /* show inbox                 */
  CMD_SHOW_LOSS        = 24, /* show loss                  */
  CMD_SHOW_SKEW        = 25, /* show skew                  */
  CMD_SHOW_REACHABLE   = 26, /* show reachable             */
  CMD_SHOW_TREE        = 27, /* show tree [U]              */
  CMD_SHOW_PATH        = 28, /* show path [N]              */
  CMD_SHOW_FDS         = 29, /* show fds                   */
  CMD_SHOW_BUFFERS     = 30, /* show buffers               */
  CMD_SHOW_WINDOWS     = 31, /* show windows               */
  CMD_SHOW_BLOOMS      = 32, /* show blooms [N]            */
  CMD_SHOW_GRAPH       = 33, /* show graph                 */
  CMD_SHOW_RUN         = 34, /* show running               */
  CMD_SHOW_RUN_TPORTS  = 35, /* show running transport [T] */
  CMD_SHOW_RUN_SVCS    = 36, /* show running service [S]   */
  CMD_SHOW_RUN_USERS   = 37, /* show running user [U]      */
  CMD_SHOW_RUN_GROUPS  = 38, /* show running group [G]     */
  CMD_SHOW_RUN_PARAM   = 39, /* show running parameter [P] */
  CMD_CONNECT          = 40, /* connect [T]                */
  CMD_LISTEN           = 41, /* listen [T]                 */
  CMD_SHUTDOWN         = 42, /* shutdown [T]               */
  CMD_NETWORK          = 43, /* network svc network        */
  CMD_CONFIGURE        = 44, /* configure                  */
  CMD_CONFIGURE_TPORT  = 45, /* configure transport T      */
  CMD_CONFIGURE_PARAM  = 46, /* configure parameter P V    */
  CMD_SAVE             = 47, /* save                       */
  CMD_SUB_START        = 48, /* sub subject [file]         */
  CMD_SUB_STOP         = 49, /* unsub subject [file]       */
  CMD_PSUB_START       = 50, /* psub rv-wildcard [file]    */
  CMD_PSUB_STOP        = 51, /* punsub rv-wildcard [file]  */
  CMD_GSUB_START       = 52, /* gsub glob-wildcard [file]  */
  CMD_GSUB_STOP        = 53, /* gunsub glob-wildcard [file]*/
  CMD_PUBLISH          = 54, /* pub subject msg            */
  CMD_TRACE            = 55, /* trace subject msg          */
  CMD_PUB_ACK          = 56, /* ack subject msg            */
  CMD_RPC              = 57, /* rpc subject msg            */
  CMD_ANY              = 58, /* any subject msg            */
  CMD_DEBUG            = 60, /* debug ival                 */
  CMD_CANCEL           = 61, /* cancel                     */
  CMD_MUTE_LOG         = 62, /* mute                       */
  CMD_UNMUTE_LOG       = 63, /* unmute                     */
  CMD_QUIT             = 64, /* quit/exit                  */

#define CMD_TPORT_BASE ( (int) CMD_QUIT + 1 )
  CMD_TPORT_ENUM /* config_const.h */
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
  const char * str, /* command match string */
             * args,
             * descr;
};

struct ConsoleCmdType {
  ConsoleCmd     cmd;  /* enum val */
  ConsoleArgType type; /* arg type */
};

#ifdef IMPORT_CONSOLE_CMDS
static const ConsoleCmdType command_type[] = {
  { CMD_PING            , PEER_ARG   }, /* ping peers */
  { CMD_REMOTE          , PEER_ARG   }, /* remote peers <cmd> */
  { CMD_CONNECT         , TPORT_ARG  }, /* connect <tport> */
  { CMD_LISTEN          , TPORT_ARG  }, /* listen <tport> */
  { CMD_SHUTDOWN        , TPORT_ARG  }, /* shutdown <tport> */
  { CMD_CONFIGURE_TPORT , TPORT_ARG  }, /* configure transport <tport> */
  { CMD_CONFIGURE_PARAM , PARM_ARG   }, /* configure parameter <parm> */
  { CMD_SUB_START       , SUB_ARG    }, /* subscribe <subject> [file] */
  { CMD_SUB_STOP        , SUB_ARG    }, /* unsubscribe <subject> [file] */
  { CMD_PSUB_START      , SUB_ARG    }, /* psubscribe <rv-pattern> [file] */
  { CMD_PSUB_STOP       , SUB_ARG    }, /* punsubscribe <rv-pattern> [file] */
  { CMD_GSUB_START      , SUB_ARG    }, /* gsubscribe <glob-pattern> [file] */
  { CMD_GSUB_STOP       , SUB_ARG    }, /* gunsubscribe <glob-pattern> [file] */
  { CMD_PUBLISH         , PUB_ARG    }, /* pub <subject> message */
  { CMD_TRACE           , PUB_ARG    }, /* trace <subject> message */
  { CMD_PUB_ACK         , PUB_ARG    }, /* ack <subject> message */
  { CMD_RPC             , PUB_ARG    }, /* rpc <subject> message */
  { CMD_ANY             , PUB_ARG    }, /* any <subject> message */
  { CMD_SHOW_SUBS       , PEER_ARG   }, /* request sub tables */
  { CMD_SHOW_PORTS      , TPORT_ARG  }, /* show ports tport */
  { CMD_SHOW_COST       , TPORT_ARG  }, /* show cost tport */
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
  { CMD_PING       , "ping"         ,0,0}, /* ping peers */
  { CMD_MPING      , "mping"        ,0,0}, /* multicast ping peers */
  { CMD_REMOTE     , "remote"       ,0,0}, /* remote peer <cmd> */
  { CMD_SHOW       , "show"         ,0,0}, /* show <subcmd> */
  { CMD_CONNECT    , "connect"      ,0,0}, /* connect <tport> */
  { CMD_LISTEN     , "listen"       ,0,0}, /* listen <tport> */
  { CMD_SHUTDOWN   , "shutdown"     ,0,0}, /* shutdown <tport> */
  { CMD_NETWORK    , "network"      ,0,0}, /* network <svc> <network> */
  { CMD_CONFIGURE  , "configure"    ,0,0}, /* configure <subcmd> */
  { CMD_SAVE       , "save"         ,0,0}, /* save config */
  { CMD_SUB_START  , "subscribe"    ,0,0}, /* subscribe <subject> */
  { CMD_SUB_STOP   , "unsubscribe"  ,0,0}, /* unsubscribe <subject> */
  { CMD_PSUB_START , "psubscribe"   ,0,0}, /* psubscribe <rv-pattern> */
  { CMD_PSUB_STOP  , "punsubscribe" ,0,0}, /* punsubscribe <rv-pattern> */
  { CMD_GSUB_START , "gsubscribe"   ,0,0}, /* gsubscribe <glob-pattern> */
  { CMD_GSUB_STOP  , "gunsubscribe" ,0,0}, /* gunsubscribe <glob-pattern> */
  { CMD_PUBLISH    , "publish"      ,0,0}, /* pub <subject> message */
  { CMD_TRACE      , "trace"        ,0,0}, /* trace <subject> message */
  { CMD_PUB_ACK    , "ack"          ,0,0}, /* ack <subject> message */
  { CMD_RPC        , "rpc"          ,0,0}, /* rpc <subject> message */
  { CMD_ANY        , "any"          ,0,0}, /* any <subject> message */
  { CMD_DEBUG      , "debug"        ,0,0}, /* debug <integer> */
  { CMD_CANCEL     , "cancel"       ,0,0}, /* cancel incomplete rpc */
  { CMD_MUTE_LOG   , "mute"         ,0,0}, /* mute log */
  { CMD_UNMUTE_LOG , "unmute"       ,0,0}, /* unmute log */
  { CMD_QUIT       , "quit"         ,0,0},
  { CMD_QUIT       , "exit"         ,0,0}
};
static const size_t num_console_cmds = ASZ( console_cmd );

static const ConsoleCmdString show_cmd[] = {
  { CMD_SHOW_SUBS      , "subscriptions" ,0,0}, /* request sub tables */
  { CMD_SHOW_SEQNO     , "seqno"         ,0,0}, /* show seqno */
  { CMD_SHOW_ADJACENCY , "adjacency"     ,0,0}, /* show adjacency */
  { CMD_SHOW_PEERS     , "peers"         ,0,0}, /* show peers */
  { CMD_SHOW_PORTS     , "ports"         ,0,0}, /* show ports tport */
  { CMD_SHOW_COST      , "cost"          ,0,0}, /* show cost tport */
  { CMD_SHOW_STATUS    , "status"        ,0,0}, /* show status tport */
  { CMD_SHOW_LINKS     , "links"         ,0,0}, /* show links */
  { CMD_SHOW_NODES     , "nodes"         ,0,0}, /* show nodes */
  { CMD_SHOW_ROUTES    , "routes"        ,0,0}, /* show routes */
  { CMD_SHOW_URLS      , "urls"          ,0,0}, /* show urls */
  { CMD_SHOW_TPORTS    , "tports"        ,0,0}, /* show tport config */
  { CMD_SHOW_USERS     , "users"         ,0,0}, /* show user concig */
  { CMD_SHOW_EVENTS    , "events"        ,0,0}, /* show events */
  { CMD_SHOW_UNKNOWN   , "unknown"       ,0,0}, /* show unknown */
  { CMD_SHOW_LOGS      , "logs"          ,0,0}, /* show logs */
  { CMD_SHOW_COUNTERS  , "counters"      ,0,0}, /* show counters */
  { CMD_SHOW_INBOX     , "inbox"         ,0,0}, /* show inbox */
  { CMD_SHOW_LOSS      , "loss"          ,0,0}, /* show loss */
  { CMD_SHOW_SKEW      , "skew"          ,0,0}, /* show skew */
  { CMD_SHOW_REACHABLE , "reachable"     ,0,0}, /* show reachable */
  { CMD_SHOW_TREE      , "tree"          ,0,0}, /* show tree */
  { CMD_SHOW_PATH      , "path"          ,0,0}, /* show path */
  { CMD_SHOW_FDS       , "fds"           ,0,0}, /* show fds */
  { CMD_SHOW_BUFFERS   , "buffers"       ,0,0}, /* show buffers */
  { CMD_SHOW_WINDOWS   , "windows"       ,0,0}, /* show windows */
  { CMD_SHOW_BLOOMS    , "blooms"        ,0,0}, /* show blooms */
  { CMD_SHOW_GRAPH     , "graph"         ,0,0}, /* show graph */
  { CMD_SHOW_RUN       , "running"       ,0,0}  /* show running */
};
static const size_t num_show_cmds = ASZ( show_cmd );

static const ConsoleCmdString run_cmd[] = {
  { CMD_SHOW_RUN_TPORTS , "transports" ,0,0}, /* config sections */
  { CMD_SHOW_RUN_SVCS   , "services"   ,0,0},
  { CMD_SHOW_RUN_USERS  , "users"      ,0,0},
  { CMD_SHOW_RUN_GROUPS , "groups"     ,0,0},
  { CMD_SHOW_RUN_PARAM  , "parameters" ,0,0}
};
static const size_t num_run_cmds = ASZ( run_cmd );

static const ConsoleCmdString config_cmd[] = {
  { CMD_CONFIGURE_TPORT , "transport" ,0,0},
  { CMD_CONFIGURE_PARAM , "parameter" ,0,0}
};
static const size_t num_config_cmds = ASZ( config_cmd );

static const ConsoleCmdString help_cmd[] = {
  { CMD_PING             , "ping", "[U]",        "Ping peers and display latency of return"          },
  { CMD_MPING            , "mping", "",          "Multicast ping all peers"                          },
  { CMD_REMOTE           , "remote", "[U] [C]",  "Run remote command on peer"                        },
  { CMD_CONNECT          , "connect", "[T]",     "Start tport connect"                               },
  { CMD_LISTEN           , "listen", "[T]",      "Start tport listener"                              },
  { CMD_SHUTDOWN         , "shutdown", "[T]",    "Shutdown tport"                                    },
  { CMD_NETWORK          , "network", "[S] [N]", "Configure service and join network"                },
  { CMD_CONFIGURE        , "configure", "",      "Configure ..."                                     },
  { CMD_CONFIGURE_TPORT  , "configure transport", "T",  "Configure tport T"                          },
  { CMD_CONFIGURE_PARAM  , "configure parameter", "P V", "Configure parameter P = V"                 },
  { CMD_SAVE             , "save", "",           "Save current config as startup"                    },
  { CMD_SHOW_SUBS        , "show subs", "[U] [W]", "Show subscriptions of peers"                     },
  { CMD_SHOW_SEQNO       , "show seqno", "[W]",  "Show subject seqno values for pub and sub"         },
  { CMD_SHOW_ADJACENCY   , "show adjacency", "", "Show the adjacency links"                          },
  { CMD_SHOW_PEERS       , "show peers", "",     "Show active peers"                                 },
  { CMD_SHOW_PORTS       , "show ports", "[T]",  "Show the active ports"                             },
  { CMD_SHOW_COST        , "show cost", "[T]",   "Show the port costs"                               },
  { CMD_SHOW_STATUS      , "show status", "[T]", "Show the port status with any errors"              },
  { CMD_SHOW_ROUTES      , "show routes", "",    "Show the primary port for each peer"               },
  { CMD_SHOW_URLS        , "show urls", "",      "Show urls of connected peers"                      },
  { CMD_SHOW_TPORTS      , "show tport", "[T]",  "Show the configured tports"                        },
  { CMD_SHOW_USERS       , "show user", "[U]",   "Show the configured users"                         },
  { CMD_SHOW_EVENTS      , "show events", "",    "Show event recorder"                               },
  { CMD_SHOW_LOGS        , "show logs", "",      "Show current log buffer"                           },
  { CMD_SHOW_COUNTERS    , "show counters", "",  "Show system seqno and time values"                 },
  { CMD_SHOW_INBOX       , "show inbox", "[U]",  "Show inbox sequences"                              },
  { CMD_SHOW_LOSS        , "show loss", "",      "Show message loss counters and time"               },
  { CMD_SHOW_SKEW        , "show skew", "",      "Show peer system clock skews"                      },
  { CMD_SHOW_REACHABLE   , "show reachable", "", "Show reachable peers through active tports"        },
  { CMD_SHOW_TREE        , "show tree", "[U]",   "Show multicast tree from me or U"                  },
  { CMD_SHOW_PATH        , "show path", "[P]",   "Show multicast path P (0->3)"                      },
  { CMD_SHOW_FDS         , "show fds", "",       "Show fd statistics"                                },
  { CMD_SHOW_BUFFERS     , "show buffers", "",   "Show fd buffer mem usage"                          },
  { CMD_SHOW_WINDOWS     , "show windows", "",   "Show pub and sub window mem usage"                 },
  { CMD_SHOW_BLOOMS      , "show blooms", "[P]", "Show bloom centric routes for path P (0-3)"        },
  { CMD_SHOW_GRAPH       , "show graph", "",     "Show network description for node graph"           },
  { CMD_SHOW_RUN         , "show running", "",   "Show current config running"                       },
  { CMD_SHOW_RUN_TPORTS  , "show running transport","[T]", "Show transports running, T or all"       },
  { CMD_SHOW_RUN_SVCS    , "show running service","[S]",   "Show services running config, S or all"  },
  { CMD_SHOW_RUN_USERS   , "show running user","[U]",      "Show users running config, U or all"     },
  { CMD_SHOW_RUN_GROUPS  , "show running group","[G]",     "Show groups running config, G or all"    },
  { CMD_SHOW_RUN_PARAM   , "show running parameter","[P]", "Show parameters running config, P or all"},
  { CMD_SUB_START        , "sub","[S] [F]",      "Subscribe subject S, output to file F"             },
  { CMD_SUB_STOP         , "unsub","[S] [F]",    "Unsubscribe subject S, stop output file F"         },
  { CMD_PSUB_START       , "psub","[W] [F]",     "Subscribe rv-wildcard W, output to file F"         },
  { CMD_PSUB_STOP        , "punsub","[W] [F]",   "Unsubscribe rv-wildcard W, stop output file F"     },
  { CMD_GSUB_START       , "gsub","[W] [F]",     "Subscribe glob-wildcard W, output to file F"       },
  { CMD_GSUB_STOP        , "gunsub","[W] [F]",   "Unsubscribe glob-wildcard W, stop output file F"   },
  { CMD_PUBLISH          , "pub","[S] [M]",      "Publish msg string M to subject S"                 },
  { CMD_TRACE            , "trace","[S] [M]",    "Publish msg string M to subject S, with reply"     },
  { CMD_PUB_ACK          , "ack","[S] [M]",      "Publish msg string M to subject S, with ack"       },
  { CMD_RPC              , "rpc","[S] [M]",      "Publish msg string M to subject S, with return"    },
  { CMD_ANY              , "any","[S] [M]",      "Publish msg string M to any subscriber of S"       },
  { CMD_CANCEL           , "cancel","",          "Cancel and show incomplete (ping, show subs)"      },
  { CMD_MUTE_LOG         , "mute","",            "Mute the log output"                               },
  { CMD_UNMUTE_LOG       , "unmute","",          "Unmute the log output"                             },
  { CMD_DEBUG            , "debug","[I]",        "Set debug flags to ival I, bit mask of:\n"
                           " 1=tcp,  2=pgm,  4=ibx,  8=transport,  0x10=user,  0x20=link_state,\n"
                           " 0x40=peer,  0x80=auth,  0x100=session,  0x200=hb,  0x400=sub,\n"
                           " 0x800=msg_recv,  0x1000=msg_hex,  0x2000=telnet,  0x4000=name,\n"
                           " dist,  kvpub,  kvps,  rv"                                               },
  { CMD_QUIT             , "quit/exit","",       "Exit console"                                      }
};

static const size_t num_help_cmds = ASZ( help_cmd );

static const ConsoleCmdString tport_cmd[] = {
  CMD_TPORT_CMD /* config_const.h */
};
static const size_t num_tport_cmds = ASZ( tport_cmd );

static const ConsoleCmd valid_tcp[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_TCP, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_mesh[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_MESH, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_pgm[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_PGM, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_rv[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_RV, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_nats[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_NATS, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_redis[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_REDIS, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_name[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_NAME, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_web[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_WEB, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmd valid_any[] =
  { CMD_TPORT_TPORT, CMD_TPORT_TYPE, VALID_ANY, CMD_TPORT_SHOW, CMD_TPORT_QUIT };

static const ConsoleCmdString tport_help_cmd[] = {
  CMD_TPORT_HELP /* config_const.h */
};
static const size_t num_tport_help_cmds = ASZ( tport_help_cmd );

struct ValidTportCmds {
  const char       * type;
  const ConsoleCmd * valid;
  size_t             nvalid;
  ConsoleCmdString * cmd;
  size_t             ncmds;
  ConsoleCmdString * help;
  size_t             nhelps;
} valid_tport_cmd[] = {
  { "tcp",  valid_tcp,  ASZ( valid_tcp ),  NULL, 0, NULL, 0 },
  { "mesh", valid_mesh, ASZ( valid_mesh ), NULL, 0, NULL, 0 },
  { "pgm",  valid_pgm,  ASZ( valid_pgm ),  NULL, 0, NULL, 0 },
  { "rv",   valid_rv,   ASZ( valid_rv ),   NULL, 0, NULL, 0 },
  { "nats", valid_nats, ASZ( valid_nats ), NULL, 0, NULL, 0 },
  { "redis",valid_redis,ASZ( valid_redis ),NULL, 0, NULL, 0 },
  { "name", valid_name, ASZ( valid_name ), NULL, 0, NULL, 0 },
  { "web",  valid_web,  ASZ( valid_web ),  NULL, 0, NULL, 0 },
  { "any",  valid_any,  ASZ( valid_any ),  NULL, 0, NULL, 0 }
};
static const size_t num_valid_tport_cmds = ASZ( valid_tport_cmd );
#undef ASZ

struct CmdMask {
  static const uint32_t max_bit = (uint32_t) CMD_BAD + 1;
  uint64_t bits[ ( max_bit + 63 ) / 64 ];
  CmdMask() { this->zero(); }
  void zero( void ) {
    kv::BitSetT<uint64_t> set( this->bits );
    set.zero( max_bit );
  }
  void mask( size_t nbits ) {
    kv::BitSetT<uint64_t> set( this->bits );
    set.zero( max_bit );
    for ( uint32_t b = 0; b < nbits; b++ )
      set.add( b );
  }
  bool is_member( size_t b ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.is_member( (uint32_t) b );
  }
  void add( size_t b ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.add( (uint32_t) b );
  }
  void remove( size_t b ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.remove( (uint32_t) b );
  }
  uint32_t count( void ) {
    kv::BitSetT<uint64_t> set( this->bits );
    return set.count( max_bit );
  }
};

static ConsoleCmd
which_show( const char *buf,  size_t buflen,  CmdMask *cmd_mask = NULL )
{
  return (ConsoleCmd)
    Console::which_cmd( show_cmd, num_show_cmds, buf, buflen, cmd_mask );
}

static ConsoleCmd
which_run( const char *buf,  size_t buflen,  CmdMask *cmd_mask = NULL )
{
  return (ConsoleCmd)
    Console::which_cmd( run_cmd, num_run_cmds, buf, buflen, cmd_mask );
}

static ConsoleCmd
which_config( const char *buf,  size_t buflen,  CmdMask *cmd_mask = NULL )
{
  return (ConsoleCmd)
    Console::which_cmd( config_cmd, num_config_cmds, buf, buflen, cmd_mask );
}

#endif

}
}

#endif
