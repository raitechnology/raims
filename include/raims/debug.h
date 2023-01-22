#ifndef __rai_raims__debug_h__
#define __rai_raims__debug_h__

#include <raikv/util.h>

namespace rai {
namespace ms {

enum DbgFlags {
  TCP_DBG          =       1, /* ev_tcp_transport */
  PGM_DBG          =       2, /* ev_pgm_transport */
  IBX_DBG          =       4, /* ev_inbox_transport */
  TRANSPORT_DBG    =       8, /* transport */
  USER_DBG         =    0x10, /* user_db */
  LINK_STATE_DBG   =    0x20, /* link_state */
  PEER_DBG         =    0x40, /* peer */
  AUTH_DBG         =    0x80, /* auth */
  SESSION_DBG      =   0x100, /* session */
  HB_DBG           =   0x200, /* heartbeat */
  SUB_DBG          =   0x400, /* sub / pat */
  MSG_RECV_DBG     =   0x800, /* show msgs recvd */
  MSG_HEX_DBG      =  0x1000, /* show msghex recvd */
  TELNET_DBG       =  0x2000, /* ev_telnet */
  NAME_DBG         =  0x4000,
  SESS_REP_DBG     =  0x8000,
  SESS_NOT_SUB_DBG = 0x10000,
  SESS_LOSS_DBG    = 0x20000
};
extern int dbg_flags;

#ifdef IMPORT_DEBUG_STRINGS
static const char *debug_str[] = {
  "tcp", "pgm", "ibx", "transport", "user", "link_state", "peer", "auth",
  "session", "hb", "sub", "msg_recv", "msg_hex", "telnet", "name", "repeat",
  "not_sub", "loss"
};
static const size_t debug_str_count =
  sizeof( debug_str ) / sizeof( debug_str[ 0 ] );
#endif

#define debug_tcp          kv_unlikely( (dbg_flags & TCP_DBG       ) != 0 )
#define debug_pgm          kv_unlikely( (dbg_flags & PGM_DBG       ) != 0 )
#define debug_ibx          kv_unlikely( (dbg_flags & IBX_DBG       ) != 0 )
#define debug_tran         kv_unlikely( (dbg_flags & TRANSPORT_DBG ) != 0 )
#define debug_usr          kv_unlikely( (dbg_flags & USER_DBG      ) != 0 )
#define debug_lnk          kv_unlikely( (dbg_flags & LINK_STATE_DBG) != 0 )
#define debug_peer         kv_unlikely( (dbg_flags & PEER_DBG      ) != 0 )
#define debug_auth         kv_unlikely( (dbg_flags & AUTH_DBG      ) != 0 )
#define debug_sess         kv_unlikely( (dbg_flags & SESSION_DBG   ) != 0 )
#define debug_hb           kv_unlikely( (dbg_flags & HB_DBG        ) != 0 )
#define debug_sub          kv_unlikely( (dbg_flags & SUB_DBG       ) != 0 )
#define debug_msgr         kv_unlikely( (dbg_flags & MSG_RECV_DBG  ) != 0 )
#define debug_msgh         kv_unlikely( (dbg_flags & MSG_HEX_DBG   ) != 0 )
#define debug_msg          ( debug_msgr || debug_msgh )
#define debug_tel          kv_unlikely( (dbg_flags & TELNET_DBG    ) != 0 )
#define debug_name         kv_unlikely( (dbg_flags & NAME_DBG      ) != 0 )
#define debug_sess_repeat  kv_unlikely( (dbg_flags & ( SESSION_DBG | SESS_REP_DBG ) ) != 0 )
#define debug_sess_not_sub kv_unlikely( (dbg_flags & ( SESSION_DBG | SESS_NOT_SUB_DBG ) ) != 0 )
#define debug_sess_loss    kv_unlikely( (dbg_flags & ( SESSION_DBG | SESS_LOSS_DBG ) ) != 0 )

#define d_tcp( ... )  do { if ( debug_tcp  ) printf( __VA_ARGS__ ); } while( 0 )
#define d_pgm( ... )  do { if ( debug_pgm  ) printf( __VA_ARGS__ ); } while( 0 )
#define d_ibx( ... )  do { if ( debug_ibx  ) printf( __VA_ARGS__ ); } while( 0 )
#define d_tran( ... ) do { if ( debug_tran ) printf( __VA_ARGS__ ); } while( 0 )
#define d_usr( ... )  do { if ( debug_usr  ) printf( __VA_ARGS__ ); } while( 0 )
#define d_lnk( ... )  do { if ( debug_lnk  ) printf( __VA_ARGS__ ); } while( 0 )
#define d_peer( ... ) do { if ( debug_peer ) printf( __VA_ARGS__ ); } while( 0 )
#define d_auth( ... ) do { if ( debug_auth ) printf( __VA_ARGS__ ); } while( 0 )
#define d_sess( ... ) do { if ( debug_sess ) printf( __VA_ARGS__ ); } while( 0 )
#define d_hb( ... )   do { if ( debug_hb   ) printf( __VA_ARGS__ ); } while( 0 )
#define d_sub( ... )  do { if ( debug_sub  ) printf( __VA_ARGS__ ); } while( 0 )
#define d_tel( ... )  do { if ( debug_tel  ) printf( __VA_ARGS__ ); } while( 0 )
#define d_name( ... ) do { if ( debug_name ) printf( __VA_ARGS__ ); } while( 0 )

}
}
#endif
