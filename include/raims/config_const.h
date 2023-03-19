#ifndef __rai_raims__config_const_h__
#define __rai_raims__config_const_h__

namespace rai {
namespace ms {

#ifdef DECLARE_CONFIG_CONST
#define CONFIG_CONST( CON, VAL ) \
extern const char CON[]; \
extern const uint16_t CON ## _SZ; \
const char CON[] = VAL; \
const uint16_t CON ## _SZ = (uint16_t) ( sizeof( CON ) - 1 );
#else
#define CONFIG_CONST( CON, VAL ) \
extern const char CON[]; \
extern const uint16_t CON ## _SZ;
#endif

/* P_: parameters */
CONFIG_CONST( P_WORKING_DIRECTORY  , "working_directory" )
CONFIG_CONST( P_IDLE_BUSY          , "idle_busy" )
CONFIG_CONST( P_MAP_FILE           , "map_file" )
CONFIG_CONST( P_IPC_NAME           , "ipc_name" )
CONFIG_CONST( P_DB_NUM             , "db_num" )
CONFIG_CONST( P_RELIABILITY        , "reliability" )
CONFIG_CONST( P_LOG_FILE           , "log_file" )
CONFIG_CONST( P_PUB_WINDOW_SIZE    , "pub_window_size" )
CONFIG_CONST( P_SUB_WINDOW_SIZE    , "sub_window_size" )
CONFIG_CONST( P_PUB_WINDOW_TIME    , "pub_window_time" )
CONFIG_CONST( P_SUB_WINDOW_TIME    , "sub_window_time" )
CONFIG_CONST( P_HEARTBEAT          , "heartbeat" )
CONFIG_CONST( P_TIMESTAMP          , "timestamp" )
CONFIG_CONST( P_PID_FILE           , "pid_file" )
CONFIG_CONST( P_TCP_TIMEOUT        , "tcp_timeout" )
CONFIG_CONST( P_TCP_IPV4ONLY       , "tcp_ipv4only" )
CONFIG_CONST( P_TCP_IPV6ONLY       , "tcp_ipv6only" )
CONFIG_CONST( P_TCP_NOENCRYPT      , "tcp_noencrypt" )
CONFIG_CONST( P_TCP_WRITE_TIMEOUT  , "tcp_write_timeout" )
CONFIG_CONST( P_TCP_WRITE_HIGHWATER, "tcp_write_highwater" )

/* T_: transport / networks */
CONFIG_CONST( T_ANY          , "any" )
CONFIG_CONST( T_MESH         , "mesh" )
CONFIG_CONST( T_MESH_LISTEN  , "mesh.listen" )
CONFIG_CONST( T_MESH_CONNECT , "mesh.connect" )
CONFIG_CONST( T_TCP          , "tcp" )
CONFIG_CONST( T_TCP_LISTEN   , "tcp.listen" )
CONFIG_CONST( T_TCP_CONNECT  , "tcp.connect" )
CONFIG_CONST( T_PGM          , "pgm" )
CONFIG_CONST( T_REDIS        , "redis" )
CONFIG_CONST( T_NATS         , "nats" )
CONFIG_CONST( T_RV           , "rv" )
CONFIG_CONST( T_TELNET       , "telnet" )
CONFIG_CONST( T_WEB          , "web" )
CONFIG_CONST( T_NAME         , "name" )
CONFIG_CONST( T_IPC          , "ipc" )

/* R_: route parameters */
CONFIG_CONST( R_TPORT              , "tport" )
CONFIG_CONST( R_TYPE               , "type" )
CONFIG_CONST( R_LISTEN             , "listen" )       /* 2,3,4,5,6,7,8 */
CONFIG_CONST( R_CONNECT            , "connect" )      /* 2,3,4,5,6,7,8 */
CONFIG_CONST( R_DEVICE             , "device" )       /* 2,3,4,5,6,7,8 */
CONFIG_CONST( R_PORT               , "port" )
CONFIG_CONST( R_TIMEOUT            , "timeout" )
CONFIG_CONST( R_MTU                , "mtu" )
CONFIG_CONST( R_TXW_SQNS           , "txw_sqns" )
CONFIG_CONST( R_RXW_SQNS           , "rxw_sqns" )
CONFIG_CONST( R_TXW_SECS           , "txw_secs" )
CONFIG_CONST( R_MCAST_LOOP         , "mcast_loop" )
CONFIG_CONST( R_EDGE               , "edge" )
CONFIG_CONST( R_USE_SERVICE_PREFIX , "use_service_prefix" )
CONFIG_CONST( R_NO_PERMANENT       , "no_permanent" )
CONFIG_CONST( R_NO_MCAST           , "no_mcast" )
CONFIG_CONST( R_NO_FAKEIP          , "no_fakeip" )
CONFIG_CONST( R_SERVICE            , "service" )
CONFIG_CONST( R_NETWORK            , "network" )
CONFIG_CONST( R_COST               , "cost" )         /* 2,3,4 */
CONFIG_CONST( R_HTTP_DIR           , "http_dir" )
CONFIG_CONST( R_HTTP_USERNAME      , "http_username" )
CONFIG_CONST( R_HTTP_PASSWORD      , "http_password" )
CONFIG_CONST( R_HTTP_REALM         , "http_realm" )
CONFIG_CONST( R_HTDIGEST           , "htdigest" )
CONFIG_CONST( R_IPV4ONLY           , "ipv4only" )
CONFIG_CONST( R_IPV6ONLY           , "ipv6only" )
CONFIG_CONST( R_NOENCRYPT          , "noencrypt" )

#undef CONFIG_CONST

/* enmerations for configure transport xyz ... */
#define CMD_TPORT_ENUM \
  CMD_TPORT_TPORT              = CMD_TPORT_BASE,\
  CMD_TPORT_TYPE               = CMD_TPORT_BASE+1,\
  CMD_TPORT_LISTEN             = CMD_TPORT_BASE+2,\
  CMD_TPORT_CONNECT            = CMD_TPORT_BASE+3,\
  CMD_TPORT_DEVICE             = CMD_TPORT_BASE+4,\
  CMD_TPORT_PORT               = CMD_TPORT_BASE+5,\
  CMD_TPORT_TIMEOUT            = CMD_TPORT_BASE+6,\
  CMD_TPORT_MTU                = CMD_TPORT_BASE+7,\
  CMD_TPORT_TXW_SQNS           = CMD_TPORT_BASE+8,\
  CMD_TPORT_RXW_SQNS           = CMD_TPORT_BASE+9,\
  CMD_TPORT_TXW_SECS           = CMD_TPORT_BASE+10,\
  CMD_TPORT_MCAST_LOOP         = CMD_TPORT_BASE+11,\
  CMD_TPORT_EDGE               = CMD_TPORT_BASE+12,\
  CMD_TPORT_USE_SERVICE_PREFIX = CMD_TPORT_BASE+13,\
  CMD_TPORT_NO_PERMANENT       = CMD_TPORT_BASE+14,\
  CMD_TPORT_NO_MCAST           = CMD_TPORT_BASE+15,\
  CMD_TPORT_NO_FAKEIP          = CMD_TPORT_BASE+16,\
  CMD_TPORT_SERVICE            = CMD_TPORT_BASE+17,\
  CMD_TPORT_NETWORK            = CMD_TPORT_BASE+18,\
  CMD_TPORT_COST               = CMD_TPORT_BASE+19,\
  CMD_TPORT_HTTP_DIR           = CMD_TPORT_BASE+20,\
  CMD_TPORT_HTTP_USERNAME      = CMD_TPORT_BASE+21,\
  CMD_TPORT_HTTP_PASSWORD      = CMD_TPORT_BASE+22,\
  CMD_TPORT_HTTP_REALM         = CMD_TPORT_BASE+23,\
  CMD_TPORT_HTDIGEST           = CMD_TPORT_BASE+24,\
  CMD_TPORT_IPV4ONLY           = CMD_TPORT_BASE+25,\
  CMD_TPORT_IPV6ONLY           = CMD_TPORT_BASE+26,\
  CMD_TPORT_NOENCRYPT          = CMD_TPORT_BASE+27,\
  CMD_TPORT_SHOW               = CMD_TPORT_BASE+28,\
  CMD_TPORT_QUIT               = CMD_TPORT_BASE+29

/* configure transport route parameters */
#define CMD_TPORT_CMD \
  { CMD_TPORT_TPORT             , R_TPORT      ,0,0},\
  { CMD_TPORT_TYPE              , R_TYPE       ,0,0},\
  { CMD_TPORT_LISTEN            , R_LISTEN     ,0,0},\
  { CMD_TPORT_CONNECT           , R_CONNECT    ,0,0},\
  { CMD_TPORT_DEVICE            , R_DEVICE     ,0,0},\
  { CMD_TPORT_PORT              , R_PORT       ,0,0},\
  { CMD_TPORT_TIMEOUT           , R_TIMEOUT    ,0,0},\
  { CMD_TPORT_MTU               , R_MTU        ,0,0},\
  { CMD_TPORT_TXW_SQNS          , R_TXW_SQNS   ,0,0},\
  { CMD_TPORT_RXW_SQNS          , R_RXW_SQNS   ,0,0},\
  { CMD_TPORT_TXW_SECS          , R_TXW_SECS   ,0,0},\
  { CMD_TPORT_MCAST_LOOP        , R_MCAST_LOOP ,0,0},\
  { CMD_TPORT_EDGE              , R_EDGE       ,0,0},\
  { CMD_TPORT_USE_SERVICE_PREFIX, R_USE_SERVICE_PREFIX,0,0},\
  { CMD_TPORT_NO_PERMANENT      , R_NO_PERMANENT,0,0},\
  { CMD_TPORT_NO_MCAST          , R_NO_MCAST   ,0,0},\
  { CMD_TPORT_NO_FAKEIP         , R_NO_FAKEIP  ,0,0},\
  { CMD_TPORT_SERVICE           , R_SERVICE    ,0,0},\
  { CMD_TPORT_NETWORK           , R_NETWORK    ,0,0},\
  { CMD_TPORT_COST              , R_COST       ,0,0},\
  { CMD_TPORT_HTTP_DIR          , R_HTTP_DIR   ,0,0},\
  { CMD_TPORT_HTTP_USERNAME     , R_HTTP_USERNAME,0,0},\
  { CMD_TPORT_HTTP_PASSWORD     , R_HTTP_PASSWORD,0,0},\
  { CMD_TPORT_HTTP_REALM        , R_HTTP_REALM ,0,0},\
  { CMD_TPORT_HTDIGEST          , R_HTDIGEST   ,0,0},\
  { CMD_TPORT_IPV4ONLY          , R_IPV4ONLY   ,0,0},\
  { CMD_TPORT_IPV6ONLY          , R_IPV6ONLY   ,0,0},\
  { CMD_TPORT_NOENCRYPT         , R_NOENCRYPT  ,0,0},\
  { CMD_TPORT_SHOW              , "show"       ,0,0},\
  { CMD_TPORT_QUIT              , "quit"       ,0,0},\
  { CMD_TPORT_QUIT              , "exit"       ,0,0}

/* configure transport route param help */
#define CMD_TPORT_HELP \
  { CMD_TPORT_TPORT      , R_TPORT,"N",    "Name of transport" },\
  { CMD_TPORT_TYPE       , R_TYPE,"T",     "Type of transport" },\
  { CMD_TPORT_LISTEN     , R_LISTEN,"A",   "Listen address for passive transport" },\
  { CMD_TPORT_CONNECT    , R_CONNECT,"A",  "Connect address for active transport" },\
  { CMD_TPORT_DEVICE     , R_DEVICE,"A",   "Device name or address" },\
  { CMD_TPORT_PORT       , R_PORT,"N",     "Port for address" },\
  { CMD_TPORT_TIMEOUT    , R_TIMEOUT,"N",  "Timeout for connect or accept" },\
  { CMD_TPORT_MTU        , R_MTU,"N",      "MTU for pgm type transport, UDP datagram size" },\
  { CMD_TPORT_TXW_SQNS   , R_TXW_SQNS,"N", "Transmit window in datagram sequences" },\
  { CMD_TPORT_RXW_SQNS   , R_RXW_SQNS,"N", "Recieve window in datagram sequences" },\
  { CMD_TPORT_TXW_SECS   , R_TXW_SECS,"N", "Transmit window in seconds" },\
  { CMD_TPORT_MCAST_LOOP , R_MCAST_LOOP,"N", "Controls multicast loop: 0 - none, 2 - host loop and exclude sender" },\
  { CMD_TPORT_EDGE       , R_EDGE,"B",     "When true, don't create a adjaceny and use existing" },\
  { CMD_TPORT_USE_SERVICE_PREFIX, R_USE_SERVICE_PREFIX,"B","When false, no service prefix" },\
  { CMD_TPORT_NO_PERMANENT, R_NO_PERMANENT,"B","Quit when no connections for 2 minutes" },\
  { CMD_TPORT_NO_MCAST   ,  R_NO_MCAST,"B","Disable multicast networks" },\
  { CMD_TPORT_NO_FAKEIP  ,  R_NO_FAKEIP,"B","Disable fake host ip used in inbox subjects" },\
  { CMD_TPORT_SERVICE    ,  R_SERVICE,"S", "Use service name" },\
  { CMD_TPORT_NETWORK    ,  R_NETWORK,"A", "Connect to network" },\
  { CMD_TPORT_COST       ,  R_COST,"N",    "Cost used for calculating routes" },\
  { CMD_TPORT_HTTP_DIR   ,  R_HTTP_DIR,"D","Use this directory for serving files" },\
  { CMD_TPORT_HTTP_USERNAME , R_HTTP_USERNAME,"N","Username for http auth" },\
  { CMD_TPORT_HTTP_PASSWORD , R_HTTP_PASSWORD,"N","Password for http auth" },\
  { CMD_TPORT_HTTP_REALM    , R_HTTP_REALM   ,"N","Realm for http auth" },\
  { CMD_TPORT_HTDIGEST      , R_HTDIGEST     ,"N","File to load for http auth" },\
  { CMD_TPORT_IPV4ONLY   ,  R_IPV4ONLY,"B","Only use IPv4 addresses" },\
  { CMD_TPORT_IPV6ONLY   ,  R_IPV6ONLY,"B","Only use IPv6 addresses" },\
  { CMD_TPORT_NOENCRYPT  ,  R_NOENCRYPT,"B","Do not use encryption" },\
  { CMD_TPORT_SHOW       , "show","",      "Show tport config" },\
  { CMD_TPORT_QUIT       , "quit/exit","", "Exit config" }

/* which route params are valid for each of the transports 
 * listen: "127.0.0.1"
 * connect: "127.0.0.1"
 * port: 17551
 */
#define VALID_COMMON CMD_TPORT_LISTEN, CMD_TPORT_CONNECT, \
                     CMD_TPORT_DEVICE, CMD_TPORT_PORT, CMD_TPORT_COST, \
                     CMD_TPORT_IPV4ONLY, CMD_TPORT_IPV6ONLY
                     
#define VALID_TCP    VALID_COMMON, CMD_TPORT_EDGE, CMD_TPORT_NOENCRYPT, \
                     CMD_TPORT_TIMEOUT

#define VALID_MESH   VALID_COMMON, CMD_TPORT_NOENCRYPT, CMD_TPORT_TIMEOUT

#define VALID_PGM    VALID_COMMON, CMD_TPORT_MTU, CMD_TPORT_TXW_SQNS, CMD_TPORT_RXW_SQNS, \
                     CMD_TPORT_TXW_SECS, CMD_TPORT_MCAST_LOOP

#define VALID_RV     CMD_TPORT_LISTEN, CMD_TPORT_DEVICE, CMD_TPORT_PORT, \
                     CMD_TPORT_USE_SERVICE_PREFIX, \
                     CMD_TPORT_NO_PERMANENT, CMD_TPORT_NO_MCAST, CMD_TPORT_NO_FAKEIP

#define VALID_NATS   CMD_TPORT_LISTEN, CMD_TPORT_DEVICE, CMD_TPORT_PORT, \
                     CMD_TPORT_SERVICE, CMD_TPORT_NETWORK, \
                     CMD_TPORT_IPV4ONLY, CMD_TPORT_IPV6ONLY

#define VALID_REDIS  CMD_TPORT_LISTEN, CMD_TPORT_DEVICE, CMD_TPORT_PORT, \
                     CMD_TPORT_SERVICE, CMD_TPORT_NETWORK, \
                     CMD_TPORT_IPV4ONLY, CMD_TPORT_IPV6ONLY

#define VALID_NAME   CMD_TPORT_LISTEN, CMD_TPORT_CONNECT, CMD_TPORT_PORT

#define VALID_WEB    CMD_TPORT_LISTEN, CMD_TPORT_DEVICE, CMD_TPORT_PORT, \
                     CMD_TPORT_HTTP_DIR, CMD_TPORT_HTTP_USERNAME, CMD_TPORT_HTTP_PASSWORD, \
                     CMD_TPORT_HTTP_REALM, CMD_TPORT_HTDIGEST, \
                     CMD_TPORT_IPV4ONLY, CMD_TPORT_IPV6ONLY

#define VALID_ANY    CMD_TPORT_DEVICE

}
}
#endif
