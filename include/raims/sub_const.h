#ifndef __rai_raims__sub_const_h__
#define __rai_raims__sub_const_h__

namespace rai {
namespace ms {

/* inbox: _I.nonce.suffix */
#define _INBOX          "_I"
/* mcast: _M.xxx */
#define _MCAST          "_M"

/* session start, hb, end */
#define _SESSION_HELLO  "_X.HELLO"
#define _SESSION_HB     "_X.HB"
#define _SESSION_BYE    "_X.BYE"
#define _SESSION_NAME   "_X.NAME"

/* peer add, del, bloom, adjacency */
#define _PEER_ADD       "_Z.ADD"
#define _PEER_DEL       "_Z.DEL"
#define _BLOOM_FILTER   "_Z.BLM"
#define _ADJACENCY      "_Z.ADJ"

/* subscription start, stop */
#define _SUB_JOIN       "_S.JOIN"
#define _SUB_LEAVE      "_S.LEAV"

/* sub patterns, start pattern, stop pattern */
#define _PSUB_START     "_P.PSUB"
#define _PSUB_STOP      "_P.STOP"

/* stats */
#define _STAT_PORT      "_N.PORT"
#define _STAT_PEER      "_N.PEER"
#define _STAT_ADJ       "_N.ADJ"
#define _STAT_ALL       "_N.ALL"

/* inbox suffix, for point to point rpc */
#define _AUTH           "auth"
#define _SUBS           "subs"
#define _PING           "ping"
#define _PONG           "pong"
#define _REM            "rem"
#define _RESUB          "resub"
#define _REPSUB         "repsub"
#define _ADD_RTE        "add_rte"
#define _SYNC_REQ       "sync_req"
#define _SYNC_RPY       "sync_rpy"
#define _BLOOM_REQ      "bloom_req"
#define _BLOOM_RPY      "bloom_rpy"
#define _ADJ_REQ        "adj_req"
#define _ADJ_RPY        "adj_rpy"
#define _MESH_REQ       "mesh_req"
#define _MESH_RPY       "mesh_rpy"
#define _UCAST_REQ      "ucast_req"
#define _UCAST_RPY      "ucast_rpy"
#define _TRACE          "trace"
#define _ACK            "ack"
#define _ANY            "any"
#define _SYNC           "sync"

#ifdef DECLARE_SUB_CONST
#define SUB_CONST( CON, VAL ) \
extern const char CON[]; \
extern const uint16_t CON ## _SZ; \
const char CON[] = VAL; \
const uint16_t CON ## _SZ = (uint16_t) ( sizeof( CON ) - 1 );
#define EX
#else
#define SUB_CONST( CON, VAL ) \
extern const char CON[]; \
extern const uint16_t CON ## _SZ;
#define EX extern
#endif

SUB_CONST( X_HELLO , ( _SESSION_HELLO    ) )
SUB_CONST( X_HB    , ( _SESSION_HB       ) )
SUB_CONST( X_BYE   , ( _SESSION_BYE      ) )
SUB_CONST( X_NAME  , ( _SESSION_NAME     ) )
SUB_CONST( Z_ADD   , ( _PEER_ADD         ) )
SUB_CONST( Z_DEL   , ( _PEER_DEL         ) )
SUB_CONST( Z_BLM   , ( _BLOOM_FILTER     ) )
SUB_CONST( Z_ADJ   , ( _ADJACENCY        ) )
SUB_CONST( S_JOIN  , ( _SUB_JOIN     "." ) )
SUB_CONST( S_LEAVE , ( _SUB_LEAVE    "." ) )
SUB_CONST( P_PSUB  , ( _PSUB_START   "." ) )
SUB_CONST( P_PSTOP , ( _PSUB_STOP    "." ) )
SUB_CONST( N_PORT  , ( _STAT_PORT    "." ) )
SUB_CONST( N_PEER  , ( _STAT_PEER    "." ) )
SUB_CONST( N_ADJ   , ( _STAT_ADJ     "." ) )
SUB_CONST( N_ALL   , ( _STAT_ALL     "." ) )
                    /* prefix string size */
/* hashes of above */
EX uint32_t hello_h, hb_h, bye_h, name_h, add_h, del_h, blm_h, adj_h,
            join_h, leave_h, psub_h, pstop_h;
#undef SUB_CONST
#undef EX

}
}

#endif
