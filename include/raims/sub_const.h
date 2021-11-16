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

/* inbox suffix, for point to point rpc */
#define _AUTH           "auth"
#define _SUBS           "subs"
#define _PING           "ping"
#define _PONG           "pong"
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
#define _TRACE          "trace"
#define _ACK            "ack"
#define _ANY            "any"

extern const char   X_HELLO[],
                    X_HB[],
                    X_BYE[],
                    Z_ADD[],
                    Z_DEL[],
                    Z_BLM[],
                    Z_ADJ[],
                    S_JOIN[],
                    S_LEAVE[],
                    P_PSUB[],
                    P_PSTOP[];
                    /* prefix string size */
extern const size_t X_HELLO_SZ,
                    X_HB_SZ,
                    X_BYE_SZ,
                    Z_ADD_SZ,
                    Z_DEL_SZ,
                    Z_BLM_SZ,
                    Z_ADJ_SZ,
                    S_JOIN_SZ,
                    S_LEAVE_SZ,
                    P_PSUB_SZ,
                    P_PSTOP_SZ;
/* hashes of above */
extern uint32_t     hello_h, hb_h, bye_h, add_h, del_h, blm_h, adj_h;

#ifdef DECLARE_SUB_CONST

const char          X_HELLO[]  = _SESSION_HELLO    ,
                    X_HB[]     = _SESSION_HB       ,
                    X_BYE[]    = _SESSION_BYE      ,
                    Z_ADD[]    = _PEER_ADD         ,
                    Z_DEL[]    = _PEER_DEL         ,
                    Z_BLM[]    = _BLOOM_FILTER     ,
                    Z_ADJ[]    = _ADJACENCY        ,
                    S_JOIN[]   = _SUB_JOIN      ".",
                    S_LEAVE[]  = _SUB_LEAVE     ".",
                    P_PSUB[]   = _PSUB_START    ".",
                    P_PSTOP[]  = _PSUB_STOP     ".";
                    /* prefix string size */
const size_t        X_HELLO_SZ = sizeof( X_HELLO ) - 1,
                    X_HB_SZ    = sizeof( X_HB    ) - 1,
                    X_BYE_SZ   = sizeof( X_BYE   ) - 1,
                    Z_ADD_SZ   = sizeof( Z_ADD   ) - 1,
                    Z_DEL_SZ   = sizeof( Z_DEL   ) - 1,
                    Z_BLM_SZ   = sizeof( Z_BLM   ) - 1,
                    Z_ADJ_SZ   = sizeof( Z_ADJ   ) - 1,
                    S_JOIN_SZ  = sizeof( S_JOIN  ) - 1,
                    S_LEAVE_SZ = sizeof( S_LEAVE ) - 1,
                    P_PSUB_SZ  = sizeof( P_PSUB  ) - 1,
                    P_PSTOP_SZ = sizeof( P_PSTOP ) - 1;

uint32_t            hello_h, hb_h, bye_h, add_h, del_h, blm_h, adj_h;

#endif

}
}

#endif
