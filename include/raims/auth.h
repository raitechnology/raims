#ifndef __rai_raims__auth_h__
#define __rai_raims__auth_h__

#include <raims/crypt.h>

namespace rai {
namespace ms {

/*
 * newer peer hello                  -> older peer       (usually, may switch)
 * older peer challenge [ hello/hb ] -> auth [ stage 1 ] newer peer trusts older
 * newer peer challenge [ stage 1  ] -> auth [ stage 2 ] older peer trusts newer
 * older peer trust     [ stage 2  ] ->      [ stage 3 ] notifies trust
 */
struct MsgHdrDecoder;
struct TransportRoute;
struct StageAuth {
  Nonce    cnonce; /* the challenge nonce */
  uint64_t seqno;  /* seqno of hb or auth message */
  uint64_t time;   /* time of hb or auth message */

  StageAuth& operator=( const StageAuth &x ) {
    this->cnonce = x.cnonce;
    this->seqno  = x.seqno;
    this->time   = x.time;
    return *this;
  }
  void zero( void ) { this->cnonce.zero(); this->seqno = this->time = 0; }
  void copy_from_peer( const MsgHdrDecoder &dec ) noexcept;
  bool copy_from_auth( const MsgHdrDecoder &dec,
                       const StageAuth &auth ) noexcept;
  void construct( uint64_t time, uint64_t seqno, const Nonce &nonce ) noexcept;
  bool copy_from_hb( const MsgHdrDecoder &dec, 
                     const TransportRoute &rte ) noexcept;
};

enum AuthStage {
  AUTH_UNKNOWN          = 0,
  AUTH_FROM_HELLO       = 1, /* recv hello challenge auth stage 1 */
  AUTH_FROM_HANDSHAKE   = 2, /* recv handshake from auth stage 2 */
  AUTH_TRUST            = 3,
  AUTH_FROM_ADJ_RESULT  = 4, /* recv _I.<n>.adj_rpy, from adj_req */
  AUTH_FROM_PEER_ADD    = 5, /* recv _Z.ADD on zombie */
  AUTH_FROM_ADD_ROUTE   = 6, /* recv _I.<n>.add_rte on zombie */
  AUTH_FROM_SYNC_RESULT = 7, /* recv _I.<n>.sync_rpy, from sync_rpy */
  MAX_AUTH              = 8
};

enum ByeReason {
  BYE_NONE       = 0,
  BYE_HB_TIMEOUT = 1,
  BYE_BYE        = 2,
  BYE_ORPHANED   = 3,
  BYE_SOURCE     = 4,
  BYE_DROPPED    = 5,
  BYE_PING       = 6,
  MAX_BYE        = 7
};

#ifdef INCLUDE_AUTH_CONST
static const char *auth_stage[] = {
  "unknown",    /* AUTH_UNKNOWN          not used */
  "hello",      /* AUTH_FROM_HELLO       _I.<nonce>.auth, challenge stage 1 */
  "handshake",  /* AUTH_FROM_HANDSHAKE   _I.<nonce>.auth, challenge stage 2 */
  "trust",      /* AUTH_TRUST            _I.<nonce>.auth, challenge stage 3 */
  "adj_result", /* AUTH_FROM_ADJ_RESULT  _I.<nonce>.adj_rpy */
  "peer_add",   /* AUTH_FROM_PEER_ADD    _Z.ADD */
  "add_route",  /* AUTH_FROM_ADD_ROUTE   _I.<nonce>.add_rte */
  "sync_result" /* AUTH_FROM_SYNC_RESULT _I.<nonce>.sync_rpy */
};
static const char *bye_reason[] = {
  "none",
  "hb_timeout",
  "bye",
  "orphaned",
  "source_close",
  "dropped",
  "ping"
};
#if __cplusplus >= 201103L
static_assert( MAX_AUTH == ( sizeof( auth_stage ) / sizeof( auth_stage[ 0 ] ) ), "auth_stage" );
static_assert( MAX_BYE == ( sizeof( bye_reason ) / sizeof( bye_reason[ 0 ] ) ), "bye_reason" );
#endif
#endif
const char *auth_stage_string( AuthStage stage ) noexcept;
const char *bye_reason_string( ByeReason reason ) noexcept;

}
}
#endif
