#ifndef __rai_raims__caba_msg_buf_h__
#define __rai_raims__caba_msg_buf_h__

/* creates caba msgs */
static const uint32_t CABA_TYPE_ID = 0x191c206;
/* 
 * TYPE_SHIFT = 8, for 8 bit FID, leaves 3 bits unused,
 *   fid alignment 16 bits, so fields are 1 byte padded when data is odd length
 *   the first two bits indecate 10 == fixed size, 01 == field (not msg)
 */
static const uint16_t 
  CLS_BOOL         = 0xc000U | ( BOOL_CLASS         << FID_TYPE_SHIFT ),
  CLS_U_SHORT      = 0xc000U | ( U_SHORT_CLASS      << FID_TYPE_SHIFT ),
  CLS_U_INT        = 0xc000U | ( U_INT_CLASS        << FID_TYPE_SHIFT ),
  CLS_U_LONG       = 0xc000U | ( U_LONG_CLASS       << FID_TYPE_SHIFT ),
  CLS_OPAQUE_16    = 0xc000U | ( OPAQUE_16_CLASS    << FID_TYPE_SHIFT ),
  CLS_OPAQUE_32    = 0xc000U | ( OPAQUE_32_CLASS    << FID_TYPE_SHIFT ),
  CLS_OPAQUE_64    = 0xc000U | ( OPAQUE_64_CLASS    << FID_TYPE_SHIFT ),
  CLS_SHORT_STRING = 0x4000U | ( SHORT_STRING_CLASS << FID_TYPE_SHIFT ),
  CLS_LONG_OPAQUE  = 0x4000U | ( LONG_OPAQUE_CLASS  << FID_TYPE_SHIFT );

#if __cplusplus >= 201103L
  /* these use OPAQUE_16 types */
  static_assert( NONCE_SIZE == 16, "nonce not 16 bytes" );
  static_assert( HMAC_SIZE == 16, "hmac not 16 bytes" );
  static_assert( HASH_DIGEST_SIZE == 64, "digest not 64 bytes" );
#endif

template <class T>
struct BMsgBufT {
  char * out, * msg;
  BMsgBufT( void *m ) : out( (char *) m ), msg( (char *) m ) {}

  void emit_u16( uint16_t val ) {   /* tib sass is big endian */
    val = kv_bswap16( val );
    ::memcpy( this->out, &val, 2 );
    this->out += 2;
  }
  void emit_u32( uint32_t val ) {
    val = kv_bswap32( val );
    ::memcpy( this->out, &val, 4 );
    this->out += 4;
  }
  void emit_u64( uint64_t val ) {
    val = kv_bswap64( val );
    ::memcpy( this->out, &val, 8 );
    this->out += 8;
  }
  T &b( uint8_t opt,  const void *in,  uint16_t in_len ) { /* string out */
    this->emit_u16( CLS_SHORT_STRING | opt );
    this->emit_u16( in_len );
    ::memcpy( this->out, in, in_len );
    this->out = &this->out[ in_len ];
    if ( ( in_len & 1 ) != 0 )
      *this->out++ = 0;
    return (T &) *this;
  }
  T &o( uint8_t opt,  const void *in,  uint32_t in_len ) { /* opaque out */
    this->emit_u16( CLS_LONG_OPAQUE | opt );
    this->emit_u32( in_len );
    ::memcpy( this->out, in, in_len );
    this->out = &this->out[ in_len ];
    if ( ( in_len & 1 ) != 0 )
      *this->out++ = 0;
    return (T &) *this;
  }
  T &u( uint8_t opt,  uint64_t n ) {  /* uint64/32/16 out */
    if ( (uint64_t) ( n >> 32 ) == 0 ) {
      if ( (uint64_t) ( n >> 16 ) == 0 ) {
        this->emit_u16( CLS_U_SHORT | opt );
        this->emit_u16( (uint16_t) n );
      }
      else {
        this->emit_u16( CLS_U_INT | opt );
        this->emit_u32( (uint32_t) n );
      }
    }
    else {
      this->emit_u16( CLS_U_LONG | opt );
      this->emit_u64( n );
    }
    return (T &) *this;
  }
  T &i( uint8_t opt,  uint32_t n ) {  /* uint32/16 out */
    if ( (uint32_t) ( n >> 16 ) == 0 ) {
      this->emit_u16( CLS_U_SHORT | opt );
      this->emit_u16( (uint16_t) n );
    }
    else {
      this->emit_u16( CLS_U_INT | opt );
      this->emit_u32( n );
    }
    return (T &) *this;
  }
  T &i2( uint8_t opt,  uint16_t n ) {  /* uint16 out */
    this->emit_u16( CLS_U_SHORT | opt );
    this->emit_u16( n );
    return (T &) *this;
  }
  T &i4( uint8_t opt,  uint32_t n ) {  /* uint16 out */
    this->emit_u16( CLS_U_INT | opt );
    this->emit_u32( n );
    return (T &) *this;
  }
  T &i8( uint8_t opt,  uint64_t n ) {  /* uint16 out */
    this->emit_u16( CLS_U_LONG | opt );
    this->emit_u64( n );
    return (T &) *this;
  }
  T &y( uint8_t opt,  uint8_t n ) {   /* bool out */
    this->emit_u16( CLS_BOOL | opt );
    this->out[ 0 ] = ( n ? 1 : 0 );
    this->out[ 1 ] = 0;
    this->out += 2;
    return (T &) *this;
  }
  T &n( uint8_t opt,  const Nonce &val ) { /* digest out */
    emit_u16( CLS_OPAQUE_16 | opt );
    ::memcpy( this->out, val.nonce, NONCE_SIZE );
    this->out += NONCE_SIZE;
    return (T &) *this;
  }
  T &h( uint8_t opt,  const HmacDigest &val ) { /* digest out */
    emit_u16( CLS_OPAQUE_16 | opt );
    ::memcpy( this->out, val.dig, HMAC_SIZE );
    this->out += HMAC_SIZE;
    return (T &) *this;
  }
  T &k( uint8_t opt,  const HashDigest &val ) { /* digest out */
    emit_u16( CLS_OPAQUE_64 | opt );
    ::memcpy( this->out, val.dig, HASH_DIGEST_SIZE );
    this->out += HASH_DIGEST_SIZE;
    return (T &) *this;
  }
  T &k( uint8_t opt,  const ed25519_signature &sig ) { /* digest out */
    emit_u16( CLS_OPAQUE_64 | opt );
    sig.copy_to( this->out );
    this->out += ED25519_SIG_LEN;
    return (T &) *this;
  }
  T &k( uint8_t opt,  const ec25519_key &key ) { /* digest out */
    emit_u16( CLS_OPAQUE_32 | opt );
    key.copy_to( this->out );
    this->out += EC25519_KEY_LEN;
    return (T &) *this;
  }
  T &x( uint8_t opt,  const HmacDigest &hmac,  const Nonce &nonce ) {
    emit_u16( CLS_OPAQUE_32 | opt );
    ::memcpy( this->out, hmac.dig, HMAC_SIZE );
    this->out += HMAC_SIZE;
    ::memcpy( this->out, nonce.nonce, NONCE_SIZE );
    this->out += NONCE_SIZE;
    return (T &) *this;
  }
  size_t len( void ) const { return this->out - this->msg; }
};

template <class T>
struct MsgBufDigestT : public BMsgBufT<T> {
  uint32_t * hdr;
  char     * dig, * sub;
  MsgBufDigestT( void *m ) : BMsgBufT<T>( m ), hdr( 0 ), dig( 0 ), sub( 0 ) {}
  T  & open       ( const Nonce &bridge,  size_t sublen ) {
    this->hdr  = (uint32_t *) (void *) this->out;
    this->out += 8;
    this->n( FID_BRIDGE, bridge );
    this->emit_u16( CLS_OPAQUE_16 | FID_DIGEST );
    this->dig  = this->out;
    this->out += HMAC_SIZE;/* skip some space for digest */
    this->sub  = this->out;
    this->out += /*fid:sz:sub*/ 4 + sublen; /* skip subject */
    if ( ( sublen & 1 ) != 0 )
      this->out++;
    return (T &) *this;
  }
  T  & open_submsg( void ) {
    this->hdr  = (uint32_t *) (void *) this->out;
    this->out += /*fid:sz*/ 6;
    return (T &) *this;
  }
  void close_msg  ( uint32_t h,  CabaFlags caba ) {
    uint32_t sz = (uint32_t) ( this->len() - 8 ),
             fl = ( (uint32_t) caba.flags << CABA_LENGTH_BITS );
    if ( sz <= CABA_LENGTH_MASK )
      sz |= fl; /* <flags><length> */
    else {
      h   = sz; /* size too big, use the hash field */
      sz  = fl; /* length bits == 0 */
    }
    this->hdr[ 0 ] = kv_bswap32( sz );
    this->hdr[ 1 ] = kv_bswap32( h );
  }
  void close_frag ( uint32_t h,  uint32_t trail_sz,  CabaFlags caba ) {
    if ( ( trail_sz & 1 ) == 1 )
      trail_sz++;
    uint32_t sz = (uint32_t) ( trail_sz + this->len() - 8 ),
             fl = ( (uint32_t) caba.flags << CABA_LENGTH_BITS );
    if ( sz <= CABA_LENGTH_MASK )
      sz |= fl; /* <flags><length> */
    else {
      h   = sz; /* size too big, use the hash field */
      sz  = fl; /* length bits == 0 */
    }
    this->hdr[ 0 ] = kv_bswap32( sz );
    this->hdr[ 1 ] = kv_bswap32( h );
  }
  void close_submsg( uint8_t opt ) {
    size_t sz = this->len();

    char * sav = this->out;
    this->out = (char *) (void *) this->hdr;
    this->emit_u16( CLS_LONG_OPAQUE | opt );
    this->emit_u32( (uint32_t) ( sz - 6 ) );
    this->out = sav;
  }
  T  & session    ( const HmacDigest &hmac,  const Nonce &bridge ) {
    return this->x( FID_SESSION, hmac, bridge ); }
  T  & bridge2    ( const Nonce &bridge ) {
    return this->n( FID_BRIDGE, bridge ); }
  T  & user_hmac  ( const HmacDigest &hmac ) {
    return this->h( FID_USER_HMAC, hmac ); }
  T  & auth_key   ( const HashDigest &key ) {
    return this->k( FID_AUTH_KEY, key ); }
  T  & sess_key   ( const HashDigest &key ) {
    return this->k( FID_SESS_KEY, key ); }
  T  & pubkey     ( const ec25519_key &key ) {
    return this->k( FID_PUBKEY, key ); }

  T  & subject    ( const char *in, size_t in_len ) {
    return this->b( FID_SUBJECT, in, (uint16_t) in_len ); }
  T  & pattern    ( const char *in, size_t in_len ) {
    return this->b( FID_PATTERN, in, (uint16_t) in_len ); }
  T  & reply      ( const char *in, size_t in_len ) {
    return this->b( FID_REPLY, in, (uint16_t) in_len ); }
  T  & ucast_url  ( const char *in, size_t in_len ) {
    return this->b( FID_UCAST_URL, in, (uint16_t) in_len ); }
  T  & mesh_url   ( const char *in, size_t in_len ) {
    return this->b( FID_MESH_URL, in, (uint16_t) in_len ); }
  T  & conn_url   ( const char *in, size_t in_len ) {
    return this->b( FID_CONN_URL, in, (uint16_t) in_len ); }
  T  & tport      ( const char *in, size_t in_len ) {
    return this->b( FID_TPORT, in, (uint16_t) in_len ); }
  T  & tport_type ( const char *in, size_t in_len ) {
    return this->b( FID_TPORT_TYPE, in, (uint16_t) in_len ); }
  T  & user       ( const char *in, size_t in_len ) {
    return this->b( FID_USER, in, (uint16_t) in_len ); }
  T  & service    ( const char *in, size_t in_len ) {
    return this->b( FID_SERVICE, in, (uint16_t) in_len ); }
  T  & create     ( const char *in, size_t in_len ) {
    return this->b( FID_CREATE, in, (uint16_t) in_len ); }
  T  & expires    ( const char *in, size_t in_len ) {
    return this->b( FID_EXPIRES, in, (uint16_t) in_len ); }
  T  & version    ( const char *in, size_t in_len ) {
    return this->b( FID_VERSION, in, (uint16_t) in_len ); }

  T  & sync_bridge( const Nonce &bridge ) {
    return this->n( FID_SYNC_BRIDGE, bridge ); }
  T  & uid_csum   ( const Nonce &csum ) {
    return this->n( FID_UID_CSUM, csum ); }
  T  & mesh_csum  ( const Nonce &csum ) {
    return this->n( FID_MESH_CSUM, csum ); }
  T  & rem_bridge ( const Nonce &bridge ) {
    return this->n( FID_REM_BRIDGE, bridge ); }

  T  & mesh_filter( const void *in, size_t in_len ) {
    return this->o( FID_MESH_FILTER, in, (uint32_t) in_len ); }
  T  & ucast_filter( const void *in, size_t in_len ) {
    return this->o( FID_UCAST_FILTER, in, (uint32_t) in_len ); }
  T  & bloom      ( const void *in, size_t in_len ) {
    return this->o( FID_BLOOM, in, (uint32_t) in_len ); }
  T  & data       ( const void *in, size_t in_len ) {
    return this->o( FID_DATA, in, (uint32_t) in_len ); }
  void data_frag( size_t in_len ) {
    this->emit_u16( CLS_LONG_OPAQUE | FID_DATA );
    this->emit_u32( in_len );
  }
  T  & cnonce( const Nonce &val ) { return this->n( FID_CNONCE, val ); }

  T  & seqno      ( uint64_t n )  { return this->u( FID_SEQNO, n ); }
  T  & sub_seqno  ( uint64_t n )  { return this->u( FID_SUB_SEQNO, n ); }
  T  & time       ( uint64_t n )  { return this->u( FID_TIME, n ); }
  T  & uptime     ( uint64_t n )  { return this->u( FID_UPTIME, n ); }
  T  & interval   ( uint32_t n )  { return this->i( FID_INTERVAL, n ); }
  T  & ref_cnt    ( uint32_t n )  { return this->i( FID_REF_CNT, n ); }
  T  & token      ( uint64_t n )  { return this->u( FID_TOKEN, n ); }
  T  & ret        ( uint64_t n )  { return this->u( FID_RET, n ); }
  T  & link_state ( uint64_t n )  { return this->u( FID_LINK_STATE, n ); }
  T  & start      ( uint64_t n )  { return this->u( FID_START, n ); }
  T  & end        ( uint64_t n )  { return this->u( FID_END, n ); }
  T  & adj_info   ( uint32_t n )  { return this->i( FID_ADJ_INFO, n ); }
  T  & auth_seqno ( uint64_t n )  { return this->u( FID_AUTH_SEQNO, n ); }
  T  & auth_time  ( uint64_t n )  { return this->u( FID_AUTH_TIME, n ); }
  T  & fmt        ( uint32_t n )  { return this->i( FID_FMT, n ); }
  T  & hops       ( uint32_t n )  { return this->i( FID_HOPS, n ); }
  T  & ref_seqno  ( uint64_t n )  { return this->u( FID_REF_SEQNO, n ); }
  T  & tportid    ( uint32_t n )  { return this->i( FID_TPORTID, n ); }
  T  & rem_tportid( uint32_t n )  { return this->i( FID_REM_TPORTID, n ); }
  T  & uid        ( uint32_t n )  { return this->i( FID_UID, n ); }
  T  & uid_cnt    ( uint32_t n )  { return this->i( FID_UID_CNT, n ); }
  T  & subj_hash  ( uint32_t n )  { return this->i4( FID_SUBJ_HASH, n ); }

  T  & auth_stage ( uint16_t n )  { return this->i2( FID_AUTH_STAGE, n ); }
  T  & link_add   ( uint8_t n )   { return this->y( FID_LINK_ADD, n ); }
  T  & conn_port  ( uint16_t n )  { return this->i2( FID_CONN_PORT, n ); }
  T  & idl_service( uint16_t n )  { return this->i2( FID_IDL_SERVICE, n ); }
  T  & idl_msg_loss( uint64_t n ) { return this->u( FID_IDL_MSG_LOSS, n ); }

  T  & fd_cnt     ( uint32_t n )  { return this->i( FID_FD_CNT, n ); }
  T  & ms_tot     ( uint64_t n )  { return this->u( FID_MS_TOT, n ); }
  T  & mr_tot     ( uint64_t n )  { return this->u( FID_MR_TOT, n ); }
  T  & bs_tot     ( uint64_t n )  { return this->u( FID_BS_TOT, n ); }
  T  & br_tot     ( uint64_t n )  { return this->u( FID_BR_TOT, n ); }
  T  & ms         ( uint64_t n )  { return this->u( FID_MS, n ); }
  T  & mr         ( uint64_t n )  { return this->u( FID_MR, n ); }
  T  & bs         ( uint64_t n )  { return this->u( FID_BS, n ); }
  T  & br         ( uint64_t n )  { return this->u( FID_BR, n ); }
  T  & sub_cnt    ( uint64_t n )  { return this->u( FID_SUB_CNT, n ); }
  T  & chain_seqno( uint64_t n )  { return this->u( FID_CHAIN_SEQNO, n ); }
  T  & stamp      ( uint64_t n )  { return this->u( FID_STAMP, n ); }
  T  & converge   ( uint64_t n )  { return this->u( FID_CONVERGE, n ); }
  T  & reply_stamp( uint64_t n )  { return this->u( FID_REPLY_STAMP, n ); }
  T  & hb_skew    ( uint64_t n )  { return this->u( FID_HB_SKEW, n ); }
  T  & cost       ( uint32_t n )  { return this->i( FID_COST, n ); }
  T  & cost2      ( uint32_t n )  { return this->i( FID_COST2, n ); }
  T  & cost3      ( uint32_t n )  { return this->i( FID_COST3, n ); }
  T  & cost4      ( uint32_t n )  { return this->i( FID_COST4, n ); }
  T  & peer       ( const char *in, size_t in_len ) {
    return this->b( FID_PEER, in, (uint16_t) in_len ); }
  T  & latency    ( const char *in, size_t in_len ) {
    return this->b( FID_LATENCY, in, (uint16_t) in_len ); }
  void pk_digest  ( void )        { this->out += 2 + HMAC_SIZE; }
  void pk_sig     ( void )        { this->out += 2 + ED25519_SIG_LEN; }

  /* insert sub_fid : subject, opt_fid 1 */
  void insert_subject( const char *subject, size_t sublen ) {
    char * sav = this->out;
    this->out = this->sub;
    this->b( FID_SUB, subject, (uint16_t) sublen );
    this->out = sav;
  }
  void insert_digest( const HashDigest &ha1 ) {
    MeowHmacDigest hmac;
    hmac.calc_2( ha1, /* msg -> digest */
                 this->msg, this->dig - this->msg,
                 /* digest -> end, skip over digest */
                 &this->dig[ HMAC_SIZE ],
                 this->out - &this->dig[ HMAC_SIZE ] );
    ::memcpy( this->dig, hmac.dig, HMAC_SIZE );
  }
  void insert_digest2( const void *trail,  size_t trail_sz,
                       const HashDigest &ha1 ) {
    MeowHmacDigest hmac;
    hmac.calc_4( ha1, /* msg -> digest */
                 this->msg, this->dig - this->msg,
                 /* digest -> end, skip over digest */
                 &this->dig[ HMAC_SIZE ],
                 this->out - &this->dig[ HMAC_SIZE ],
                 trail, trail_sz, "", trail_sz & 1 );
    ::memcpy( this->dig, hmac.dig, HMAC_SIZE );
  }
  void insert_pk_digest( const HashDigest &pk_ha1 ) {
    MeowHmacDigest hmac;
    this->out -= 2 + HMAC_SIZE;
    hmac.calc_2( pk_ha1, /* msg -> digest */
                 this->msg, this->dig - this->msg,
                 /* digest -> end, skip over digest */
                 &this->dig[ HMAC_SIZE ],
                 this->out - &this->dig[ HMAC_SIZE ] );
    this->h( FID_PK_DIGEST, hmac );
  }
  void insert_dsa_sig( const HashDigest &pk_ha1,  DSA &dsa ) {
    PolyHmacDigest hmac;
    this->out -= 2 + ED25519_SIG_LEN;
    hmac.calc_2( pk_ha1, /* msg -> digest */
                 this->msg, this->dig - this->msg,
                 /* digest -> end, skip over digest */
                 &this->dig[ HMAC_SIZE ],
                 this->out - &this->dig[ HMAC_SIZE ] );
    dsa.sign( hmac.digest(), HMAC_SIZE );
    this->k( FID_PK_SIG, dsa.sig );
  }
  /* sign the message */
  void sign( const char *sub,  size_t sublen,  const HashDigest &ha1 ) {
    this->insert_subject( sub, sublen );
    this->insert_digest( ha1 );
  }
  void sign_frag( const char *sub,  size_t sublen,  const void *trail,
                  size_t trail_sz,  const HashDigest &ha1 ) {
    this->insert_subject( sub, sublen );
    this->insert_digest2( trail, trail_sz, ha1 );
  }
  /* sign a hb message */
  void sign_hb( const char *sub,  size_t sublen,  const HashDigest &ha1,
                const HashDigest &pk_ha2 ) {
    this->insert_subject( sub, sublen );
    this->insert_pk_digest( pk_ha2 );
    this->insert_digest( ha1 );
  }
  /* sign a hb message */
  void sign_dsa( const char *sub,  size_t sublen,  const HashDigest &ha1,
                 const HashDigest &key,  DSA &dsa ) {
    this->insert_subject( sub, sublen );
    this->insert_dsa_sig( key, dsa );
    this->insert_digest( ha1 );
  }
  void sign_debug( const char *sub,  size_t sublen,  const HashDigest &ha1 ) {
    printf( "sub: %.*s\n", (int) sublen, sub );
    printf( "ha1: " ); ha1.print(); printf( "\n" );
    this->insert_subject( sub, sublen );
    ::memset( this->dig, 0, HMAC_SIZE );
    md::MDHexDump::print_hex( this->msg, this->out - this->msg );
    this->insert_digest( ha1 );
  }
};

static inline size_t fid_est( uint32_t fid, size_t len ) {
  switch ( fid ) {
    case FID_DATA:
    case FID_MESH_FILTER:
    case FID_UCAST_FILTER:
    case FID_BLOOM:
      return 2 + 4 + len + 1; /* long opaque, aligned */
    case FID_PEER_DB:
    case FID_MESH_DB:
    case FID_UCAST_DB:
    case FID_ADJACENCY:
      return 2 + 4 + 8 + len + 1; /* long opaque, msg, aligned */
    default:
      return 2 + 2 + len + 1; /* strings are aligned on 2 byte boundary */
  }
}
static inline size_t fid_est( uint32_t fid ) {
  switch ( fid ) {
    case FID_SESSION:     return 2 + HMAC_SIZE + NONCE_SIZE;
    case FID_DIGEST:
    case FID_USER_HMAC:
    case FID_PK_DIGEST:   return 2 + HMAC_SIZE;
    case FID_BRIDGE:
    case FID_CNONCE:
    case FID_SYNC_BRIDGE:
    case FID_REM_BRIDGE:
    case FID_UID_CSUM:
    case FID_MESH_CSUM:   return 2 + NONCE_SIZE;
    case FID_AUTH_KEY:
    case FID_SESS_KEY:    return 2 + HASH_DIGEST_SIZE;
    case FID_PK_SIG:      return 2 + ED25519_SIG_LEN;
    case FID_PUBKEY:      return 2 + EC25519_KEY_LEN;
    default:              return 2 +  8; /* 64 bit int */
  }
}

struct MsgEst {
  size_t sz;
  MsgEst( size_t sublen ) : sz( fid_est( FID_BRIDGE ) +
                                fid_est( FID_DIGEST ) +
                                fid_est( FID_SUB, sublen ) + 8 ) {}
  MsgEst() : sz( 6 /* fid : <size> */ ) {}
  MsgEst & session    ( void ) { sz += fid_est( FID_SESSION ); return *this; }
  MsgEst & bridge2    ( void ) { sz += fid_est( FID_BRIDGE ); return *this; }
  MsgEst & user_hmac  ( void ) { sz += fid_est( FID_USER_HMAC ); return *this; }
  MsgEst & auth_key   ( void ) { sz += fid_est( FID_AUTH_KEY ); return *this; }
  MsgEst & sess_key   ( void ) { sz += fid_est( FID_SESS_KEY ); return *this; }
  MsgEst & pubkey     ( void ) { sz += fid_est( FID_PUBKEY ); return *this; }

  MsgEst & subject    ( size_t l ) { sz += fid_est( FID_SUBJECT, l ); return *this; }
  MsgEst & pattern    ( size_t l ) { sz += fid_est( FID_PATTERN, l ); return *this; }
  MsgEst & reply      ( size_t l ) { sz += fid_est( FID_REPLY, l ); return *this; }
  MsgEst & ucast_url  ( size_t l ) { sz += fid_est( FID_UCAST_URL, l ); return *this; }
  MsgEst & mesh_url   ( size_t l ) { sz += fid_est( FID_MESH_URL, l ); return *this; }
  MsgEst & conn_url   ( size_t l ) { sz += fid_est( FID_CONN_URL, l ); return *this; }
  MsgEst & tport      ( size_t l ) { sz += fid_est( FID_TPORT, l ); return *this; }
  MsgEst & tport_type ( size_t l ) { sz += fid_est( FID_TPORT_TYPE, l ); return *this; }
  MsgEst & user       ( size_t l ) { sz += fid_est( FID_USER, l ); return *this; }
  MsgEst & service    ( size_t l ) { sz += fid_est( FID_SERVICE, l ); return *this; }
  MsgEst & create     ( size_t l ) { sz += fid_est( FID_CREATE, l ); return *this; }
  MsgEst & expires    ( size_t l ) { sz += fid_est( FID_EXPIRES, l ); return *this; }
  MsgEst & version    ( size_t l ) { sz += fid_est( FID_VERSION, l ); return *this; }

  MsgEst & sync_bridge( void ) { sz += fid_est( FID_SYNC_BRIDGE ); return *this; }
  MsgEst & rem_bridge ( void ) { sz += fid_est( FID_REM_BRIDGE ); return *this; }
  MsgEst & uid_csum   ( void ) { sz += fid_est( FID_UID_CSUM ); return *this; }
  MsgEst & mesh_csum  ( void ) { sz += fid_est( FID_MESH_CSUM ); return *this; }

  MsgEst & mesh_filter( size_t l ) { sz += fid_est( FID_MESH_FILTER, l ); return *this; }
  MsgEst & ucast_filter( size_t l ){ sz += fid_est( FID_UCAST_FILTER, l ); return *this; }
  MsgEst & bloom      ( size_t l ) { sz += fid_est( FID_BLOOM, l ); return *this; }
  MsgEst & data       ( size_t l ) { sz += fid_est( FID_DATA, l ); return *this; }
  MsgEst & data_frag  ( void )     { sz += fid_est( FID_DATA, 0 ); return *this; }
  MsgEst & peer_db    ( size_t l ) { sz += fid_est( FID_PEER_DB, l ); return *this; }
  MsgEst & mesh_db    ( size_t l ) { sz += fid_est( FID_MESH_DB, l ); return *this; }
  MsgEst & ucast_db   ( size_t l ) { sz += fid_est( FID_UCAST_DB, l ); return *this; }
  MsgEst & adjacency  ( size_t l ) { sz += fid_est( FID_ADJACENCY, l ); return *this; }
  MsgEst & cnonce     ( void ) { sz += fid_est( FID_CNONCE ); return *this; }

  MsgEst & seqno      ( void ) { sz += fid_est( FID_SEQNO ); return *this; }
  MsgEst & sub_seqno  ( void ) { sz += fid_est( FID_SUB_SEQNO ); return *this; }
  MsgEst & time       ( void ) { sz += fid_est( FID_TIME ); return *this; }
  MsgEst & uptime     ( void ) { sz += fid_est( FID_UPTIME ); return *this; }
  MsgEst & interval   ( void ) { sz += fid_est( FID_INTERVAL ); return *this; }
  MsgEst & ref_cnt    ( void ) { sz += fid_est( FID_REF_CNT ); return *this; }
  MsgEst & token      ( void ) { sz += fid_est( FID_TOKEN ); return *this; }
  MsgEst & ret        ( void ) { sz += fid_est( FID_RET ); return *this; }
  MsgEst & link_state ( void ) { sz += fid_est( FID_LINK_STATE ); return *this; }
  MsgEst & start      ( void ) { sz += fid_est( FID_START ); return *this; }
  MsgEst & end        ( void ) { sz += fid_est( FID_END ); return *this; }
  MsgEst & adj_info   ( void ) { sz += fid_est( FID_ADJ_INFO ); return *this; }
  MsgEst & auth_seqno ( void ) { sz += fid_est( FID_AUTH_SEQNO ); return *this; }
  MsgEst & auth_time  ( void ) { sz += fid_est( FID_AUTH_TIME ); return *this; }
  MsgEst & fmt        ( void ) { sz += fid_est( FID_FMT ); return *this; }
  MsgEst & hops       ( void ) { sz += fid_est( FID_HOPS ); return *this; }
  MsgEst & ref_seqno  ( void ) { sz += fid_est( FID_REF_SEQNO ); return *this; }
  MsgEst & tportid    ( void ) { sz += fid_est( FID_TPORTID ); return *this; }
  MsgEst & rem_tportid( void ) { sz += fid_est( FID_REM_TPORTID ); return *this; }
  MsgEst & uid        ( void ) { sz += fid_est( FID_UID ); return *this; }
  MsgEst & uid_cnt    ( void ) { sz += fid_est( FID_UID_CNT ); return *this; }
  MsgEst & subj_hash  ( void ) { sz += fid_est( FID_SUBJ_HASH ); return *this; }

  MsgEst & auth_stage ( void ) { sz += fid_est( FID_AUTH_STAGE ); return *this; }
  MsgEst & link_add   ( void ) { sz += fid_est( FID_LINK_ADD ); return *this; }
  MsgEst & conn_port  ( void ) { sz += fid_est( FID_CONN_PORT ); return *this; }
  MsgEst & idl_service( void ) { sz += fid_est( FID_IDL_SERVICE ); return *this; }
  MsgEst & idl_msg_loss( void ){ sz += fid_est( FID_IDL_MSG_LOSS ); return *this; }

  MsgEst & fd_cnt     ( void ) { sz += fid_est( FID_FD_CNT ); return *this; }
  MsgEst & ms_tot     ( void ) { sz += fid_est( FID_MS_TOT ); return *this; }
  MsgEst & mr_tot     ( void ) { sz += fid_est( FID_MR_TOT ); return *this; }
  MsgEst & bs_tot     ( void ) { sz += fid_est( FID_BS_TOT ); return *this; }
  MsgEst & br_tot     ( void ) { sz += fid_est( FID_BR_TOT ); return *this; }
  MsgEst & ms         ( void ) { sz += fid_est( FID_MS ); return *this; }
  MsgEst & mr         ( void ) { sz += fid_est( FID_MR ); return *this; }
  MsgEst & bs         ( void ) { sz += fid_est( FID_BS ); return *this; }
  MsgEst & br         ( void ) { sz += fid_est( FID_BR ); return *this; }
  MsgEst & sub_cnt    ( void ) { sz += fid_est( FID_SUB_CNT ); return *this; }
  MsgEst & chain_seqno( void ) { sz += fid_est( FID_CHAIN_SEQNO ); return *this; }
  MsgEst & stamp      ( void ) { sz += fid_est( FID_STAMP ); return *this; }
  MsgEst & converge   ( void ) { sz += fid_est( FID_CONVERGE ); return *this; }
  MsgEst & reply_stamp( void ) { sz += fid_est( FID_REPLY_STAMP ); return *this; }
  MsgEst & hb_skew    ( void ) { sz += fid_est( FID_HB_SKEW ); return *this; }
  MsgEst & cost       ( void ) { sz += fid_est( FID_COST ); return *this; }
  MsgEst & cost2      ( void ) { sz += fid_est( FID_COST2 ); return *this; }
  MsgEst & cost3      ( void ) { sz += fid_est( FID_COST3 ); return *this; }
  MsgEst & cost4      ( void ) { sz += fid_est( FID_COST4 ); return *this; }
  MsgEst & peer       ( size_t l ) { sz += fid_est( FID_PEER, l ); return *this; }
  MsgEst & latency    ( size_t l ) { sz += fid_est( FID_LATENCY, l ); return *this; }

  MsgEst & pk_digest  ( void ) { sz += fid_est( FID_PK_DIGEST ); return *this; }
  MsgEst & pk_sig     ( void ) { sz += fid_est( FID_PK_SIG ); return *this; }
};

#endif
