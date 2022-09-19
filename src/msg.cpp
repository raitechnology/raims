#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raimd/md_dict.h>
#include <raimd/cfile.h>
#include <raimd/rv_msg.h>
#define INCLUDE_MSG_CONST
#include <raims/msg.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

MDDict * MsgFrameDecoder::msg_dict;

const char *
rai::ms::publish_type_to_string( PublishType t ) noexcept
{
  return publish_type_str[ t>=U_NORMAL&&t<=UNKNOWN_SUBJECT?t:UNKNOWN_SUBJECT ];
}
static const uint16_t bridge_cls = CLS_OPAQUE_16 | FID_BRIDGE;
static MDMatch cabamsg_match;
#if 0
{
  .off         = 8,
  .len         = 2, /* cnt of buf[] */
  .hint_size   = 1, /* cnt of hint[] */
  .ftype       = (uint8_t) CABA_TYPE_ID,
  .buf         = { ( bridge_cls >> 8 ) & 0xff, bridge_cls & 0xff },
  .hint        = { CABA_TYPE_ID },
  .is_msg_type = CabaMsg::is_cabamsg,
  .unpack      = (md_msg_unpack_f) CabaMsg::unpack
};
#endif
const char *
CabaMsg::get_proto_string( void ) noexcept
{
  return "CABA_MSG";
}

uint32_t
CabaMsg::get_type_id( void ) noexcept
{
  return CABA_TYPE_ID;
}

void
CabaMsg::init_auto_unpack( void ) noexcept
{
  if ( MsgFrameDecoder::msg_dict == NULL )
    MsgFrameDecoder::msg_dict = MsgFrameDecoder::build_msg_dict();
  cabamsg_match.off         = 8;
  cabamsg_match.len         = 2; /* cnt of buf[] */
  cabamsg_match.hint_size   = 1; /* cnt of hint[] */
  cabamsg_match.ftype       = (uint8_t) CABA_TYPE_ID;
  cabamsg_match.buf[ 0 ]    = (uint8_t) ( ( bridge_cls >> 8 ) & 0xff );
  cabamsg_match.buf[ 1 ]    = (uint8_t) ( bridge_cls & 0xff );
  cabamsg_match.hint[ 0 ]   = CABA_TYPE_ID;
  cabamsg_match.is_msg_type = CabaMsg::is_cabamsg;
  cabamsg_match.unpack      = (md_msg_unpack_f) CabaMsg::unpack;
  MDMsg::add_match( cabamsg_match );
}

bool
CabaMsg::is_cabamsg( void *bb,  size_t off,  size_t end,
                     uint32_t ) noexcept
{
  /* 0    4    8   10     26  28     44  46     48 */
  /* size hash fid bridge fid digest fid sublen subject */
  if ( off + 48 <= end ) {
    uint16_t fid;
    fid = get_u16<MD_BIG>( &((uint8_t *) bb)[ off + 8 ] );
    if ( fid != ( CLS_OPAQUE_16 | FID_BRIDGE ) ) /* bridge fid */
      return false;
    fid = get_u16<MD_BIG>( &((uint8_t *) bb)[ off + 26 ] );
    if ( fid != ( CLS_OPAQUE_16 | FID_DIGEST ) ) /* digest fid */
      return false;
    fid = get_u16<MD_BIG>( &((uint8_t *) bb)[ off + 44 ] );
    if ( fid != ( CLS_SHORT_STRING | FID_SUB ) ) /* sub fid */
      return false;
    return true;
  }
  return false;
}

int
CabaMsg::unpack2( uint8_t *bb,  size_t off,  size_t &end,  MDMsgMem *m,
                  CabaMsg *&msg ) noexcept
{
  uint32_t len   = get_u32<MD_BIG>( &bb[ off ] ),
           hash  = get_u32<MD_BIG>( &bb[ off + 4 ] );
  uint16_t flags = len >> CABA_LENGTH_BITS;

  len &= CABA_LENGTH_MASK;
  if ( len == 0 ) {
    len  = hash;
    hash = 0;
  }
  if ( CabaFlags::get_ver( flags ) != CABA_MSG_VERSION )
    return Err::BAD_MAGIC_NUMBER;
  if ( off + len + 8 > end )
    return Err::BAD_BOUNDS;
  end = off + len + 8;

  /* 0    4    8   10     26  28     44  46     48 */
  /* size hash fid bridge fid digest fid sublen subject */
  size_t    start = off + 8 + 2 + NONCE_SIZE + 2 + HMAC_SIZE;
  uint8_t * field = &bb[ start ];
  if ( start + 4 >= end )
    return Err::INVALID_MSG;
  uint16_t  fid    = get_u16<MD_BIG>( field ),
            sublen = get_u16<MD_BIG>( &field[ 2 ] );

  if ( fid != ( CLS_SHORT_STRING | FID_SUB ) )
    return Err::INVALID_MSG;
  if ( start + (size_t) sublen + 4 > end )
    return Err::INVALID_MSG;

  msg = new ( m->make( sizeof( CabaMsg ) ) )
    CabaMsg( bb, off, end, MsgFrameDecoder::msg_dict, m );

  msg->sub        = (const char *) &field[ 4 ];
  msg->subhash    = hash;
  msg->sublen     = sublen;
  msg->caba.flags = flags;
  if ( hash == 0 )
    msg->subhash = kv_crc_c( msg->sub, sublen, 0 );
  return 0;
}

CabaMsg *
CabaMsg::unpack( void *bb,  size_t off,  size_t end,  uint32_t,  MDDict *,
                 MDMsgMem *m ) noexcept
{
  CabaMsg *msg;
  if ( CabaMsg::unpack2( (uint8_t *) bb, off, end, m, msg ) == 0 )
    return msg;
  return NULL;
}

CabaMsg *
CabaMsg::submsg( void *bb,  size_t len ) noexcept
{
  return new ( this->mem->make( sizeof( CabaMsg ) ) )
    CabaMsg( (uint8_t *) bb - 8, 0, len + 8, this->dict, this->mem );
}

bool
CabaMsg::verify( const HashDigest &key ) const noexcept
{
  size_t          off = this->msg_off,
                  end = this->msg_end;
  const uint8_t * buf = (uint8_t *) this->msg_buf;
  /* 0    4    8   10     26  28     44  46     48 */
  /* size hash fid bridge fid digest fid sublen subject */
  static const size_t digest_off = 8 + 2 + NONCE_SIZE + 2;
  MeowHmacDigest hmac, hmac2;
  hmac.copy_from( &buf[ off + digest_off ] );
  hmac2.calc_2( key,
    /* msg -> digest */ &buf[ off ], digest_off,
    /* digest -> end */ &buf[ off + digest_off + HMAC_SIZE ],
                        end - ( off + digest_off + HMAC_SIZE ) );
  return ( hmac == hmac2 );
}

bool
CabaMsg::verify_hb( const HashDigest &key ) const noexcept
{
  size_t          off = this->msg_off,
                  end = this->msg_end - ( HMAC_SIZE + 2 );
  const uint8_t * buf = (uint8_t *) this->msg_buf;
  static const size_t digest_off = 8 + 2 + NONCE_SIZE + 2;
  MeowHmacDigest hmac, hmac2;
  if ( this->msg_end < 48 + HMAC_SIZE + 2 )
    return false;
  hmac.copy_from( &buf[ end + 2 ] );
  hmac2.calc_2( key,
    /* msg -> digest */ &buf[ off ], digest_off,
    /* digest -> end */ &buf[ off + digest_off + HMAC_SIZE ],
                        end - ( off + digest_off + HMAC_SIZE ) );
  return hmac == hmac2;
}

bool
CabaMsg::verify_sig( const HashDigest &key,  DSA &dsa ) const noexcept
{
  size_t          off = this->msg_off,
                  end = this->msg_end - ( ED25519_SIG_LEN + 2 );
  const uint8_t * buf = (uint8_t *) this->msg_buf;
  static const size_t digest_off = 8 + 2 + NONCE_SIZE + 2;
  PolyHmacDigest hmac;
  if ( this->msg_end < 48 + HMAC_SIZE + 2 )
    return false;
  dsa.sig.copy_from( &buf[ end + 2 ] );
  hmac.calc_2( key,
    /* msg -> digest */ &buf[ off ], digest_off,
    /* digest -> end */ &buf[ off + digest_off + HMAC_SIZE ],
                        end - ( off + digest_off + HMAC_SIZE ) );
  return dsa.verify( hmac.digest(), HMAC_SIZE );
}

MsgFrameDecoder::MsgFrameDecoder()
{
  this->init();
}

int
MsgFrameDecoder::unpack( const void *msgbuf,  size_t &msglen ) noexcept
{
  int status;
  this->release();
  if ( (status = CabaMsg::unpack2( (uint8_t *) msgbuf, 0, msglen,
                                   &this->mem, this->msg )) != 0 ) {
    if ( status == Err::BAD_BOUNDS ) {
      msglen = 0;
      return 0;
    }
    return status;
  }
  return 0;
}

uint32_t
CabaMsg::caba_to_rvmsg( MDMsgMem &mem,  void *&data,
                        size_t &datalen ) noexcept
{
  MDFieldIter * iter;
  MDName        name;
  MDReference   mref;
  size_t        buflen = ( this->msg_end - this->msg_off ) * 16;
  void        * buf    = mem.make( buflen );
  RvMsgWriter   rvmsg( buf, buflen );
  int           status = 0;
  if ( this->get_field_iter( iter ) == 0 ) {
    if ( iter->first() == 0 ) {
      do {
        if ( iter->get_name( name ) == 0 ) {
          FidTypeName &t = fid_type_name[ fid_value( name.fid ) ];
          if ( t.cvt_fld == XCL )
            continue;
          size_t flen = (size_t) t.name_len + 1;
          if ( iter->get_reference( mref ) == 0 ) {
            if ( t.cvt_fld == LIT ) {
              status = rvmsg.append_ref( t.type_name, flen, mref );
            }
            else if ( t.cvt_fld == BIN ) {
              char   buf[ KV_BASE64_SIZE( 64 ) ];
              size_t len = bin_to_base64( mref.fptr, mref.fsize, buf, false );
              status = rvmsg.append_string( t.type_name, flen, buf, len );
            }
            else if ( t.cvt_fld == TIM ) {
              char   buf[ 2 + 1 + 2 + 1 + 2 + 1 ];
              MDStamp stamp;
              if ( stamp.get_stamp( mref ) == 0 ) {
                uint64_t secs   = stamp.seconds() + tz_stamp_sec;
                uint32_t hr     = ( secs / 60 / 60 ) % 24,
                         min    = ( secs / 60 ) % 60,
                         sec    = secs % 60;
                uint32_to_string( hr, buf, 2 );
                uint32_to_string( min, &buf[ 3 ], 2 );
                uint32_to_string( sec, &buf[ 6 ], 2 );
                buf[ 2 ] = buf[ 5 ] = ':';
                buf[ 8 ] = '\0';
                status = rvmsg.append_string( t.type_name, flen, buf, 8 );
              }
            }
            if ( status != 0 ) {
              fprintf( stderr, "caba_to_rvmsg failed\n" );
              return CABA_TYPE_ID;
            }
          }
        }
      } while ( iter->next() == 0 );
    }
  }
  datalen = rvmsg.update_hdr();
  data    = buf;
  return RVMSG_TYPE_ID;
}

void
MsgFrameDecoder::print( void ) noexcept
{
  MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );
  printf( "\"%.*s\"\n", (int) this->msg->sublen, this->msg->sub );
  this->msg->print( &mout );
}

void
MsgCat::print( void ) noexcept
{
  MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );
  MDMsgMem mem;
  MDMsg  * m;

  m = CabaMsg::unpack( this->msg, 0, this->len(), 0, MsgFrameDecoder::msg_dict,
                       &mem );
  if ( m != NULL ) {
    m->print( &mout );
  }
}

uint32_t
MsgCat::caba_to_rvmsg( MDMsgMem &mem,  void *&data,
                        size_t &datalen ) noexcept
{
  MDMsgMem tmp;
  MDMsg  * m;

  m = CabaMsg::unpack( this->msg, 0, this->len(), 0, MsgFrameDecoder::msg_dict,
                       &tmp );
  if ( m != NULL )
    return ((CabaMsg *) m)->caba_to_rvmsg( mem, data, datalen );
  return CABA_TYPE_ID;
}

void
MsgCat::print_hex( void ) noexcept
{
  MDOutput mout;
  mout.print_hex( this->msg, this->len() );
  md::MDHexDump::print_hex( this->msg, this->out - this->msg );
}

void
MsgCat::reserve_error( size_t rsz ) noexcept
{
  fprintf( stderr, "reserve size %" PRIu64
                   "is less then message len %" PRIu64 "\n",
           rsz, this->len() );
  this->print_hex();
}

bool
MsgHdrDecoder::get_bridge( Nonce &bridge ) const noexcept
{
  size_t    bridge_off = this->msg->msg_off + 8;
  uint8_t * buf        = (uint8_t *) this->msg->msg_buf;

  uint16_t bridge_fid = get_u16<MD_BIG>( &buf[ bridge_off ] );
  if ( fid_value( bridge_fid ) != FID_BRIDGE )
    return false;
  bridge.copy_from( &buf[ bridge_off + 2 ] );
  return true;
}

int
MsgHdrDecoder::decode_msg( void ) noexcept
{
  /* 0    4    8   10     26  28     44  46     48 */
  /* size hash fid bridge fid digest fid sublen subject */
  size_t    bridge_off = this->msg->msg_off + 8,
            digest_off = bridge_off + 2 + NONCE_SIZE,
            sub_off    = digest_off + 2 + HMAC_SIZE,
            off        = sub_off + 4 + this->msg->sublen,
            end        = this->msg->msg_end;
  uint8_t * buf        = (uint8_t *) this->msg->msg_buf;
  if ( ( this->msg->sublen & 1 ) != 0 )
    off++;

  uint16_t bridge_fid = get_u16<MD_BIG>( &buf[ bridge_off ] ),
           digest_fid = get_u16<MD_BIG>( &buf[ digest_off ] );
  if ( bridge_fid != ( CLS_OPAQUE_16 | FID_BRIDGE ) ||
       digest_fid != ( CLS_OPAQUE_16 | FID_DIGEST ) )
    return Err::INVALID_MSG;

  MDReference & digest_ref = this->mref[ FID_DIGEST ];
  digest_ref.set( &buf[ digest_off + 2 ], NONCE_SIZE, MD_OPAQUE );

  MDReference & bridge_ref = this->mref[ FID_BRIDGE ];
  bridge_ref.set( &buf[ bridge_off + 2 ], HMAC_SIZE, MD_OPAQUE );

  MDReference & sub_ref = this->mref[ FID_SUB ];
  sub_ref.set( (uint8_t *) this->msg->sub, this->msg->sublen, MD_STRING );

  this->set( FID_BRIDGE ).set( FID_DIGEST ).set( FID_SUB );

  while ( off + 2 < end ) {
    uint8_t     * field    = &buf[ off ];
    uint16_t      fid_bits = get_u16<MD_BIG>( field ),
                  fid      = fid_value( fid_bits );
    FldTypeClass  type     = fid_type( fid_bits );
    MDReference & ref      = this->mref[ fid ];
    size_t        hdr_sz   = 2,
                  fsize    = fid_size( type );
    MDType        ftype    = cls_to_md( type );

    if ( type == SHORT_STRING_CLASS ) {
      if ( off + 4 > end )
        return Err::BAD_FIELD_SIZE;
      fsize = get_u16<MD_BIG>( &field[ 2 ] );
      ftype = MD_STRING;
      hdr_sz = 4;
    }
    else if ( type == LONG_OPAQUE_CLASS ) {
      if ( off + 6 > end )
        return Err::BAD_FIELD_SIZE;
      fsize = get_u32<MD_BIG>( &field[ 2 ] );
      ftype = MD_OPAQUE;
      hdr_sz = 6;
    }

    off += hdr_sz + fsize;
    if ( off > end )
      return Err::BAD_FIELD_SIZE;
    if ( ( fsize & 1 ) != 0 )
      off++;

    ref.set( &field[ hdr_sz ], fsize, ftype, MD_BIG );
    this->set( fid );
  }
  return 0;
}

const char *
MsgHdrDecoder::get_return( char *ret_buf,
                           const char *default_suf ) const noexcept
{
  uint32_t ret;
  if ( this->get_ival<uint32_t>( FID_RET, ret ) && ret != 0 ) {
    size_t n = uint_str( ret, ret_buf );
    if ( n > 0 ) {
      ret_buf[ n ] = '\0';
      return ret_buf;
    }
  }
  return default_suf;
}

MDDict *
MsgFrameDecoder::build_msg_dict( void ) noexcept
{
  MDDict     * dict = NULL;
  MDDictBuild  dict_build;
  char         dict_buf[ 16 * 1024 ];
  char       * out = dict_buf,
             * end = &dict_buf[ sizeof( dict_buf ) ];
  const char * fmt;
  int          fid,
               status;

  static const size_t last_idx = sizeof( fid_type_name ) /
                                 sizeof( fid_type_name[ 0 ] );
  FidTypeName * fid_type_name_end = &fid_type_name[ last_idx ];

  for ( FidTypeName * t = fid_type_name; t < fid_type_name_end; t++ ) {
    if ( t != &fid_type_name[ t->fid ] ) {
      fprintf( stderr, "fid incorrect place: %u\n", t->fid );
      exit( 1 );
    }
    t->name_len = (uint8_t) ::strlen( t->type_name );
    if ( ( t->type_mask & BOOL_1 ) != 0 ) {
      fmt = "%s_b { CLASS_ID %d; DATA_SIZE 1; DATA_TYPE boolean; }\n";
      fid = t->fid | ( BOOL_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & U_SHORT ) != 0 ) {
      fmt = "%s_2 { CLASS_ID %d; DATA_SIZE 2; DATA_TYPE u_short; }\n";
      fid = t->fid | ( U_SHORT_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & U_INT ) != 0 ) {
      fmt = "%s_4 { CLASS_ID %d; DATA_SIZE 4; DATA_TYPE u_int; }\n";
      fid = t->fid | ( U_INT_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & U_LONG ) != 0 ) {
      fmt = "%s_8 { CLASS_ID %d; DATA_SIZE 8; DATA_TYPE u_long; }\n";
      fid = t->fid | ( U_LONG_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & OPAQUE_16) != 0 ) {
      fmt = "%s_16 { CLASS_ID %d; DATA_SIZE 16; DATA_TYPE opaque; }\n";
      fid = t->fid | ( OPAQUE_16_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & OPAQUE_32) != 0 ) {
      fmt = "%s_16 { CLASS_ID %d; DATA_SIZE 32; DATA_TYPE opaque; }\n";
      fid = t->fid | ( OPAQUE_32_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & OPAQUE_64) != 0 ) {
      fmt = "%s_64 { CLASS_ID %d; DATA_SIZE 64; DATA_TYPE opaque; }\n";
      fid = t->fid | ( OPAQUE_64_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & SHORT_STRING) != 0 ) {
      fmt = "%s_s2 { CLASS_ID %d; DATA_SIZE 1024; IS_FIXED false; DATA_TYPE string; }\n";
      fid = t->fid | ( SHORT_STRING_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
    if ( ( t->type_mask & LONG_OPAQUE) != 0 ) {
      fmt = "%s_o4 { CLASS_ID %d; DATA_SIZE 65536; IS_FIXED false; DATA_TYPE opaque; }\n";
      fid = t->fid | ( LONG_OPAQUE_CLASS << FID_TYPE_SHIFT );
      out += ::snprintf( out, end - out, fmt, t->type_name, fid );
    }
  }
  *out = '\0';

  status = CFile::parse_string( dict_build, dict_buf, out - dict_buf );
  if ( status == 0 )
    dict_build.index_dict( "cfile", dict );
  else
    fprintf( stderr, "bad cfile dict, status %d\n", status );
#if 0
  printf( "entry count %lu\n", dict_build.idx->entry_count );
  printf( "fid min %u max %u\n", dict_build.idx->min_fid,
                                 dict_build.idx->max_fid );
  printf( "type count %u/%u\n", dict_build.idx->type_hash->htcnt,
                             dict_build.idx->type_hash->htsize );
  printf( "index size %u\n", dict->dict_size );
#endif
  dict_build.clear_build();
  return dict;
}

