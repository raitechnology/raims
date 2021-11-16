#ifndef __rai_raims__send_window_h__
#define __rai_raims__send_window_h__

#include <raikv/dlinklist.h>
#include <raikv/key_hash.h>

namespace rai {
namespace ms {

struct SendWindow {
  static const uint32_t ACTIVE_REFS = 1;
  void   * bufp;
  uint32_t offw,   /* num 8 byte words available */
           sizew,  /* size in 8 byte words */
           availw, /* num words available */
           refs;   /* ref count of window */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  SendWindow( void *p,  size_t avail )
    : bufp( p ), offw( 0 ), sizew( avail / 8 ),
      availw( avail / 8 ), refs( ACTIVE_REFS ) {}

  void reset( void ) {
    this->offw   = 0;
    this->availw = this->sizew;
  }
  static size_t align( size_t len ) {
    return ( len + 7 ) & ~(size_t) 7;
  }
  size_t avail( void ) const {
    return (size_t) this->availw * 8;
  }
  size_t size( void )  const { return (size_t) this->sizew * 8; }

  void *buf_ptr( size_t off ) {
    uint8_t * b = (uint8_t *) this->bufp;
    return &b[ off ];
  }
  void *end_ptr( void ) {
    return this->buf_ptr( this->size() );
  }
  void set_end( void * new_end ) {
    this->availw = ( (char *) this->end_ptr() - (char *) new_end ) / 8;
    this->offw   = this->sizew - this->availw;
  }
  void *off_ptr( void ) {
    return this->buf_ptr( this->offw * 8 );
  }
  void *alloc( size_t len ) {
    size_t idxw = this->offw,
           used = ( len + 7 ) / 8;
    this->offw   += used;
    this->availw -= used;
    this->refs++;
    return this->buf_ptr( idxw * 8 );
  }
  uint32_t deref( void ) {
    return --this->refs;
  }
  void deref_delete( void ) {
    if ( this->deref() == 0 )
      delete this;
  }
  bool fits( size_t len ) {
    if ( len <= this->avail() )
      return true;
    if ( this->refs > ACTIVE_REFS ) /* still used */
      return false;
    if ( len > this->size() ) /* not used, but need more */
      return false;
    this->reset();
    return true;
  }
  bool fits_deref( size_t len ) {
    if ( ! this->fits( len ) ) {
      if ( ( this->refs -= ACTIVE_REFS ) == 0 )
        delete this;
      return false;
    }
    return true;
  }
};

static const uint32_t TRAILER_MARK = 0xff44aa99U; /* spells frag, hah */
struct FragTrailer { /* trailer bytes */
  uint64_t src_id,   /* source of the fragment */
           src_time; /* time that the mssage was published */
  uint32_t off,      /* offset of the fragment */
           msg_len,  /* total size of the message */
           hash,     /* hash of this trailer */
           mark;     /* TRAILER_MARK */
  /* create new trailer on publish */
  FragTrailer( uint64_t src,  uint64_t t,  uint32_t len )
    : src_id( src ), src_time( t ), off( 0 ), msg_len( len ),
      hash( 0 ), mark( TRAILER_MARK ) {
    this->hash = kv_crc_c( this, sizeof( *this ), 0 );
  }
  /* create from message buffer on recv */
  FragTrailer( const void *msg,  size_t mlen ) {
    ::memcpy( this, &((char *) msg)[ mlen - sizeof( *this ) ],
              sizeof( *this ) );
  }
  /* first frag has offset 0 and has a hash computed from the first trailer */
  bool is_first_fragment( size_t len ) {
    if ( this->off     == 0 &&           /* first pkt, off must be zero */
         this->msg_len > len &&          /* msg len must have more fragments */
         this->mark    == TRAILER_MARK ) { /* magic */
      uint32_t h = this->hash;
      this->hash = 0; /* hash of trailer must match */
      bool matches = kv_crc_c( this, sizeof( *this ), 0 ) == h;
      this->hash = h;
      return matches;
    }
    return false;
  }
  static bool is_trailer( const uint8_t *msg,  size_t mlen ) {
    if ( mlen <= sizeof( FragTrailer ) )
      return false;
    uint32_t magic;
    ::memcpy( &magic, &msg[ mlen - 4 ], 4 );
    return magic == TRAILER_MARK;
  }
};

/* messages larger than max_payload are fragmented */
struct Fragment {
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  Fragment * next,     /* list links of message fragments pending */
           * back;
  uint64_t   src_id,   /* the source that created the frags */
             src_time; /* the time that the message was published */
  uint32_t   hash,     /* hash of the subject envelope */
             off,      /* offset of the fragments recvd */
             msg_len,  /* total length of fragment */
             left;     /* alignment */

  /* constructs a list element that coalesces fragments */
  Fragment( const FragTrailer &trl,  const void *data,  size_t len )
    : next( 0 ), back( 0 ), src_id( trl.src_id ), src_time( trl.src_time ),
      hash( trl.hash ), off( 0 ), msg_len( trl.msg_len ), left( trl.msg_len ) {
    this->merge( trl, data, len );
  }
  /* data follows */
  uint8_t *msg_ptr( void ) {
    return (uint8_t *) (void *) &this[ 1 ];
  }
  /* if fragment is the next in the message */
  bool matches( const FragTrailer &trl ) {
    return this->src_id   == trl.src_id   &&  /* the source matches */
           this->src_time == trl.src_time &&  /* the time the message created */
           this->off      == trl.off      &&  /* offset of fragment */
           this->msg_len  == trl.msg_len  &&  /* the total length of the msg */
           this->hash     == trl.hash     &&  /* the subject hash */
           TRAILER_MARK   == trl.mark;
  }
  /* merge a fragment into the message, if it matches */
  bool merge( const FragTrailer &trl,  const void *data,  size_t len ) {
    if ( ! this->matches( trl ) )
      return false;
    ::memcpy( this->msg_ptr() + trl.off, data, len );
    this->off   = trl.off + len;
    this->left -= len;
    return true;
  }
};

typedef kv::DLinkList<Fragment> FragList;  /* large message fragments */

}
}

#endif
