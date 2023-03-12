#ifndef __rai_raims__sub_list_h__
#define __rai_raims__sub_list_h__

#include <raikv/dlinklist.h>

namespace rai {
namespace ms {

enum SubAction {
  ACTION_SUB_JOIN   = 0, /* subscribe start */
  ACTION_PSUB_START = 1, /* pattern start */
};

struct SubElem {
  static const size_t SUB_ELEM_CAP = 64;
  SubElem * next,
          * back;
  uint16_t  drop,  /* count of dropped */
            count, /* count of elems */
            first, /* first index used */
            last;  /* last index used + 1 */
  uint64_t  action; /* 64 action bits, 0 == sub, 1 = psub */
  uint64_t  seqno[ SUB_ELEM_CAP ]; /* list of seqno, hash */
  uint32_t  hash[ SUB_ELEM_CAP ];

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  SubElem() : next( 0 ), back( 0 ), drop( 0 ), count( 0 ), first( 0 ),
              last( 0 ), action( 0 ) {}
  bool is_full( void ) const {
    return this->count - this->drop == SUB_ELEM_CAP;
  }
  bool is_empty( void ) const {
    return this->count - this->drop == 0;
  }
  bool push( uint64_t sno,  uint32_t h,  SubAction a ) {
    uint64_t mask, act;
    if ( this->last == SUB_ELEM_CAP ) {
      if ( this->is_full() )
        return false;
      uint16_t i, j = 0;
      for ( i = this->first; i < this->last; i++ ) {
        if ( this->seqno[ i ] != 0 ) {
          mask = ~( (uint64_t) 1 << j );
          act  = (uint64_t) ( ( this->action >> i ) & 1 ) << j;
          this->action = ( this->action & mask ) | act;
          this->seqno[ j ]  = this->seqno[ i ];
          this->hash[ j++ ] = this->hash[ i ];
        }
      }
      this->drop  = 0;
      this->count = j;
      this->first = 0;
      this->last  = j;
    }
    mask = ~( (uint64_t) 1 << this->last );
    act  = (uint64_t) a << this->last;
    this->action = ( this->action & mask ) | act;
    this->seqno[ this->last ]  = sno;
    this->hash[ this->last++ ] = h;
    this->count++;
    return true;
  }
  bool exists( uint64_t sno,  uint16_t &i ) {
    if ( this->is_empty() || this->seqno[ this->last - 1 ] < sno )
      return false;
    for ( i = this->first; ; ) {
      if ( this->seqno[ i ] >= sno ) {
        if ( this->seqno[ i ] > sno )
          return false;
        return true;
      }
      if ( ++i == this->last )
        return false;
    }
  }
  bool pop( uint64_t sno ) {
    uint16_t i;
    if ( ! this->exists( sno, i ) )
      return false;
    this->seqno[ i ] = 0;
    this->drop++;
    if ( this->drop == this->count ) {
      this->first = 0;
      this->last  = 0;
    }
    else if ( i == this->first ) {
      while ( this->seqno[ ++i ] == 0 )
        ;
      this->first = i;
    }
    else if ( i == this->last - 1 ) {
      while ( this->seqno[ --i ] == 0 )
        ;
      this->last = i + 1;
    }
    return true;
  }
  /* locate first sequence that is >= sno */
  bool get_first_seqno( uint16_t &off,  uint64_t &sno,  uint32_t &h,
                        SubAction &a ) {
    if ( this->is_empty() || this->seqno[ this->last - 1 ] < sno )
      return false;
    for ( uint16_t i = this->first; ; ) {
      if ( this->seqno[ i ] >= sno ) {
        off = i;
        sno = this->seqno[ i ];
        h   = this->hash[ i ];
        a   = (SubAction) ( ( this->action >> i ) & 1 );
        return true;
      }
      if ( ++i == this->last )
        return false;
    }
  }
  /* increment sequence off */
  bool get_next_seqno( uint16_t &off,  uint64_t &sno,  uint32_t &h,
                       SubAction &a ) {
    for ( uint16_t i = off; ; ) {
      if ( ++i == this->last  )
        return false;
      if ( this->seqno[ i ] != 0 ) {
        off = i;
        sno = this->seqno[ i ];
        h   = this->hash[ i ];
        a   = (SubAction) ( ( this->action >> i ) & 1 );
        return true;
      }
    }
  }
};

struct SubList {
  /* linked list of arrays */
  kv::DLinkList<SubElem> list;
  /* this presumes sequences are pushed in increasing values */
  void push( uint64_t sno,  uint32_t h,  SubAction a ) {
    if ( this->list.hd == NULL || this->list.tl->is_full() )
      this->list.push_tl( new ( ::malloc( sizeof( SubElem ) ) ) SubElem() );
    this->list.tl->push( sno, h, a );
  }
  bool pop( uint64_t sno ) {
    for ( SubElem *el = this->list.hd; el != NULL; el = el->next ) {
      if ( el->pop( sno ) ) {
        if ( el->is_empty() ) {
          this->list.pop( el );
          delete el;
        }
        return true;
      }
    }
    return false;
  }
  bool exists( uint64_t sno ) {
    uint16_t i;
    for ( SubElem *el = this->list.hd; el != NULL; el = el->next ) {
      if ( el->exists( sno, i ) )
        return true;
    }
    return false;
  }
  void release( void ) {
    while ( ! this->list.is_empty() ) {
      SubElem * el = this->list.pop_hd();
      delete el;
    }
  }
};

struct SubListIter {
  SubElem * el;     /* current list element */
  uint64_t  start,  /* search from start -> end, inclusive */
            end;
  uint64_t  seqno;  /* current sequence at el->seqno[ off ] */
  uint32_t  hash;   /* hash at el->hash[ off ] */
  uint16_t  off;    /* ptr to el */
  SubAction action;

  SubListIter( SubList &subs,  uint64_t start,  uint64_t end ) :
      hash( 0 ), off( 0 ), action( ACTION_SUB_JOIN ) {
    this->el    = subs.list.hd;
    this->seqno = start; /* start search here */
    this->start = start;
    this->end   = end;
  }
  /* find the first sequence >= seqno */
  bool first( void ) {
    for (;;) {
      if ( this->el == NULL )
        return false;
      if ( this->el->get_first_seqno( this->off, this->seqno, this->hash,
                                      this->action ) )
        return this->seqno <= this->end;
      this->el = this->el->next;
    }
  }
  /* incrementing off also gets the next sequences in order */
  bool next( void ) {
    if ( this->el->get_next_seqno( this->off, this->seqno, this->hash,
                                   this->action ) )
      return this->seqno <= this->end;
    this->el = this->el->next;
    this->seqno++;
    return this->first();
  }
  size_t count( void ) const {
    size_t n = 0;
    for ( SubElem *e = this->el; e != NULL; e = e->next )
      n += e->count;
    return n;
  }
};

}
}
#endif
