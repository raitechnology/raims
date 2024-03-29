#ifndef __rai__raims__string_tab_h__
#define __rai__raims__string_tab_h__

#include <raimd/md_msg.h>
#include <raikv/uint_ht.h>
#include <raikv/key_hash.h>
#include <raikv/dlinklist.h>

namespace rai {
namespace ms {

struct StringVal {
  void * operator new( size_t, void *ptr ) { return ptr; }
  const char * val; /* stirng value */
  uint32_t     id,  /* unique string id */
               len; /* strlen */
  bool equals( const char *s,  size_t sz ) const {
    return (size_t) this->len == sz && ::memcmp( this->val, s, sz ) == 0;
  }
  bool equals( const char *s ) const {
    return this->equals( s, ::strlen( s ) );
  }
  bool equals( const StringVal &sv ) const {
    if ( sv.id == this->id && this->id != 0 )
      return true;
    return this->equals( sv.val, sv.len );
  }
  int cmp( const StringVal &sv ) const {
    if ( sv.id == this->id && this->id != 0 )
      return 0;
    return ::strcmp( this->val, sv.val );
  }
  bool is_null( void ) const {
    return this->len == 0;
  }
  StringVal( const StringVal &s ) : val( s.val ), id( s.id ), len( s.len ) {}
  StringVal( const char *s = NULL,  uint32_t l = 0 )
    : val( s ), id( 0 ), len( l ) {}
  StringVal & operator=( const StringVal &s ) {
    this->val = s.val; this->id = s.id; this->len = s.len;
    return *this;
  }
  void print_js( md::MDOutput &p ) const noexcept;
  void print_y( md::MDOutput &p ) const noexcept;
  void zero( void ) { this->val = NULL; this->id = 0; this->len = 0; }
  bool get_int( int &ival ) const {
    if ( this->val[ 0 ] >= '0' && this->val[ 0 ] <= '9' ) {
      ival = atoi( this->val );
      return true;
    }
    ival = 0;
    return false;
  }
  bool get_bool( bool &bval ) const {
    const char *s = this->val;
    bval = ( s[ 0 ] == '1' || s[ 0 ] == 't' || s[ 0 ] == 'T' ||
             s[ 0 ] == 'y' || s[ 0 ] == 'Y' );
    return bval || s[ 0 ] == '0' || s[ 0 ] == 'f' || s[ 0 ] == 'F' ||
                   s[ 0 ] == 'n' || s[ 0 ] == 'N';
  }
};

/* combines references to strings to the same ptr and assigns a unique
 * integer id to each string for easy comparison */
struct StringTab {
  struct StringArray {
    void * operator new( size_t, void *ptr ) { return ptr; }
    StringArray * next;
    char        * str[ 64 ];
    uint32_t      first,
                  last;

    StringArray( uint32_t f ) : next( 0 ), first( f ), last( f + 64 ) {
      memset( this->str, 0, sizeof( this->str ) );
    }
  };
  struct StringCollision {
    void * operator new( size_t, void *ptr ) { return ptr; }
    StringCollision * next;
    char            * str;
    uint32_t          id;
    StringCollision() : next( 0 ), str( 0 ), id( 0 ) {}
  };
  struct FreeObj {
    FreeObj * next, * back;
    size_t    size;
  };

  kv::SLinkList<StringArray> str; /* list of strings[32] alloced */
  md::MDMsgMem    & mem;          /* store strings here */
  kv::UIntHashTab * id,           /* hash(str) -> unique str id */
                  * uid;          /* make str id unique hash value */
  StringCollision * str_col;      /* list of hash(str) collisions */
  uint32_t          next_id,      /* next avail str id */
                    small_left;
  char            * small_str;
  kv::DLinkList<FreeObj> free_list;
  uint64_t          free_bits;

  uint32_t ref_string( const char *str,  size_t len,  StringVal &sv ) noexcept;
  uint32_t add_string( StringVal &sv ) {
    if ( sv.id == 0 )
      this->ref_string( sv.val, sv.len, sv );
    return sv.id;
  }
  StringVal & add( StringVal &sv ) { this->add_string( sv ); return sv; }
  void reref_string( const char *str,  size_t len,  StringVal &sv ) {
    if ( len != sv.len || ::memcmp( str, sv.val, len ) != 0 )
      this->ref_string( str, len, sv );
  }
  bool get_string( uint32_t val,  StringVal &sv ) noexcept;
  void * make_obj( size_t sz ) noexcept;
  void free_obj( size_t sz,  void *p ) noexcept;

  template<class Obj, class... Ts>
  Obj *make( Ts... args ) {
    return new ( this->make_obj( sizeof( Obj ) ) ) Obj( args... );
  }
  template<class Obj>
  void release( Obj *o ) {
    return this->free_obj( sizeof( Obj ), o );
  }

  StringTab( md::MDMsgMem &m )
      : mem( m ), id( 0 ), uid( 0 ), str_col( 0 ), next_id( 1 ),
        small_left( 0 ), small_str( 0 ), free_bits( 0 ) {
    this->id  = kv::UIntHashTab::resize( NULL );
    this->uid = kv::UIntHashTab::resize( NULL );
  }
  ~StringTab() {
    if ( this->id != NULL )
      delete this->id;
    if ( this->uid != NULL )
      delete this->uid;
  }
};

}
}

#endif
