#ifndef __rai__raims__string_tab_h__
#define __rai__raims__string_tab_h__

#include <raimd/md_msg.h>
#include <raikv/uint_ht.h>
#include <raikv/key_hash.h>
#include <raikv/dlinklist.h>

namespace rai {
namespace ms {

struct ConfigPrinter;

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
    if ( sv.id != 0 && this->id != 0 )
      return sv.id == this->id;
    return this->equals( sv.val, sv.len );
  }
  bool is_null( void ) const {
    return this->len == 0;
  }
  StringVal( const StringVal &s ) : val( s.val ), id( s.id ), len( s.len ) {}
  StringVal( const char *s = NULL,  uint32_t l = 0 )
    : val( s ), id( 0 ), len( l ) {}
  void print_js( ConfigPrinter &p ) const noexcept;
  void print_y( ConfigPrinter &p ) const noexcept;
  void zero( void ) { this->val = NULL; this->id = 0; this->len = 0; }
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

  kv::SLinkList<StringArray> str; /* list of strings[32] alloced */
  md::MDMsgMem    & mem;          /* store strings here */
  kv::UIntHashTab * id,           /* hash(str) -> unique str id */
                  * uid;          /* make str id unique hash value */
  StringCollision * str_col;      /* list of hash(str) collisions */
  uint32_t          next_id,      /* next avail str id */
                    small_left;
  char            * small_str;

  uint32_t ref_string( const char *str,  size_t len,  StringVal &sv ) noexcept;
  void reref_string( const char *str,  size_t len,  StringVal &sv ) noexcept {
    if ( len != sv.len || ::memcmp( str, sv.val, len ) != 0 )
      this->ref_string( str, len, sv );
  }
  bool get_string( uint32_t val,  StringVal &sv ) noexcept;

  template<class Obj>
  Obj *make( void ) {
    return new ( this->mem.make( sizeof( Obj ) ) ) Obj();
  }

  StringTab( md::MDMsgMem &m )
      : mem( m ), id( 0 ), uid( 0 ), str_col( 0 ), next_id( 1 ),
        small_left( 0 ), small_str( 0 ) {
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
