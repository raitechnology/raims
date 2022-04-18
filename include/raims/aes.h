#ifndef __rai__raims__aes_h__
#define __rai__raims__aes_h__

namespace rai {
namespace ms {

struct AES128 {
  ~AES128() { this->zero(); }
#ifndef _MSC_VER
  uint8_t key_sched[ 128 * 20 / 8 ] __attribute__((__aligned__(64)));
#else
  uint8_t __declspec(align(64)) key_sched[ 128 * 20 / 8 ];
#endif
  void expand_key( const void *key  ) noexcept;
  void encrypt( const void *plain,  void *cipher ) noexcept;
  void decrypt( const void *cipher,  void *plain ) noexcept;
  void zero( void ) volatile {
    ::memset( (void *) this->key_sched, 0, sizeof( this->key_sched ) );
  }
};

}
}
#endif
