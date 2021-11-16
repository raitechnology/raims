#ifndef __rai_raims__state_test_h__
#define __rai_raims__state_test_h__

namespace rai {
namespace ms {

template <class T>
struct StateTest {
  uint32_t is_set( uint32_t fl )  const { return ((T *) this)->state & fl; }
  bool     all_set( uint32_t fl ) const { return (((T *) this)->state & fl) == fl; }
  void     set( uint32_t fl )           { ((T *) this)->state |= fl; }
  void     clear( uint32_t fl )         { ((T *) this)->state &= ~fl; }

  uint32_t test_clear( uint32_t fl ) {
    uint32_t old = ((T *) this)->state;
    this->clear( fl );
    return old & fl;
  }
  uint32_t test_set( uint32_t fl ) {
    uint32_t old = ((T *) this)->state;
    this->set( fl );
    return old & fl;
  }
};

}
}
#endif
