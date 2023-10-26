#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/sub.h>

using namespace rai;
using namespace ms;
using namespace kv;

int
main( int argc, char *argv[] )
{
  static const char *test[] = {
    "_INBOX", "_QUEUE", "_INBOX.test", "_QUEUE.test", "_INBOX.test.one",
    "_QUEUE.test.one", "_INBOX_suffix", "_INBOX_suffix.test",

    "_7500._INBOX", "_7500._QUEUE", "_7500._INBOX.test", "_7500._QUEUE.test",
    "_7500._INBOX.test.one",
    "_7500._QUEUE.test.one", "_7500._INBOX_suffix", "_7500._INBOX_suffix.test",
    NULL
  };
  static const char *type[] =
    { "NO_MATCH", "IS_QUEUE", "IS_INBOX", "IS_INBOX_PREFIX" };
  static const char *ipc_subj[ 3 ] = { "_QUEUE.", "_INBOX.", "_INBOX" };
  static size_t      ipc_len[ 3 ]  = { 7, 7, 6 };

  for ( int i = 1; i < argc; i++ ) {
    const char * s = argv[ i ];
    IpcSubjectMatch m( ipc_subj, ipc_len, 3 );
    int n = m.match( s, ::strlen( s ) );
    printf( "%s s=\"%s\" pre=\"%.*s\" name=\"%.*s\" subj=\"%.*s\"\n",
            type[ n ], s, (int) m.pre_len, m.pre, (int) m.name_len, m.name,
            (int) m.subj_len, m.subj );
  }
  if ( argc != 1 )
    return 0;
  for ( int i = 0; test[ i ] != NULL; i++ ) {
    const char * s = test[ i ];
    IpcSubjectMatch m( ipc_subj, ipc_len, 3 );
    int n = m.match( s, ::strlen( s ) );
    printf( "%s s=\"%s\" pre=\"%.*s\" name=\"%.*s\" subj=\"%.*s\"\n",
            type[ n ], s, (int) m.pre_len, m.pre, (int) m.name_len, m.name,
            (int) m.subj_len, m.subj );
  }
  return 0;
}

