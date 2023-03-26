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
  const char * pre, * name, * subj;
  size_t       pre_len, name_len, subj_len;
  for ( int i = 1; i < argc; i++ ) {
    const char * s = argv[ i ];
    int n = SubDB::match_ipc_subject( s, ::strlen( s ), pre, pre_len,
                                      name, name_len, subj, subj_len,
                                    SubDB::IPC_IS_QUEUE | SubDB::IPC_IS_INBOX );
    printf( "%s s=\"%s\" pre=\"%.*s\" name=\"%.*s\" subj=\"%.*s\"\n",
            type[ n ], s, (int) pre_len, pre, (int) name_len, name,
            (int) subj_len, subj );
  }
  if ( argc != 1 )
    return 0;
  for ( int i = 0; test[ i ] != NULL; i++ ) {
    const char * s = test[ i ];
    int n = SubDB::match_ipc_subject( s, ::strlen( s ), pre, pre_len,
                                      name, name_len, subj, subj_len,
                                    SubDB::IPC_IS_QUEUE | SubDB::IPC_IS_INBOX );
    printf( "%s s=\"%s\" pre=\"%.*s\" name=\"%.*s\" subj=\"%.*s\"\n",
            type[ n ], s, (int) pre_len, pre, (int) name_len, name,
            (int) subj_len, subj );
  }
  return 0;
}

