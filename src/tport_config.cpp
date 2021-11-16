#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <raikv/util.h>
#include <raikv/key_hash.h>
#include <raims/parse_config.h>

using namespace rai;
using namespace ms;
using namespace md;
using namespace kv;

static const char example_tport_config[] =
"transports:\n"
"  - tport: my_telnet\n"
"    type: telnet\n"
"    listen: 127.0.0.1\n"
"    port: 2300\n"
"  - tport: my_tcp\n"
"    type: tcp\n"
"    listen: 127.0.0.1\n"
"    connect: 127.0.0.1\n"
"    port: 7127\n"
"    timeout: 10\n"
"  - tport: my_mesh\n"
"    type: mesh\n"
"    listen: 127.0.0.1\n"
"    connect: 127.0.0.1\n"
"    port: 8127\n"
"    timeout: 10\n"
"  - tport: my_pgm\n"
"    type: pgm\n"
"    listen: ;226.6.6.6\n"
"    connect: ;226.6.6.6\n"
"    port: 9666\n"
"    mtu: 1500\n"
"    txw_sqns: 1024\n"
"    rxw_sqns: 256\n"
"    mcast_loop: 2\n";

ConfigTree *
ConfigDB::parse_tport_examples( StringTab &st ) noexcept
{
  ConfigTree * tree = new ( st.mem.make( sizeof( ConfigTree ) ) ) ConfigTree();
  ConfigDB db( *tree, st.mem, NULL, st );
  if ( db.parse_jsconfig( example_tport_config,
                         sizeof( example_tport_config ) - 1, "ex.yaml" ) == 0 )
    return &db.cfg;
  return NULL;
}

