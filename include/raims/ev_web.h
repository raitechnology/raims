#ifndef __rai_raims__ev_web_h__
#define __rai_raims__ev_web_h__

#include <raids/ev_http.h>
#include <raikv/stream_buf.h>
#include <raikv/dlinklist.h>
#include <raims/console.h>

namespace rai {
namespace ms {

struct WebService;
struct NullOutput : public ConsoleOutput {
  void * operator new( size_t, void *ptr ) { return ptr; }
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
};

enum WebType {
  W_HTML,
  W_JSON
};

struct WebReqData {
  const char * path,         /* GET /path */
             * cmd,          /* GET ?cmd */
             * template_buf, /* html or json data */
             * data,         /* file data */
             * mime,         /* mime derived from path */
             * graph,        /* graph computation json */
             * graph_source, /* graph source description */
             * trail;
  size_t       path_len,
               cmd_len,
               template_len,
               data_len,
               mime_len,
               graph_len,
               graph_source_len,
               trail_len;
  char         paren;        /* template variable paren @(var) or @{var} */
  bool         is_immutable; /* data is read only, gzipped */

  WebReqData() {
    ::memset( (void *) this, 0, sizeof( *this ) );
  }
};

struct WebOutput : public kv::StreamBuf::BufQueue, public ConsoleOutput {
  WebService & svc;

  WebOutput( WebService &str,  WebType type );
  void template_substitute( WebReqData &data ) noexcept;
  bool template_property( const char *var,  size_t varlen,
                          WebReqData &data ) noexcept;
  void make_graph_data( WebReqData &data ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
};

struct HtmlOutput : public WebOutput {
  size_t strm_start;
  bool   in_progress;
  HtmlOutput( WebService &str,  WebType type );
  void init( WebType type ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
  void add_http_header( const char *mime,  size_t mlen ) noexcept;
};

struct SubOutput : public WebOutput {
  SubOutput * next, * back;
  char      * trail;
  uint32_t    trail_len;
  bool        in_progress,
              is_local_cmd;
  void * operator new( size_t, void *ptr ) { return ptr; }
  SubOutput( WebService &str );
  void init( void ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
};

typedef kv::DLinkList<SubOutput> WebSubList;

struct WebListen : public kv::EvTcpListen {
  Console    & console;
  const char * http_dir;
  size_t       http_dir_len;
  void * operator new( size_t, void *ptr ) { return ptr; }
  WebListen( kv::EvPoll &p,  Console &c )
    : kv::EvTcpListen( p, "web_listen", "web_sock" ), console( c ),
      http_dir( 0 ), http_dir_len( 0 ) {}

  virtual EvSocket *accept( void ) noexcept;
};

struct tar_header;
struct TarEntry {
  char         fname[ 100 + 155 + 1 ],
               uname[ 32 ],
               gname[ 32 ];
  uint32_t     mode, /* o-rwx low bits, g-rwx mid, u-rwx high */
               uid,  /* uid & gid number */
               gid,
               mtime; /* seconds */
  const void * data;
  size_t       size, /* maximum is 8G */
               fname_off,
               fname_len;

  void to_entry( tar_header &hdr,  const void *ptr ) noexcept;
};

struct WebService : public ds::EvHttpConnection {
  Console    * console;
  WebSubList   sub_list,
               free_list;
  HtmlOutput   out;
  const char * http_dir;
  size_t       http_dir_len;
#if 0
  int          debug_fd;
#endif
  static const uint32_t MAX_ENTRIES = 64;
  static TarEntry entry[ MAX_ENTRIES ];
  static uint32_t entry_count;

  static NullOutput * null_output;
  static NullOutput * get_null_output( void ) noexcept;
  void * operator new( size_t, void *ptr ) { return ptr; }

  WebService( kv::EvPoll &p,  const uint8_t t )
    : ds::EvHttpConnection( p, t ), console( 0 ), out( *this, W_HTML ),
      http_dir( 0 ), http_dir_len( 0 )/*, debug_fd( -1 )*/ {}

  uint32_t tar_entry_count( void ) noexcept;
  void process_get( WebReqData &data ) noexcept;
  virtual bool process_post( const ds::HttpReq &hreq ) noexcept;
  virtual bool process_get_file( const char *path,  size_t len ) noexcept;
  bool process_get_file2( WebReqData &data ) noexcept;
  void template_substitute( WebReqData &data ) noexcept;
  virtual void process_wsmsg( ds::WSMsg &wmsg ) noexcept;
  virtual void write( void ) noexcept;
  virtual void process_close( void ) noexcept;
  virtual void process_shutdown( void ) noexcept;
};

}
}

#endif
