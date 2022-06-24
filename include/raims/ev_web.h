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

struct WebOutput : public kv::StreamBuf::BufQueue, public ConsoleOutput {
  WebService & svc;
  size_t       out_size;

  WebOutput( WebService &str,  WebType type );
  size_t template_substitute( const char *cmd,  size_t cmd_len,
                              const char *template_buf,  size_t template_sz,
                              char paren = '(' ) noexcept;
  bool template_property( const char *var,  size_t varlen ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
};

struct HtmlOutput : public WebOutput {
  size_t strm_start;
  bool   in_progress;
  HtmlOutput( WebService &str,  WebType type );
  void init( WebType type ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
  void add_http_header( const char *mime,  size_t mlen,
                        size_t size ) noexcept;
};

struct SubOutput : public WebOutput {
  SubOutput * next, * back;
  bool   in_progress;
  void * operator new( size_t, void *ptr ) { return ptr; }
  SubOutput( WebService &str );
  void init( void ) noexcept;
  virtual bool on_output( const char *buf,  size_t buflen ) noexcept;
};

typedef kv::DLinkList<SubOutput> WebSubList;

struct WebListen : public kv::EvTcpListen {
  Console    * console;
  const char * http_dir;
  size_t       http_dir_len;
  void * operator new( size_t, void *ptr ) { return ptr; }
  WebListen( kv::EvPoll &p )
    : kv::EvTcpListen( p, "web_listen", "web_sock" ), console( 0 ),
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
  WebSubList   sub_list;
  HtmlOutput   out;
  const char * http_dir;
  size_t       http_dir_len;

  static const uint32_t MAX_ENTRIES = 64;
  static TarEntry entry[ MAX_ENTRIES ];
  static uint32_t entry_count;

  static NullOutput * null_output;
  static NullOutput * get_null_output( void ) noexcept;
  void * operator new( size_t, void *ptr ) { return ptr; }

  WebService( kv::EvPoll &p,  const uint8_t t )
    : ds::EvHttpConnection( p, t ), console( 0 ), out( *this, W_HTML ),
      http_dir( 0 ), http_dir_len( 0 ) {}

  uint32_t tar_entry_count( void ) noexcept;
  void process_get( const char *path,  size_t path_len,
                    const char *cmd,  size_t cmd_len,
                    const void *data,  size_t data_len,
                    bool is_immutable ) noexcept;
  virtual bool process_get_file( const char *path,  size_t len ) noexcept;
  void template_substitute( const char *cmd,  size_t cmd_len,
                            const char *mime,  size_t mlen,
                            const char *template_buf,
                            size_t template_sz ) noexcept;
  virtual void process_wsmsg( ds::WSMsg &wmsg ) noexcept;
  virtual void write( void ) noexcept;
  virtual void process_close( void ) noexcept;
  virtual void process_shutdown( void ) noexcept;
};

}
}

#endif
