#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define IMPORT_ICO_DATA
#include <raims/ev_web.h>
#include <raikv/os_file.h>
#include <raims/user_db.h>

using namespace rai;
using namespace ds;
using namespace ms;
using namespace kv;

NullOutput * rai::ms::WebService::null_output;

bool
NullOutput::on_output( const char *,  size_t ) noexcept
{
  return true;
}

WebOutput::WebOutput( WebService &str ) :
  kv::StreamBuf::BufQueue( str, 256, 4 * 1024 ), ConsoleOutput( true ),
  svc( str ), out_size( 0 ), strm_start( 0 ), in_progress( false ),
  orphaned( false ) {}

void
WebOutput::init( size_t p,  size_t s ) noexcept
{
  this->StreamBuf::BufQueue::init( p, s );
  this->out_size    = 0;
  this->strm_start  = 0;
  this->rpc         = NULL;
  this->is_html     = true;
  this->in_progress = false;
}

EvSocket *
WebListen::accept( void ) noexcept
{
  WebService *c =
    this->poll.get_free_list<WebService>( this->accept_sock_type );
  if ( c == NULL )
    return NULL;
  if ( ! this->accept2( *c, "web" ) )
    return NULL;
  c->initialize_state();
  c->console = this->console;
  return c;
}

void
WebService::process_wsmsg( WSMsg & ) noexcept
{
}

static inline size_t
cat( char *buf, const void *data,  size_t data_len )
{
  ::memcpy( buf, data, data_len );
  return data_len;
}

bool
WebOutput::on_output( const char *buf,  size_t buflen ) noexcept
{
  this->out_size += this->append_bytes( buf, buflen );
  if ( this->in_progress ) {
    static const char templ_trail[] = "</body>\n</html>\n";
    this->out_size += this->append_bytes( templ_trail, sizeof( templ_trail ) - 1 );
    this->svc.add_http_header( *this, "text/html",  9, this->out_size );
    this->svc.append_iov( *this );
    this->svc.idle_push_write();
    this->in_progress = false;
  }
  return true;
}

bool
WebService::process_get_file( const char *path,  size_t path_len ) noexcept
{
  static const char index[] = "index.html";
  if ( path_len == sizeof( index ) - 1  &&
       ::memcmp( path, index, sizeof( index ) - 1 ) == 0 ) {
    static const char templ[] =
    "<!DOCTYPE html>\n"
    "<html><head>\n"
    "<link rel=\"icon\" href=\"favicon.svg.gz\" type=\"image/svg+xml\"/>\n"
    "<script>\n"
    "function jsgo(id, s) { var el = document.getElementById(id);"
                          " s = \"?\" + s + \" \" + el.value;"
                          " window.location.href = s; }\n"
    "function jskey(el, s) { if ( event.key != 'Enter' ) return; "
                          " s = \"?\" + s + \" \" + el.value;"
                          " window.location.href = s; }\n"
    "</script>\n"
    "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF8\"/>\n"
    "<title>$(user).$(service)</title>\n"
    "</head>\n"
    "<body>\n$(help)\n"
    "</body>\n"
    "</html>\n";

    this->template_substitute( "text/html", 9, templ, sizeof( templ ) - 1 );
    return true;
  }
  if ( path_len > 1 && path[ 0 ] == '?' ) {
    static const char templ[] =
    "<!DOCTYPE html>\n"
    "<html><head>\n"
    "<link rel=\"icon\" href=\"favicon.svg.gz\" type=\"image/svg+xml\"/>\n"
    "<style>\n"
    "table { border-collapse: collapse; width: 100%; }\n"
    "th, td { padding: 0.25rem; text-align: left; border: 1px solid #ccc; }\n"
    "</style>\n"
    "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF8\"/>\n"
    "<title>",  templ_mid[] = "</title>\n"
    "</head>\n"
    "<body>\n", templ_trail[] =
    "</body>\n"
    "</html>\n";

    size_t size = 0;
    if ( this->out.in_progress ) {
      if ( WebService::null_output == NULL )
        WebService::null_output =
          new ( ::malloc( sizeof( NullOutput ) ) ) NullOutput();
      this->out.rpc->out = WebService::null_output;
      this->truncate( this->out.strm_start );
    }
    this->out.init( 256, 4 * 1024 );
    this->out.strm_start = this->pending();
    size += this->out.append_bytes( templ, sizeof( templ ) - 1 );
    size += this->out.append_bytes( &path[ 1 ], path_len - 1 );
    size += this->out.append_bytes( templ_mid, sizeof( templ_mid ) - 1 );
    this->console->on_input( &this->out, &path[ 1 ], path_len - 1 );
    size += this->out.out_size;
    if ( this->out.rpc == NULL || this->out.rpc->complete ) {
      size += this->out.append_bytes( templ_trail, sizeof( templ_trail ) - 1 );
      this->add_http_header( this->out, "text/html",  9, size );
      this->append_iov( this->out );
    }
    else {
      this->out.in_progress = true;
      this->out.out_size    = size;
    }
    return true;
  }
  if ( ::strcmp( path, "favicon.svg.gz" ) == 0 ) {
    static const char fmt[] =
      "HTTP/1.1 200 OK\r\n"
      "Connection: keep-alive\r\n"
      "Cache-Control: immutable\r\n"
      "Content-Type: ", fmt_mid[] = "\r\n"
      "Content-Length: ", fmt_trail[] = "\r\n"
      "Content-Encoding: gzip\r\n"
      "\r\n";
    WebOutput q( *this );
    size_t       size = q.append_bytes( ico_data_gz, sizeof( ico_data_gz ) ),
                 mlen,
                 prefix_len;
    bool         is_gzip;
    const char * mime = get_mime_type( path, path_len, mlen, is_gzip );
    size_t       fmt_off,
                 d = uint64_digits( size );

    prefix_len = sizeof( fmt ) + sizeof( fmt_mid ) +
                 sizeof( fmt_trail ) + mlen + d - 3;
    char * hdr = q.prepend_buf( prefix_len );

    fmt_off  = cat( hdr, fmt, sizeof( fmt ) - 1 );
    fmt_off += cat( &hdr[ fmt_off ], mime, mlen );
    fmt_off += cat( &hdr[ fmt_off ], fmt_mid, sizeof( fmt_mid ) - 1 );
    fmt_off += uint64_to_string( size, &hdr[ fmt_off ], d );
    ::memcpy( &hdr[ fmt_off ], fmt_trail, sizeof( fmt_trail ) - 1 );

    this->append_iov( q );
    return true;
  }
  return false;
#if 0
  else {
    MapFile map( path );

    if ( ! map.open() ) {
      perror( path );
      return false;
    }
    static const char fmt_gzip[] =
      "\r\nContent-Encoding: gzip";
    static const char fmt[] =
      "HTTP/1.1 200 OK\r\n"
      "Connection: keep-alive\r\n"
      "Cache-Control: no-cache\r\n"
      "Content-Type: ", fmt_mid[] = "\r\n"
      "Content-Length: ", fmt_trail[] = "\r\n"
      "\r\n";
    WebOutput q( *this, sizeof( fmt ) + sizeof( fmt_mid ) +
                 sizeof( fmt_trail ) + 80, 4 * 1024 );
    size_t       size = q.append_bytes( map.map, map.map_size ),
                 mlen,
                 prefix_len;
    bool         is_gzip;
    const char * mime = get_mime_type( path, path_len, mlen, is_gzip );
    size_t       fmt_off,
                 d = uint64_digits( size );

    prefix_len = sizeof( fmt ) + sizeof( fmt_mid ) +
                 sizeof( fmt_trail ) + mlen + d - 3 +
                 ( is_gzip ? sizeof( fmt_gzip ) - 1 : 0 );
    char * hdr = q.prepend_buf( prefix_len );

    fmt_off  = cat( hdr, fmt, sizeof( fmt ) - 1 );
    fmt_off += cat( &hdr[ fmt_off ], mime, mlen );
    fmt_off += cat( &hdr[ fmt_off ], fmt_mid, sizeof( fmt_mid ) - 1 );
    fmt_off += uint64_to_string( size, &hdr[ fmt_off ], d );
    if ( is_gzip )
      fmt_off += cat( &hdr[ fmt_off ], fmt_gzip, sizeof( fmt_gzip ) - 1 );
    ::memcpy( &hdr[ fmt_off ], fmt_trail, sizeof( fmt_trail ) - 1 );

    this->append_iov( q );
  }
  return true;
#endif
}

bool
WebService::template_property( WebOutput &q,  const char *var,
                               size_t varlen ) noexcept
{
  switch ( var[ 0 ] ) {
    case 'u':
      if ( varlen == 4 && ::memcmp( "user", var, 4 ) == 0 ) {
        const char * user    = this->console->user_db.user.user.val;
        size_t       userlen = this->console->user_db.user.user.len;
        q.out_size = q.append_bytes( user, userlen );
        return true;
      }
      break;
    case 's':
      if ( varlen == 7 && ::memcmp( "service", var, 7 ) == 0 ) {
        const char * svc    = this->console->user_db.svc.svc.val;
        size_t       svclen = this->console->user_db.svc.svc.len;
        q.out_size = q.append_bytes( svc, svclen );
        return true;
      }
      break;
    case 'h':
      if ( varlen == 4 && ::memcmp( "help", var, 4 ) == 0 ) {
        const ConsoleCmdString *cmds;
        size_t ncmds;
        this->console->get_valid_help_cmds( cmds, ncmds );
        #define STR( s ) s, sizeof( s ) - 1
        q.out_size = q.append_bytes( STR( "<dl>" ) );
        for ( uint32_t i = 0; i < ncmds; i++ ) {
          if ( cmds[ i ].cmd == CMD_QUIT ||
               cmds[ i ].cmd == CMD_CANCEL ||
               cmds[ i ].cmd == CMD_DEBUG ||
               cmds[ i ].cmd == CMD_MUTE_LOG ||
               cmds[ i ].cmd == CMD_UNMUTE_LOG )
            continue;
          size_t slen = ::strlen( cmds[ i ].str ),
                 dlen = ::strlen( cmds[ i ].descr );
          char buf[ 256 ], link[ 128 ];
          size_t n;
          q.out_size += q.append_bytes( STR( "\n<dt><a href=\"" ) );

          if ( cmds[ i ].args[ 0 ] != '\0' ) {
            n = ::snprintf( link, sizeof( link ),
                            "javascript:jsgo('t%u', '%s')", i, cmds[ i ].str );
          }
          else {
            n = ::snprintf( link, sizeof( link ), "?%s", cmds[ i ].str );
          }
          q.out_size += q.append_bytes( link, n );
          q.out_size += q.append_bytes( STR( "\">" ) );
          q.out_size += q.append_bytes( cmds[ i ].str, slen );
          q.out_size += q.append_bytes( STR( "</a>" ) );

          if ( cmds[ i ].args[ 0 ] != '\0' ) {
            n = ::snprintf( buf, sizeof( buf ),
              " %s: <input id=\"t%u\" type=\"text\" "
                "onkeydown=\"jskey(this, '%s')\"></input>",
                cmds[ i ].args, i, cmds[ i ].str );
            q.out_size += q.append_bytes( buf, n );
          }
          q.out_size += q.append_bytes( STR( "</dt><dd>" ) );
          q.out_size += q.append_bytes( cmds[ i ].descr, dlen );
          q.out_size += q.append_bytes( STR( "</dd>" ) );
        }
        q.out_size += q.append_bytes( STR( "</dl>" ) );
        #undef STR
        return true;
      }
      break;
    default:
      break;
  }
  return false;
}

void
WebService::template_substitute( const char *mime,  size_t mlen,
                                 const char *template_buf,
                                 size_t template_sz ) noexcept
{
  WebOutput q( *this );
  const char * m  = (const char *) template_buf,
             * e  = &m[ template_sz ];
  const char * p;
  size_t       size = 0;
  for (;;) {
    p = (const char *) ::memchr( m, '$', e - m );
    if ( p == NULL ) {
      size += q.append_bytes( m, e - m );
      break;
    }
    if ( &p[ 2 ] < e && p[ 1 ] == '(' ) {
      const char * s = (const char *) ::memchr( &p[ 2 ], ')', e - &p[ 2 ] );
      if ( s != NULL ) {
        size += q.append_bytes( m, p - m );
        const char * var = &p[ 2 ];
        size_t       varlen = s - &p[ 2 ];
        if ( ! this->template_property( q, var, varlen ) )
          this->console->on_input( &q, var, varlen );
        size += q.out_size; q.out_size = 0;
        m = &s[ 1 ];
        continue;
      }
    }
    size += q.append_bytes( m, &p[ 1 ] - m );
    m = &p[ 1 ];
  }

  this->add_http_header( q, mime, mlen, size );
  this->append_iov( q );
}

void
WebService::add_http_header( WebOutput &q,  const char *mime,  size_t mlen,
                             size_t size ) noexcept
{
  static const char fmt[] =
    "HTTP/1.1 200 OK\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-cache\r\n"
    "Content-Type: ", fmt_mid[] = "\r\n"
    "Content-Length: ", fmt_trail[] = "\r\n"
    "\r\n";
  size_t prefix_len,
         fmt_off,
         d = uint64_digits( size );

  prefix_len = sizeof( fmt ) + sizeof( fmt_mid ) +
               sizeof( fmt_trail ) + mlen + d - 3;
  char * hdr = q.prepend_buf( prefix_len );

  fmt_off  = cat( hdr, fmt, sizeof( fmt ) - 1 );
  fmt_off += cat( &hdr[ fmt_off ], mime, mlen );
  fmt_off += cat( &hdr[ fmt_off ], fmt_mid, sizeof( fmt_mid ) - 1 );
  fmt_off += uint64_to_string( size, &hdr[ fmt_off ], d );
  ::memcpy( &hdr[ fmt_off ], fmt_trail, sizeof( fmt_trail ) - 1 );
}
