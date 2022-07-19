#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raims/ev_web.h>
#include <raikv/os_file.h>
#include <raims/user_db.h>
#include <raims/ev_web_tar.h>

using namespace rai;
using namespace ds;
using namespace ms;
using namespace kv;

TarEntry rai::ms::WebService::entry[ MAX_ENTRIES ];
uint32_t rai::ms::WebService::entry_count;
NullOutput * rai::ms::WebService::null_output;

NullOutput *
WebService::get_null_output( void ) noexcept
{
  if ( WebService::null_output == NULL )
    WebService::null_output =
      new ( ::malloc( sizeof( NullOutput ) ) ) NullOutput();
  return WebService::null_output;
}

#pragma pack(1)
struct rai::ms::tar_header {
   char name[ 100 ];       /*   NUL-terminated if NUL fits */
   char mode[ 8 ];
   char uid[ 8 ];
   char gid[ 8 ];
   char size[ 12 ];
   char mtime[ 12 ];
   char chksum[ 8 ];
   char typeflag[ 1 ];     /*   see below */
   char linkname[ 100 ];   /*   NUL-terminated if NUL fits */
   char magic[ 6 ];        /*   must be TMAGIC (NUL term.) */
   char version[ 2 ];      /*   must be TVERSION */
   char uname[ 32 ];       /*   NUL-terminated */
   char gname[ 32 ];       /*   NUL-terminated */
   char devmajor[ 8 ];
   char devminor[ 8 ];
   char prefix[ 155 ];     /*   NUL-terminated if NUL fits */
   char trail[ 12 ];
};
#pragma pack()

static uint64_t
octal( const char *s,  size_t len ) noexcept
{
  uint64_t val = 0;
  while ( len > 0 && ( *s <= '0' || *s > '7' ) ) { len--; s++; }
  while ( len > 0 && ( *s >= '0' && *s <= '7' ) ) {
    val = ( val << 3 ) + ( *s - '0' );
    len--; s++;
  }
  return val;
}

void
TarEntry::to_entry( tar_header &hdr,  const void *ptr ) noexcept
{
  size_t i, j = 0;

  /* most likely will be empty */
  for ( i = 0; i < sizeof( hdr.prefix ); i++ ) {
    if ( hdr.prefix[ i ] == 0 )
      break;
    this->fname[ j++ ] = hdr.prefix[ i ];
  }
  if ( j > 0 ) {
    if ( this->fname[ j - 1 ] != '/' )
      this->fname[ j++ ] = '/';
  }
  this->fname_off = j;
  /* file or dir name */
  for ( i = 0; i < sizeof( hdr.name ); i++ ) {
    this->fname[ j ] = hdr.name[ i ];
    if ( hdr.name[ i ] == 0 )
      break;
    if ( this->fname[ j ] == '/' )
      this->fname_off = j + 1;
    j++;
  }
  this->fname_len = j;
  ::strncpy( this->uname, hdr.uname, sizeof( this->uname ) );
  ::strncpy( this->gname, hdr.gname, sizeof( this->gname ) );
  this->mode  = octal( hdr.mode, sizeof( hdr.mode ) );
  this->uid   = octal( hdr.uid, sizeof( hdr.uid ) );
  this->gid   = octal( hdr.gid, sizeof( hdr.gid ) );
  this->mtime = octal( hdr.mtime, sizeof( hdr.mtime ) );
  this->data  = ptr;
  this->size  = octal( hdr.size, sizeof( hdr.size ) );
}

uint32_t
WebService::tar_entry_count( void ) noexcept
{
  if ( entry_count != 0 )
    return entry_count;

  static const char zeromagic[] = { 0, 0, 0, 0, 0, 0 };
  tar_header tarhdr;
  size_t     taroff, i = 0;

  for ( taroff = 0; taroff + sizeof( tarhdr ) < sizeof( ev_web_tar_data ); ) {
    tar_header tarhdr;
    TarEntry & te = entry[ i ];
    ::memcpy( &tarhdr, &ev_web_tar_data[ taroff ], sizeof( tarhdr ) );
    taroff += 512;
    if ( ::memcmp( tarhdr.magic, zeromagic, sizeof( tarhdr.magic ) ) == 0 )
      continue;
    if ( ::strncmp( tarhdr.magic, "ustar", 5 ) != 0 ) {
      fprintf( stderr, "Bad tar magic %lu\n", taroff );
      return 0;
    }
    te.to_entry( tarhdr, &ev_web_tar_data[ taroff ] );
    taroff += te.size;
    if ( taroff % 512 != 0 )
      taroff += ( 512 - ( taroff % 512 ) );
    if ( te.fname_off < te.fname_len ) {
      if ( ++i == MAX_ENTRIES )
        break;
    }
  }
  entry_count = i;
  return i;
}

bool
NullOutput::on_output( const char *,  size_t ) noexcept
{
  return true;
}

WebOutput::WebOutput( WebService &str,  WebType type ) :
  kv::StreamBuf::BufQueue( str, 256, 4 * 1024 ),
  ConsoleOutput( type == W_HTML, type == W_JSON ),
  svc( str ), out_size( 0 ) {}

HtmlOutput::HtmlOutput( WebService &str,  WebType type ) :
  WebOutput( str, type ), strm_start( 0 ), in_progress( false ) {}

SubOutput::SubOutput( WebService &str ) :
  WebOutput( str, W_JSON ), next( 0 ), back( 0 ), in_progress( false ) {}

void
HtmlOutput::init( WebType type ) noexcept
{
  this->StreamBuf::BufQueue::init( 256, 4 * 1024 );
  this->out_size    = 0;
  this->strm_start  = 0;
  this->rpc         = NULL;
  this->is_html     = ( type == W_HTML );
  this->is_json     = ( type == W_JSON );
  this->in_progress = false;
}

void
SubOutput::init( void ) noexcept
{
  this->StreamBuf::BufQueue::init( 256, 4 * 1024 );
  this->out_size    = 0;
  this->rpc         = NULL;
  this->is_html     = false;
  this->is_json     = true;
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
  c->console      = this->console;
  c->http_dir     = this->http_dir;
  c->http_dir_len = this->http_dir_len;
  return c;
}

void
WebService::process_wsmsg( WSMsg &wmsg ) noexcept
{
  char * cmd  = &wmsg.inptr[ wmsg.inoff ];
  size_t size = wmsg.inlen - wmsg.inoff;
  wmsg.inoff += size;

  if ( size > 4 && ( ::memcmp( cmd, "sub ", 4 ) == 0 ||
                     ::memcmp( cmd, "psub ", 5 ) == 0 ) ) {
    SubOutput * q = new ( ::malloc( sizeof( SubOutput ) ) ) SubOutput( *this );
    this->sub_list.push_tl( q );
    this->console->on_input( q, cmd, size );
    q->in_progress = true;
  }
  else {
    WebOutput      q( *this, W_JSON );
    WebSocketFrame ws;
    char         * frame;

    if ( size > 9 && ::memcmp( cmd, "template ", 9 ) == 0 ) {
      q.out_size = q.template_substitute( NULL, 0, &cmd[ 9 ], size - 9, '{' );
    }
    else {
      this->console->on_input( &q, cmd, size );
    }
    ws.set( q.out_size, 0, WebSocketFrame::WS_TEXT, true );
    frame = q.prepend_buf( ws.hdr_size() );
    ws.encode( frame );
    this->append_iov( q );
    this->msgs_sent++;
  }
}

void
WebService::write( void ) noexcept
{
  return this->EvConnection::write();
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
  return true;
}

bool
HtmlOutput::on_output( const char *buf,  size_t buflen ) noexcept
{
  this->out_size += this->append_bytes( buf, buflen );
  if ( ! this->in_progress )
    return true;

  static const char templ_trail[] = "</body>\n</html>\n";
  this->out_size += this->append_bytes( templ_trail, sizeof( templ_trail ) - 1 );
  this->add_http_header( "text/html",  9, this->out_size );
  this->svc.append_iov( *this );
  this->svc.msgs_sent++;
  this->in_progress = false;
  return this->svc.idle_push_write();
}

bool
SubOutput::on_output( const char *buf,  size_t buflen ) noexcept
{
  if ( ! this->in_progress )
    return true;

  WebSocketFrame ws;
  char         * frame;

  this->append_bytes( buf, buflen );
  ws.set( buflen, 0, WebSocketFrame::WS_TEXT, true );
  frame = this->prepend_buf( ws.hdr_size() );
  ws.encode( frame );
  this->svc.append_iov( *this );
  this->StreamBuf::BufQueue::reset();
  this->svc.msgs_sent++;
  return this->svc.idle_push_write();
}

void
WebService::process_shutdown( void ) noexcept
{
  if ( this->out.in_progress || ! this->sub_list.is_empty() ) {
    if ( this->out.in_progress ) {
      if ( this->out.rpc != NULL ) {
        this->out.rpc->out.replace( &this->out, WebService::get_null_output() );
        this->out.on_output( "bye", 3 );
      }
    }
    SubOutput * q;
    for ( q = this->sub_list.hd; q != NULL; q = q->next )
      q->in_progress = false;
    while ( ! this->sub_list.is_empty() ) {
      q = this->sub_list.pop_hd();
      if ( q->rpc != NULL )
        this->console->stop_rpc( q, q->rpc );
      ::free( q );
    }
  }
  else {
    this->pushpop( EV_CLOSE, EV_SHUTDOWN );
  }
}

void
WebService::process_close( void ) noexcept
{
  this->EvSocket::process_close();
}

void
WebService::process_get( const char *path,  size_t path_len,
                         const char *cmd,  size_t cmd_len,
                         const void *data,  size_t data_len,
                         bool is_immutable ) noexcept
{
  static const char fmt_gzip[]    = "\r\nContent-Encoding: gzip\r\n\r\n",
                    fmt_immutab[] = "Cache-Control: immutable\r\n",
                    fmt_nocache[] = "Cache-Control: no-cache\r\n";
  size_t       mlen;
  bool         is_gzip;
  const char * mime = get_mime_type( path, path_len, mlen, is_gzip );

  if ( ! is_gzip && mlen > 4 && ::memcmp( mime, "text/", 5 ) == 0 ) {
    this->template_substitute( cmd, cmd_len, mime, mlen,
                               (const char *) data, data_len );
  }
  else {
    static const char fmt_hdr[] =
      "HTTP/1.1 200 OK\r\n"
      "Connection: keep-alive\r\n", fmt_type[] =
      "Content-Type: ", fmt_len[] = "\r\n"
      "Content-Length: ", fmt_end[] = "\r\n"
      "\r\n";
    HtmlOutput   q( *this, W_HTML );
    size_t       size,
                 prefix_len;
    size_t       fmt_off,
                 d;
    size = q.append_bytes( data, data_len );
    d = uint64_digits( size );
    prefix_len = sizeof( fmt_hdr ) - 1 +
               ( is_immutable ? ( sizeof( fmt_immutab ) - 1 ) :
                                ( sizeof( fmt_nocache ) - 1 ) ) +
                 sizeof( fmt_type ) - 1 + mlen +
                 sizeof( fmt_len ) - 1 + d +
               ( is_gzip ? ( sizeof( fmt_gzip ) - 1 ) :
                           ( sizeof( fmt_end ) - 1 ) );
    char * hdr = q.prepend_buf( prefix_len );

    fmt_off = cat( hdr, fmt_hdr, sizeof( fmt_hdr ) - 1 );
    if ( is_immutable )
      fmt_off += cat( &hdr[ fmt_off ], fmt_immutab, sizeof( fmt_immutab ) - 1 );
    else
      fmt_off += cat( &hdr[ fmt_off ], fmt_nocache, sizeof( fmt_nocache ) - 1 );
    fmt_off += cat( &hdr[ fmt_off ], fmt_type, sizeof( fmt_type ) - 1 );
    fmt_off += cat( &hdr[ fmt_off ], mime, mlen );
    fmt_off += cat( &hdr[ fmt_off ], fmt_len, sizeof( fmt_len ) - 1 );
    fmt_off += uint64_to_string( size, &hdr[ fmt_off ], d );
    if ( is_gzip )
      fmt_off += cat( &hdr[ fmt_off ], fmt_gzip, sizeof( fmt_gzip ) - 1 );
    else
      ::memcpy( &hdr[ fmt_off ], fmt_end, sizeof( fmt_end ) - 1 );

    this->append_iov( q );
    this->msgs_sent++;
  }
}

bool
WebService::process_get_file( const char *path,  size_t path_len ) noexcept
{
  const char * cmd     = NULL;
  size_t       cmd_len = 0;

  if ( this->out.in_progress ) {
    if ( this->out.rpc != NULL )
      this->out.rpc->out.replace( &this->out, WebService::get_null_output() );
    this->truncate( this->out.strm_start );
  }
  const char * p;
  if ( (p = (const char *) ::memchr( path, '?', path_len )) != NULL ) {
    cmd       = &p[ 1 ];
    cmd_len   = &path[ path_len ] - cmd;
    path_len -= cmd_len + 1;
  }
  if ( path_len == 0 ) {
    this->out.init( W_JSON );
    this->console->on_input( &this->out, cmd, cmd_len );
    if ( this->out.out_size != 0 ) {
      this->out.add_http_header( "application/json", 16, this->out.out_size );
      this->append_iov( this->out );
      this->out.reset();
      this->msgs_sent++;
      return true;
    }
    return false;
    /*if ( this->rpc != NULL && ! this->rpc->complete )
      return size;*/
  }
  int num = 0;
  if ( this->http_dir_len != 0 ) {
    char path2[ 1024 ];
    ::snprintf( path2, sizeof( path2 ), "%.*s%.*s",
                (int) this->http_dir_len, this->http_dir,
                (int) path_len, path );
    MapFile map( path2 );

    if ( map.open() ) {
      this->process_get( path, path_len, cmd, cmd_len, map.map,
                         map.map_size, false );
      return true;
    }
    num = errno;
  }
  uint32_t count = this->tar_entry_count();
  for ( uint32_t i = 0; i < count; i++ ) {
    size_t   off       = entry[ i ].fname_off,
             fname_len = entry[ i ].fname_len - off;
    const char * fname = &entry[ i ].fname[ off ];
    if ( fname_len >= path_len &&
         ::memcmp( path, fname, path_len ) == 0 ) {
      if ( fname_len == path_len ||
           ( path_len + 3 == fname_len &&
             ::memcmp( &fname[ fname_len - 3 ], ".gz", 3 ) == 0 ) ) {
        this->process_get( fname, fname_len, cmd, cmd_len, entry[ i ].data,
                           entry[ i ].size, true );
        return true;
      }
    }
  }
  if ( this->http_dir_len == 0 ) {
    fprintf( stderr, "web service file get: \"%.*s\": not found\n",
             (int) path_len, path );
    return false;
  }
  fprintf( stderr, "web service file get: \"%.*s\": %d/%s\n",
           (int) path_len, path, num, strerror( num ) );
  return false;
}

void
WebService::template_substitute( const char *cmd,  size_t cmd_len,
                                 const char *mime,  size_t mlen,
                                 const char *template_buf,
                                 size_t template_sz ) noexcept
{
  size_t size;
  this->out.init( mlen == 9 ? W_HTML : W_JSON /* text/html */);
  size = this->out.template_substitute( cmd, cmd_len,
                                        template_buf, template_sz );
  if ( this->out.rpc == NULL || this->out.rpc->complete ) {
    this->out.add_http_header( mime, mlen, size );
    this->append_iov( this->out );
    this->out.reset();
    this->msgs_sent++;
  }
  else {
    this->out.in_progress = true;
    this->out.out_size    = size;
  }
}

bool
WebOutput::template_property( const char *var,  size_t varlen ) noexcept
{
  switch ( var[ 0 ] ) {
    case 'u':
      if ( varlen == 4 && ::memcmp( "user", var, 4 ) == 0 ) {
        const char * user    = this->svc.console->user_db.user.user.val;
        size_t       userlen = this->svc.console->user_db.user.user.len;
        this->out_size = this->append_bytes( user, userlen );
        return true;
      }
      break;
    case 's':
      if ( varlen == 7 && ::memcmp( "service", var, 7 ) == 0 ) {
        const char * svc    = this->svc.console->user_db.svc.svc.val;
        size_t       svclen = this->svc.console->user_db.svc.svc.len;
        this->out_size = this->append_bytes( svc, svclen );
        return true;
      }
      break;
    case 'h':
      if ( varlen == 4 && ::memcmp( "help", var, 4 ) == 0 ) {
        static const char script[] =
          "<script>\n"
          "function jsgo(id, s) { var el = document.getElementById(id);"
                                " s = \"cmd.html?\" + s + \" \" + el.value;"
                                " window.location.href = s; }\n"
          "function jskey(el, s) { if ( event.key != 'Enter' ) return; "
                                " s = \"cmd.html?\" + s + \" \" + el.value;"
                                " window.location.href = s; }\n"
          "</script>\n";
        const ConsoleCmdString *cmds;
        size_t ncmds;
        this->svc.console->get_valid_help_cmds( cmds, ncmds );
        #define STR( s ) s, sizeof( s ) - 1
        this->out_size = this->append_bytes( STR( script ) );
        this->out_size = this->append_bytes( STR( "<dl>" ) );
        for ( uint32_t i = 0; i < ncmds; i++ ) {
          if ( cmds[ i ].cmd < CMD_CONNECT ) {
            size_t slen = ::strlen( cmds[ i ].str ),
                   dlen = ::strlen( cmds[ i ].descr );
            char buf[ 256 ], link[ 128 ];
            size_t n;
            this->out_size += this->append_bytes( STR( "\n<dt><a href=\"" ) );

            if ( cmds[ i ].args[ 0 ] != '\0' ) {
              n = ::snprintf( link, sizeof( link ),
                     "javascript:jsgo('t%u', '%s')", i, cmds[ i ].str );
            }
            else {
              n = ::snprintf( link, sizeof( link ), "cmd.html?%s",
                              cmds[ i ].str);
            }
            this->out_size += this->append_bytes( link, n );
            this->out_size += this->append_bytes( STR( "\">" ) );
            this->out_size += this->append_bytes( cmds[ i ].str, slen );
            this->out_size += this->append_bytes( STR( "</a>" ) );

            if ( cmds[ i ].args[ 0 ] != '\0' ) {
              n = ::snprintf( buf, sizeof( buf ),
                " %s: <input id=\"t%u\" type=\"text\" "
                  "onkeydown=\"jskey(this, '%s')\"></input>",
                  cmds[ i ].args, i, cmds[ i ].str );
              this->out_size += this->append_bytes( buf, n );
            }
            this->out_size += this->append_bytes( STR( "</dt><dd>" ) );
            this->out_size += this->append_bytes( cmds[ i ].descr, dlen );
            this->out_size += this->append_bytes( STR( "</dd>" ) );
          }
        }
        this->out_size += this->append_bytes( STR( "</dl>" ) );
        #undef STR
        return true;
      }
      break;
    default:
      break;
  }
  return false;
}

size_t
WebOutput::template_substitute( const char *cmd,  size_t cmd_len,
                                const char *template_buf,  size_t template_sz,
                                char paren ) noexcept
{
  const char   open = ( paren == '(' ? '(' : '{' ),
               clos = ( paren == '(' ? ')' : '}' );
  const char * m    = (const char *) template_buf,
             * e    = &m[ template_sz ];
  size_t       size = 0;
  for (;;) {
    const char * p = (const char *) ::memchr( m, '@', e - m );
    if ( p == NULL ) {
      size += this->append_bytes( m, e - m );
      break;
    }
    if ( &p[ 2 ] < e && p[ 1 ] == open ) {
      const char * s = (const char *) ::memchr( &p[ 2 ], clos, e - &p[ 2 ] );
      if ( s != NULL ) {
        size += this->append_bytes( m, p - m );
        static const char cmd_str[] = "cmd";
        const char * var    = &p[ 2 ];
        size_t       varlen = s - &p[ 2 ];
        if ( varlen == sizeof( cmd_str ) && var[ 0 ] == '_' &&
             ::memcmp( &var[ 1 ], cmd_str, varlen - 1 ) == 0 ) {
          size += this->append_bytes( cmd, cmd_len );
        }
        else {
          bool run_var = false;
          if ( varlen == sizeof( cmd_str ) - 1 &&
               ::memcmp( var, cmd_str, varlen ) == 0 ) {
            var     = cmd;
            varlen  = cmd_len;
            run_var = true;
          }
          else {
            run_var = ! this->template_property( var, varlen );
          }
          if ( run_var ) {
            this->svc.console->on_input( this, var, varlen );
            if ( this->rpc != NULL && ! this->rpc->complete )
              return size;
          }
          size += this->out_size; this->out_size = 0;
        }
        m = &s[ 1 ];
        continue;
      }
    }
    size += this->append_bytes( m, &p[ 1 ] - m );
    m = &p[ 1 ];
  }
  return size;
}

void
HtmlOutput::add_http_header( const char *mime,  size_t mlen,
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
  char * hdr = this->prepend_buf( prefix_len );

  fmt_off  = cat( hdr, fmt, sizeof( fmt ) - 1 );
  fmt_off += cat( &hdr[ fmt_off ], mime, mlen );
  fmt_off += cat( &hdr[ fmt_off ], fmt_mid, sizeof( fmt_mid ) - 1 );
  fmt_off += uint64_to_string( size, &hdr[ fmt_off ], d );
  ::memcpy( &hdr[ fmt_off ], fmt_trail, sizeof( fmt_trail ) - 1 );
}
