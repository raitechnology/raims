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
using namespace md;

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
  svc( str ) {}

HtmlOutput::HtmlOutput( WebService &str,  WebType type ) :
  WebOutput( str, type ), strm_start( 0 ), in_progress( false ) {}

/*static int sub_counter;*/

SubOutput::SubOutput( WebService &str ) :
  WebOutput( str, W_JSON ), next( 0 ), back( 0 ), trail( 0 ), trail_len( 0 ),
  /*output_id( sub_counter++ ),*/ in_progress( false ), is_local_cmd( false ) {}

void
HtmlOutput::init( WebType type ) noexcept
{
  this->StreamBuf::BufQueue::init( 256, 4 * 1024 );
  this->strm_start  = 0;
  this->rpc         = NULL;
  this->is_html     = ( type == W_HTML );
  this->is_json     = ( type == W_JSON );
  this->is_remote   = false;
  this->in_progress = false;
}

void
SubOutput::init( void ) noexcept
{
  this->StreamBuf::BufQueue::init( 256, 4 * 1024 );
  this->rpc          = NULL;
  this->is_html      = false;
  this->is_json      = true;
  this->is_remote    = false;
  this->in_progress  = false;
  this->is_local_cmd = false;
  this->trail        = NULL;
  this->trail_len    = 0;
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
  c->console      = &this->console;
  c->http_dir     = this->http_dir;
  c->http_dir_len = this->http_dir_len;
  /*c->debug_fd     = os_open( "debug.txt", O_APPEND | O_WRONLY | O_CREAT, 0666 );*/
  return c;
}

void
WebService::process_wsmsg( WSMsg &wmsg ) noexcept
{
  SubOutput * q;
  char * cmd  = &wmsg.inptr[ wmsg.inoff ];
  size_t size = wmsg.inlen - wmsg.inoff;
  wmsg.inoff += size;

  if ( ! this->free_list.is_empty() )
    q = new ( this->free_list.pop_hd() ) SubOutput( *this );
  else
    q = new ( ::malloc( sizeof( SubOutput ) ) ) SubOutput( *this );
  if ( size > 4 && ( ::memcmp( cmd, "sub ", 4 ) == 0 ||
                     ::memcmp( cmd, "psub ", 5 ) == 0 ) ) {
    this->sub_list.push_tl( q );
    this->console->on_input( q, cmd, size );
    q->in_progress = true;
  }
  else {
    WebSocketFrame ws;
    char         * frame;

    q->in_progress = true;
    q->is_local_cmd = true;
    if ( size > 9 && ::memcmp( cmd, "template ", 9 ) == 0 ) {
      WebReqData data;
      data.template_buf = &cmd[ 9 ];
      data.template_len = size - 9;
      data.paren = '{';
      q->template_substitute( data );
      if ( q->rpc != NULL && ! q->rpc->complete ) {
        if ( data.trail_len != 0 ) {
          q->trail = (char *) ::malloc( data.trail_len );
          ::memcpy( q->trail, data.trail, data.trail_len );
          q->trail_len = data.trail_len;
        }
      }
    }
    else {
      this->console->on_input( q, cmd, size );
    }
    if ( q->rpc != NULL && ! q->rpc->complete ) {
      q->is_local_cmd = false;
      return;
    }
    ws.set( q->used_size(), 0, WebSocketFrame::WS_TEXT, true );
    frame = q->prepend_buf( ws.hdr_size() );
    ws.encode( frame );
    this->append_iov( *q );
    this->msgs_sent++;
    this->free_list.push_hd( q );
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
  this->append_bytes( buf, buflen );
  return true;
}

bool
HtmlOutput::on_output( const char *buf,  size_t buflen ) noexcept
{
  this->append_bytes( buf, buflen );
  if ( ! this->in_progress )
    return true;

  if ( this->is_html ) {
    static const char templ_trail[] = "</body>\n</html>\n";
    this->append_bytes( templ_trail, sizeof( templ_trail ) - 1 );
    this->add_http_header( "text/html", 9 );
  }
  else {
    this->add_http_header( "application/json", 16 );
  }
  this->svc.append_iov( *this );
  this->svc.msgs_sent++;
  this->in_progress = false;
  return this->svc.idle_push_write();
}

bool
SubOutput::on_output( const char *buf,  size_t buflen ) noexcept
{
  if ( ! this->in_progress ) {
#if 0
    if ( this->svc.debug_fd != -1 ) {
      char tmp[ 40 ];
      int n = ::snprintf( tmp, sizeof( tmp ), "%d -> %d, ", this->output_id,
                          this->svc.fd );
      os_write( this->svc.debug_fd, tmp, n );
      os_write( this->svc.debug_fd, buf, buflen );
    }
#endif
    return true;
  }

  this->append_bytes( buf, buflen );
  if ( this->is_local_cmd )
    return true;

  WebSocketFrame ws;
  char         * frame;

  if ( this->trail_len != 0 ) {
    this->append_bytes( this->trail, this->trail_len );
    ::free( this->trail );
    this->trail     = NULL;
    this->trail_len = 0;
  }
  ws.set( this->used_size(), 0, WebSocketFrame::WS_TEXT, true );
  frame = this->prepend_buf( ws.hdr_size() );
  ws.encode( frame );
  this->svc.append_iov( *this );
  this->StreamBuf::BufQueue::reset();
  this->svc.msgs_sent++;

  if ( this->rpc->complete )
    this->svc.free_list.push_hd( this );
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
#if 0
      if ( this->debug_fd != -1 ) {
        char tmp[ 40 ];
        int n = ::snprintf( tmp, sizeof( tmp ), "shutdown %d -> %d\n",
                            q->output_id, this->fd );
        os_write( this->debug_fd, tmp, n );
      }
#endif
      ::free( q );
    }
    while ( ! this->free_list.is_empty() ) {
      q = this->free_list.pop_hd();
      ::free( q );
    }
  }
  else {
    this->pushpop( EV_CLOSE, EV_SHUTDOWN );
  }
#if 0
  if ( this->debug_fd != -1 ) {
    os_close( this->debug_fd );
    this->debug_fd = -1;
  }
#endif
}

void
WebService::process_close( void ) noexcept
{
  this->EvSocket::process_close();
}

bool
WebService::process_post( const HttpReq &hreq ) noexcept
{
  MDMsgMem     mem;
  const char * obj = hreq.path,
             * end = &hreq.path[ hreq.path_len ];
  char         path[ 1024 ],
             * data_buf,
             * start = NULL;
  size_t       data_len;
  WebReqData   data;

  data.path     = path;
  data.path_len = HttpReq::decode_uri( &obj[ 1 ], end, path, sizeof( path ) );

  data_buf = (char *) mem.make( hreq.content_length );
  data_len = hreq.content_length;

  data_len = HttpReq::decode_uri( hreq.data, &hreq.data[ hreq.content_length ],
                                  data_buf, data_len );
  for ( size_t i = data_len; i > 0; ) {
    if ( data_buf[ --i ] == '&' &&
         ::strncmp( &data_buf[ i + 1 ], "start=", 6 ) == 0 ) {
      data_len = i;
      data_buf[ i ] = '\0';
      start = &data_buf[ i + 7 ];
    }
  }

  if ( ::strncmp( data_buf, "graph_data=", 11 ) == 0 ) {
    kv::ArrayOutput out;

    data_buf       = &data_buf[ 11 ];
    data_len       = data_len - 11;

    compute_message_graph( start, data_buf, data_len, out );

    data.graph     = out.ptr;
    data.graph_len = out.count;

    if ( start != NULL ) {
      if ( ::strncmp( data_buf, "start ", 6 ) == 0 ) {
        size_t start_len = ::strlen( start );
        char * eol       = (char *) ::memchr( &data_buf[ 6 ], '\n',
                                              data_len - 6 ),
             * end       = &data_buf[ data_len ],
             * new_eol   = &data_buf[ 6 + start_len ];

        if ( eol != NULL ) {
          ::memmove( new_eol, eol, end - eol );
          ::memcpy( &data_buf[ 6 ], start, start_len );
          data_len = 6 + start_len + ( end - eol );
        }
      }
    }
    data.graph_source     = data_buf;
    data.graph_source_len = data_len;

    return this->process_get_file2( data );
  }
  return false;
}

bool
WebService::process_get_file( const char *path,  size_t path_len ) noexcept
{
  WebReqData data;
  data.path     = path;
  data.path_len = path_len;
  return this->process_get_file2( data );
}

bool
WebService::process_get_file2( WebReqData &data ) noexcept
{
  if ( this->out.in_progress ) {
    if ( this->out.rpc != NULL )
      this->out.rpc->out.replace( &this->out, WebService::get_null_output() );
    this->truncate( this->out.strm_start );
  }
  const char * p = (const char *) ::memchr( data.path, '?', data.path_len );
  if ( p != NULL ) {
    data.cmd       = &p[ 1 ];
    data.cmd_len   = &data.path[ data.path_len ] - data.cmd;
    data.path_len -= data.cmd_len + 1;
  }
  if ( data.path_len == 0 ) {
    this->out.init( W_JSON );
    this->console->on_input( &this->out, data.cmd, data.cmd_len );
    if ( this->out.used_size() != 0 ) {
      this->out.add_http_header( "application/json", 16 );
      this->append_iov( this->out );
      this->out.reset();
      this->msgs_sent++;
      return true;
    }
    if ( this->out.rpc == NULL || this->out.rpc->complete )
      return false;
    this->out.in_progress = true;
    return true;
  }
  int num = 0;
  if ( this->http_dir_len != 0 ) {
    char path2[ 1024 ];
    ::snprintf( path2, sizeof( path2 ), "%.*s%.*s",
                (int) this->http_dir_len, this->http_dir,
                (int) data.path_len, data.path );
    MapFile map( path2 );

    if ( map.open() ) {
      data.data         = (const char *) map.map;
      data.data_len     = map.map_size;
      data.is_immutable = false;

      this->process_get( data );
      return true;
    }
    num = errno;
  }
  uint32_t count = this->tar_entry_count();
  for ( uint32_t i = 0; i < count; i++ ) {
    size_t   off       = entry[ i ].fname_off,
             fname_len = entry[ i ].fname_len - off;
    const char * fname = &entry[ i ].fname[ off ];
    if ( fname_len >= data.path_len &&
         ::memcmp( data.path, fname, data.path_len ) == 0 ) {
      if ( fname_len == data.path_len ||
           ( data.path_len + 3 == fname_len &&
             ::memcmp( &fname[ fname_len - 3 ], ".gz", 3 ) == 0 ) ) {
        data.path         = fname;
        data.path_len     = fname_len;
        data.data         = (const char *) entry[ i ].data;
        data.data_len     = entry[ i ].size;
        data.is_immutable = true;

        this->process_get( data );
        return true;
      }
    }
  }
  if ( this->http_dir_len == 0 ) {
    fprintf( stderr, "web service file get: \"%.*s\": not found\n",
             (int) data.path_len, data.path );
    return false;
  }
  fprintf( stderr, "web service file get: \"%.*s\": %d/%s\n",
           (int) data.path_len, data.path, num, strerror( num ) );
  return false;
}

void
WebService::process_get( WebReqData &data ) noexcept
{
  static const char fmt_gzip[]    = "\r\nContent-Encoding: gzip\r\n\r\n",
                    fmt_immutab[] = "Cache-Control: immutable\r\n",
                    fmt_nocache[] = "Cache-Control: no-cache\r\n";
  bool is_gzip;
  data.mime = get_mime_type( data.path, data.path_len, data.mime_len, is_gzip );

  if ( ! is_gzip && data.mime_len > 4 &&
       ::memcmp( data.mime, "text/", 5 ) == 0 ) {
    data.template_buf = data.data;
    data.template_len = data.data_len;
    data.paren = '(';
    this->template_substitute( data );
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
    size = q.append_bytes( data.data, data.data_len );
    d = uint64_digits( size );
    prefix_len = sizeof( fmt_hdr ) - 1 +
               ( data.is_immutable ? ( sizeof( fmt_immutab ) - 1 ) :
                                     ( sizeof( fmt_nocache ) - 1 ) ) +
                 sizeof( fmt_type ) - 1 + data.mime_len +
                 sizeof( fmt_len ) - 1 + d +
               ( is_gzip ? ( sizeof( fmt_gzip ) - 1 ) :
                           ( sizeof( fmt_end ) - 1 ) );
    char * hdr = q.prepend_buf( prefix_len );

    fmt_off = cat( hdr, fmt_hdr, sizeof( fmt_hdr ) - 1 );
    if ( data.is_immutable )
      fmt_off += cat( &hdr[ fmt_off ], fmt_immutab, sizeof( fmt_immutab ) - 1 );
    else
      fmt_off += cat( &hdr[ fmt_off ], fmt_nocache, sizeof( fmt_nocache ) - 1 );
    fmt_off += cat( &hdr[ fmt_off ], fmt_type, sizeof( fmt_type ) - 1 );
    fmt_off += cat( &hdr[ fmt_off ], data.mime, data.mime_len );
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

void
WebService::template_substitute( WebReqData &data ) noexcept
{
  this->out.init( data.mime_len == 9 ? W_HTML : W_JSON /* text/html */);
  this->out.template_substitute( data );
  if ( this->out.rpc == NULL || this->out.rpc->complete ) {
    this->out.add_http_header( data.mime, data.mime_len );
    this->append_iov( this->out );
    this->out.reset();
    this->msgs_sent++;
  }
  else {
    this->out.in_progress = true;
  }
}

void
WebOutput::make_graph_data( WebReqData &data ) noexcept
{
  AdjDistance & peer_dist = this->svc.console->user_db.peer_dist;
  kv::ArrayOutput out, out2;

  peer_dist.message_graph_description( out );
  compute_message_graph( NULL, out.ptr, out.count, out2 );

  char * src = this->strm.alloc_temp( out.count ),
       * gr  = this->strm.alloc_temp( out2.count );
  data.graph_source     = src;
  data.graph_source_len = out.count;
  data.graph            = gr;
  data.graph_len        = out2.count;

  ::memcpy( src, out.ptr, out.count );
  ::memcpy( gr, out2.ptr, out2.count );
}

bool
WebOutput::template_property( const char *var,  size_t varlen,
                              WebReqData &data ) noexcept
{
  switch ( var[ 0 ] ) {
    case 'u':
      if ( varlen == 4 && ::memcmp( "user", var, 4 ) == 0 ) {
        const char * user    = this->svc.console->user_db.user.user.val;
        size_t       userlen = this->svc.console->user_db.user.user.len;
        this->append_bytes( user, userlen );
        return true;
      }
      break;
    case 's':
      if ( varlen == 7 && ::memcmp( "service", var, 7 ) == 0 ) {
        const char * svc    = this->svc.console->user_db.svc.svc.val;
        size_t       svclen = this->svc.console->user_db.svc.svc.len;
        this->append_bytes( svc, svclen );
        return true;
      }
      break;
    case 'g':
      if ( varlen == 10 && ::memcmp( "graph_data", var, 10 ) == 0 ) {
        if ( data.graph_len == 0 )
          this->make_graph_data( data );
        this->append_bytes( data.graph, data.graph_len );
        return true;
      }
      if ( varlen == 12 && ::memcmp( "graph_source", var, 12 ) == 0 ) {
        if ( data.graph_source_len == 0 )
          this->make_graph_data( data );
        this->append_bytes( data.graph_source, data.graph_source_len );
        return true;
      }
      break;
    case 'h':
      if ( varlen == 4 && ::memcmp( "help", var, 4 ) == 0 ) {
        const ConsoleCmdString *cmds;
        size_t ncmds;
        this->svc.console->get_valid_help_cmds( cmds, ncmds );
        #define STR( s ) s, sizeof( s ) - 1
        this->append_bytes( STR( "[" ) );
        for ( uint32_t i = 0; i < ncmds; i++ ) {
          if ( cmds[ i ].cmd != CMD_REMOTE && cmds[ i ].cmd <= CMD_SHOW_RUN ) {
            size_t slen = ::strlen( cmds[ i ].str ),
                   dlen = ::strlen( cmds[ i ].descr ),
                   alen = ::strlen( cmds[ i ].args );

            this->append_bytes( STR( "{cmd:\"" ) );
            this->append_bytes( cmds[ i ].str, slen );
            this->append_bytes( STR( "\",args:\"" ) );
            this->append_bytes( cmds[ i ].args, alen );
            this->append_bytes( STR( "\",descr:\"" ) );
            this->append_bytes( cmds[ i ].descr, dlen );
            if ( i < ncmds - 1 )
              this->append_bytes( STR( "\"}," ) );
            else
              this->append_bytes( STR( "\"}" ) );
          }
        }
        this->append_bytes( STR( "]" ) );
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
WebOutput::template_substitute( WebReqData &data ) noexcept
{
  const char   open = ( data.paren == '(' ? '(' : '{' ),
               clos = ( data.paren == '(' ? ')' : '}' );
  const char * m    = data.template_buf,
             * e    = &m[ data.template_len ];
  for (;;) {
    const char * p = (const char *) ::memchr( m, '@', e - m );
    if ( p == NULL ) {
      this->append_bytes( m, e - m );
      break;
    }
    if ( &p[ 2 ] < e && p[ 1 ] == open ) {
      const char * s = (const char *) ::memchr( &p[ 2 ], clos, e - &p[ 2 ] );
      if ( s != NULL ) {
        this->append_bytes( m, p - m );
        static const char cmd_str[] = "cmd";
        const char * var    = &p[ 2 ];
        size_t       varlen = s - &p[ 2 ];
        if ( varlen == sizeof( cmd_str ) && var[ 0 ] == '_' &&
             ::memcmp( &var[ 1 ], cmd_str, varlen - 1 ) == 0 ) {
          this->append_bytes( data.cmd, data.cmd_len );
        }
        else {
          bool run_var = false;
          if ( varlen == sizeof( cmd_str ) - 1 &&
               ::memcmp( var, cmd_str, varlen ) == 0 ) {
            var     = data.cmd;
            varlen  = data.cmd_len;
            run_var = true;
          }
          else {
            run_var = ! this->template_property( var, varlen, data );
          }
          if ( run_var ) {
            this->svc.console->on_input( this, var, varlen );
            if ( this->rpc != NULL && ! this->rpc->complete ) {
              data.trail = &s[ 1 ];
              data.trail_len = e - data.trail;
              return;
            }
          }
        }
        m = &s[ 1 ];
        continue;
      }
    }
    this->append_bytes( m, &p[ 1 ] - m );
    m = &p[ 1 ];
  }
}

void
HtmlOutput::add_http_header( const char *mime,  size_t mlen ) noexcept
{
  static const char fmt[] =
    "HTTP/1.1 200 OK\r\n"
    "Connection: keep-alive\r\n"
    "Cache-Control: no-cache\r\n"
    "Content-Type: ", fmt_mid[] = "\r\n"
    "Content-Length: ", fmt_trail[] = "\r\n"
    "\r\n";
  size_t size = this->used_size(),
         prefix_len,
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
