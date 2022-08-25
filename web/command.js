"use strict";

var ws = null, timer = null, containers = [], c_free = 0;
var time_fmt = new Intl.DateTimeFormat('en-GB',
    { hour: "numeric", minute: "numeric", second: "numeric", hour12: false } );

function on_interval( me ) {
  let now = Date.now();
  for ( let i = 0; i < containers.length; i++ ) {
    if ( containers[ i ] != null && containers[ i ].auto_update ) {
      if ( now > containers[ i ].update_last + 1999 ) {
        on_table_refresh( containers[ i ].id );
      }
    }
  }
}

function on_table_refresh( key ) {
  let key_container = document.getElementById( key );
  if ( key_container == null || key_container.update_in_progress )
    return;
  let val = key;
  if ( key_container.hasOwnProperty( "path_select" ) ) {
    let select  = key_container.path_select,
        new_sel = select.value;
    val += " " + new_sel.charAt( new_sel.length - 1 );
  }
  if ( key_container.hasOwnProperty( "user_select" ) ) {
    let select  = key_container.user_select,
        new_sel = select.value;
    if ( key.startsWith( "show subs" ) ) {
      val += " " + new_sel;
    }
    else if ( new_sel != my_user ) {
      val = "remote " + new_sel + " " + val;
    }
  }
  if ( key_container.hasOwnProperty( "sub_select" ) ) {
    let select  = key_container.sub_select,
        new_sel = select.value.split( " " );
    if ( new_sel.length == 0 )
      new_sel = "*";
    else
      new_sel = new_sel[ new_sel.length - 1 ];
    val += " " + new_sel;
  }
  let s = "template { \"" + val + "\" : @{" + val + "} }";
  key_container.update_in_progress = true;
  key_container.update_count++;
  ws.send( s );
}

function on_table_user_select( key ) {
  let key_container = document.getElementById( key );
  if ( key_container == null || key_container.update_in_progress )
    return;
  if ( key_container.update_count > 0 ||
       ! key_container.hasOwnProperty( "sub_select" ) )
    on_table_refresh( key );
}

function on_table_close( key ) {
  let key_container = document.getElementById( key );
  if ( key_container != null ) {
    key_container.remove();
    containers[ key_container.index ] = null;
    if ( c_free > key_container.index )
      c_free = key_container.index;
  }
}

function on_table_auto_update( key ) {
  let key_container = document.getElementById( key );
  if ( key_container != null ) {
    key_container.auto_update = ! key_container.auto_update;
    if ( key_container.auto_update ) {
      key_container.auto_div.className = "table-main-barend-clicked";
      key_container.auto_a.title = "switch auto update off";
    }
    else {
      key_container.auto_div.className = "table-main-barend";
      key_container.auto_a.title = "switch auto update on";
    }
  }
}

const spacing = "  ";

function is_string( obj )  { return typeof obj == "string"; }
function is_boolean( obj ) { return typeof obj == "boolean"; }
function is_number( obj )  { return typeof obj == "number"; }
function is_null( obj )    { return obj == null || typeof obj == "undefined"; }
function is_array( obj )   { return obj instanceof Array; }
function is_object( obj )  { return typeof obj == "object"; }

function convert_json( obj, ret ) {
  if      ( is_array( obj ) )   ret = convert_array( obj, ret );
  else if ( is_string( obj ) )  ret.push( normalize_string( obj ) );
  else if ( is_boolean( obj ) ) ret.push( obj ? 'true' : 'false' );
  else if ( is_number( obj ) )  ret.push( obj.toString() );
  else if ( is_null( obj ) )    ret.push( 'null' );
  else                          ret = convert_hash( obj, ret );
  return ret;
}

function convert_array( obj, ret ) {
  if ( obj.length === 0 ) {
    ret.push('[]');
    return;
  }
  for ( let i = 0; i < obj.length; i++ ) {
    let recurse = convert_json( obj[ i ], [] );

    for ( let j = 0; j < recurse.length; j++ )
      ret.push( ( j == 0 ? "- " : spacing ) + recurse[ j ] );
  }
  return ret;
}

function normalize_string( str ) {
  if ( str.match( /^[\w]+$/ ) ) return str;
  return '"' + str + '"';
}

function convert_hash( obj, ret ) {
  for ( let k in obj ) {
    if ( obj.hasOwnProperty( k ) ) {
      var ele = obj[ k ];
      let recurse = convert_json( ele, [] );

      if ( is_string( ele ) || is_null( ele ) ||
           is_number( ele ) || is_boolean( ele ) ) {
        ret.push( normalize_string( k ) + ": " +  recurse[ 0 ] );
      }
      else {
        ret.push( normalize_string( k ) + ": " );
        for ( let i = 0; i < recurse.length; i++ )
          ret.push( spacing + recurse[ i ] );
      }
    }
  }
  return ret;
}

function document_create( type, clazz ) {
  let el = document.createElement( type );
  el.className = clazz;
  return el;
}

function make_table_body( tr, body, msg, invert_order, peer ) {
  if ( ! tr.hasOwnProperty( "hdr_init" ) ) {
    tr.hdr_init = true;
    if ( peer != null ) {
      let th = document_create( "th", "thead-text" );
      th.appendChild( document.createTextNode( "peer" ) );
      tr.appendChild( th );
    }
    if ( is_object( msg[ 0 ] ) ) {
      for ( let prop in msg[ 0 ] ) {
        let th = document_create( "th", "thead-text" );
        th.appendChild( document.createTextNode( prop ) );
        tr.appendChild( th );
      }
    }
    else {
      let th = document_create( "th", "thead-text" );
      th.appendChild( document.createTextNode( "text" ) );
      tr.appendChild( th );
    }
  }
  /* an array of objects */
  if ( is_object( msg[ 0 ] ) ) {
    /* normal order */
    if ( ! invert_order ) {
      for ( let i = 0; i < msg.length; i++ ) {
        let values = Object.values( msg[ i ] ),
            tr     = document_create( "tr", "tr-main" );
        if ( peer != null ) {
          let td = document_create( "td", "td-main" );
          if ( i == 0 ) {
            td.className = "td-main-peer";
            td.appendChild( document.createTextNode( peer ) );
          }
          tr.appendChild( td );
        }
        for ( let j = 0; j < values.length; j++ ) {
          let td = document_create( "td", "td-main" );
          td.appendChild( document.createTextNode( values[ j ] ) );
          tr.appendChild( td );
        }
        body.appendChild( tr );
      }
    }
    /* invert log and events, show last first */
    else {
      for ( let i = msg.length; i > 0; i-- ) {
        let values = Object.values( msg[ i-1 ] ),
            tr     = document_create( "tr", "tr-main" );
        if ( peer != null ) {
          let td = document_create( "td", "td-main" );
          if ( i == msg.length ) {
            td.className = "td-main-peer";
            td.appendChild( document.createTextNode( peer ) );
          }
          tr.appendChild( td );
        }
        for ( let j = 0; j < values.length; j++ ) {
          let val = values[ j ];
          let td = document_create( "td", "td-main" );
          if ( j == 1 && val.charAt( 0 ) == "!" ) { /* highlight errors */
            val = val.substr( 2, val.length - 2 );
            td.className = "td-main-err";
          }
          td.appendChild( document.createTextNode( val ) );
          tr.appendChild( td );
        }
        body.appendChild( tr );
      }
    }
  }
  /* an array of strings */
  else {
    for ( let j = 0; j < msg.length; j++ ) {
      let tr = document_create( "tr", "tr-main" ), td;
      if ( peer != null ) {
        td = document_create( "td", "td-main" );
        if ( j == 0 ) {
          td.className = "td-main-peer";
          td.appendChild( document.createTextNode( peer ) );
        }
        tr.appendChild( td );
      }
      td = document_create( "td", "td-main" );
      td.appendChild( document.createTextNode( msg[ j ] ) );
      tr.appendChild( td );
      body.appendChild( tr );
    }
  }
}

function make_table_peer_no_data( body, msg, peer, max_arity )
{
  let tr  = document_create( "tr", "tr-main" ),
      td  = document_create( "td", "td-main-peer" ),
      txt = "no data";
  td.appendChild( document.createTextNode( peer ) );
  tr.appendChild( td );
  if ( is_array( msg ) ) {
    if ( msg.length > 0 )
      if ( is_string( msg[ 0 ] ) )
        txt = msg[ 0 ];
  }
  td = document_create( "td", "td-main" );
  td.appendChild( document.createTextNode( txt ) );
  if ( max_arity > 1 )
    td.colSpan = max_arity;
  tr.appendChild( td );
  body.appendChild( tr );
}

function update_table( key, msg ) {
  let end = null, show_subs_user = null, sub_match = null, rem = my_user;

  let is_show         = false,
      is_show_subs    = false,
      is_show_seqno   = false,
      is_show_log     = false,
      is_show_events  = false,
      is_show_running = false,
      is_path_cmd     = false;

  /* remote B show loss */
  if ( key.startsWith( "remote " ) ) {
    let args = key.split( ' ' );
    if ( args.length > 2 ) {
      rem = args[ 1 ];
      let prefix = 6 + 1 + rem.length + 1;
      key = key.substr( prefix, key.length - prefix );
    }
  }
  if ( key.startsWith( "show subs" ) )         is_show_subs    = true;
  else if ( key.startsWith( "show seqno" ) )   is_show_seqno   = true;
  else if ( key.startsWith( "show log" ) )     is_show_log     = true;
  else if ( key.startsWith( "show events" ) )  is_show_events  = true;
  else if ( key.startsWith( "show running" ) ) is_show_running = true;
  if ( key.startsWith( "show " ) )             is_show         = true;

  /* show subs <user> <match> */
  /* show seqno <match> */
  if ( is_show_subs || is_show_seqno ) {
    let args = key.split( ' ' );
    show_subs_user = my_user;
    sub_match = "*";
    if ( args.length > 2 ) {
      let prefix = args[ 0 ].length + 1 + args[ 1 ].length;
      if ( args.length > 3 ) {
        show_subs_user = args[ 2 ];
        sub_match = args[ 3 ];
      }
      else if ( is_show_subs ) {
        show_subs_user = args[ 2 ];
      }
      else {
        show_subs_user = rem;
        sub_match = args[ 2 ];
      }
      key = key.substr( 0, prefix );
    }
  }
  /* show blooms 0, show path 1 */
  else if ( key.length > 2 ) {
    end = key.charAt( key.length - 1 );
    if ( ! isNaN( end ) && key.charAt( key.length - 2 ) == " " ) {
      key = key.substr( 0, key.length - 2 );
      is_path_cmd = true;
    }
    else
      end = null;
  }
  let key_container = document.getElementById( key ),
      is_new = false;

  if ( key_container == null ) {
    let work = document.getElementById( "work" );
    key_container = document_create( "div", "work-table" );
    key_container.id = key;
    work.appendChild( key_container );
    if ( c_free < containers.length ) {
      containers[ c_free ] = key_container;
      key_container.index = c_free;
      while ( ++c_free < containers.length )
        if ( containers[ c_free ] == null )
          break;
    }
    else {
      containers.push( key_container );
      key_container.index = c_free++;
    }
    key_container.auto_update  = false;
    key_container.update_count = 0;
    is_new = true;
  }
  else {
    while ( key_container.firstChild )
      key_container.removeChild( key_container.firstChild );
  }
  key_container.update_in_progress = false;

  let table = document_create( "table", "table-main" ),
      thead = document_create( "thead", "thead-main" ),
      tr    = document_create( "tr", "tr-main" );

  thead.appendChild( tr );
  table.appendChild( thead );
  /* make the body of the table */
  let txt = null,
      is_multi_user = false,
      max_arity = 0;
  /* check message is empty array [] */
  if ( is_array( msg ) ) {
    if ( msg.length == 0 )
      txt = document.createTextNode( "no data" );
  }
  /* a string result */
  else if ( is_string( msg ) ) {
    txt = document.createTextNode( msg );
  }
  /* a complex object, "show running" or multi reply with "remote * cmd" */
  else {
    if ( is_show ) {
      if ( ! is_show_subs && rem == "*" ) {
        is_multi_user = true;
        for ( let prop in msg ) {
          if ( ! active_uid_map.hasOwnProperty( prop ) ) {
            is_multi_user = false;
            break;
          }
          let vals = msg[ prop ];
          if ( is_array( vals ) && vals.length > 0 ) {
            let len = Object.keys( vals[ 0 ] ).length;
            if ( len > max_arity )
              max_arity = len;
          }
        }
      }
    }
    if ( ! is_multi_user ) {
      txt = document.createElement( "pre" );
      txt.appendChild(
        document.createTextNode( convert_json( msg, [] ).join( "\n" ) ) );
    }
  }
  /* if not an array */
  if ( txt != null ) {
    let td  = document_create( "td", "td-main" );
    td.appendChild( txt );
    tr.appendChild( td );
  }
  else {
    let body = document_create( "tbody", "tbody-main" ),
        invert_order = ( is_show_log || is_show_events );
    if ( ! is_multi_user )
      make_table_body( tr, body, msg, invert_order, null );
    else {
      let no_data = [];
      for ( let prop in msg ) {
        let vals = msg[ prop ];
        if ( is_array( vals ) && vals.length > 0 &&
             Object.keys( vals[ 0 ] ).length == max_arity )
          make_table_body( tr, body, msg[ prop ], invert_order, prop );
        else
          no_data.push( prop );
      }
      if ( no_data.length != 0 ) {
        for ( let i = 0; i < no_data.length; i++ ) {
          let x = no_data[ i ];
          make_table_peer_no_data( body, msg[ x ], x, max_arity );
        }
      }
    }
    table.appendChild( body );
  }
  let cap = table.createCaption(),
      bar = document_create( "div", "table-main-caption" ),
      cd, a;
  /* make top bar */
  cd = document_create( "div", "table-main-time" );
  key_container.update_last = Date.now();
  cd.appendChild(
    document.createTextNode( time_fmt.format( key_container.update_last ) ) );
  bar.appendChild( cd );
  /* table title, refresh */
  cd = document_create( "div", "table-main-title" );
  a  = document_create( "a", "table-link" );
  a.onclick   = function() { on_table_refresh( key ); }
  a.title     = "refresh";
  a.appendChild( document.createTextNode( key ) );
  cd.appendChild( a );
  bar.appendChild( cd );
  /* make user select option */
  if ( is_show ) {
    if ( active_uid_cnt > 1 ) {
      let sel, opt;
      cd = document_create( "div", "table-main-select" );
      sel = document.createElement( "select" );
      if ( ! is_show_running ) {
        opt = document.createElement( "option" );
        opt.text  = "*";
        opt.value = "*";
        if ( ( ! is_show_subs && rem == "*" ) ||
             ( is_show_subs && show_subs_user == "*" ) )
          opt.selected = true;
        sel.appendChild( opt );
      }
      for ( let prop in active_uid_map ) {
        opt = document.createElement( "option" );
        opt.text  = prop;
        opt.value = prop;
        if ( ( ! is_show_subs && rem == prop ) ||
             ( is_show_subs && show_subs_user == prop ) )
          opt.selected = true;
        sel.appendChild( opt );
      }
      sel.onchange = function() { on_table_user_select( key ); }
      key_container.user_select = sel;
      cd.appendChild( sel );
      bar.appendChild( cd );
    }
  }
  /* show path N, make path select option */
  if ( is_path_cmd ) {
    cd = document_create( "div", "table-main-select" );
    let sel = document.createElement( "select" );

    for ( let i = 0; i < 4; i++ ) {
      let opt  = document.createElement( "option" ),
          ival = i.toString(),
          txt  = "path " + ival;
      opt.text  = txt;
      opt.value = txt;
      if ( end == ival )
        opt.selected = true;
      sel.appendChild( opt );
    }
    key_container.path_select = sel;
    sel.onchange = function() { on_table_refresh( key ); }
    cd.appendChild( sel );
    bar.appendChild( cd );
  }
  /* show subs <user> <match>, make input for match */
  if ( is_show_subs || is_show_seqno ) {
    cd = document_create( "div", "table-main-select" );
    let inp = document.createElement( "input" );
    inp.type = "search";
    inp.value = "match " + sub_match;
    key_container.sub_select = inp;
    cd.appendChild( inp );
    bar.appendChild( cd );
  }
  /* create "U" auto update clicker */
  cd = document.createElement( "div" );
  a  = document_create( "a", "table-link" );
  key_container.auto_div = cd;
  key_container.auto_a   = a;
  a.onclick   = function() { on_table_auto_update( key ); }
  a.appendChild( document.createTextNode( "U" ) );
  if ( key_container.auto_update ) {
    cd.className = "table-main-barend-clicked";
    a.title = "switch auto update off";
  }
  else {
    cd.className = "table-main-barend";
    a.title = "switch auto update on";
  }
  cd.appendChild( a );
  bar.appendChild( cd );
  /* create "X" close clicker */
  cd = document_create( "div", "table-main-barend" );
  a  = document_create( "a", "table-link" );
  a.onclick   = function() { on_table_close( key ); }
  a.title     = "close";
  a.appendChild( document.createTextNode( "X" ) );
  cd.appendChild( a );
  bar.appendChild( cd );
  cap.appendChild( bar );

  key_container.appendChild( table );

  if ( is_new ) {
    let scr = document.getElementById( "main-scroller" ),
        key_top    = key_container.offsetTop,
        key_height = key_container.clientHeight,
        key_bottom = key_top + key_height,
        scr_top    = scr.scrollTop,
        scr_height = scr.clientHeight,
        scr_bottom = scr_top + scr_height;

    if ( key_top > scr_bottom ) {
      if ( key_height > scr_height )
        key_bottom = key_top + scr_height;
      scr.scrollTop += key_bottom - scr_bottom;
    }
  }
}

function on_msg( key, msg ) {
  if ( key.startsWith( "_N.ADJ." ) ) {
    ws.send(
"template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
  }
  else if ( msg.hasOwnProperty( "nodes" ) ) {
    update_user_uid_map( msg );
  }
  else {
    update_table( key, msg );
  }
}

function on_close() {
  on_disconnect();
  if ( timer != null && typeof timer == "number" ) {
    clearInterval( timer );
    timer = null;
  }
}

function on_startup( webs ) {
  ws = webs;
  ws.onmessage = function( event ) {
    /*let t   = Date.now();*/
    let msg = JSON.parse( event.data );
    /*let t2  = Date.now();*/
    let key = Object.keys( msg )[ 0 ];
    /*if ( t2 > t )
      console.log( "parse time " + ( t2 - t ) );*/
    on_msg( key, msg[ key ] );
    /*let t3  = Date.now();
    if ( t3 > t2 )
      console.log( "table time " + ( t3 - t2 ) );*/
  };
  ws.onopen = function( event ) {
    ws.send(
"template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
    ws.send( "sub _N.ADJ.@(user)" ); /* notify when adjacency chenges */
    timer = setInterval( on_interval, 1000, this );
  };
  ws.onclose = function( event ) {
    on_close();
  };
}

