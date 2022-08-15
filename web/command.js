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
  if ( key_container != null && ! key_container.update_in_progress ) {
    let val = key;
    if ( key_container.hasOwnProperty( "path_select" ) ) {
      let select  = key_container.path_select,
          new_sel = select.value;
      val += " " + new_sel.charAt( new_sel.length - 1 );
    }
    if ( key_container.hasOwnProperty( "user_select" ) ) {
      let select  = key_container.user_select,
          new_sel = select.value;
      val += " " + new_sel;
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
    ws.send( s );
  }
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
  return '"' + escape( str ).replace( /%u/g, "\\u" )
                            .replace( /%U/g, "\\U" )
                            .replace( /%/g, "\\x" ) + '"';
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

function update_table( key, msg ) {
  let end = null, user = null, sub = null;

  let is_show_subs   = false,
      is_show_seqno  = false,
      is_show_log    = false,
      is_show_events = false,
      is_path_cmd    = false;

  if ( key.startsWith( "show subs" ) )        is_show_subs   = true;
  else if ( key.startsWith( "show seqno" ) )  is_show_seqno  = true;
  else if ( key.startsWith( "show log" ) )    is_show_log    = true;
  else if ( key.startsWith( "show events" ) ) is_show_events = true;

  if ( is_show_subs || is_show_seqno ) {
    user = "*";
    sub  = "*";
    for ( let i = 9; i < key.length; i++ ) {
      if ( key.charAt( i ) == " " ) {
        if ( i + 1 == key.length || key.charAt( i + 1 ) != " " ) {
          if ( i + 1 < key.length )
            user = key.substr( i + 1, key.length - ( i + 1 ) );
          break;
        }
      }
    }
    if ( is_show_subs ) {
      for ( let j = 1; j < user.length; j++ ) {
        if ( user.charAt( j ) == " " ) {
          if ( j + 1 == user.length || user.charAt( j + 1 ) != " " ) {
            if ( j + 1 < user.length )
              sub = user.substr( j + 1, user.length - ( j + 1 ) );
            user = user.substr( 0, j );
            break;
          }
        }
      }
      key = "show subs";
    }
    else {
      sub  = user;
      user = null;
      key  = "show seqno";
    }
  }
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
    key_container = document.createElement( "div" );
    key_container.className = "work-table";
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
    key_container.auto_update = false;
    is_new = true;
  }
  else {
    while ( key_container.firstChild )
      key_container.removeChild( key_container.firstChild );
  }
  key_container.update_in_progress = false;

  let table = document.createElement( "table" ),
      thead = document.createElement( "thead" ),
      tr    = document.createElement( "tr" );

  thead.className = "thead-main";
  thead.appendChild( tr );
  table.className = "table-main";
  table.appendChild( thead );
  /* make the body of the table */
  let txt = null;
  /* check message is empty array [] */
  if ( is_array( msg ) ) {
    if ( msg.length == 0 )
      txt = document.createTextNode( "no data" );
  }
  /* a string result */
  else if ( is_string( msg ) ) {
    txt = document.createTextNode( msg );
  }
  /* a complex object, "show running" */
  else {
    txt = document.createElement( "pre" );
    txt.appendChild(
      document.createTextNode( convert_json( msg, [] ).join( "\n" ) ) );
  }
  /* if not an array */
  if ( txt != null ) {
    let td  = document.createElement( "td" );
    td.className = "td-main";
    td.appendChild( txt );
    tr.appendChild( td );
  }
  else {
    let body = document.createElement( "tbody" );
    /* an array of objects */
    if ( is_object( msg[ 0 ] ) ) {
      for ( let prop in msg[ 0 ] ) {
        let th = document.createElement( "th" );
        th.className = "thead-text";
        th.appendChild( document.createTextNode( prop ) );
        tr.appendChild( th );
      }

      if ( ! is_show_log && ! is_show_events ) {
        for ( let i = 0; i < msg.length; i++ ) {
          let values = Object.values( msg[ i ] ),
              tr     = document.createElement( "tr" );
          tr.className = "tr-main";
          for ( let j = 0; j < values.length; j++ ) {
            let td = document.createElement( "td" );
            td.className = "td-main";
            td.appendChild( document.createTextNode( values[ j ] ) );
            tr.appendChild( td );
          }
          body.appendChild( tr );
        }
      }
      else {
        for ( let i = msg.length; i > 0; i-- ) {
          let values = Object.values( msg[ i-1 ] ),
              tr     = document.createElement( "tr" );
          tr.className = "tr-main";
          for ( let j = 0; j < values.length; j++ ) {
            let val = values[ j ];
            let td = document.createElement( "td" );
            if ( j == 1 && is_show_log &&
                 val.charAt( 0 ) == "!" ) { /* highlight errors */
              val = val.substr( 2, val.length - 2 );
              td.className = "td-main-err";
            }
            else
              td.className = "td-main";
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
        let tr = document.createElement( "tr" ),
            td = document.createElement( "td" );
        tr.className = "tr-main";
        td.className = "td-main";
        td.appendChild( document.createTextNode( msg[ j ] ) );
        tr.appendChild( td );
        body.appendChild( tr );
      }
    }
    table.appendChild( body );
  }
  let cap = table.createCaption(),
      bar = document.createElement( "div" ),
      cd, a;

  bar.className = "table-main-caption";
  cd = document.createElement( "div" );
  cd.className = "table-main-time";
  key_container.update_last = Date.now();
  cd.appendChild(
    document.createTextNode( time_fmt.format( key_container.update_last ) ) );
  bar.appendChild( cd );

  cd = document.createElement( "div" );
  a  = document.createElement( "a" );
  a.onclick   = function() { on_table_refresh( key ); }
  a.title     = "refresh";
  a.className = "table-link";
  a.appendChild( document.createTextNode( key ) );
  cd.className = "table-main-title";
  cd.appendChild( a );
  bar.appendChild( cd );

  if ( is_path_cmd || is_show_subs || is_show_seqno ) {
    /* make drop down for path or user */
    if ( is_path_cmd ) { /* path select option */
      cd = document.createElement( "div" );
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
      cd.className = "table-main-select";
      cd.appendChild( sel );
      bar.appendChild( cd );
    }
    else if ( is_show_subs ) { /* user select option */
      cd = document.createElement( "div" );
      let sel = document.createElement( "select" ),
          opt = document.createElement( "option" );
      opt.text  = "*";
      opt.value = "*";
      if ( user == "*" )
        opt.selected = true;
      sel.appendChild( opt );
      for ( let prop in user_uid_map ) {
        opt = document.createElement( "option" );
        opt.text  = prop;
        opt.value = prop;
        if ( user == prop )
          opt.selected = true;
        sel.appendChild( opt );
      }
      key_container.user_select = sel;
      cd.className = "table-main-select";
      cd.appendChild( sel );
      bar.appendChild( cd );
    }
    if ( is_show_subs || is_show_seqno ) { /* text input for sub */
      cd = document.createElement( "div" );
      let inp = document.createElement( "input" );
      inp.type = "search";
      inp.value = "match " + sub;
      key_container.sub_select = inp;
      cd.className = "table-main-select";
      cd.appendChild( inp );
      bar.appendChild( cd );
    }
  }
  cd = document.createElement( "div" );
  a  = document.createElement( "a" );
  key_container.auto_div = cd;
  key_container.auto_a   = a;
  a.onclick   = function() { on_table_auto_update( key ); }
  a.className = "table-link";
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

  cd = document.createElement( "div" );
  a  = document.createElement( "a" );
  a.onclick   = function() { on_table_close( key ); }
  a.title     = "close";
  a.className = "table-link";
  a.appendChild( document.createTextNode( "X" ) );
  cd.className = "table-main-barend";
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
    let msg = JSON.parse( event.data );
    let key = Object.keys( msg )[ 0 ];
    on_msg( key, msg[ key ] );
  };
  ws.onopen = function( event ) {
    ws.send(
"template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
    timer = setInterval( on_interval, 1000, this );
  };
  ws.onclose = function( event ) {
    on_close();
  };
}

