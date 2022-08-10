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
    let s = "template { \"" + key + "\" : @{" + key + "} }";
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

function update_table( key, msg ) {
  let key_container = document.getElementById( key );

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

  if ( msg.length == 0 || typeof msg == "string" ) {
    let td  = document.createElement( "td" ),
        txt = document.createTextNode( msg.length == 0 ? "no data" : msg );
    td.className = "td-main";
    td.appendChild( txt );
    tr.appendChild( td );
  }
  else {
    let body = document.createElement( "tbody" );
    if ( typeof msg[ 0 ] == "object" ) {
      for ( let prop in msg[ 0 ] ) {
        let th = document.createElement( "th" );
        th.className = "thead-text";
        th.appendChild( document.createTextNode( prop ) );
        tr.appendChild( th );
      }

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

