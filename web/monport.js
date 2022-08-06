"use strict";

var nodes_active     = {},
    next_gid         = 0,
    user_gid_map     = {},
    user_tport_count = {};

function update_msg_rate( msg ) {
  let user      = msg[ "user" ],
      peer      = null,
      tportid   = msg[ "tportid" ] | 0,
      ms        = msg[ "ms" ] | 0,
      mr        = msg[ "mr" ] | 0,
      bs        = msg[ "bs" ] | 0,
      br        = msg[ "br" ] | 0,
      time      = msg[ "stamp" ],
      total_m   = ms + mr,
      total_b   = bs + br,
      last_ms   = 0,
      last_mr   = 0,
      last_bs   = 0,
      last_br   = 0,
      last_m    = 0,
      last_b    = 0,
      rate      = null,
      last_time = null,
      user_tpid = user + "." + tportid;
  let i, j = 0;

  if ( user_gid_map.hasOwnProperty( user_tpid ) ) {
    rate = user_rate[ user_gid_map[ user_tpid ] ];
    if ( ! rate.active ) {
      if ( msg.hasOwnProperty( "peer" ) )
        peer = msg[ "peer" ];
      if ( peer != null && user_uid_map.hasOwnProperty( peer ) )
        rate.uid = user_uid_map[ peer ];
      rate.active = true;
    }
  }

  if ( rate == null ) {
    let active = false,
        uid    = next_gid;
    if ( nodes_active.hasOwnProperty( user ) )
      active = nodes_active[ user ];
    if ( peer == null && msg.hasOwnProperty( "peer" ) )
      peer = msg[ "peer" ];
    if ( peer != null && user_uid_map.hasOwnProperty( peer ) )
      uid = user_uid_map[ peer ];
    rate = new_rate( user, uid, active );
    user_gid_map[ user_tpid ] = next_gid;
    user_rate[ next_gid ] = rate;
    next_gid++;
    if ( ! user_tport_count.hasOwnProperty( user ) ||
         user_tport_count[ user ] < tportid )
      user_tport_count[ user ] = tportid;

    for ( i = 0; i < graph_secs - 1; i++ )
      rate_zero( rate );
    rate_push( rate, time, total_m, total_b, mr, ms, br, bs );
  }
  else {
    i = rate.time.length - 1;
    if ( i >= 0 ) {
      j = i;
      last_time = rate.time[ j ];
      last_ms   = rate.ms[ j ];
      last_mr   = rate.mr[ j ];
      last_bs   = rate.bs[ j ];
      last_br   = rate.br[ j ];
      last_m    = rate.msgs[ j ];
      last_b    = rate.bytes[ j ];
    }
    while ( i < graph_secs - 1 ) {
      rate_zero( rate );
      i++;
    }
    i = rate.time.length - 1;
    if ( rate.time[ i ] == null )
      rate_set( rate, i, time, total_m, total_b, mr, ms, br, bs );
    else if ( rate.time[ i ] != time )
      rate_push( rate, time, total_m, total_b, mr, ms, br, bs );
    else
      total_m = rate_sum( rate, i, total_m, total_b, mr, ms, br, bs );
  }
  if ( total_m > max_rate )
    set_max_rate( total_m );
  if ( rate.g == null ) {
    if ( rate.checked )
      rate.add = true;
      /*add_graph_line( rate );*/
  }
  if ( last_time != null && last_time != time ) {
    if ( ! rate.checked ) {
      while ( rate.time.length > graph_secs )
        rate_shift( rate );
    }
  }
}

var rows  = [],
    clock = 0;

function user_change_state( user_name, state ) {
  if ( ! user_tport_count.hasOwnProperty( user_name ) )
    return;
  let tport_count = user_tport_count[ user_name ];
  nodes_active[ user_name ] = state;
  for ( let i = 0; i <= tport_count; i++ ) {
    let user_tpid = user_name + "." + i;
    if ( ! state ) {
      let tr = document.getElementById( user_tpid );
      if ( tr != null && tr.active ) {
        tr.remove();
        tr.active = false;
      }
    }
    if ( user_gid_map.hasOwnProperty( user_tpid ) ) {
      let gid = user_gid_map[ user_tpid ],
          rate = user_rate[ gid ];
      rate.active  = state;
      rate.checked = state;
      max_shifted  = true;
    }
  }
}

function on_interval( me ) {
  for ( let prop in user_rate ) {
    let rate = user_rate[ prop ];
    if ( rate.add )
      add_graph_line( rate );
  }
  for ( var key in rows ) {
    let tr = rows[ key ];
    if ( clock > tr.clock + 3 ) {
      let gid = user_gid_map[ tr.id ],
          rate = user_rate[ gid ];
      rate.active  = false;
      rate.checked = false;
      rate.add     = false;
      max_shifted  = true;

      if ( tr.active ) {
        tr.remove();
        tr.active = false;
      }
      delete rows[ key ];
    }
  }
  clock++;
  if ( ( max_shifted && clock % 5 == 0 ) || ( clock % 30 == 0 ) ) {
    let new_max_total = 20;
    for ( let prop in user_rate ) {
      let rate = user_rate[ prop ];
      if ( rate.g != null && rate.checked ) {
        let msgs = rate.msgs;
        for ( let i = 0; i < msgs.length; i++ ) {
          if ( msgs[ i ] > new_max_total )
            new_max_total = msgs[ i ];
        }
      }
    }
    max_shifted = false;
    set_max_rate( new_max_total );
  }
}

var port = null, port_body = null;
const port_fields = ["stamp", "tport", "peer", "bs", "br", "ms", "mr" ];

function init_port_table( name, msg ) {
  let table = document.getElementById( name ),
      thead = document.createElement( "thead" );
  table.appendChild( thead );
  for ( let i = 0; i < port_fields.length; i++ ) {
    let th = document.createElement( "th" );
    thead.appendChild( th );
    let f = ( i == 0 ? "time" : port_fields[ i ] );
    th.appendChild( document.createTextNode( f ) );
  }
  let body = document.createElement( "tbody" );
  table.appendChild( body );
  return [ table, body ];
}

function port_radio( event ) {
  event.srcElement.active = ! event.srcElement.active;
  event.srcElement.checked = event.srcElement.active;
  let gid = event.srcElement.id | 0;
  if ( user_rate.hasOwnProperty( gid ) ) {
    user_rate[ gid ].checked = event.srcElement.active;
    max_shifted = true;
  }
}

function update_port_table( msg ) {
  let user   = msg[ "user" ],
      peer   = null;
  let active = false;

  if ( nodes_active.hasOwnProperty( user ) )
    active = nodes_active[ user ];
  if ( ! active )
    return;
  if ( msg.hasOwnProperty( "peer" ) )
    peer = msg[ "peer" ];

  if ( port == null )
    [ port, port_body ] = init_port_table( "port-container", msg );

  let table = port,
      body  = port_body;

  let tpid      = msg[ "tportid" ],
      user_tpid = user + "." + tpid,
      tr        = document.getElementById( user_tpid ),
      gid;

  if ( ! user_gid_map.hasOwnProperty( user_tpid ) )
    return;
  gid = user_gid_map[ user_tpid ];

  let rate = null;
  if ( user_rate.hasOwnProperty( gid ) ) {
    rate = user_rate[ gid ];
    if ( ! rate.active ) {
      if ( user_uid_map.hasOwnProperty( peer ) )
        rate.uid = user_uid_map[ peer ];
      rate.active = true;
      rate.add    = true;
    }
  }

  if ( tr == null ) {
    tr = document.createElement( "tr" );
    tr.id     = user_tpid;
    tr.clock  = clock;
    tr.active = true;
    rows.push( tr );

    body.appendChild( tr );
    for ( let i = 0; i < port_fields.length; i++ ) {
      let prop = port_fields[ i ],
          td   = document.createElement( "td" ),
          txt, span;
      tr.appendChild( td );
      if ( prop == "tport" ) {
        let radio = document.createElement( "input" );
        radio.type    = "radio";
        radio.id      = gid;
        radio.value   = user_tpid;
        radio.onclick = port_radio;
        radio.active  = true;
        radio.checked = true;

        if ( rate != null )
          rate.checked = true;

        let label = document.createElement( "label" );
        label.htmlFor = gid;
        if ( peer != null && user_uid_map.hasOwnProperty( peer ) )
          label.style.color = color( user_uid_map[ peer ] );
        else
          label.style.color = color( gid );

        let s = document.createTextNode(
          user + "." + msg[ "tport" ] + "." + tpid );
        label.appendChild( s );

        td.appendChild( radio );
        td.appendChild( label );
      }
      else if ( prop == "peer" ) {
        if ( peer != null ) {
          if ( user_uid_map.hasOwnProperty( peer ) ) {
            let uid = user_uid_map[ peer ];
            txt  = document.createTextNode( peer + "." + uid );
            span = document.createElement( "span" );
            span.appendChild( txt );
            span.style.color = color( uid );
            td.appendChild( span );
          }
          else {
            td.appendChild( document.createTextNode( peer ) );
          }
        }
      }
      else {
        if ( msg.hasOwnProperty( prop ) ) {
          txt = msg[ prop ];
          td.appendChild( document.createTextNode( txt ) );
        }
      }
    }
  }
  else {
    tr.clock = clock;
    for ( let i = 0; i < port_fields.length; i++ ) {
      let prop = port_fields[ i ];
      if ( prop != "tport" && prop != "peer" ) {
        if ( msg.hasOwnProperty( prop ) ) {
          let td = tr.childNodes[ i ];
          update_td( td, msg[ prop ] );
        }
      }
    }
  }
}

var ws = null, timer = null, user = [], g = null;

function node_radio( event ) {
  let state = ! event.srcElement.active;
  event.srcElement.active = state;
  event.srcElement.checked = state;
  let user_name = event.srcElement.id;

  user_change_state( user_name, state );
}

function make_node_radios( msg ) {
  let container = document.getElementById( "radio-container" );
  let nodes = msg.nodes;
  for ( let i = 0; i < nodes.length; i++ ) {
    let radio, label, txt, user_name;
    let user_exists = user.hasOwnProperty( i );
    if ( user_exists )
      user_name = user[ i ];
    else
      user_name = nodes[ i ].user;
    if ( nodes[ i ].tports == 0 ) {
      if ( user_exists ) {
        radio = document.getElementById( user_name );
        label = document.getElementById( user_name + ".label" );
        if ( radio != null )
          radio.remove();
        if ( label != null )
          label.remove();
        if ( user_tport_count.hasOwnProperty( user_name ) ) {
          user_change_state( user_name, false );
          delete user_tport_count[ user_name ];
        }
        if ( nodes_active.hasOwnProperty( user_name ) )
          delete nodes_active[ user_name ];
        delete user[ i ];
      }
      continue;
    }
    if ( ! user_exists ) {
      user[ i ] = user_name;

      radio = document.createElement( "input" ),
      txt   = user_name + "." + nodes[ i ].uid;

      radio.type    = "radio";
      radio.id      = user_name;
      radio.value   = txt;
      radio.onclick = node_radio;

      if ( nodes_active.hasOwnProperty( user_name ) &&
           nodes_active[ user_name ] ) {
        radio.active  = true;
        radio.checked = true;
      }
      else {
        radio.active  = false;
        radio.checked = false;
      }
      label = document.createElement( "label" );
      label.htmlFor = user_name;
      label.id = user_name + ".label";

      let s = document.createTextNode( txt );
      label.appendChild( s );

      container.appendChild( radio );
      container.appendChild( label );
    }
  }
}
var adj_update_pending = false;
var port_msg_save = [];

function on_msg( key, msg ) {
  if ( key.startsWith( "_N.PORT." ) ) {
    if ( g == null )
      g = init_geom();
    if ( graph_svg == null )
      init_graph( g.graph_width, g.graph_height );
    if ( adj_update_pending ) {
      port_msg_save.push( msg );
    } else {
      update_port_table( msg );
      update_msg_rate( msg );
    }
  }
  else if ( key.startsWith( "_N.ADJ." ) ) {
    adj_update_pending = true;
    ws.send(
"template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
  }
  else if ( msg.hasOwnProperty( "nodes" ) ) {
    if ( g == null )
      g = init_geom();
    update_user_uid_map( msg );
    update_nodes( msg, g.nodes_width, g.nodes_height );
    make_node_radios( msg );
    adj_update_pending = false;
    while ( port_msg_save.length != 0 ) {
      let msg = port_msg_save.shift();
      update_port_table( msg );
      update_msg_rate( msg );
    }
  }
}

function on_close() {
  for ( let prop in user_rate ) {
    let rate = user_rate[ prop ];
    rate.active = false;
  }
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
    nodes_active[ "@(user)" ] = true; /* initially graphed */
    ws.send(
"template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
    ws.send( "psub _N.PORT.>" ); /* port table */
    ws.send( "sub _N.ADJ.@(user)" ); /* notify when adjacency chenges */
    timer = setInterval( on_interval, 1000, this );
  };
  ws.onclose = function( event ) {
    on_close();
  };
}

