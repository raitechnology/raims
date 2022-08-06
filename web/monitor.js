"use strict";

function update_msg_rate( msg ) {
  let user      = msg[ "user" ],
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
      last_time = null;
  let i, j = 0;

  if ( ! user_uid_map.hasOwnProperty( user ) )
    return;

  let uid = user_uid_map[ user ];
  if ( user_rate.hasOwnProperty( uid ) ) {
    rate = user_rate[ uid ];
    rate.active = true;
  }

  let user_uid = user + "." + uid;
  if ( rate == null ) {
    let tr = document.getElementById( user_uid );
    rate = new_rate( user, uid, true );
    tr.rate = rate;
      
    for ( i = 0; i < graph_secs - 1; i++ )
      rate_zero( rate );
    rate_push( rate, time, total_m, total_b, mr, ms, br, bs );
    user_rate[ uid ] = rate;
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
    let td_ms = document.getElementById( user_uid + ".ms" ),
        td_mr = document.getElementById( user_uid + ".mr" ),
        td_bs = document.getElementById( user_uid + ".bs" ),
        td_br = document.getElementById( user_uid + ".br" );
    update_td( td_ms, last_ms );
    update_td( td_mr, last_mr );
    update_td( td_bs, last_bs );
    update_td( td_br, last_br );
    if ( ! rate.checked ) {
      while ( rate.time.length > graph_secs )
        rate_shift( rate );
    }
  }
}

var rows = [],
    clock = 0;

function on_interval( me ) {
  for ( let prop in user_rate ) {
    let rate = user_rate[ prop ];
    if ( rate.add )
      add_graph_line( rate );
  }
  for ( var key in rows ) {
    let tr = rows[ key ];
    if ( clock > tr.clock + 3 ) {
      if ( tr.hasOwnProperty( "rate" ) ) {
        tr.rate.active  = false;
        tr.rate.checked = false;
        tr.rate.add     = false;
        max_shifted     = true;
      }
      tr.remove();
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

var peer = null, peer_body = null;
const peer_fields = ["stamp", "user", "sub_cnt", "latency",
                     "bs", "br", "ms", "mr" ];

function init_peer_table( name, msg ) {
  let table = document.getElementById( name ),
      thead = document.createElement( "thead" );
  table.appendChild( thead );
  for ( let i = 0; i < peer_fields.length; i++ ) {
    let th = document.createElement( "th" );
    thead.appendChild( th );
    let f = ( i == 0 ? "time" : peer_fields[ i ] );
    th.appendChild( document.createTextNode( f ) );
  }
  let body = document.createElement( "tbody" );
  table.appendChild( body );
  return [ table, body ];
}

function peer_radio( event ) {
  event.srcElement.active = ! event.srcElement.active;
  event.srcElement.checked = event.srcElement.active;
  let uid = event.srcElement.id | 0;
  if ( user_rate.hasOwnProperty( uid ) ) {
    user_rate[ uid ].checked = event.srcElement.active;
    max_shifted = true;
  }
}

function update_peer_table( msg ) {
  if ( peer == null )
    [ peer, peer_body ] = init_peer_table( "peer-container", msg );

  let table = peer,
      body  = peer_body;

  let uid      = msg[ "uid" ],
      user_uid = msg[ "peer" ] + "." + uid,
      tr       = document.getElementById( user_uid );

  if ( tr == null ) {
    tr = document.createElement( "tr" );
    tr.id    = user_uid;
    tr.clock = clock;
    rows.push( tr );

    body.appendChild( tr );
    for ( let i = 0; i < peer_fields.length; i++ ) {
      let prop = peer_fields[ i ],
          td   = document.createElement( "td" ),
          txt  = 0;
      tr.appendChild( td );
      if ( prop == "user" ) {
        let radio = document.createElement( "input" );
        radio.type    = "radio";
        radio.id      = uid;
        radio.value   = user_uid;
        radio.onclick = peer_radio;
        radio.active  = true;
        radio.checked = true;
 
        let label = document.createElement( "label" );
        label.htmlFor = uid;
        label.style.color = color( uid );
 
        let s = document.createTextNode( user_uid );
        label.appendChild( s );
 
        td.appendChild( radio );
        td.appendChild( label );
      }
      else {
        if ( msg.hasOwnProperty( prop ) )
          txt = msg[ prop ];
        else
          td.id = user_uid + "." + prop;
        td.appendChild( document.createTextNode( txt ) );
      }
    }
  }
  else {
    tr.clock = clock;
    for ( let i = 0; i < peer_fields.length; i++ ) {
      let prop = peer_fields[ i ];
      if ( prop != "user" ) {
        if ( ! msg.hasOwnProperty( prop ) )
          break;
        let td = tr.childNodes[ i ];
        update_td( td, msg[ prop ] );
      }
    }
  }
}

var ws = null, timer = null, g = null;

function on_msg( key, msg ) {
  if ( key.startsWith( "_N.ALL." ) ) {
    if ( g == null )
      g = init_geom();
    if ( graph_svg == null )
      init_graph( g.graph_width, g.graph_height );
    update_msg_rate( msg );
  }
  else if ( key.startsWith( "_N.PEER." ) ) { 
    update_peer_table( msg );
  }
  else if ( key.startsWith( "_N.ADJ." ) ) { 
    // update current node and link sets
    ws.send(
"template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
  }
  else if ( msg.hasOwnProperty( "nodes" ) ) {
    // result of template above
    if ( g == null )
      g = init_geom();
    update_user_uid_map( msg );
    update_nodes( msg, g.nodes_width, g.nodes_height );
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
    /* graph node adjacency for node graph */
    ws.send(
"template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
    ws.send( "psub _N.ALL.>" ); /* line graph stats for all ports together */
    ws.send( "psub _N.PEER.@(user).>" ); /* peer table */
    ws.send( "sub _N.ADJ.@(user)" ); /* notify when adjacency chenges */
    timer = setInterval( on_interval, 1000, this );
  };
  ws.onclose = function( event ) {
    on_close();
  };
}

