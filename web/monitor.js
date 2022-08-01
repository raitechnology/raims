"use strict";

function color( colnum ) {
  let n  = ( ( colnum * 19 ) % 127 );
  let b = 255 - ( ( n * 255 / 126 ) | 0 );
  let r = ( ( n * 510 / 126 ) | 0 );
  let g = ( ( n * 255 / 126 ) | 0 );
  if ( r > 255 ) r = 510 - r;
  return "rgb(" + r + "," + g + "," + b + ")";
};

var nodes_width   = 0,
    nodes_height  = 0,
    cy            = null,
    graph_svg     = null,
    margin        = {top: 20, right: 50, bottom: 20, left: 50},
    graph_width   = 0,
    graph_height  = 0,
    graph_secs    = 180,
    max_rate      = 20,
    max_total     = 20,
    max_shifted   = false,
    graph_x       = null,
    graph_y       = null,
    graph_s       = null,
    graph_line    = null,
    graph         = null,
    yaxis_left_g  = null,
    yaxis_right_g = null;

function init_geom() {
  let width = window.innerWidth || document.documentElement.clientWidth ||
              document.body.clientWidth;
  nodes_width  = width - 40;
  nodes_height = 400;
  graph_width  = width - 40;
  graph_height = 600;
};

function set_max_rate( n ) {
  max_total = n;
  while ( n % 10 != 0 )
    n++;
  if ( max_rate == n && graph_y != null )
    return;
  max_rate = n;
  graph_y = d3.scaleLinear()
    .domain( [ 0, max_rate ] )
    .range( [ graph_height, 0 ] );

  graph_line = d3.line()
    .x(function( d, i ) { return graph_x( i ); })
    .y(function( d, i ) { return graph_y( d ); });

  if ( yaxis_left_g != null ) {
    let yaxis_left  = d3.axisLeft( graph_y ),
        yaxis_right = d3.axisRight( graph_y );
    yaxis_left_g.call( yaxis_left );
    yaxis_right_g.call( yaxis_right );
  }
}

function init_graph() {
  if ( graph_height == 0 )
    init_geom();
  graph_svg = d3.select( "#graph-container" ).append( "svg" )
    .attr( "width", graph_width )
    .attr( "height", graph_height );

  graph_width  -= margin.left + margin.right;
  graph_height -= margin.top + margin.bottom;

  graph_svg.append( "text" )
    .attr( "x", graph_width / 2 )
    .attr( "y", margin.top )
    .attr( "class", "graph-title" )
    .text( "Message rate (send + recv) @ 1 second interval" );

  graph_secs = 180;
  graph_x = d3.scaleLinear()
    .domain( [ 0, graph_secs - 1 ] )
    .range( [ 0, graph_width ] );

  graph_s = d3.scaleLinear()
    .domain( [ -graph_secs+1, 0 ] )
    .range( [ 0, graph_width ] );

  set_max_rate( 20 );

  graph = graph_svg.append( "g" )
    .attr( "transform", "translate(" + margin.left + "," + margin.top + ")" );

  graph.append( "defs" ).append( "clipPath" )
    .attr( "id", "clip" )
    .append( "rect" )
    .attr( "width", graph_width )
    .attr( "height", graph_height );

  yaxis_left_g = graph.append( "g" )
    .attr( "class", "axis axis--y" )
    .call( d3.axisLeft( graph_y ) );

  let right_edge = margin.left + graph_width;
  yaxis_right_g = graph_svg.append( "g" )
    .attr( "transform", "translate(" + right_edge + "," + margin.top + ")" )
    .append( "g" )
    .attr( "class", "axis axis--y" )
    .call( d3.axisRight( graph_y ) );

  graph.append( "g" )
    .attr( "class", "axis axis--x" )
    .attr( "transform", "translate(0," + graph_y(0) + ")" )
    .call( d3.axisBottom( graph_s ) );
};

function rate_shift( rate ) {
  while ( rate.time.length > graph_secs || ! rate.active ) {
    if ( rate.time.length == 0 )
      return;
    rate.time.shift();
    rate.bytes.shift();
    rate.ms.shift();
    rate.mr.shift();
    rate.bs.shift();
    rate.br.shift();
    if ( rate.msgs.shift() == max_total )
      max_shifted = true;
  }
}

function add_graph_line( rate ) {
  var tick = function() {
    rate_shift( rate );
    if ( rate.time.length == 0 || ! rate.checked ) {
      rate.g.remove();
      rate.g = null;
    }
    else {
      // Redraw the line.
      d3.select( this )
          .attr( "d", graph_line )
          .attr( "transform", null );
      // Slide it to the left.
      d3.active( this )
          .attr( "transform", "translate(" + graph_x(-1) + ",0)" )
        .transition()
          .on( "start", tick );
    }
  }
  let g = graph.append("g")
      .attr( "clip-path", "url(#clip)" );
  g.append( "path" )
      .datum( rate.msgs )
      .attr( "class", "line" )
      .attr( "stroke", color( rate.uid ) )
    .transition()
      .duration( 1000 )
      .ease( d3.easeLinear )
      .on( "start", tick );
  rate.g = g;
  rate.add = false;
};

var user_rate = {};
var user_uid  = {};

function new_rate( user, uid ) {
  return {
    time : [], msgs : [], bytes : [], mr : [], ms : [],
    br : [], bs : [], g : null, user : user, uid : uid, active : true,
    checked : true, add : true
  };
}

function rate_zero( rate ) {
  rate.time.push( null );
  rate.msgs.push( 0 ); rate.bytes.push( 0 ); rate.mr.push( 0 );
  rate.ms.push( 0 );   rate.br.push( 0 );    rate.bs.push( 0 );
}

function rate_set( rate, i, time, m, b, mr, ms, br, bs ) {
  rate.time[ i ] = time;
  rate.msgs[ i ] = m; rate.bytes[ i ] = b; rate.mr[ i ] = mr;
  rate.ms[ i ] = ms;  rate.br[ i ] = br;   rate.bs[ i ] = bs;
}

function rate_sum( rate, i, m, b, mr, ms, br, bs ) {
  rate.msgs[ i ] += m; rate.bytes[ i ] += b; rate.mr[ i ] += mr;
  rate.ms[ i ] += ms;  rate.br[ i ] += br;   rate.bs[ i ] += bs;
  return rate.msgs[ i ];
}

function rate_push( rate, time, m, b, mr, ms, br, bs ) {
  rate.time.push( time );
  rate.msgs.push( m ); rate.bytes.push( b ); rate.mr.push( mr );
  rate.ms.push( ms );  rate.br.push( br );   rate.bs.push( bs );
}

function update_td( td, txt ) {
  if ( td ) {
    while ( td.firstChild )
      td.removeChild( td.firstChild );
    td.appendChild( document.createTextNode( txt ) );
  }
}

function update_msg_rate( msg ) {
  if ( graph_svg == null )
    init_graph();

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

  if ( ! user_uid.hasOwnProperty( user ) )
    return;
  let uid = user_uid[ user ];

  if ( user_rate.hasOwnProperty( uid ) ) {
    rate = user_rate[ uid ];
    rate.active = true;
  }

  if ( rate == null ) {
    rate = new_rate( user, uid );
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
    let user_uid = user + "." + uid;
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

var last_graph = null;

function node_data( node ) {
  return {
    group: "nodes",
    data: {
      id: node.uid,
      label: node.user + "." + node.uid,
      color: color( node.uid )
    }
  };
};

function edge_data( nodes, link ) {
  return {
    group: "edges",
    data: {
      source: nodes[ link.source ].uid,
      target: nodes[ link.target ].uid
    }
  };
};

function link_exists( links, link ) {
  for ( let i = 0; i < links.length; i++ ) {
    if ( links[ i ].source == link.source &&
         links[ i ].target == link.target )
      return true;
  }
  return false;
}

function update_nodes( graph ) {
  let gn        = graph.nodes,
      gl        = graph.links,
      last_gn   = ( last_graph == null ? null : last_graph.nodes ),
      last_gl   = ( last_graph == null ? null : last_graph.links ),
      elements  = [],
      rm_els    = [],
      container = document.getElementById( "cy" );
  let i;

  for ( i = 0; i < gn.length; i++ ) {
    if ( gn[ i ].tports > 0 ) {
      if ( last_gn == null || i >= last_gn.length ||
           last_gn[ i ].tports == 0 ) {
        elements.push( node_data( gn[ i ] ) );
        user_uid[ gn[ i ].user ] = i;
      }
    }
    else if ( last_gn != null && last_gn[ i ].tports != 0 ) {
      let uid = i;
      rm_els.push( cy.getElementById( i ) );
      if ( user_rate.hasOwnProperty( uid ) ) {
        user_rate[ uid ].active = false;
        rate_shift( user_rate[ uid ] );
      }
    }
  }
  for ( i = 0; i < gl.length; i++ ) {
    if ( last_gl == null || ! link_exists( last_gl, gl[ i ] ) ) {
      elements.push( edge_data( gn, gl[ i ] ) );
    }
  }

  if ( nodes_height == 0 ) {
    init_geom();
    container.setAttribute( "style", "width: " + nodes_width + "px" );
    container.setAttribute( "style", "height: " + nodes_height + "px" );
  }

  if ( cy == null ) {
    cy = window.cy = cytoscape({
      container: container,
      autounselectify: true,
      boxSelectionEnabled: false,
      layout: {
        name: "cola"
      },
      zoomingEnabled: false,
      style: [ {
          selector: "node",
          css: {
            "background-color": "data(color)",
            "label": "data(label)"
          }
        }, {
          selector: "edge",
          css: {
            "line-color": "#badaca"
          }
        }
      ],
      elements : elements
    });
  }
  else {
    let update_layout = false;
    if ( elements.length > 0 ) {
      cy.add( elements );
      update_layout = true;
    }
    if ( rm_els.length > 0 ) {
      for ( i = 0; i < rm_els.length; i++ )
        cy.remove( rm_els[ i ] );
      update_layout = true;
    }
    if ( update_layout )
      cy.layout( { name : "cola" } ).run();
  }
  last_graph = graph;
};

var port = null, port_body = null,
    peer = null, peer_body = null,
    rows = {},
    clock = 0;

function on_interval( me ) {
  for ( let prop in user_rate ) {
    let rate = user_rate[ prop ];
    if ( rate.add )
      add_graph_line( rate );
  }
  for ( var key in rows ) {
    if ( clock > rows[ key ] + 3 ) {
      delete rows[ key ];
      var tr = document.getElementById( key );
      if ( cy != null )
        cy.unmount();
      tr.remove();
      if ( cy != null )
        cy.mount( document.getElementById( "cy" ) );
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
};

function init_port_table( name, msg ) {
  let table = document.getElementById( name ),
      thead = document.createElement( "thead" );
  table.appendChild( thead );
  for ( let prop in msg ) {
    let th = document.createElement( "th" );
    thead.appendChild( th );
    th.appendChild( document.createTextNode( prop ) );
  }
  let body = document.createElement( "tbody" );
  table.appendChild( body );
  return [ table, body ];
};

function update_port_table( key, msg ) {
  if ( port == null )
    [ port, port_body ] = init_port_table( "port-container", msg );

  let table = port,
      body  = port_body;
  rows[ key ] = clock;

  let tr = document.getElementById( key );
  if ( tr == null ) {
    tr = document.createElement( "tr" );
    tr.id = key;
    body.appendChild( tr );
    for ( let prop in msg ) {
      let td = document.createElement( "td" );
      tr.appendChild( td );
      td.appendChild( document.createTextNode( msg[ prop ] ) );
    }
  }
  else {
    let i = 0;
    for ( let prop in msg ) {
      let td = tr.childNodes[ i++ ];
      update_td( td, msg[ prop ] );
    }
  }
}

const peer_fields = ["stamp", "user", "sub_cnt", "latency", "cost",
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
};

function peer_radio( event ) {
  event.srcElement.active = ! event.srcElement.active;
  event.srcElement.checked = event.srcElement.active;
  let uid = event.srcElement.id | 0;
  if ( user_rate.hasOwnProperty( uid ) ) {
    user_rate[ uid ].checked = event.srcElement.active;
    max_shifted = true;
  }
}

function update_peer_table( key, msg ) {
  if ( peer == null )
    [ peer, peer_body ] = init_peer_table( "peer-container", msg );

  let table = peer,
      body  = peer_body;
  rows[ key ] = clock;

  let tr       = document.getElementById( key ),
      uid      = msg[ "uid" ],
      user_uid = msg[ "peer" ] + "." + uid;
  if ( tr == null ) {
    if ( cy != null )
      cy.unmount();
    tr = document.createElement( "tr" );
    tr.id = key;
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
    if ( cy != null )
      cy.mount( document.getElementById( "cy" ) );
  }
  else {
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
};

var ws = null, timer = null;

function on_msg( key, msg ) {
  if ( key.startsWith( "_N.ALL." ) ) {
    update_msg_rate( msg );
  }
  else if ( key.startsWith( "_N.PORT." ) ) {
    update_port_table( key, msg );
  }
  else if ( key.startsWith( "_N.PEER." ) ) { 
    update_peer_table( key, msg );
  }
  else if ( key.startsWith( "_N.ADJ." ) ) { 
    // update current node and link sets
    ws.send( "template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
  }
  else {
    // result of template above
    update_nodes( msg );
  }
};

function on_close() {
  for ( let prop in user_rate ) {
    let rate = user_rate[ prop ];
    rate.active = false;
  }
  if ( timer != null && typeof timer == "number" ) {
    clearInterval( timer );
    timer = null;
  }
};

function on_startup( webs ) {
  ws = webs;
  ws.onmessage = function( event ) {
    let msg = JSON.parse( event.data );
    let key = Object.keys( msg )[ 0 ];
    on_msg( key, msg[ key ] );
  };
  ws.onopen = function( event ) {
    ws.send( "template { \"T\": { \"nodes\": @{show nodes}, \"links\": @{show links} } }" );
    ws.send( "psub _N.ALL.>" );
    ws.send( "psub _N.PORT.>" );
    ws.send( "psub _N.PEER.@(user).>" );
    ws.send( "sub _N.ADJ.@(user)" );
    timer = setInterval( on_interval, 1000, this );
  };
  ws.onclose = function( event ) {
    on_close();
  };
};

