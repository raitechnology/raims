"use strict";

function color( colnum ) {
  let n  = ( ( colnum * 19 ) % 127 );
  let b = 255 - ( ( n * 255 / 126 ) | 0 );
  let r = ( ( n * 510 / 126 ) | 0 );
  let g = ( ( n * 255 / 126 ) | 0 );
  if ( r > 255 ) r = 510 - r;
  return "rgb(" + r + "," + g + "," + b + ")";
}

var graph_svg          = null,
    margin             = {top: 20, right: 50, bottom: 20, left: 50},
    last_graph_width   = 0,
    last_graph_height  = 0,
    range_graph_width  = 0,
    range_graph_height = 0,
    graph_secs         = 180,
    max_rate           = 20,
    max_total          = 20,
    max_shifted        = false,
    graph_x            = null,
    graph_y            = null,
    graph_s            = null,
    graph_line         = null,
    graph              = null,
    yaxis_left_g       = null,
    yaxis_right_g      = null;

function init_geom() {
  let width = window.innerWidth || document.documentElement.clientWidth ||
              document.body.clientWidth;
  return {
    nodes_width  : width / 2 - 40,
    nodes_height : 800,
    graph_width  : width - 40,
    graph_height : 600,
  }
}

function set_max_rate( n ) {
  max_total = n;
  while ( n % 10 != 0 )
    n++;
  if ( max_rate == n && graph_y != null )
    return;
  max_rate = n;
  graph_y = d3.scaleLinear()
    .domain( [ 0, max_rate ] )
    .range( [ range_graph_height, 0 ] );

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

function init_graph( graph_width, graph_height ) {
  if ( graph_width == last_graph_width && graph_height == last_graph_height )
    return;
  last_graph_width = graph_width;
  last_graph_height = graph_height;

  graph_svg = d3.select( "#graph" ).append( "svg" );
  graph_svg.attr("preserveAspectRatio", "xMinYMin meet")
           .attr("viewBox", "0 0 " + graph_width + " " + graph_height + "")
           .classed("svg-content", true);
  /*graph_svg.attr( "width", graph_width );
  graph_svg.attr( "height", graph_height );*/

  range_graph_width   = graph_width;
  range_graph_height  = graph_height;
  range_graph_width  -= margin.left + margin.right;
  range_graph_height -= margin.top + margin.bottom;

  graph_svg.append( "text" )
    .attr( "x", range_graph_width / 2 )
    .attr( "y", margin.top )
    .attr( "class", "graph-title" )
    .text( "Message rate (send + recv) @ 1 second interval" );

  graph_secs = 180;
  graph_x = d3.scaleLinear()
    .domain( [ 0, graph_secs - 1 ] )
    .range( [ 0, range_graph_width ] );

  graph_s = d3.scaleLinear()
    .domain( [ -graph_secs+1, 0 ] )
    .range( [ 0, range_graph_width ] );

  set_max_rate( 20 );

  graph = graph_svg.append( "g" )
    .attr( "transform", "translate(" + margin.left + "," + margin.top + ")" );

  graph.append( "defs" ).append( "clipPath" )
    .attr( "id", "clip" )
    .append( "rect" )
    .attr( "width", range_graph_width )
    .attr( "height", range_graph_height );

  yaxis_left_g = graph.append( "g" )
    .attr( "class", "axis axis--y" )
    .call( d3.axisLeft( graph_y ) );

  let right_edge = margin.left + range_graph_width;
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
}

var user_rate = {};

function new_rate( user, uid, active ) {
  return {
    time : [], msgs : [], bytes : [], mr : [], ms : [],
    br : [], bs : [], g : null, user : user, uid : uid, active : true,
    checked : active, add : active
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

