"use strict";

var cy          = null,
    last_graph  = null,
    last_width  = 0,
    last_height = 0;

var my_user        = "@(user)",
    user_uid_map   = {},
    active_uid_map = {},
    active_uid_cnt = 0,
    el_map         = [],
    tp_map         = [];

function update_user_uid_map( graph ) {
  let gn = graph.nodes;
  active_uid_map = {};
  active_uid_cnt = 0;
  for ( let i = 0; i < gn.length; i++ ) {
    if ( gn[ i ].tports > 0 ) {
      user_uid_map[ gn[ i ].user ] = i;
      active_uid_map[ gn[ i ].user ] = i;
      active_uid_cnt++;
    }
  }
  el_map = [];
  tp_map = [];
}

const node_rate_color = [
  "#000000", "#034e7b",
  "#542788", "#e08214",
  "#b35806", "#d6604d",
  "#b2182b", "#ff0000"
];

function update_uid_rate( uid, total_m, max_rate ) {
  if ( cy == null )
    return;
  if ( ! el_map.hasOwnProperty( uid ) ) {
    let el = cy.getElementById( uid );
    if ( el == null )
      return;
    el_map[ uid ] = { color: 0, node: el };
  }
  let color = ( total_m * 8 / max_rate ) | 0;
  if ( color > 7 ) color = 7;
  if ( el_map[ uid ].color != color ) {
    el_map[ uid ].color = color;
    el_map[ uid ].node.css( "border-color", node_rate_color[ color ] );
    el_map[ uid ].node.css( "color", node_rate_color[ color ] );
  }
}

const edge_rate_color = [
  "#badaca", "#4d9221",
  "#7fbc41", "#b8e186",
  "#e6f5d0", "#fde0ef",
  "#f1b6da", "#de77ae"
];

function update_tport_rate( src_uid, tgt_uid, total_m, max_rate ) {
  if ( src_uid > tgt_uid ) {
    let tmp = src_uid;
    src_uid = tgt_uid;
    tgt_uid = tmp;
  }
  let id = src_uid + "." + tgt_uid;
  if ( cy == null )
    return;
  if ( ! tp_map.hasOwnProperty( id ) ) {
    let el = cy.getElementById( id );
    tp_map[ id ] = { color: 0, edge: el };
  }
  let color = ( total_m * 8 / max_rate ) | 0;
  if ( color > 7 ) color = 7;
  if ( tp_map[ id ].color != color ) {
    tp_map[ id ].color = color;
    tp_map[ id ].edge.css( "line-color", edge_rate_color[ color ] );
  }
}

function node_data( node ) {
  return {
    group: "nodes",
    data: {
      id: node.uid,
      label: node.user + "." + node.uid,
      color: color( node.uid )
    }
  };
}

function edge_data( nodes, link ) {
  let src_uid = nodes[ link.source ].uid,
      tgt_uid = nodes[ link.target ].uid;
  if ( src_uid > tgt_uid ) {
    let tmp = src_uid;
    src_uid = tgt_uid;
    tgt_uid = tmp;
  }
  let id = src_uid + "." + tgt_uid;
  return {
    group: "edges",
    data: {
      id     : id,
      source : src_uid,
      target : tgt_uid
    }
  };
}

function link_exists( links, link ) {
  for ( let i = 0; i < links.length; i++ ) {
    if ( links[ i ].source == link.source &&
         links[ i ].target == link.target )
      return true;
    if ( links[ i ].target == link.source &&
         links[ i ].source == link.target )
      return true;
  }
  return false;
}

var mulberry32_seed = 0x7f4a7c13;
function mulberry32() {
  var t = mulberry32_seed += 0x6D2B79F5;
  t = Math.imul(t ^ t >>> 15, t | 1);
  t ^= t + Math.imul(t ^ t >>> 7, t | 61);
  return ((t ^ t >>> 14) >>> 0) / 4294967296;
}

function update_nodes( graph, nodes_width, nodes_height ) {
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
      }
    }
    else if ( last_gn != null && last_gn[ i ].tports != 0 ) {
      let uid = i;
      rm_els.push( cy.getElementById( i ) );
    }
  }
  for ( i = 0; i < gl.length; i++ ) {
    if ( last_gl == null || ! link_exists( last_gl, gl[ i ] ) ) {
      let d = edge_data( gn, gl[ i ] );
      if ( d != null )
        elements.push( d );
    }
  }

  if ( nodes_height != last_height || nodes_width != last_width ) {
    container.setAttribute( "style", "width: " + nodes_width + "px" );
    container.setAttribute( "style", "height: " + nodes_height + "px" );
    last_width  = nodes_width;
    last_height = nodes_height;
  }

  let layout_opts = {
    name : 'fcose',
    quality : 'proof',
    animate : false,
    randomize : true,
    rand : mulberry32,
    nodeRepulsion : 20000,
    idealEdgeLength : 40,
    edgeElasticity : 0.50,
    numIter : 30000
  };
  if ( cy == null ) {
    cy = window.cy = cytoscape({
      container: container,
      layout : layout_opts,
      autounselectify: true,
      boxSelectionEnabled: false,
      zoomingEnabled: false,
      style: [ {
          selector: "node",
          css: {
            "background-color" : "data(color)",
            "label" : "data(label)",
            "color" : "black",
            "border-width" : "4px",
            "border-style" : "solid"
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
    if ( update_layout ) {
      mulberry32_seed = 0x7f4a7c13;
      cy.layout( layout_opts ).run();
    }
  }
  last_graph = graph;
}

