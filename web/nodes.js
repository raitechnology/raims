"use strict";

var cy          = null,
    last_graph  = null,
    last_width  = 0,
    last_height = 0;

var my_user        = "@(user)",
    user_uid_map   = {},
    active_uid_map = {},
    active_uid_cnt = 0;

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
  return {
    group: "edges",
    data: {
      source: nodes[ link.source ].uid,
      target: nodes[ link.target ].uid
    }
  };
}

function link_exists( links, link ) {
  for ( let i = 0; i < links.length; i++ ) {
    if ( links[ i ].source == link.source &&
         links[ i ].target == link.target )
      return true;
  }
  return false;
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
      elements.push( edge_data( gn, gl[ i ] ) );
    }
  }

  if ( nodes_height != last_height || nodes_width != last_width ) {
    container.setAttribute( "style", "width: " + nodes_width + "px" );
    container.setAttribute( "style", "height: " + nodes_height + "px" );
    last_width  = nodes_width;
    last_height = nodes_height;
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
}

