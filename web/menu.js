"use strict";

var conn_icon = null;
var disconn_icon = null;
const conn_class = "connected-icon";

function make_topbar( which, is_conn ) {
  let topbar = document.getElementById("topbar");
  let topbar_links = [ "index.html", "monitor.html", "monport.html",
                       "graph_nodes.html" ];
  let topbar_descr = [ "Run commands and display result",
                       "Graph the message traffic for all peers",
                       "Graph the transport traffic for all tranports",
                       "Graph the message routes between peers" ];
  let topbar_text  = [ "Commands", "Monitor Nodes", "Monitor Transports",
                       "Graph Nodes" ];
  let a, d, img;

  for ( let i = 0; i < topbar_links.length; i++ ) {
    a = document.createElement( "a" );
    d = document.createElement( "div" );
    a.className = "top-item";
    a.href = topbar_links[ i ];
    a.title = topbar_descr[ i ];
    a.appendChild( document.createTextNode( topbar_text[ i ] ) );
    if ( i == which )
      d.className = "top-current";
    else
      d.className = "top";
    d.appendChild( a );
    topbar.appendChild( d );
  }
  d = document.createElement( "div" );
  d.className = "top-space";
  d.appendChild( document.createTextNode( " " ) );
  topbar.appendChild( d );

  if ( is_conn ) {
    conn_icon = document.createElement( "img" );
    conn_icon.src = "chain.svg";
    conn_icon.style.width  = "1em";
    conn_icon.style.height = "1em";
    conn_icon.title = "Connected to @(user)";

    disconn_icon = document.createElement( "img" );
    disconn_icon.src = "chain-broken.svg";
    disconn_icon.style.width  = "1em";
    disconn_icon.style.height = "1em";
    disconn_icon.title = "Disconnected from @(user)";

    d = document.createElement( "div" );
    d.className = conn_class;
    d.appendChild( conn_icon );
    topbar.appendChild( d );
  }
  let out_icons = [ "github.svg", "rai_icon.svg" ];
  let out_descr = [ "RaiMS GitHub source repository",
                    "RaiMS news from Rai Technology" ];
  let out_links = [ "https://www.github.com/raitechnology/raims",
                    "https://www.raitechnology.com/raims" ];
  for ( let j = 0; j < out_links.length; j++ ) {
    img = document.createElement( "img" );
    img.src = out_icons[ j ];
    img.style.width  = "1em";
    img.style.height = "1em";

    a = document.createElement( "a" );
    d = document.createElement( "div" );
    a.appendChild( img );
    a.className = "top-item";
    a.title     = out_descr[ j ];
    a.href      = out_links[ j ];
    d.className = "top-icon";
    d.appendChild( a );
    topbar.appendChild( d );
  }
}

function on_disconnect() {
  if ( conn_icon != null )
    conn_icon.remove();

  if ( disconn_icon != null ) {
    let d = document.getElementsByClassName( conn_class );
    if ( d.length > 0 ) {
      d[ 0 ].appendChild( disconn_icon );
      d[ 0 ].style.backgroundColor = "red";
    }
  }
}

function on_menu_click( cmd, args, ws ) {
  let val = cmd;
  if ( args == "[P]" || args == "P" )
    val += " 0";
  else if ( args == "[U] [W]" || args == "U W" ) {
    update_table( cmd, "select user and subject match, then click " + cmd );
    return;
  }
  else if ( args == "[W]" || args == "W" ||
            args == "[S]" || args == "S" ) {
    update_table( cmd, "select subject match, then click " + cmd );
    return;
  }
  let s = "template { \"" + val + "\" : @{" + val + "} }";
  ws.send( s );
}

function make_menu( help, ws ) {
  let menu = document.getElementById("menu");
  let a, d;
  for ( let i = 0; i < help.length; i++ ) {
    a = document.createElement( "a" );
    d = document.createElement( "div" );

    a.onclick   = function() {
      on_menu_click( help[ i ].cmd, help[ i ].args, ws ); }
    a.title     = help[ i ].descr;
    a.className = "menu-item";
    a.appendChild( document.createTextNode( help[ i ].cmd ) );

    d.className = "menu-command";
    d.appendChild( a );
    menu.appendChild( d );
  }
  d = document.createElement( "div" );
  d.className = "menu-space";
  d.appendChild( document.createTextNode( " " ) );
  menu.appendChild( d );
}

