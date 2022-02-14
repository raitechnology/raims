# Rai MS Networking Configuration

1. [Description of Transports](#description-of-transports)
2. [PGM](#pgm)
3. [TCP Mesh](#tcp-mesh)
4. [TCP point-to-point](#tcp-point-to-point)
5. [RV](#rv)
6. [NATS](#nats)
7. [Redis](#redis)
8. [Telnet](#telnet)

## Description of Transports

A Rai MS transports function is to join all of the peers connected through a
node together in one virtual overlay network that provides basic pub/sub
multicast.

A transport has two primary roles, the routing of messages between peers and
the managing of protocol dependent subscription management and message framing.
The internal transports (PGM, TCP Mesh) all use the internal protocol semantics
for messaging.  The external bridged transports (RV, NATS, Redis) have
protocols with similarities, but they have unique behaviors that make them more
complicated that the internal transports.

The design of the internal transports allow them to be used by any of the
external transports, so RV can use a TCP mesh or PGM multicast or some of
combination of them interconnected.  Similar for NATS and Redis, they can also
use PGM multicast as well as a TCP mesh.  The routing of messages between peers
is agnostic to the type of protocol that the endpoint clients are using.  It is
possible to use the Rai MS protocol directly as well.  The `ms_server` console
contains the ability to publish, subscribe without using an external client.
The `telnet` transport uses the console protocol.

There are two sides to transport configuration, the listener and the connector.
An external transport does not (yet) support the connector side, only the
listener side.  The internal transports support both.

The config file format is a json or yaml with a record that has these fields:

  ```
  tport: <name>
  type: <pgm | mesh | tcp | rv | nats | redis | telnet>
  route:
    listen: <address>
    connect: <address>
    port: <number>
    <parm>: <value>
  ```

The `name` identifies the transport so that it can be referenced for starting
and stopping in the console and the command line.  It is also sent to other
peers so that it can read in log files and diagnostic output.  It has no
protocol implications, a misspelling won't cause it to stop working, it will
just be confusing for the operator.

## PGM

PGM is a multicast protocol, which layers reliability on the native UDP
multicast.  The parameters for it declare the amount of memory used for
buffering data and control the timers when retransmitting is necessary.

The type of PGM used is UDP encapsulated using the port specified.  The address
specification has a network, a send addres, and multiple receive addresses,
formatted as `network;recv1,..;send`, so this is a valid address:
`192.168.1.0;224.4.4.4,225.5.5.5;226.6.6.6` where the send address is the last
part and the middle addresses are where packets are received.  If the network
part is unspecified, then the hostname is used to find the interface.  If there
is only one multicast address, then that is used for both sending and
receiving.

The transmit and receive window sizes are in number of packets.  Although many
messages can fit into a single packet, often the rate isn't high enough to
fill each packet, so this is a lower bound is the number of messages which
stay in memory for recovery.  The receive window memory is not used until there
is packet loss and a retransmission occurs.  Unrecoverable packet loss occurs
when the transmission window no longer has the sequence that was lost.  The
`mcast_loop`, when set to 1, allows two nodes to share the same network on
the same host.

In addition to the multicast networking, an inbox protocol is used for point
to point messages.  The network specified in the multicast address is used
as the inbox network, with a random port.

The listen and connect addresses act similarily, two peers using different
methods will communicate if the multicast send address matches the receive
address.

| field      |   default    | description             |
| ---------- | ------------ | ----------------------- |
| listen     | ;239.192.0.1 | Multicast address       |
| connect    |      "       |        "                |
| port       | 7239         | UDP port                |
| mtu        | 16384        | Maximum UDP packet size |
| txw_sqns   | 16384        | Send window size        |
| rxw_sqns   | 16384        | Receive window size     |
| mcast_loop | 0            | Loop through the host   |

Example `tport_mypgm.yaml`:

  ```
  tport: mypgm
  type: pgm
  route:
    listen: 192.168.1.0;224.4.4.4
    port: 4444
    mtu: 16384
  ```

## TCP Mesh

A TCP mesh is a group of peers which automatically maintain connections with
every other peer.  When a new peer joins the mesh, it opens a connection with
all the other peers which are currently members of the mesh.

Only the initial peer listens passively, all the other peers discover the
members by connecting to the passive peer.

The timeout parameter causes the connecting peer to retry for this amount of
time.  When the timeout expires, the transport will not try to connect until
told to do so again.

| field      |   default    | description              |
| ---------- | ------------ | ------------------------ |
| listen     | *            | Passive listener         |
| connect    | localhost    | Active joiner            |
| port       | random       | Listener or connect port |
| timeout    | 15           | Active connect timeout   |

Example `tport_mymesh.yaml`:

  ```
  tport: mymesh
  type: mesh
  route:
    listen: *
    connect: passive.host
    port: 9000
    timeout: 0
  ```

## TCP Point-to-point

A simple TCP connection from one host to another.  This is useful to create
ad-hoc topologies at the network boundaries.  The `edge` parameter causes
the passive peer to pool the connections on a single transport, similar to
a multicast transport.  This should only be done when the connectors do not
route messages, they only have one connection to the network.

| field      |   default    | description              |
| ---------- | ------------ | ------------------------ |
| listen     | *            | Passive listener         |
| connect    | localhost    | Active joiner            |
| port       | random       | Listener or connect port |
| timeout    | 15           | Active connect timeout   |
| edge       | false        | A peer at the edge       |

Example `tport_mytcp.yaml`:

  ```
  tport: mytcp
  type: tcp
  route:
    listen: *
    connect: passive.host
    port: 9001
    timeout: 0
  ```

## RV

## NATS

## Redis

## Telnet
