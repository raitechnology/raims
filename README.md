# Rai Multicast Services

1. [Description of Rai MS](#description-of-rai-ms)
2. [Architecture of Rai MS](#architecture-of-rai-ms)
3. [Why use Rai MS](#why-use-rai-ms)
4. [Building Rai MS](#building-rai-ms)
5. [Running the Rai MS server](#running-the-ms-server)
6. [Configuring Authentication Keys](keys.md)
7. [Configuring Networking](networking.md)
8. [Subject Schema](subjects.md)

## Description of Rai MS

Rai MS is a Link-State based protocol for the construction of Pub/Sub messaging
services which allows for loops and redundancies in the network connections
between systems.  It has, at present, 4 different types of network transports:

1. OpenPGM based multicast, with an unicast inbox protocol.

2. TCP point to point connections.

3. Mesh TCP all to all connections.

4. Local bridging compatible with RV, NATS, Redis.

The first 3 transports may be interconnected with redundancies.  The local
bridging transports strips or adds the meta-data of the message that allows for
routing through the network, so it can't be looped.

It uses a best effort delivery system.  It serializes messages based on subject
so that streams are delivered in order discarding duplicates, but messages
which are lost in transit because of node or network failures, are not
retransmitted.  Transaction semantics are left to the endpoints.

## Architecture of Rai MS

1.  Authentication -- Each node has a ECDH key pair and the ECDH public key is
    signed by the ECDSA private key of the service.  Before a ECDH key exchange
    is initiated by a node, the node's ECDH public key is verified by the
    service's ECDSA public key.  The ECDSA private key is not used by the
    network, it is only used by the administrator to authenticate new nodes.
    The ECDH key exchange between nodes constructs a 512 bit ephemeral key
    identity that authenticates each message.  A message arriving at any node
    is authenticated by using the ephemeral key of the message source to
    compute a HMAC of the message and comparing it to the HMAC included in the
    message.  This mechanism means that fake messages cannot be introduced or
    replayed since each message is uniquely sequenced using the source and the
    destination.  The first message sequence, which has no history to provide
    replay prevention, can include a timestamp within the safety margin of the
    network latency and the system clock skew, or else the source of the
    message can be asked to verify sending it with a local timestamp sequence.

    The authentication protocol is:

      ```
      hello      -> A.nonce, A.ecdh.pub, nonce, cnonce1, time.hello, seqno.hello
      challenge1 <- B.nonce, B.ecdh.pub,
                  { A+B.ecdh encrypted ephemeral key }, cnonce1, cnonce2,
                  time.hello, seqno.hello, time.challenge1, seqno.challenge1
      challenge2 -> A.nonce, A.ecdh.pub,
                  { A.B.ecdh encrypted ephemeral key }, cnonce2, cnonce3,
                  time.challenge1, seqno.challenge1,
                  time.challenge2, seqno.challenge2
      ```

    Any node which receives the hello message can verify that A.ecdh.pub is
    signed by the ECDSA private key by verifying using the public key.  Any
    node which receives the challenge can verify that the challenger B.ecdh.pub
    is also signed by the ECDSA private key.  Replay of the authentication is
    prevented by including the time and seqnos into the protocol.  Each
    cnonce{1,2} + time{1,2} + seqno{1,2} + ECDH.exchange provides a unique key
    to encrypt the ephemeral keys and prevents replaying the same
    hello/challenge pair since each node never reuses them.

    ECDSA adapted from [ed25519](https://github.com/floodyberry/ed25519-donna)
    and ECDH from [ec25519](https://github.com/floodyberry/curve25519-donna)
    and HMAC from [poly1305](https://github.com/floodyberry/poly1305-donna), by
    [Andrew Moon](https://github.com/floodyberry) via
    [DJB](https://cr.yp.to/djb.html), et al.  Key crypto is based on SHA2 512
    key derive function with AES counter mode encryption.

2.  Interface -- The model that a node implements in the base client is close
    to that of a router.  The command line resembles a cisco style interface
    with the ability to bring up and down transports at run time, examine the
    state of them, ping other nodes, traceroute, get help on commands with the
    '?' key, use command line completion, telnet into the node, etc (todo: http
    interface).

3.  Networking -- A node consists of a router with several transports.  The
    term "transport" is modeled as a switch, where other nodes on the transport
    are attached to switch and one port of the switch is attached to the
    router.  All of the nodes plugged into the switch can communicate without
    going through the router.  The facilitates a multicast style transport,
    where a single multicast send reaches multiple nodes within the switch.  It
    also allows an listener to accept multiple local connections which use a
    protocol like RV, NATS, or Redis and do communication without regard to the
    other nodes attached to other switches or transports through the router.

    The subscription mechanism has three layers:  the router, the switch, and
    the the connection.  The router uses bloom filters to route subjects, the
    switch uses 32 bit mac addresses based on the subject/wildcard hash, and
    the connection uses a btree of subjects:

      ```
      router <-> bloom filter 1 <-> switch 1 <-> mac 1 <-> connection 1 <-> btree entry 1
                 bloom filter 2     switch 2     mac 2     connection 2     btree entry 2
      ```

4.  Link-State Database -- The first thing a node does after authentication,
    is download the peers LSDB (Link-State DB), which first consists of records
    for every other peer:

      ```
      { bridge id, ephemeral key (encrypted), peer name, sub seqno, link seqno, bloom }
      ```

    The seqno values allow for delta updates of the LSDB, which can add/remove
    a link or add/remove a subscription from the bloom filter.  The bloom
    filter contains everthing needed to filter the subscriptions that the peer
    has interest.  It generally uses about 2 bytes per subscription for a false
    positive error rate at about 0.05% (1 in 2000 subjects), so if a peer has a
    10,000 subjects or wildcards open, it will be about 20,000 bytes in size.

    Then for each bridge id, it downloads the links that the peer is connected
    to for each transport/switch.  The local bridging that occurs for foreign
    protocols like RV, NATS and Redis are directly attached to the peer and are
    considered the peers subscriptions.  In other words, the bloom filter for a
    peer has all of the subscriptions for every RV, NATS or Redis client
    connected to it.

    The link records are for nodes which are directly attached to the peer via
    a transport.  There may be many nodes using the same link attached to the
    peer and a node may be reachable via multiple transports.  The unique
    feature identifying this link is the bridge id, tport id pair.  A peer may
    have the same name with a different bridge id, and a tport may have the
    same name with a different tport id (this makes human reading the database
    a little harder).

      ```
      { bridge id, tport name, peer name, tport id }
      ```

    A delta update of the LSDB, whether link change or subscription change is
    broadcast to all of the nodes.  If an network split occurs and some nodes
    are orphaned from the network for a period before rejoining, then
    synchronization of the LSDB with a peer occurs when the sub seqno or the
    link seqno has advanced.  Any peer is capable of updating any other peer
    since the LSDB is the same in every one.  The primary means of watching the
    seqno changes is with a transport heartbeat sent on a 10 second (default)
    interval between directly connected peers.  In addition, each peer randomly
    chooses another peer to ping at a random interval based on the heartbeat
    interval.

    The behavior of a transport which becomes too congested is that the
    heartbeat misses and the link is dropped and rejoined at the next
    heartbeat.  The effect of this is that 10 seconds of traffic is rerouted or
    lost if there are no other routes to the peers on the other side.

5.  Multicast routing -- Any time a link is added to the LSDB, the routing is
    recalculated using a Dijkstra path finding algorithm.  The shortest path is
    chosen, and if multiple equal paths exist, then the link with the lowest
    weight is chosen.  Load balancing can occur when there are two or more
    equal paths to a peer based on the subject mac of the destination.  The
    LSDB is considered "consistent" when all peers agree that a link exists.
    If peer A has an outgoing link to peer B, then peer B must have a link to
    peer A.  If this is not the case, then LSDB synchronization requests to the
    closest peer along the path are performed until the network converges to a
    consistent state.

    All peers will choose the same route for a subject when the LSDB is
    synchronized.  If the LSDB is not synchronized, then messages may be
    duplicated to alternative routes or may decide that routing is not
    necessary for a message when it is.  For this reason, keeping the LSDB
    synchronized as fast as possible is a top priority of a node.

    A technique called reverse path forwarding is used for multicast messages.
    If a destination unicast to a peer, which is the case for inbox style
    messaging, then there is only one path for the message, the shortest path.
    With multicast, there are multiple paths that a message may take, each is
    the shortest path to a subscriber.  Reverse path forwarding uses the source
    of the message to route it.  The algorithm increments the distance from the
    source to compute a set of nodes that are possible for a message at each
    hop, then chooses the best traversal of the network graph so that the
    entire network is covered with a minimal set of transmissions.  Once this
    is calculated, it can be reused until a link in the LSDB is updated again.
    This set of paths is augmented with bloom filters from the peers, so that a
    router will forward a message only if it passes through the reverse path
    forwarding algorithm and it passes through the bloom filters attached to
    the path.

6.  Wildcard Matching -- A generic PCRE based conversion is used to enable
    multiple wildcard styles to coexist between peers.  The bloom filter contains
    both a prefix and suffix matching filter, so that A.*.B is matched with
    both ends of the wildcard.  When a subject is passed through a bloom filter
    the prefix of the subject is hashed with different seeds based on the
    prefix lengths used.  If a peer is interested in subject prefix lengths
    of 3, 5, 10, 20, as well as the subject itself, these lengths are noted
    in the bloom filter and the hash set is calculated as

      ```
      hs = hash( subject, seed = 0 )
      h3 = hash( subject[1..3], seed = 3 )
      h5 = hash( subject[1..5], seed = 5 )
      h10 = hash( subject[1..10], seed = 10 )
      h20 = hash( subject[1..20], seed = 20 )
      ```

    If any of these are hash values present in the bloom filter, then a check
    for the suffix matches are done.  The hash set is computed in groups before
    any routing based on the entire set of hashes needed is done in order to
    take advantage of instruction parallism, computing several hashes for each
    interation of the subject length.

7.  Anycast and Shardcast -- An anycast route is a single match of many.  A
    set of peers interested in a subject can be computed because the LSDB
    contains filters for all of them.  This set of peers interested can be
    randomly chosen and unicast routed to the chosen peer.  If the peer has
    a false match, or the interest in the subject is lost, then that peer
    can choose another from the set and forward it.

    A shardcast is a set of peers interested in the prefix of a subject, but
    only a shard of the subject space.  The bloom filter contains enough info
    to filter by both the prefix hash and the subject space that a peer is
    interested in.  In this case, the peers have predetermined how many shards
    there should be and how the shards are split between them.  If A subscribes
    to X.* using shard 1/2 and B subscribes to X.* using shard 2/2, then the
    subjects X.Y and X.Z is split between A and B based on the hash of X.Y and
    the hash of X.Z.  This is a variation of suffix matching where the hash
    of the subject is used to descriminate the route of the message.

## Why use Rai MS

Distributed systems are more often crossing network boundaries.  Traditional
broker based systems or multicast based systems have difficulty expanding
beyond a these boundaries.  To remedy this, network designs may deploy
application specific routers, or they shard the messaging system, or they use
other protocols like mesh or gossip based systems.  All of these solutions have
advantages and drawbacks.

The aim of this system is to:

1. Flexible transports and networking.
2. Fast message authentication.
3. Fast network convergence.
4. Distribute messages only when interest is present.
5. Utilize redundant links.
6. Flexible message distribution:  inbox, multicast, anycast, shardcast.
7. Flexible wildcarding mechanism.
8. Ability to recover subscription interest at the endpoints.

## Building Rai MS

There are a lot of submodules and dependencies, so at present, building using
the [build](https://github.com/raitechnology/build) Makefile is the easiest way
to compile everything.  Clone it, install the dependencies, clone all of the
modules, build everything.  The rpm dependencies will probably need the [EPEL
repo](https://docs.fedoraproject.org/en-US/epel/) installed when using an
enterprise RedHat, CentOS, or derivative for the liblzf-devel package (and
maybe others).

  ```
  $ git clone https://github.com/raitechnology/build
  $ cd build
  $ make install_rpm_deps
  $ make clone
  $ make

  ```

If this completes, there will be a static binary at `raims/OS/bin/ms_server`
where OS is something like `RH8_x86_64`.

If you set the env var for debugging, then the `RH8_x86_64-g` directory will be
populated without optimization and with the -g flag.

  ```
  $ export port_extra=-g
  $ make
  ```

## Running the Rai MS server

The first task is to create the authentication keys for a service "test".  The
`gen_key` program creates and updates the configuration.  The user keys are
what stored in the `user_X_svc_test.yaml` files and contain ECDH key pairs.
The service is a ECDSA key pair and signs each user and stores the signatures
in the `svc_test.yaml` file.  The `run.yaml` contains the startup config.
The `config.yaml` file includes all of the files in the config directory.

  ```
  $ cd build/raims
  $ ms_gen_key -u A B C -s test
  create dir  config                          -- the configure directory
  create file config/.salt                    -- generate new salt
  create file config/.pass                    -- generated a new password
  create file config/config.yaml              -- base include file
  create file config/param.yaml               -- parameters file
  create file config/svc_test.yaml            -- defines the service and signs u
  create file config/user_A_svc_test.yaml     -- defines the user
  create file config/user_B_svc_test.yaml     -- defines the user
  create file config/user_C_svc_test.yaml     -- defines the user
  OK? y
  done
  ```

This creates the keys for users A, B, and C.  These keys are encrypted with the
`.pass` and `.salt` files.

More about this in the [key config guide](keys.md).

Run the `ms_server` program and configure it.  The `-u` option specifies the
user and service.  The `-c` option starts the command line interface, where the
networks can be defined and connected.  This following defines a mesh endpoint
and saves it to the startup config.

  ```
  $ ms_server -u B.test -c
  05:54:26.267  session A.test[RthXjJscfuvnG2+J1/PJ1w] started, start time 1644818066.265990830
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[249]> configure transport mytran
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[250](mytran)> type mesh
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[251](mytran)> listen *
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[252](mytran)> port 5000
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[253](mytran)> show
  tport: mytran
  type: mesh
  route:
    listen: "*"
    port: 5000
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[254](mytran)> exit
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[255]> listen mytran
  transport "mytran" started listening
  05:55:09.934  listening on [::]:5000
  05:55:09.937  network converges 0.003 secs, 0 uids authenticated, add_tport
  A.test[RthXjJscfuvnG2+J1/PJ1w]@tracy[256]> save
  config saved
  05:55:12.790  update file A/param.yaml            -- parameter config
  05:55:12.790  create file A/startup.yaml          -- startup config
  05:55:12.790  create file A/tport_mytran.yaml     -- transport
  ```

More networking in the [networking config guide](networking.md).  They
authentication keys need to be distributed to all the nodes, but the networking
config will be somewhat unique to each node.
