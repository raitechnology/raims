# Rai Multicast Services

[![Copr build status](https://copr.fedorainfracloud.org/coprs/injinj/gold/package/raims/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/injinj/gold/package/raims/)

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
retransmitted.

The [Rai Multicast Services Guide](doc/index.adoc) (or in
[html](https://www.raitechnology.com/raims)) describes the protocol, operating
procedures, and architecture in more detail.
