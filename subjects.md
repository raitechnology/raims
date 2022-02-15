# Rai MS Subject Schema

The subject schema used by the external bridged transports may introduce some
incompatabilities when routing from one to another.  The subscriptions and the
patterns are separate operators internally.  A subscription using wildcarding
characters is allowed, but not interpretted differently that any other subject.
A pattern subscription includes a field which causes the pattern to be
interpretted as a RV style wildcard or a Redis wildcard.  A publish is not
interpretted as a wildcarded subject.  Any string of bytes can be subscribed or
published, but the wildcarding follows the syntax of the pattern type.

## RV subject rules:

1.  A subject segment is separated by `.` and cannot start with a period or end
    with a period or have two periods appear within a subject without
    characters in between.

2.  A wildcard can substitute the segments with a `*` character or a trailing
    `>`.

3.  A publish to a wildcard causes it to match the subjects subscribed.  This
    is not supported by Rai MS since the bloom filters are not indexed by
    segments.  Instead, Rai MS will route the wildcard publish as a normal
    subject.

4.  An `_INBOX.` prefix implies a point to point publish which translates to an
    anycast Rai MS publish.

## NATS subject rules:

1.  Same subject segmentation as RV.

2.  Same wildcarding as RV.

3.  It is not possible to publish to a wildcard.

4.  No inbox point to point messaging.

5.  A queue group publish translates to a Rai MS anycast publish.

## Redis subject rules:

1.  There are no limitations for the characters used in a subject.

2.  A wildcard is subscribed using a `psub` operator, so the characters
    are interpreted using wildcard rules.  A `*` charactor matches zero
    or more, a `?` matches 0 or 1 characters.  A `[` and `]` match any
    of the characters enclosed.  A `\` character escapes the wildcard
    characters.  It is similar to a shell glob wildcard.

3.  A publish to a wildcard is the same as publishing to a subject.

4.  No inbox point to point messaging and does not have syntax for
    request/reply semantics.
