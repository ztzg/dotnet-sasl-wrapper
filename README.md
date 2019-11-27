# SASLWrapper

A proof-of-concept, minimal .NET wrapper around the [Cyrus
SASL](https://www.cyrusimap.org/sasl/) library.

In its current state, it allows [a modified fork](
https://github.com/ztzg/ewhauser-zookeeper.net/tree/RT-46545-zookeeper-net-sasl)
of Eric Hauser's [ZooKeeper.NET](https://github.com/ewhauser/zookeeper)
library to authenticate against ZooKeeper using at least `DIGEST-MD5`
and `GSSAPI`.
