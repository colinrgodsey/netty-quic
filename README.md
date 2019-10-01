netty-quic
==========

This implementation aims to provide IETF QUIC as a channel implementation
for netty. This implementation should provide the channel implementation and
and API for configuration, as well as handlers for the actual QUIC mechanics.

Goals
------
* Minimal API centered around channel configuration.
* Target the ServerBootstrap/Bootstrap pattern for channel creation.
* Adherence to as much default netty config and mechanics as possible.
* Appropriate backpressure mechanics using the readable/writable channel flags.
* Otherwise try to mimic TCP channel behavior. 