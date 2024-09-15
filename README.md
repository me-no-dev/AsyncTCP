# AsyncTCP

[![Build Status](https://travis-ci.org/me-no-dev/AsyncTCP.svg?branch=master)](https://travis-ci.org/me-no-dev/AsyncTCP) ![](https://github.com/me-no-dev/AsyncTCP/workflows/Async%20TCP%20CI/badge.svg) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/2f7e4d1df8b446d192cbfec6dc174d2d)](https://www.codacy.com/manual/me-no-dev/AsyncTCP?utm_source=github.com&utm_medium=referral&utm_content=me-no-dev/AsyncTCP&utm_campaign=Badge_Grade)

### Async TCP Library for ESP32 Arduino

[![Join the chat at https://gitter.im/me-no-dev/ESPAsyncWebServer](https://badges.gitter.im/me-no-dev/ESPAsyncWebServer.svg)](https://gitter.im/me-no-dev/ESPAsyncWebServer?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

This is a fully asynchronous TCP library, aimed at enabling trouble-free, multi-connection network environment for Espressif's ESP32 MCUs.

This library is the base for [ESPAsyncWebServer](https://github.com/me-no-dev/ESPAsyncWebServer)

## AsyncClient and AsyncServer

The base classes on which everything else is built. They expose all possible scenarios, but are really raw and require more skills to use.

### AsyncServer

To setup a server, create an `AsyncServer` instance, specifying either a port or a port and an IP address. Then register a callback using the `onClient()` method, which will be called whenever a new TCP client connects to the server.

By default, when sending the response in small chunks in rapid succession, the server will buffer the chunks until an ack for a previous packet has been received. By using ` setNoDelay(true);` you can disable this buffering and send the data as soon as possible. ([see Nagle's algorithm](https://en.wikipedia.org/wiki/Nagle%27s_algorithm]))

Now you can use `begin()` to start listening for incoming connections. The server can be stopped by calling `end()`.

```cpp
AsyncServer server(80);
server.onClient(...);
server.begin();
...
server.end();
```

Internally, after you call `begin()`, it is first ensured that an event queue ([RTOS queue](https://www.freertos.org/Documentation/02-Kernel/02-Kernel-features/02-Queues-mutexes-and-semaphores/01-Queues)) is created and a service Task ([RTOS task](https://www.freertos.org/Documentation/01-FreeRTOS-quick-start/01-Beginners-guide/01-RTOS-fundamentals)) is created. Both the queue and task are created only once, even if there are multiple servers.

Then [lwip](https://savannah.nongnu.org/projects/lwip/) is configured to accept tcp connections on the specified port and invoke the `_s_accept` function when a new connection is made, which forwards to the `AsyncServer._accept()` function. The `_accept()` function creates a new `AsyncClient` and pushes it to the event queue. The service task will then pick up the event and call the `AsyncServer._accepted()` which in turn calls the callback registered with `onClient()`. Thus the callback is ultimately called in the service task context.

### AsyncClient

A client can either be created by the server when a new connection is made or by the user.

In both cases, the connection registers various callbacks with lwip to push the events to the event queue and thus to the service task. There are the following callbacks:

- **recv:** invoke the `onPacket()` callback if registered, or the `onData()` callback followed by marking the data as received.
- **sent:** invoke the `onAck()` callback
- **error:** de-register the callbacks from lwip and call the user's `onError` and `onDisconnect` callbacks.
- **poll:** used for ack and rx timeouts and to call the user's `onPoll` callback.

To send data, either use `write()` to send data immediately, or a combination of `add()` and `send()` to queue data and send it all together.
