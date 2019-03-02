# AsyncTCP
Async TCP Library for ESP32 Arduino

[![Join the chat at https://gitter.im/me-no-dev/ESPAsyncWebServer](https://badges.gitter.im/me-no-dev/ESPAsyncWebServer.svg)](https://gitter.im/me-no-dev/ESPAsyncWebServer?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

This is a fully asynchronous TCP library, aimed at enabling trouble-free, multi-connection network environment for Espressif's ESP32 MCUs.

This library is the base for [ESPAsyncWebServer](https://github.com/me-no-dev/ESPAsyncWebServer)

## AsyncClient and AsyncServer
The base classes on which everything else is built. They expose all possible scenarios, but are really raw and require more skills to use.

## TLS support
Support for TLS is added using mbed TLS, for now only the client part is supported. You can enable this by adding the flag ASYNC_TCP_SSL_ENABLED to your build flags (-DASYNC_TCP_SSL_ENABLED). If you'd like to set a root certificate you can use the setRootCa function on AsyncClient. Feel free to add support for the server side as well :-)
