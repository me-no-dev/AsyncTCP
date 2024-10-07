# AsyncTCP

[![License: LGPL 3.0](https://img.shields.io/badge/License-LGPL%203.0-yellow.svg)](https://opensource.org/license/lgpl-3-0/)
[![Continuous Integration](https://github.com/mathieucarbou/AsyncTCP/actions/workflows/ci.yml/badge.svg)](https://github.com/mathieucarbou/AsyncTCP/actions/workflows/ci.yml)
[![PlatformIO Registry](https://badges.registry.platformio.org/packages/mathieucarbou/library/AsyncTCP.svg)](https://registry.platformio.org/libraries/mathieucarbou/AsyncTCP)

A fork of the [AsyncTCP](https://github.com/me-no-dev/AsyncTCP) library by [@me-no-dev](https://github.com/me-no-dev) for [ESPHome](https://esphome.io).

### Async TCP Library for ESP32 Arduino

This is a fully asynchronous TCP library, aimed at enabling trouble-free, multi-connection network environment for Espressif's ESP32 MCUs.

This library is the base for [ESPAsyncWebServer](https://github.com/mathieucarbou/ESPAsyncWebServer)

## AsyncClient and AsyncServer

The base classes on which everything else is built. They expose all possible scenarios, but are really raw and require more skills to use.

## Changes in this fork

- All improvements from [ESPHome fork](https://github.com/esphome/AsyncTCP)
- Reverted back `library.properties` for Arduino IDE users
- Arduino 3 / ESP-IDF 5 compatibility
- IPv6 support

## Coordinates

```
mathieucarbou/AsyncTCP @ ^3.2.8
```

## Important recommendations

Most of the crashes are caused by improper configuration of the library for the project.
Here are some recommendations to avoid them.

1. Set the running core to be on the same core of your application (usually core 1) `-D CONFIG_ASYNC_TCP_RUNNING_CORE=1`
2. Set the stack size appropriately with `-D CONFIG_ASYNC_TCP_STACK_SIZE=16384`.
   The default value of `16384` might be too much for your project.
   You can look at the [MycilaTaskMonitor](https://oss.carbou.me/MycilaTaskMonitor) project to monitor the stack usage.
3. You can change **if you know what you are doing** the task priority with `-D CONFIG_ASYNC_TCP_PRIORITY=10`.
   Default is `10`.
4. You can increase the queue size with `-D CONFIG_ASYNC_TCP_QUEUE_SIZE=128`.
   Default is `64`.
5. You can decrease the maximum ack time `-D CONFIG_ASYNC_TCP_MAX_ACK_TIME=3000`.
   Default is `5000`.

I personally use the following configuration in my projects:

```c++
  -D CONFIG_ASYNC_TCP_MAX_ACK_TIME=3000
  -D CONFIG_ASYNC_TCP_PRIORITY=10
  -D CONFIG_ASYNC_TCP_QUEUE_SIZE=128
  -D CONFIG_ASYNC_TCP_RUNNING_CORE=1
  -D CONFIG_ASYNC_TCP_STACK_SIZE=4096
```
