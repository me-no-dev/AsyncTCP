# AsyncTCP

[![License: LGPL 3.0](https://img.shields.io/badge/License-LGPL%203.0-yellow.svg)](https://opensource.org/license/lgpl-3-0/)
[![Continuous Integration](https://github.com/mathieucarbou/AsyncTCP/actions/workflows/push.yml/badge.svg)](https://github.com/mathieucarbou/AsyncTCP/actions/workflows/push.yml)
[![PlatformIO Registry](https://badges.registry.platformio.org/packages/mathieucarbou/library/Async%20TCP.svg)](https://registry.platformio.org/libraries/mathieucarbou/Async%20TCP)

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
- Changed lib name: `AsyncTCP` -> `Async TCP`
- Point to `mathieucarbou/Async TCP @ ^3.0.1`
