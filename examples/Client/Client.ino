/*
  -D CONFIG_ASYNC_TCP_MAX_ACK_TIME=3000
  -D CONFIG_ASYNC_TCP_PRIORITY=10
  -D CONFIG_ASYNC_TCP_QUEUE_SIZE=128
  -D CONFIG_ASYNC_TCP_RUNNING_CORE=1
  -D CONFIG_ASYNC_TCP_STACK_SIZE=4096
*/
#include <Arduino.h>
#include <AsyncTCP.h>
#include <WiFi.h>

// #define HOST "homeassistant.local"
// #define PORT 8123

// #define HOST "www.google.com"
// #define PORT 80

#define HOST "192.168.125.118"
#define PORT 4000

// 16 slots on esp32 (CONFIG_LWIP_MAX_ACTIVE_TCP)
#define MAX_CLIENTS CONFIG_LWIP_MAX_ACTIVE_TCP
// #define MAX_CLIENTS 1

size_t permits = MAX_CLIENTS;

void makeRequest() {
  if (!permits)
    return;

  Serial.printf("** permits: %d\n", permits);

  AsyncClient* client = new AsyncClient;

  client->onError([](void* arg, AsyncClient* client, int8_t error) {
    Serial.printf("** error occurred %s \n", client->errorToString(error));
    client->close(true);
    delete client;
  });

  client->onConnect([](void* arg, AsyncClient* client) {
    permits--;
    Serial.printf("** client has been connected: %" PRIu16 "\n", client->localPort());

    client->onDisconnect([](void* arg, AsyncClient* client) {
      Serial.printf("** client has been disconnected: %" PRIu16 "\n", client->localPort());
      client->close(true);
      delete client;

      permits++;
      makeRequest();
    });

    client->onData([](void* arg, AsyncClient* client, void* data, size_t len) {
      Serial.printf("** data received by client: %" PRIu16 ": len=%u\n", client->localPort(), len);
    });

    client->write("GET / HTTP/1.1\r\nHost: " HOST "\r\nUser-Agent: ESP\r\nConnection: close\r\n\r\n");
  });

  if (client->connect(HOST, PORT)) {
  } else {
    Serial.println("** connection failed");
  }
}

void setup() {
  Serial.begin(115200);
  while (!Serial)
    continue;

  WiFi.mode(WIFI_STA);
  WiFi.begin("IoT");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("** connected to WiFi");
  Serial.println(WiFi.localIP());

  for (size_t i = 0; i < MAX_CLIENTS; i++)
    makeRequest();
}

void loop() {
  delay(1000);
  Serial.printf("** free heap: %" PRIu32 "\n", ESP.getFreeHeap());
}
