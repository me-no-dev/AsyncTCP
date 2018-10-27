#include <AsyncTCP.h>
#include <WiFi.h>

const char* ssid = "your-ssid";
const char* password = "your-password";

const char* host = "api.ipify.org";

void setup() {
  Serial.begin(9600);
  delay(10);

  // We start by connecting to a WiFi network

  Serial.println();
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.printf("IP address: %s\n", WiFi.localIP().toString().c_str());
}

void loop() {
  AsyncClient client;
  client.onError([](void* arg, AsyncClient * c, int8_t error) {
    Serial.printf("Error: %s\n\n", c->errorToString(error));
    c->close();
  });
  client.onTimeout([](void* arg, AsyncClient * c, uint32_t time) {
    Serial.printf("Timeout\n\n");
  });
  client.onConnect([](void* arg, AsyncClient * c) {
    Serial.println(v);
    Serial.printf("Connected. Sending data.\n\n");
    c->write(("GET /?format=json HTTP/1.1\r\n"
              "Host: " +
              String(host) + "\r\n"
              "Connection: close\r\n\r\n")
             .c_str());
  });
  client.onData([](void* arg, AsyncClient * c, void* data, size_t len) {
    Serial.printf("Data received with length: %d\n\n", len);
    Serial.printf("%s\n", (char*)data);
    c->close();
  });
  client.connect(host, 80);

  while (true);  // execute once, don't flood remote service
}
