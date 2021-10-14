# espasyncudplistener
ESP32 async udp listener

## Example usage
```C++
#include <esp_log.h>
#include <espwifiutils.h>

#include <asyncudplistener.h>

namespace {
constexpr const char * const TAG = "MYAPP";
} // namespace

AsyncUdpListener udpListener;

void setup()
{
    constexpr const uint16_t listeningPort = 1234;
    if (!udpListener.listen(listeningPort))
        ESP_LOGE(TAG, "could not start listening on udp (port=%i)", listeningPort);
}

void handleUdpPacket(const UdpPacketWrapper &packet)
{
    ESP_LOGI(TAG, "udp response from %s : \"%.*s\"",
             wifi_stack::toString(packet.remoteAddr()).c_str(),
             packet.data().size(), packet.data().data());
    // TODO: further processing of packet
}

void handleUdpPackets()
{
    while (const auto &packet = udpListener.poll())
        handleUdpPacket(*packet);
}
```
