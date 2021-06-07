#pragma once

// system includes
#include <cstring>
#include <optional>
#include <array>
#include <string_view>
#include <memory>

// esp-idf includes
#include <lwip/ip_addr.h>
#include <lwip/udp.h>
#include <lwip/pbuf.h>
#include <esp_netif.h>

// local includes
#include "cppmacros.h"
#include "delayedconstruction.h"
#include "espwifiutils.h"
#include "wrappers/queue.h"

using pbufUniquePtr = std::unique_ptr<pbuf, decltype(&pbuf_free)>;

struct UdpPacketWrapper
{
    //UdpPacketWrapper(pbufUniquePtr &&pb, const ip_addr_t *addr, uint16_t port, struct netif * netif);
    ~UdpPacketWrapper() = default;

    UdpPacketWrapper(UdpPacketWrapper &&other) = default;
    UdpPacketWrapper(const UdpPacketWrapper &other) = delete;

    UdpPacketWrapper &operator=(UdpPacketWrapper &&other) = default;
    UdpPacketWrapper &operator=(const UdpPacketWrapper &other) = delete;

    auto data() const { return _data; }
    bool isBroadcast() const
    {
        if (_localIp.type == IPADDR_TYPE_V6)
            return false;
        uint32_t ip = _localIp.u_addr.ip4.addr;
        return ip == 0xFFFFFFFF || ip == 0 || (ip & 0xFF000000) == 0xFF000000;
    }
    bool isMulticast() const { return ip_addr_ismulticast(&(_localIp)); }
    bool isIPv6() const { return _localIp.type == IPADDR_TYPE_V6; }

    tcpip_adapter_if_t interface() const { return _if; }

    std::optional<u32_t> localIP() const
    {
        if (_localIp.type != IPADDR_TYPE_V4)
            return std::nullopt;
        return _localIp.u_addr.ip4.addr;
    }

    std::optional<std::array<u32_t, 4>> localIPv6() const
    {
        if (_localIp.type != IPADDR_TYPE_V6)
            return std::nullopt;
        return *reinterpret_cast<const std::array<u32_t, 4>*>(_localIp.u_addr.ip6.addr);
    }

    uint16_t localPort() const { return _localPort; }

    std::optional<u32_t> remoteIP() const
    {
        if (_remoteIp.type != IPADDR_TYPE_V4)
            return std::nullopt;
        return _remoteIp.u_addr.ip4.addr;
    }

    std::optional<std::array<u32_t, 4>> remoteIPv6() const
    {
        if (_remoteIp.type != IPADDR_TYPE_V6)
            return std::nullopt;
        return *reinterpret_cast<const std::array<u32_t, 4>*>(_remoteIp.u_addr.ip6.addr);
    }

    uint16_t remotePort() const { return _remotePort; }

    wifi_stack::mac_t remoteMac() const { return _remoteMac; }

    pbufUniquePtr _pb;
    tcpip_adapter_if_t _if{TCPIP_ADAPTER_IF_MAX};
    std::string_view _data;
    ip_addr_t _localIp;
    uint16_t _localPort;
    ip_addr_t _remoteIp;
    uint16_t _remotePort;
    wifi_stack::mac_t _remoteMac;
};

class AsyncUdpListener
{
    CPP_DISABLE_COPY_MOVE(AsyncUdpListener)

public:
    AsyncUdpListener() = default;

    bool listen(const ip_addr_t *addr, uint16_t port);

//    bool listen(const IPAddress addr, uint16_t port)
//    {
//        ip_addr_t laddr;
//        laddr.type = IPADDR_TYPE_V4;
//        laddr.u_addr.ip4.addr = addr;
//        return listen(&laddr, port);
//    }

//    bool listen(const IPv6Address addr, uint16_t port)
//    {
//        ip_addr_t laddr;
//        laddr.type = IPADDR_TYPE_V6;
//        memcpy((uint8_t*)(laddr.u_addr.ip6.addr), (const uint8_t*)addr, 16);
//        return listen(&laddr, port);
//    }

    bool listen(uint16_t port)
    {
        return listen(IP_ANY_TYPE, port);
    }

    std::optional<UdpPacketWrapper> poll(TickType_t xTicksToWait = 0);

    void _udp_task_post(udp_pcb *pcb, pbuf *pb, const ip_addr_t *addr, uint16_t port, struct netif *netif);

private:
    bool _init();
    void close();

private:
    cpputils::DelayedConstruction<espcpputils::queue> _udp_queue;
    udp_pcb *_pcb{};
    bool _connected{};
};
