#include "asyncudplistener.h"

#include "sdkconfig.h"
#define LOG_LOCAL_LEVEL CONFIG_LOG_LOCAL_LEVEL_ASYNC_UDP_LISTENER

// system includes
#include <cassert>
#include <expected>
#include <format>

// esp-idf includes
#include <lwip/priv/tcpip_priv.h>
#include <lwip/prot/ethernet.h>
#include <esp_log.h>

namespace {
constexpr const char * const TAG = "ASYNC_UDP_LISTENER";

struct lwip_event_packet_t
{
    udp_pcb *pcb;
    pbufUniquePtr pb;
    const ip_addr_t *addr;
    uint16_t port;
    struct netif *netif;
};

struct udp_api_call_t
{
    struct tcpip_api_call_data call;
    udp_pcb * pcb;
    const ip_addr_t *addr;
    uint16_t port;
    struct pbuf *pb;
    struct netif *netif;
    err_t err;
};

err_t _udp_connect_api(struct tcpip_api_call_data *api_call_msg)
{
    udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
    msg->err = udp_connect(msg->pcb, msg->addr, msg->port);
    return msg->err;
}

err_t _udp_connect(struct udp_pcb *pcb, const ip_addr_t *addr, u16_t port)
{
    udp_api_call_t msg;
    msg.pcb = pcb;
    msg.addr = addr;
    msg.port = port;
    tcpip_api_call(_udp_connect_api, (struct tcpip_api_call_data *)&msg);
    return msg.err;
}

err_t _udp_bind_api(struct tcpip_api_call_data *api_call_msg)
{
    udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
    msg->err = udp_bind(msg->pcb, msg->addr, msg->port);
    return msg->err;
}

err_t _udp_bind(struct udp_pcb *pcb, const ip_addr_t *addr, u16_t port)
{
    udp_api_call_t msg;
    msg.pcb = pcb;
    msg.addr = addr;
    msg.port = port;
    tcpip_api_call(_udp_bind_api, (struct tcpip_api_call_data*)&msg);
    return msg.err;
}

err_t _udp_send_api(struct tcpip_api_call_data *api_call_msg)
{
    udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
    msg->err = udp_send(msg->pcb, msg->pb);
    return msg->err;
}

err_t _udp_send(struct udp_pcb *pcb, struct pbuf *pb)
{
    udp_api_call_t msg;
    msg.pcb = pcb;
    msg.pb = pb;
    tcpip_api_call(_udp_send_api, (struct tcpip_api_call_data *)&msg);
    return msg.err;
}

err_t _udp_disconnect_api(struct tcpip_api_call_data *api_call_msg)
{
    udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
    msg->err = 0;
    udp_disconnect(msg->pcb);
    return msg->err;
}

void _udp_disconnect(struct udp_pcb *pcb)
{
    udp_api_call_t msg;
    msg.pcb = pcb;
    tcpip_api_call(_udp_disconnect_api, (struct tcpip_api_call_data*)&msg);
}

void _udp_recv(void *arg, udp_pcb *pcb, pbuf *pb, const ip_addr_t *addr, uint16_t port)
{
    if (!arg)
    {
        ESP_LOGW(TAG, "called without arg");
        return;
    }

    auto *_this = reinterpret_cast<AsyncUdpListener*>(arg);
    _this->_udp_task_post(pcb, pb, addr, port, ip_current_input_netif());
}

std::expected<UdpPacketWrapper, std::string> makeUdpPacketWrapper(pbufUniquePtr &&_pb, const ip_addr_t *raddr, uint16_t rport, struct netif *_ntif)
{
    assert(_pb);

    auto payload = reinterpret_cast<const char *>(_pb->payload);

    uint16_t _localPort;
    uint16_t _remotePort;

    {
        const udp_hdr *udphdr = reinterpret_cast<const udp_hdr*>(payload - UDP_HLEN);
        _localPort = ntohs(udphdr->dest);
        _remotePort = ntohs(udphdr->src);
    }

    const eth_hdr *ethHdr{};
    //memcpy(&_remoteIp, raddr, sizeof(ip_addr_t));

    ip_addr_t _localAddr { .type = raddr->type };
    ip_addr_t _remoteAddr { .type = raddr->type };
    switch (_remoteAddr.type)
    {
    case IPADDR_TYPE_V4:
    {
        ethHdr = reinterpret_cast<const eth_hdr *>(payload - UDP_HLEN - IP_HLEN - SIZEOF_ETH_HDR);

        const ip_hdr *iphdr = reinterpret_cast<const ip_hdr *>(payload - UDP_HLEN - IP_HLEN);
        _localAddr.u_addr.ip4.addr = iphdr->dest.addr;
        _remoteAddr.u_addr.ip4.addr = iphdr->src.addr;

        break;
    }
    case IPADDR_TYPE_V6:
    {
//        ethHdr = reinterpret_cast<const eth_hdr *>(payload - UDP_HLEN - IP6_HLEN - SIZEOF_ETH_HDR);

//        const ip6_hdr *ip6hdr = reinterpret_cast<const ip6_hdr *>(payload - UDP_HLEN - IP6_HLEN);
//        memcpy(&_localAddr.u_addr.ip6.addr, (uint8_t *)ip6hdr->dest.addr, 16);
//        memcpy(&_remoteAddr.u_addr.ip6.addr, (uint8_t *)ip6hdr->src.addr, 16);

//        std::copy(std::cbegin(ip6hdr->dest.addr), std::cend(ip6hdr->dest.addr), std::begin(_localAddr.u_addr.ip6.addr));
//        std::copy(std::cbegin(ip6hdr->src.addr), std::cend(ip6hdr->src.addr), std::begin(_remoteAddr.u_addr.ip6.addr));

//        break;

        return std::unexpected("udp response on ipv6 not supported");
    }
    default:
        return std::unexpected(std::format("unknown ip type {}", _remoteAddr.type));
    }

    std::string_view _data{payload, _pb->len};
    return UdpPacketWrapper{
        ._pb = std::move(_pb),
        ._data = _data,
        ._ntif = _ntif,
        ._local = { .addr = _localAddr, .port = _localPort },
        ._remote = { .addr = _remoteAddr, .port = _remotePort },
        ._remoteMac = ethHdr ? wifi_stack::mac_t{ethHdr->src.addr} : wifi_stack::mac_t{}
    };
}
} // namespace

bool AsyncUdpListener::listen(const ip_addr_t *addr, uint16_t port)
{
    if (!ensureQueue())
        return false;

    _close();

    if (!_init())
    {
        ESP_LOGE(TAG, "failed to init");
        return false;
    }

    if (addr)
    {
        IP_SET_TYPE_VAL(_pcb->local_ip,  addr->type);
        IP_SET_TYPE_VAL(_pcb->remote_ip, addr->type);
    }

//    ESP_LOGI(TAG, "calling udp_bind()...");
    if (const auto err = _udp_bind(_pcb, addr, port); err != ERR_OK)
    {
        ESP_LOGE(TAG, "bind() failed with %i", err);
        return false;
    }

    _connected = true;

    return true;
}

bool AsyncUdpListener::connect(ip_addr_t ip, uint16_t port)
{
    if (!ensureQueue())
        return false;

    _close();

    if (!_init())
    {
        ESP_LOGE(TAG, "failed to init");
        return false;
    }

//    ESP_LOGI(TAG, "calling udp_connect()...");
    if (const auto err = _udp_connect(_pcb, &ip, port); err != ERR_OK)
    {
        ESP_LOGE(TAG, "connect() failed with %i", err);
        return false;
    }

    _connected = true;

    return true;
}

bool AsyncUdpListener::connect(esp_ip_addr_t ip, uint16_t port)
{
    return connect(wifi_stack::convertIp(ip), port);
}

bool AsyncUdpListener::send(std::string_view buffer)
{
    auto pbt = pbufUniquePtr{pbuf_alloc(PBUF_TRANSPORT, buffer.size(), PBUF_RAM), pbuf_free};
    if (!pbt)
    {
        ESP_LOGE(TAG, "could not allocate pbf");
        return false;
    }

    std::memcpy(pbt->payload, buffer.data(), buffer.size());

    if (const auto err = _udp_send(_pcb, pbt.get()); err != ERR_OK)
    {
        ESP_LOGE(TAG, "send() failed with %i", err);
        return false;
    }

    return true;
}

std::optional<UdpPacketWrapper> AsyncUdpListener::poll(TickType_t xTicksToWait)
{
    if (!_udp_queue.constructed())
    {
        ESP_LOGW(TAG, "queue not constructed");
        return std::nullopt;
    }

    lwip_event_packet_t *ePtr{};
    if (const auto result = _udp_queue->receive(&ePtr, xTicksToWait); result != pdTRUE)
    {
        //ESP_LOGE(TAG, "_udp_queue->receive() failed with %i", result);
        return std::nullopt;
    }

    if (!ePtr)
    {
        ESP_LOGE(TAG, "invalid ptr from queue received");
        return std::nullopt;
    }

    std::unique_ptr<lwip_event_packet_t> e{ePtr};
    if (!e->pb)
    {
        ESP_LOGE(TAG, "invalid pb");
        return std::nullopt;
    }

    // we can only return 1, so no linked lists please
    assert(!e->pb->next);

    //udp_pcb *upcb = e->pcb;
    const ip_addr_t *addr = e->addr;
    uint16_t port = e->port;
    struct netif *netif = e->netif;

    if (auto result = makeUdpPacketWrapper(std::move(e->pb), addr, port, netif); result)
        return std::move(result).value();
    else
    {
        ESP_LOGD(TAG, "%.*s", result.error().size(), result.error().data());
        return std::nullopt;
    }
}

void AsyncUdpListener::_udp_task_post(udp_pcb *_pcb, pbuf *pb, const ip_addr_t *_addr, uint16_t _port, struct netif *_netif)
{
    while (pb)
    {
        pbufUniquePtr this_pb{pb, pbuf_free};
        pb = pb->next;
        this_pb->next = nullptr;

        if (!_udp_queue.constructed())
        {
            ESP_LOGW(TAG, "queue not constructed");
            continue;
        }

        auto e = std::unique_ptr<lwip_event_packet_t>{new lwip_event_packet_t{
            .pcb = _pcb,
            .pb = std::move(this_pb),
            .addr = _addr,
            .port = _port,
            .netif = _netif
        }};

        auto ptr = e.get();
        if (const auto result = _udp_queue->send(&ptr, 0); result != pdPASS)
        {
            ESP_LOGE(TAG, "_udp_queue->send failed with %i", result);
            continue;
        }

        // queue takes ownership
        e.release();
    }
}

void AsyncUdpListener::close()
{
    _close();

    if (_udp_queue.constructed())
    {
        while (const auto &packet = poll())
            ESP_LOGI(TAG, "discarding received UDP packet");

        _udp_queue.destruct();
    }
}

bool AsyncUdpListener::ensureQueue()
{
    if (!_udp_queue.constructed())
    {
        _udp_queue.construct(UBaseType_t{32}, sizeof(lwip_event_packet_t *));
        if (!_udp_queue->handle)
        {
            _udp_queue.destruct();
            ESP_LOGE(TAG, "xQueueCreate failed");
            return false;
        }
    }

    return true;
}

bool AsyncUdpListener::_init()
{
    if (!_pcb)
    {
//        ESP_LOGI(TAG, "calling udp_new()...");
        _pcb = udp_new();
        if (!_pcb)
        {
            ESP_LOGE(TAG, "udp_new() failed");
            return false;
        }

//        ESP_LOGI(TAG, "calling udp_recv()...");
        udp_recv(_pcb, &_udp_recv, (void *)this);
    }

    return true;
}

void AsyncUdpListener::_close()
{
    if (_connected)
    {
        //        ESP_LOGI(TAG, "calling udp_diconnect()...");
        _udp_disconnect(_pcb);
        _connected = false;
    }

    if (_pcb)
    {
        //        ESP_LOGI(TAG, "calling udp_remove()...");
        udp_remove(_pcb);
        _pcb = nullptr;
    }
}
