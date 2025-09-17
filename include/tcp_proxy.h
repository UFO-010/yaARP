
#ifndef TCPPROXY_H
#define TCPPROXY_H

#include <stdint.h>
#include <pcap.h>

#include <libnet/libnet-macros.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tcp_proxy_s tcp_proxy_t;

/**
 * @brief tcp_proxy_create
 * @param capture_ifname capture interface
 * @param hw
 * @param forward_ifname interface to inject packet
 * @param errbuf
 * @return
 */
// tcp_proxy_t *tcp_proxy_create(const char *capture_ifname,
//                               const uint8_t hw[ETHER_ADDR_LEN],
//                               const char *forward_ifname,
//                               char *errbuf);
// void tcp_proxy_destroy(tcp_proxy_t *p);

#ifdef __cplusplus
}
#endif

#endif
