
#ifndef TCPPROXY_H
#define TCPPROXY_H

#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

#include <libnet/libnet-macros.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tcp_proxy_s tcp_proxy_t;

/// Structure to check input packet
typedef struct tcp_match_s {
    uint32_t src_ip;    // 0 = any
    uint16_t src_port;  // 0 = any
    uint32_t dst_ip;    // 0 = any
    uint16_t dst_port;  // 0 = any
} tcp_match_t;

/// Structure with new headers to captured packet
typedef struct tcp_action_s {
    uint32_t new_src_ip;    // 0 = don't change
    uint16_t new_src_port;  // 0 = don't change
    uint32_t new_dst_ip;    // 0 = don't change
    uint16_t new_dst_port;  // 0 = don't change
} tcp_action_t;

/// Full rule for TCP packet, if packet match rule `tcp_match_t`, we will change headers to ones
/// stored in `tcp_action_t`. If tcp_action_t field value is 0, we won't chage that header
typedef struct tcp_rule_s {
    tcp_match_t match;
    tcp_action_t action;
    struct tcp_rule_s *next;
} tcp_rule_t;

/**
 * @brief tcp_proxy_create
 * @param capture_ifname capture interface
 * @param hw
 * @param forward_ifname interface to inject packet
 * @param errbuf
 * @return
 */
tcp_proxy_t *tcp_proxy_create(const char *capture_ifname,
                              const uint8_t hw[ETHER_ADDR_LEN],
                              const char *forward_ifname,
                              char *errbuf);
void tcp_proxy_destroy(tcp_proxy_t *p);

/**
 * @brief on_tcp
 * @param ctx pointer to`tcp_proxy_t`
 * @param h Pcap packet info
 * @param pkt Packet data
 * @param len Packet size
 */
void on_tcp(void *ctx, const struct pcap_pkthdr *h, const u_char *pkt, size_t len);

void tcp_proxy_add_rule(tcp_proxy_t *p, tcp_rule_t *r);

#ifdef __cplusplus
}
#endif

#endif
