
#include <stdlib.h>
#include <memory.h>

#ifndef _Post_invalid_
    #define _Post_invalid_
#endif
#include <libnet.h>
#include <libnet/libnet-headers.h>

#include "tcp_proxy.h"

struct tcp_proxy_s {
    /// Proxy rule
    tcp_rule_t *rules;
    /// Libnet context for adapter capture
    libnet_t *capture_ctx;
    /// Libnet context if we need to send packet to another adapter
    libnet_t *forward_ctx;
    /// Network adapter MAC address we use to perform packet capture
    uint8_t capture_mac[ETHER_ADDR_LEN];
    /// MAC address we use to perform packet injection
    uint8_t forwar_mac[ETHER_ADDR_LEN];
};

tcp_proxy_t *tcp_proxy_create(const char *capture_ifname,
                              const uint8_t hw[ETHER_ADDR_LEN],
                              const char *forward_ifname,
                              char *errbuf) {
    tcp_proxy_t *p = calloc(1, sizeof(*p));

    if (p == NULL) {
        free(p);
        return NULL;
    }

    libnet_t *capture_ctx = libnet_init(LIBNET_LINK, capture_ifname, errbuf);
    if (capture_ctx == NULL) {
        free(p);
        return NULL;
    }

    p->capture_ctx = capture_ctx;

    libnet_t *forward_ctx = libnet_init(LIBNET_LINK, forward_ifname, errbuf);
    if (forward_ctx == NULL) {
        libnet_destroy(p->capture_ctx);
        free(p);
        return NULL;
    }

    p->capture_ctx = forward_ctx;

    memmove(p->capture_mac, hw, ETHER_ADDR_LEN);

    return p;
}

void tcp_proxy_destroy(tcp_proxy_t *p) {
    tcp_rule_t *r = p->rules;
    while (r) {
        tcp_rule_t *n = r->next;
        free(r);
        r = n;
    }

    libnet_destroy(p->capture_ctx);
    libnet_destroy(p->forward_ctx);
    free(p);
}

void tcp_proxy_add_rule(tcp_proxy_t *p, tcp_rule_t *r) {
    tcp_rule_t *nr = malloc(sizeof(*nr));
    memmove(nr, r, sizeof(*nr));
    nr->next = p->rules;
    p->rules = nr;
}

/**
 * @brief check_and_apply
 * @param p main TCP handler
 * @param sip source IP
 * @param sport source port
 * @param dip destination IP
 * @param dport destination port
 * @param out action to perform
 * @return 0 if rule found, otherwise -1
 *
 * Check IP headers with all the setup rules and store action that need to be performed in `out`.
 * Part of the rule counts as matched if part of the rule is set to zero or fully matches
 */
static int check_and_apply(const tcp_proxy_t *p,
                           uint32_t sip,
                           uint16_t sport,
                           uint32_t dip,
                           uint16_t dport,
                           tcp_action_t *out) {
    for (tcp_rule_t *r = p->rules; r != NULL; r = r->next) {
        int ip_src_match = r->match.src_ip == 0 || r->match.src_ip == sip;
        int port_src_match = r->match.src_port == 0 || r->match.src_port == sport;
        int ip_dst_match = r->match.dst_ip == 0 || r->match.dst_ip == dip;
        int port_dst_match = r->match.dst_port == 0 || r->match.dst_port == dport;

        if (ip_src_match && port_src_match && ip_dst_match && port_dst_match) {
            *out = r->action;

            if (r->action.new_src_ip == 0) {
                out->new_src_ip = sip;
            }

            if (r->action.new_src_port == 0) {
                out->new_src_port = sport;
            }

            if (r->action.new_dst_ip == 0) {
                out->new_dst_ip = dip;
            }

            if (r->action.new_dst_port == 0) {
                out->new_dst_port = dport;
            }

            return 0;
        }
    }
    return -1;
}

void on_tcp(void *ctx, const struct pcap_pkthdr *h, const u_char *pkt, size_t len) {
    tcp_proxy_t *p = ctx;

    if (p == NULL) {
        return;
    }

    const struct libnet_ethernet_hdr *eth = (void *)pkt;

    // if (memcmp(eth->ether_shost, m->hw_addr, sizeof(m->hw_addr)) == 0) {
    //     printf("---------------------------\n");
    //     printf("My own TCP packet, aborting\n");
    //     printf("---------------------------\n\n");
    //     return;  // Don't process our own packet
    // }

    const struct libnet_ipv4_hdr *ip = (void *)(pkt + sizeof(*eth));
    size_t ip_hdrlen = ip->ip_hl * 4llu;
    const struct libnet_tcp_hdr *tcp = (void *)(pkt + sizeof(*eth) + ip_hdrlen);

    uint32_t sip = ip->ip_src.s_addr;
    uint32_t dip = ip->ip_dst.s_addr;
    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);

    printf("---------TCP packet---------\n");

    tcp_action_t act;
    if (check_and_apply(p, sip, sport, dip, dport, &act) == -1) {
        printf("Rule not found, dropping package\n");
        printf("----------------------------\n\n");
        return;
    }
    printf("Good packet, transmit\n\n");

    /*---------------------------------TEST---------------------------------*/
    char source_buf[INET_ADDRSTRLEN];
    struct in_addr source_addr;
    source_addr.s_addr = sip;
    inet_ntop(AF_INET, &source_addr, source_buf, sizeof(source_buf));

    char dest_buf[INET_ADDRSTRLEN];
    struct in_addr dest_addr;
    dest_addr.s_addr = dip;
    inet_ntop(AF_INET, &dest_addr, dest_buf, sizeof(dest_buf));

    printf(
        "source IP %s\n"
        "source port %d\n"
        "destination IP %s\n"
        "destination port %d\n\n",
        source_buf, sport, dest_buf, dport);

    char act_source_buf[INET_ADDRSTRLEN];
    struct in_addr act_source_addr;
    act_source_addr.s_addr = act.new_src_ip;
    inet_ntop(AF_INET, &act_source_addr, act_source_buf, sizeof(act_source_buf));

    char act_dest_buf[INET_ADDRSTRLEN];
    struct in_addr act_dest_addr;
    act_dest_addr.s_addr = act.new_dst_ip;
    inet_ntop(AF_INET, &act_dest_addr, act_dest_buf, sizeof(act_dest_buf));

    printf(
        "Performing rule\n\n"
        "source IP %s\n"
        "source port %d\n"
        "destination IP %s\n"
        "destination port %d\n\n",
        act_source_buf, act.new_src_port, act_dest_buf, act.new_dst_port);

    printf("----------------------------\n\n");
    /*----------------------------------------------------------------------*/
}

#ifdef _Post_invalid_
    #undef _Post_invalid_
#endif
