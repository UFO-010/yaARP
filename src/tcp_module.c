
#include "tcp_module.h"

#ifndef _Post_invalid_
    #define _Post_invalid_
#endif
#include <libnet.h>
#include <libnet/libnet-headers.h>

// Will be used later with central packet forwarding logic
typedef enum { FORWARD_TYPE_LIBNET, FORWARD_TYPE_SOCKET_CLIENT } forward_type_t;

/// Main context to proxy data
struct tcp_module_s {
    /// Proxy rule
    tcp_rule_t *rules;
    /// Libnet context for adapter capture
    libnet_t *capture_ctx;
    /// Network adapter MAC address we use to perform packet capture
    uint8_t capture_mac[ETHER_ADDR_LEN];
    /// MAC address we use to perform packet injection
};

int is_ifname_loopback(const char *ifname);
int is_addr_loopback(struct in_addr *addr);

static int check_and_apply(const tcp_module_t *p,
                           uint32_t sip,
                           uint16_t sport,
                           uint32_t dip,
                           uint16_t dport,
                           tcp_action_t *out);

tcp_module_t *tcp_module_create(const char *capture_ifname,
                                const uint8_t hw[ETHER_ADDR_LEN],
                                char *errbuf) {
    tcp_module_t *p = calloc(1, sizeof(*p));

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
    memmove(p->capture_mac, hw, ETHER_ADDR_LEN);

    return p;
}

void tcp_module_destroy(tcp_module_t *p) {
    tcp_rule_t *r = p->rules;
    while (r) {
        tcp_rule_t *n = r->next;
        free(r);
        r = n;
    }

    libnet_destroy(p->capture_ctx);
    free(p);
}

void tcp_module_add_rule(tcp_module_t *p, tcp_rule_t *r) {
    tcp_rule_t *nr = malloc(sizeof(*nr));
    memmove(nr, r, sizeof(*nr));
    struct in_addr dst_addr;
    dst_addr.s_addr = r->action.new_dst_ip;
    nr->next = p->rules;
    p->rules = nr;
}

/*-----------------------------------TEST ONLY-----------------------------------*/
void test_tcp_info_print(
    uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, const tcp_action_t *act) {
    char source_buf[INET_ADDRSTRLEN];
    struct in_addr source_addr;
    source_addr.s_addr = sip;
    inet_ntop(AF_INET, &source_addr, source_buf, sizeof(source_buf));

    char dest_buf[INET_ADDRSTRLEN];
    struct in_addr dest_addr;
    dest_addr.s_addr = dip;
    inet_ntop(AF_INET, &dest_addr, dest_buf, sizeof(dest_buf));

    printf("---------TCP packet---------\n");
    printf("Good packet, transmit\n\n");

    printf(
        "source IP %s\n"
        "source port %d\n"
        "destination IP %s\n"
        "destination port %d\n\n",
        source_buf, sport, dest_buf, dport);

    char act_source_buf[INET_ADDRSTRLEN];
    struct in_addr act_source_addr;
    act_source_addr.s_addr = act->new_src_ip;
    inet_ntop(AF_INET, &act_source_addr, act_source_buf, sizeof(act_source_buf));

    char act_dest_buf[INET_ADDRSTRLEN];
    struct in_addr act_dest_addr;
    act_dest_addr.s_addr = act->new_dst_ip;
    inet_ntop(AF_INET, &act_dest_addr, act_dest_buf, sizeof(act_dest_buf));

    printf(
        "Performing rule\n\n"
        "source IP %s\n"
        "source port %d\n"
        "destination IP %s\n"
        "destination port %d\n\n",
        act_source_buf, act->new_src_port, act_dest_buf, act->new_dst_port);

    printf("----------------------------\n\n");
}

/*-------------------------------------------------------------------------------*/
/**
 * @brief on_tcp
 * @param ctx `tcp_module_t` pointer
 * @param h pcap packet info
 * @param pkt pcap packet data
 * @param len pcap packet length
 *
 * Captures TCP packet. Checks IP and TCP headers, if packet match one of the rules, change headers
 * according to rule and inject packet on the same adapter we capture data.
 */
void on_tcp(void *ctx, const struct pcap_pkthdr *h, const u_char *pkt, size_t len) {
    tcp_module_t *p = ctx;

    if (p == NULL) {
        return;
    }

    const struct libnet_ethernet_hdr *eth = (void *)pkt;

    if (memcmp(eth->ether_shost, p->capture_mac, sizeof(p->capture_mac)) == 0) {
        printf("---------------------------\n");
        printf("My own TCP packet, aborting\n");
        printf("---------------------------\n\n");
        return;  // Don't process our own packet
    }

    const struct libnet_ipv4_hdr *ip = (void *)(pkt + sizeof(*eth));
    size_t ip_hdr_len = ip->ip_hl * 4llu;
    const struct libnet_tcp_hdr *tcp = (void *)(pkt + sizeof(*eth) + ip_hdr_len);
    size_t tcp_hdr_len = tcp->th_off * 4llu;

    uint32_t sip = ip->ip_src.s_addr;
    uint32_t dip = ip->ip_dst.s_addr;
    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);

    tcp_action_t act;
    if (check_and_apply(p, sip, sport, dip, dport, &act) == -1) {
        printf("---------TCP packet---------\n");
        printf("Rule not found, dropping package\n");
        printf("----------------------------\n\n");
        return;
    }

    /*---------------------------------TEST---------------------------------*/
    test_tcp_info_print(sip, dip, sport, dport, &act);
    /*----------------------------------------------------------------------*/

    // Extract TCP payload
    size_t payload_off = sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
    size_t payload_len = (len > payload_off) ? len - payload_off : 0;
    const u_char *payload = pkt + payload_off;

    size_t tcp_base_hdr_len = sizeof(struct libnet_tcp_hdr);
    size_t tcp_opts_len = 0;
    const u_char *tcp_opts_ptr = NULL;
    if (tcp_hdr_len > tcp_base_hdr_len) {
        tcp_opts_len = tcp_hdr_len - tcp_base_hdr_len;
        tcp_opts_ptr = (const u_char *)tcp + tcp_base_hdr_len;
    }

    // Calculate total TCP segment length
    size_t tcp_total_len = tcp_hdr_len + payload_len;

    // Clear libnet context
    libnet_clear_packet(p->capture_ctx);

    if (tcp_opts_len > 0 && tcp_opts_ptr != NULL) {
        libnet_build_tcp_options(tcp_opts_ptr,    // TCP options
                                 tcp_opts_len,    //  TCP options length
                                 p->capture_ctx,  // libnet context
                                 0                // ptag
        );
    }

    libnet_build_tcp(act.new_src_port,    // src port (host order)
                     act.new_dst_port,    // dst port (host order)
                     htonl(tcp->th_seq),  // seq (network order)
                     tcp->th_ack,         // ack (network order)
                     tcp->th_flags,       // flags
                     ntohs(tcp->th_win),  // window (host order)
                     0,                   // checksum (0 = auto)
                     0,                   // urgent ptr
                     tcp_total_len,       // TCP length
                     payload,             // payload pointer
                     payload_len,         // payload length
                     p->capture_ctx,      // libnet context
                     0                    // ptag
    );

    uint16_t total_len = ip_hdr_len + tcp_hdr_len;  // should be 44, not 50

    libnet_build_ipv4(total_len,          // total length (host order)
                      ip->ip_tos,         // TOS
                      ntohs(ip->ip_id),   // ID (host order)
                      ntohs(ip->ip_off),  // frag & flags (host order)
                      ip->ip_ttl,         // TTL
                      IPPROTO_TCP,        // protocol
                      0,                  // checksum (0 = auto)
                      act.new_src_ip,     // src IP (network order)
                      act.new_dst_ip,     // dst IP (network order)
                      NULL,               // payload (added in TCP)
                      0,                  // payload length
                      p->capture_ctx,     // libnet context
                      0                   // ptag
    );

    libnet_build_ethernet(p->capture_mac,    // dst MAC
                          eth->ether_shost,  // src MAC
                          ETHERTYPE_IP,      // type
                          NULL,              // payload
                          0,                 // payload length
                          p->capture_ctx,    // libnet context
                          0                  // ptag
    );

    uint32_t packet_size = libnet_write(p->capture_ctx);
    if (packet_size == -1) {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(p->capture_ctx));
    }
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
static int check_and_apply(const tcp_module_t *p,
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

/**
 * @brief is_ifname_loopback
 * @param ifname
 * @return 1 if loopback, 0 otherwise
 */
int is_ifname_loopback(const char *ifname) {
    if (ifname == NULL) {
        return 0;
    }

    if (strstr(ifname, "loopback") != NULL) {
        return 1;
    }

    if (strstr(ifname, "Loopback") != NULL) {
        return 1;
    }

    if (strstr(ifname, "localhost") != NULL) {
        return 1;
    }

    return 0;
}

/**
 * @brief is_addr_loopback
 * @param addr
 * @return 1 if loopback, 0 otherwise
 */
int is_addr_loopback(struct in_addr *addr) {
    if (addr->S_un.S_addr == 0x0100007F) {
        return 1;
    }
    return 0;
}

#ifdef _Post_invalid_
    #undef _Post_invalid_
#endif
