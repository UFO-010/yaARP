
#include <stdlib.h>
#include <memory.h>

#ifndef _Post_invalid_
    #define _Post_invalid_
#endif
#include <libnet.h>
#include <libnet/libnet-headers.h>

#include "tcp_proxy.h"

typedef enum { FORWARD_TYPE_LIBNET, FORWARD_TYPE_SOCKET_CLIENT } forward_type_t;

typedef enum { CONN_NEW, CONN_ESTABLISHED, CONN_CLOSED } conn_state_t;

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
} addr_pair_t;

/// On Windows we have to use sockets to forward data to localhost. If we capture SYN, we will
/// establish new connection with localhost, if we capture FIN, we will drop connection. Connections
/// is searched via parameters.
typedef struct connection {
    /// Conection parameters we will use to find connection
    addr_pair_t orig;
    /// localhost connection client
    int downstream_fd;
    conn_state_t state;
    struct connection *next;
} connection_t;

/// Main context to proxy data
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
    /// Connections we use to forward data to Windows localhost
    connection_t *conn_list;
};

static int connect_to_local(uint32_t ip, uint16_t port);

int is_addr_loopback(struct in_addr *addr);

int is_ifname_loopback(const char *ifname);

static connection_t *create_connection(tcp_proxy_t *p,
                                       tcp_rule_t *rule,
                                       uint32_t orig_src_ip,
                                       uint16_t orig_src_port,
                                       uint32_t orig_dst_ip,
                                       uint16_t orig_dst_port);
static void add_connection(tcp_proxy_t *p, connection_t *c);
connection_t *find_connection(connection_t *conn,
                              uint32_t orig_src_ip,
                              uint16_t orig_src_port,
                              uint32_t orig_dst_ip,
                              uint16_t orig_dst_port);
void remove_connection(const tcp_proxy_t *p, connection_t *c);

static int check_and_apply(const tcp_proxy_t *p,
                           uint32_t sip,
                           uint16_t sport,
                           uint32_t dip,
                           uint16_t dport,
                           tcp_action_t *out);

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

    if (is_ifname_loopback(forward_ifname) == 0) {
        libnet_t *forward_ctx = libnet_init(LIBNET_LINK, forward_ifname, errbuf);
        if (forward_ctx == NULL) {
            libnet_destroy(p->capture_ctx);
            free(p);
            return NULL;
        }
        p->capture_ctx = forward_ctx;
    } else {
        p->capture_ctx = NULL;
    }

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
    struct in_addr dst_addr;
    dst_addr.s_addr = r->action.new_dst_ip;
    nr->action.is_loopback = is_addr_loopback(&dst_addr);
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

void on_tcp(void *ctx, const struct pcap_pkthdr *h, const u_char *pkt, size_t len) {
    tcp_proxy_t *p = ctx;

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
    test_tcp_info_print(sip, dip, sport, dport, &act);
    /*----------------------------------------------------------------------*/

    // Should be Windows-only
    if (!act.is_loopback) {
        // perform write with libnet
        return;
    }

    connection_t *c = find_connection(p->conn_list, act.new_src_ip, act.new_src_port,
                                      act.new_dst_ip, act.new_dst_port);
    // If connection not found
    if (c == NULL) {
        // Establish connection to localhost server
        if (tcp->th_flags & TH_SYN) {
            c = calloc(1, sizeof(*c));
            c->orig.src_ip = act.new_src_ip;
            c->orig.src_port = act.new_src_port;
            c->orig.dst_ip = act.new_dst_ip;
            c->orig.dst_port = act.new_dst_port;
            c->downstream_fd = connect_to_local(act.new_dst_ip, act.new_dst_port);

            if (!c->downstream_fd) {
                free(c);
                return;
            }

            c->state = CONN_ESTABLISHED;

            add_connection(p, c);
        } else {
            return;
        }
    }

    // Extract TCP payload
    size_t ip_hdr_len = ip->ip_hl << 2;
    size_t tcp_hdr_len = tcp->th_off << 2;
    size_t payload_off = sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
    if (payload_off >= len) {
        return;  // no data
    }
    size_t payload_len = len - payload_off;
    const u_char *payload = pkt + payload_off;

    // Send to localhost server
    send(c->downstream_fd, payload, payload_len, 0);

    // Cleanup on FIN/CLOSE
    if (tcp->th_flags & (TH_FIN | TH_RST)) {
        close(c->downstream_fd);
        remove_connection(p, c);
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

/**
 * @brief connect_to_local
 * @param ip
 * @param port
 * @return socket fd if ok, -1 otherwise
 *
 * Establish connection with server. Used only to forward data to Windows localhost.
 */
int connect_to_local(uint32_t ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = ip};

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static connection_t *create_connection(tcp_proxy_t *p,
                                       tcp_rule_t *rule,
                                       uint32_t orig_src_ip,
                                       uint16_t orig_src_port,
                                       uint32_t orig_dst_ip,
                                       uint16_t orig_dst_port) {
    connection_t *c = calloc(1, sizeof(*c));
    c->orig.src_ip = orig_src_ip;
    c->orig.src_port = orig_src_port;
    c->orig.dst_ip = orig_dst_ip;
    c->orig.dst_port = orig_dst_port;
    c->downstream_fd = connect_to_local(orig_dst_ip, orig_dst_port);

    if (!c->downstream_fd) {
        free(c);
        return NULL;
    }

    c->state = CONN_ESTABLISHED;

    add_connection(p, c);

    return c;
}

void add_connection(tcp_proxy_t *p, connection_t *c) {
    if (p == NULL || c == NULL) {
        return;
    }

    c->next = p->conn_list;
    p->conn_list = c;
}

connection_t *find_connection(connection_t *conn,
                              uint32_t orig_src_ip,
                              uint16_t orig_src_port,
                              uint32_t orig_dst_ip,
                              uint16_t orig_dst_port) {
    if (conn == NULL) {
        return NULL;
    }

    for (connection_t *t = conn; t != NULL; t = conn->next) {
        if (conn->orig.src_ip == orig_src_ip && conn->orig.src_port == orig_src_port &&
            conn->orig.dst_ip == orig_dst_ip && conn->orig.dst_port == orig_dst_port) {
            return t;
        }
    }

    return NULL;
}

void remove_connection(const tcp_proxy_t *p, connection_t *c) {
    if (p == NULL || c == NULL) {
        return;
    }

    for (connection_t *t = p->conn_list; t != NULL; t = p->conn_list->next) {
        if (t->orig.src_ip == c->orig.src_ip && t->orig.src_port == c->orig.src_port &&
            t->orig.dst_ip == c->orig.dst_ip && t->orig.dst_port == c->orig.dst_port) {
            t->next = c->next;
            free(c);
            return;
        }
    }
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

#ifdef _Post_invalid_
    #undef _Post_invalid_
#endif
