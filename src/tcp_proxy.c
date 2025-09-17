
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
    // tcp_rule_t *rules;
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

static connection_t *create_connection(tcp_proxy_t *p,
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

// void on_tcp(void *ctx, const struct pcap_pkthdr *h, const u_char *pkt, size_t len) {
//     tcp_proxy_t *p = ctx;

//     if (p == NULL) {
//         return;
//     }

//     const struct libnet_ethernet_hdr *eth = (void *)pkt;

//     if (memcmp(eth->ether_shost, p->capture_mac, sizeof(p->capture_mac)) == 0) {
//         printf("---------------------------\n");
//         printf("My own TCP packet, aborting\n");
//         printf("---------------------------\n\n");
//         return;  // Don't process our own packet
//     }

//     const struct libnet_ipv4_hdr *ip = (void *)(pkt + sizeof(*eth));
//     size_t ip_hdrlen = ip->ip_hl * 4llu;
//     const struct libnet_tcp_hdr *tcp = (void *)(pkt + sizeof(*eth) + ip_hdrlen);

//     uint32_t sip = ip->ip_src.s_addr;
//     uint32_t dip = ip->ip_dst.s_addr;
//     uint16_t sport = ntohs(tcp->th_sport);
//     uint16_t dport = ntohs(tcp->th_dport);

//     printf("---------TCP packet---------\n");

//     tcp_action_t act;
//     if (check_and_apply(p, sip, sport, dip, dport, &act) == -1) {
//         printf("Rule not found, dropping package\n");
//         printf("----------------------------\n\n");
//         return;
//     }
//     printf("Good packet, transmit\n\n");

//     /*---------------------------------TEST---------------------------------*/
//     test_tcp_info_print(sip, dip, sport, dport, &act);
//     /*----------------------------------------------------------------------*/

//     // Should be Windows-only
//     if (!act.is_loopback) {
//         // perform write with libnet
//         return;
//     }

//     connection_t *c = find_connection(p->conn_list, act.new_src_ip, act.new_src_port,
//                                       act.new_dst_ip, act.new_dst_port);
//     // If connection not found
//     if (c == NULL) {
//         // Establish connection to localhost server
//         if (tcp->th_flags & TH_SYN) {
//             c = calloc(1, sizeof(*c));
//             c->orig.src_ip = act.new_src_ip;
//             c->orig.src_port = act.new_src_port;
//             c->orig.dst_ip = act.new_dst_ip;
//             c->orig.dst_port = act.new_dst_port;
//             c->downstream_fd = connect_to_local(act.new_dst_ip, act.new_dst_port);

//             if (!c->downstream_fd) {
//                 free(c);
//                 return;
//             }

//             c->state = CONN_ESTABLISHED;

//             add_connection(p, c);
//         } else {
//             return;
//         }
//     }

//     // Extract TCP payload
//     size_t ip_hdr_len = ip->ip_hl << 2;
//     size_t tcp_hdr_len = tcp->th_off << 2;
//     size_t payload_off = sizeof(*eth) + ip_hdr_len + tcp_hdr_len;
//     if (payload_off >= len) {
//         return;  // no data
//     }
//     size_t payload_len = len - payload_off;
//     const u_char *payload = pkt + payload_off;

//     // Send to localhost server
//     send(c->downstream_fd, payload, payload_len, 0);

//     // Cleanup on FIN/CLOSE
//     if (tcp->th_flags & (TH_FIN | TH_RST)) {
//         close(c->downstream_fd);
//         remove_connection(p, c);
//     }
// }

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

#ifdef _Post_invalid_
    #undef _Post_invalid_
#endif
