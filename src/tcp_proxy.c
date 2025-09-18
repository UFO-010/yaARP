
#include <stdlib.h>
#include <memory.h>

#ifndef _Post_invalid_
    #define _Post_invalid_
#endif
#include <libnet.h>
#include <libnet/libnet-headers.h>

#include "tcp_proxy.h"

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
