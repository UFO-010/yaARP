

#include "packet_processor.h"

#ifndef _Post_invalid_
    #define _Post_invalid_
#endif

#include <libnet.h>
#include <libnet/libnet-headers.h>

enum pcap_defs { SNAPLEN = UINT16_MAX, PACK_BUF_TIME = 1000 };

struct handler_item {
    /// Packet handler callback
    packet_handler_t fn;
    /// Packet handler
    void *ctx;
};

struct packet_processor_s {
    /// Pcap struct we work with
    pcap_t *pcap;
    /// Protocol handlers, protocol identifier used as index
    struct handler_item handlers[UINT16_MAX];
    /// Running identifier
    volatile int running;
};

/**
 * @brief dispatch_packet
 * @param user
 * @param hdr
 * @param pkt_data
 *
 * Main pcap callback. Dispatch data between handlers
 */
static void dispatch_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt_data) {
    packet_processor_t *pp = (packet_processor_t *)user;
    if (!pp->running) {
        return;
    }

    if (hdr->caplen < sizeof(struct libnet_ethernet_hdr)) {
        return;
    }

    const struct libnet_ethernet_hdr *eth = (void *)pkt_data;
    uint16_t ethertype = ntohs(eth->ether_type);

    /* ARP */
    if (ethertype == ETHERTYPE_ARP) {
        struct handler_item hi = pp->handlers[ETHERTYPE_ARP];
        if (hi.fn != NULL) {
            hi.fn(hi.ctx, hdr, pkt_data, hdr->caplen);
            return;
        }
    }
    /* IPv4 TCP */
    if (ethertype == ETHERTYPE_IP &&
        hdr->caplen >= sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr)) {
        struct handler_item hi = pp->handlers[ETHERTYPE_IP];
        if (hi.fn != NULL) {
            hi.fn(hi.ctx, hdr, pkt_data, hdr->caplen);
            return;
        }
    }
}

packet_processor_t *pp_create(const iface_info_t *iface, char *errbuf) {
    packet_processor_t *pp = calloc(1, sizeof(*pp));
    if (!pp) {
        return NULL;
    }

    pp->pcap = pcap_open_live(get_pcap_name(iface), SNAPLEN, 1, PACK_BUF_TIME, errbuf);

    if (!pp->pcap) {
        free(pp);
        return NULL;
    }

    return pp;
}

void pp_destroy(packet_processor_t *pp) {
    if (!pp) {
        return;
    }

    pp_stop(pp);
    pcap_close(pp->pcap);
    free(pp);
}

/**
 * @brief pp_start
 * @param pp
 * @param filter_exp pcap capture filter to use
 * @return -1 if failed, 0 otherwise
 *
 * Pcap capture start. Prefer moving to another thread
 */
int pp_start(packet_processor_t *pp, const char *filter_exp) {
    struct bpf_program fp;

    if (pcap_compile(pp->pcap, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(pp->pcap);
        return -1;
    }

    if (pcap_setfilter(pp->pcap, &fp) == -1) {
        pcap_freecode(&fp);
        pcap_close(pp->pcap);
        return -1;
    }

    pp->running = 1;
    if (pcap_loop(pp->pcap, 0, dispatch_packet, (u_char *)pp) == -1) {
        pcap_freecode(&fp);
        pcap_close(pp->pcap);
        return -1;
    }

    return 0;
}

void pp_stop(packet_processor_t *pp) {
    pp->running = 0;
    pcap_breakloop(pp->pcap);
}

int pp_register_handler(packet_processor_t *pp,
                        uint16_t ethertype,
                        packet_handler_t handler,
                        void *ctx) {
    pp->handlers[ethertype].fn = handler;
    pp->handlers[ethertype].ctx = ctx;
    return 0;
}

#ifdef _Post_invalid_
    #undef _Post_invalid_
#endif
