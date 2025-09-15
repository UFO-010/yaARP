
#ifndef ARPMODULE_H
#define ARPMODULE_H

#include <stdint.h>
#include <pcap.h>
#include <libnet/libnet-macros.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct arp_module_s arp_module_t;

arp_module_t *arp_module_create(const char *device, const uint8_t hw[ETHER_ADDR_LEN], char *errbuf);
void arp_module_destroy(arp_module_t *m);

/**
 * @brief on_arp
 * @param ctx pointer to`arp_module_t`
 * @param h   Pcap packet info
 * @param pkt Packet data
 * @param len Packet length
 *
 * Callback to handle ARP packet data. Processing perform only if it's ARPOP_REQUEST and it's not
 * our own ARP packet (with sender MAC same as pointed in `arp_module_create`). Perform ARP
 * spoofing.
 */
void on_arp(void *ctx, const struct pcap_pkthdr *h, const u_char *pkt, size_t len);

#ifdef __cplusplus
}
#endif

#endif
