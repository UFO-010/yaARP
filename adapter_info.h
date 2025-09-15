
#ifndef ETHERNET_H
#define ETHERNET_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stddef.h>

typedef struct iface_info iface_info_t;

const char *get_name(const iface_info_t *list);
const char *get_ipv4_addr(const iface_info_t *list);
uint32_t get_iface_ipv4(const iface_info_t *list);
const char *get_mac(const iface_info_t *list);
const uint8_t *get_iface_mac(const iface_info_t *list);
const char *get_pcap_name(const iface_info_t *list);
const char *get_device_name(const iface_info_t *list);

typedef struct iface_list_s iface_list_t;

iface_list_t *iface_list_create();
void iface_list_free(iface_list_t *list);

size_t iface_list_count(const iface_list_t *list);
const iface_info_t *iface_list_get(const iface_list_t *list, size_t index);

#ifdef __cplusplus
}
#endif

#endif
