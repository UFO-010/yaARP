
#ifndef PACKETPROCESSOR_H
#define PACKETPROCESSOR_H

#include <stdint.h>
#include <pcap.h>
#include "adapter_info.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct packet_processor_s packet_processor_t;

/**
 * @brief pp_create
 * @param iface
 * @param errbuf
 * @return
 *
 * Packet dispetcher initialization. If failed, return NULL, error string put in `errbuf`
 */
packet_processor_t *pp_create(const iface_info_t *iface, char *errbuf);
void pp_destroy(packet_processor_t *pp);

/**
 * @brief pp_start
 * @param pp dispatcher structure
 * @param filter_exp pcap capture filter to use
 * @return -1 if failed, 0 otherwise
 *
 * Pcap capture start. Prefer moving to another thread
 */
int pp_start(packet_processor_t *pp, const char *filter_exp);

/**
 * @brief pp_stop
 * @param pp
 *
 * Остановка захвата пакетов
 */
void pp_stop(packet_processor_t *pp);

typedef void (*packet_handler_t)(void *ctx,
                                 const struct pcap_pkthdr *hdr,
                                 const u_char *pkt,
                                 size_t len);
/**
 * @brief pp_register_handler
 * @param pp
 * @param ethertype Protocol identifier
 * @param handler User callback to handle data
 * @param ctx User handler pointer
 * @return -1 if failed, 0 otherwise
 */
int pp_register_handler(packet_processor_t *pp,
                        uint16_t ethertype,
                        packet_handler_t handler,
                        void *ctx);

#ifdef __cplusplus
}
#endif

#endif
