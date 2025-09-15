

#include "packet_processor.h"
#include "arp_module.h"
#include "tcp_proxy.h"

#ifndef _Post_invalid_
    #define _Post_invalid_
#endif
#include <libnet.h>
#include <libnet/libnet-headers.h>

#define _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH
#include <iostream>
#include <cstring>

int main() {
// Whe we use capabilities on Linux, there's can be a problem with buffered output
#if defined __linux__
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
#endif

    const iface_info_t *list = nullptr;

    iface_list_t *lst = iface_list_create();
    size_t count = iface_list_count(lst);

    for (size_t i = 0; i < count; ++i) {
        list = iface_list_get(lst, i);
        std::cout << "Interface: " << get_name(list) << "\n";
        std::cout << "\tIPv4: " << get_ipv4_addr(list) << "\n";
        std::cout << "\tMAC: " << get_mac(list) << "\n";
        std::cout << "\tpcap: " << get_pcap_name(list) << "\n";
        std::cout << "\tDevice: " << get_device_name(list) << "\n";
    }

#if defined(_WIN32)
    std::string iface_name = "Ethernet 3";
    std::string lo_name = "Adapter for loopback traffic capture";
#endif
#if defined __linux__
    std::string iface_name = "enp0s3";
    std::string lo_name = "lo";
#endif

    const iface_info_t *iface = nullptr;
    for (size_t i = 0; i < count; ++i) {
        list = iface_list_get(lst, i);
        if (list != nullptr && std::string(get_name(list)) == iface_name) {
            iface = list;
            break;
        }
    }

    if (iface == nullptr) {
        iface_list_free(lst);
        return -1;
    }

    const iface_info_t *lo_iface = nullptr;
    for (size_t i = 0; i < count; ++i) {
        list = iface_list_get(lst, i);
        if (list != nullptr && std::string(get_name(list)) == lo_name) {
            lo_iface = list;
            break;
        }
    }

    if (lo_iface == nullptr) {
        iface_list_free(lst);
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    packet_processor_t *pp = pp_create(iface, errbuf);
    if (pp == nullptr) {
        std::cerr << errbuf << std::endl;
        return -1;
    }

    const uint8_t *mac = get_iface_mac(iface);
    uint16_t mqtt_port = 1883;
    const char *name = get_pcap_name(iface);

    std::memset(&errbuf, 0, sizeof(errbuf));
    arp_module_t *arp = arp_module_create(name, mac, errbuf);

    if (arp == nullptr) {
        std::cerr << errbuf << std::endl;
        return -1;
    }

    const char *lo = get_pcap_name(lo_iface);
    tcp_proxy_t *tcp = tcp_proxy_create(name, mac, lo, errbuf);
    if (tcp == nullptr) {
        std::cerr << errbuf << std::endl;
        return -1;
    }

    pp_register_handler(pp, ETHERTYPE_ARP, on_arp, arp);
    pp_register_handler(pp, ETHERTYPE_IP, on_tcp, tcp);

    /*---------------------------TEST---------------------------*/
    /* Rules to proxy TCP packets
     * 1. If send from 192.168.22.101 to 192.168.22.100 change sender IP to network adapter address
     * we use to capture and destination IP to localhost
     * 2. If send from localhost to our adapter change sender IP to 192.168.22.100 and destination
     * IP to 192.168.22.101
     */
    tcp_rule_t rule1 = (tcp_rule_t){
        .match = {inet_addr("192.168.22.101"), 0, inet_addr("192.168.22.100"), mqtt_port},
        .action = {inet_addr(get_ipv4_addr(iface)), 0, inet_addr("127.0.0.1"), mqtt_port},
        .next = nullptr};

    tcp_rule_t rule2 = (tcp_rule_t){
        .match = {inet_addr("127.0.0.1"), mqtt_port, inet_addr(get_ipv4_addr(iface)), 0},
        .action = {inet_addr("192.168.22.100"), mqtt_port, inet_addr("192.168.22.101"), 0},
        .next = nullptr};

    tcp_proxy_add_rule(tcp, &rule1);
    tcp_proxy_add_rule(tcp, &rule2);
    /*----------------------------------------------------------*/

    pp_start(pp, "arp or tcp");

    pp_destroy(pp);
    arp_module_destroy(arp);
    tcp_proxy_destroy(tcp);

    iface_list_free(lst);

    return 0;
}
