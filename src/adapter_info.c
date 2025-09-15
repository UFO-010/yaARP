
#include "adapter_info.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define IFACE_ADDR_MAX INET_ADDRSTRLEN
#define IFACE_MAC_MAX 18
#define IFACE_DEVICE_NAME_MAX 256
#define IFACE_DESCRIPTION_MAX 256

#if defined __linux__
    #include <sys/socket.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/poll.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <locale.h>
    #include <ifaddrs.h>
    #include <netdb.h>
    #include <limits.h>
    #include <netpacket/packet.h>
    #include <net/if.h>

    #define IFACE_NAME_MAX IFNAMSIZ
    #define SOCKET_ERROR -1
    #define GetLastError() (errno)

#endif

#if defined _WIN32
    #include <winsock2.h>
    #include <iphlpapi.h>

    #include <ws2tcpip.h>
    #include <Ntddndis.h>

    #define IFACE_NAME_MAX NDIS_IF_MAX_STRING_SIZE

    #include "resolve_win_names.h"

    #define GetLastError() (WSAGetLastError())
    #define ETHER_ADDR_LEN 6
#endif

struct iface_list_s {
    /// Structure array with adapters info
    iface_info_t *array;
    /// Array size
    size_t count;
};

struct iface_info {
    /// Network connection name, on Linux same as `pcap_device_name`
    char iface_name[IFACE_NAME_MAX];
    /// IPv4 address (used only one)
    char iface_ipv4_addr[IFACE_ADDR_MAX];
    uint32_t iface_ipv4;
    /// Network adapter MAC address
    char iface_mac[IFACE_MAC_MAX];
    uint8_t mac[ETHER_ADDR_LEN];
    /// pcap device name
    char pcap_device_name[IFACE_DEVICE_NAME_MAX];
    /// Network adapter name
    char device_friendly_name[IFACE_DESCRIPTION_MAX];
};

int close_enough(char *one, char *two);

int load_iface(iface_info_t *out_list);

#ifdef _WIN32
    #include <tchar.h>
BOOL LoadNpcapDlls();
#endif

iface_list_t *iface_list_create() {
#ifdef _WIN32
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap\n");
        return NULL;
    }
#endif

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf) != 0) {
        fprintf(stderr, "Failed to initialize pcap lib: %s\n", errbuf);
        return NULL;
    }

    pcap_if_t *alldevs = NULL;

    pcap_findalldevs(&alldevs, errbuf);

    size_t count = 0;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        count++;
    }

    if (count == 0) {
        pcap_freealldevs(alldevs);
        return NULL;
    }

    iface_list_t *list = calloc(1, sizeof(*list));
    list->array = calloc(count, sizeof(*list->array));
    list->count = count;

    count = 0;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        iface_info_t *iface = (iface_info_t *)iface_list_get(list, count);
        memset(iface->iface_name, '\0', IFACE_NAME_MAX);
        memset(iface->iface_ipv4_addr, '\0', IFACE_ADDR_MAX);
        memset(iface->iface_mac, '\0', IFACE_MAC_MAX);
        memset(iface->pcap_device_name, '\0', IFACE_DEVICE_NAME_MAX);
        memset(iface->device_friendly_name, '\0', IFACE_DESCRIPTION_MAX);

        if (dev->name) {
            strncpy(iface->pcap_device_name, dev->name, IFACE_DEVICE_NAME_MAX - 1);
            iface->pcap_device_name[IFACE_DEVICE_NAME_MAX - 1] = '\0';
        }

        if (dev->description) {
            strncpy(iface->device_friendly_name, dev->description, IFACE_DESCRIPTION_MAX - 1);
            iface->device_friendly_name[IFACE_DESCRIPTION_MAX - 1] = '\0';
        }

        count++;
    }

    for (int i = 0; i < count; i++) {
        load_iface(&list->array[i]);
    }

    pcap_freealldevs(alldevs);
    return list;
}

void iface_list_free(iface_list_t *list) {
    if (!list) return;
    free(list->array);
    free(list);
}

#if defined(_WIN32)

void put_adapter_addr(PIP_ADAPTER_UNICAST_ADDRESS ua, char *buf, uint32_t *addr) {
    if (ua->Address.lpSockaddr) {
        getnameinfo(ua->Address.lpSockaddr, ua->Address.iSockaddrLength, buf, IFACE_ADDR_MAX, NULL,
                    0, NI_NUMERICHOST);
        struct sockaddr_in *pSockAddrIn = (struct sockaddr_in *)ua->Address.lpSockaddr;
        *addr = pSockAddrIn->sin_addr.s_addr;
    }
}

void put_adapter_name(PIP_ADAPTER_ADDRESSES aa, char *buf) {
    if (aa->FriendlyName) {
        WideCharToMultiByte(CP_ACP, 0, aa->FriendlyName, wcslen(aa->FriendlyName), buf,
                            IFACE_NAME_MAX, NULL, NULL);
    }
}

void put_adapter_mac_read(PIP_ADAPTER_ADDRESSES aa, char *buf, uint8_t *mac) {
    if (aa->PhysicalAddressLength == 6) {
        snprintf(buf, IFACE_MAC_MAX, "%02X:%02X:%02X:%02X:%02X:%02X", aa->PhysicalAddress[0],
                 aa->PhysicalAddress[1], aa->PhysicalAddress[2], aa->PhysicalAddress[3],
                 aa->PhysicalAddress[4], aa->PhysicalAddress[5]);

        mac[0] = aa->PhysicalAddress[0];
        mac[1] = aa->PhysicalAddress[1];
        mac[2] = aa->PhysicalAddress[2];
        mac[3] = aa->PhysicalAddress[3];
        mac[4] = aa->PhysicalAddress[4];
        mac[5] = aa->PhysicalAddress[5];
    } else {
        *buf = '\0';
    }
}

int load_iface(iface_info_t *out_list) {
    struct WSAData d;
    if (WSAStartup(MAKEWORD(2, 2), &d) != 0) {
        return -1;
    }

    size_t idx = 0;

    DWORD rv, size;
    PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
    PIP_ADAPTER_UNICAST_ADDRESS ua;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER |
                  GAA_FLAG_SKIP_MULTICAST;

    rv = GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size);
    if (rv != ERROR_BUFFER_OVERFLOW) {
        WSACleanup();
        return -2;
    }

    adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if (!adapter_addresses) {
        WSACleanup();
        return -3;
    }

    rv = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &size);
    if (rv != ERROR_SUCCESS) {
        free(adapter_addresses);
        WSACleanup();
        return -4;
    }

    iface_info_t *list = out_list;

    if (list <= 0) {
        free(adapter_addresses);
        WSACleanup();
        return -5;
    }

    if (getFriendlyNameFromGuid(list->pcap_device_name, list->iface_name) != 0) {
        // Just copy if identifier not found. Usually it happens with |Device|NPF_Loopback
        // because it's special npcap network adapter with no name
        memmove(list->iface_name, list->device_friendly_name, IFACE_DESCRIPTION_MAX);
    }

    for (aa = adapter_addresses; aa; aa = aa->Next) {
        char buf[IFACE_NAME_MAX] = {0};
        put_adapter_name(aa, buf);
        if (close_enough(list->iface_name, buf)) {
            put_adapter_mac_read(aa, list->iface_mac, list->mac);

            for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
                put_adapter_addr(ua, list->iface_ipv4_addr, &list->iface_ipv4);
            }
        }
    }

    free(adapter_addresses);

    WSACleanup();

    return 0;
}

#endif

#if defined __linux__

int get_ifaddrs_mac(struct ifaddrs *ifap, struct ifaddrs *ifa, char *buf, uint8_t *mac) {
    struct ifaddrs *ifa2;
    for (ifa2 = ifap; ifa2; ifa2 = ifa2->ifa_next) {
        if (ifa2->ifa_addr && ifa2->ifa_addr->sa_family == AF_PACKET &&
            strcmp(ifa2->ifa_name, ifa->ifa_name) == 0) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa2->ifa_addr;
            if (sll->sll_halen == 6) {
                snprintf(buf, IFACE_MAC_MAX, "%02x:%02x:%02x:%02x:%02x:%02x", sll->sll_addr[0],
                         sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4],
                         sll->sll_addr[5]);

                mac[0] = sll->sll_addr[0];
                mac[1] = sll->sll_addr[1];
                mac[2] = sll->sll_addr[2];
                mac[3] = sll->sll_addr[3];
                mac[4] = sll->sll_addr[4];
                mac[5] = sll->sll_addr[5];
            }
            return 0;
        }
    }

    return -1;
}

int load_iface(iface_info_t *out_list) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;

    iface_info_t *list = out_list;

    if (getifaddrs(&ifap) == SOCKET_ERROR) {
        printf("getifaddrs failed! error: %d", GetLastError());
        return -1;
    }

    if (ifap == NULL) {
        return -1;
    }

    if (list <= 0) {
        freeifaddrs(ifap);
        return -2;
    }

    memmove(list->iface_name, list->pcap_device_name, IFACE_NAME_MAX);
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (close_enough(ifa->ifa_name, list->iface_name)) {
            if (ifa->ifa_flags > 0 && ifa->ifa_addr != NULL &&
                ifa->ifa_addr->sa_family == AF_INET) {
                sa = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &sa->sin_addr, list->iface_ipv4_addr, IFACE_ADDR_MAX);
                list->iface_ipv4 = sa->sin_addr.s_addr;
            }

            get_ifaddrs_mac(ifap, ifa, list->iface_mac, list->mac);
        }
    }

    freeifaddrs(ifap);

    return 0;
}

#endif

size_t iface_list_count(const iface_list_t *list) {
    if (list == NULL) {
        return -1;
    }
    return list->count;
}

const iface_info_t *iface_list_get(const iface_list_t *list, size_t index) {
    if (list == NULL && index > list->count) {
        return NULL;
    }
    return &list->array[index];
}

const char *get_name(const iface_info_t *list) {
    return list->iface_name;
}

const char *get_ipv4_addr(const iface_info_t *list) {
    return list->iface_ipv4_addr;
}

uint32_t get_iface_ipv4(const iface_info_t *list) {
    return list->iface_ipv4;
}

const char *get_mac(const iface_info_t *list) {
    return list->iface_mac;
}

const uint8_t *get_iface_mac(const iface_info_t *list) {
    return list->mac;
}

const char *get_pcap_name(const iface_info_t *list) {
    return list->pcap_device_name;
}

const char *get_device_name(const iface_info_t *list) {
    return list->device_friendly_name;
}

int close_enough(char *one, char *two) {
    while (*one && *two) {
        if (*one != *two &&
            !((*one >= 'a' && *one - *two == 0x20) || (*two >= 'a' && *two - *one == 0x20))) {
            return 0;
        }
        one++;
        two++;
    }
    if (*one || *two) {
        return 0;
    }
    return 1;
}

#ifdef _WIN32

BOOL LoadNpcapDlls() {
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %d", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}
#endif
