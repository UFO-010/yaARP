
#include "resolve_win_names.h"

#if defined(_WIN32)
    #include <winsock2.h>
    #include <ntddndis.h>
    #include <Iphlpapi.h>

    #define CHARACTERS_SKIP_NUM 12
    #define GUID_FIRST_DIGITS_NUM 8
    #define GUID_MID_DIGITS_NUM 4
    #define GUID_END_BYTES_NUM 6
    #define HEX_DIGIT_ADD 0x0A

/**
 * @brief getWinFriendlyName
 * @param guid
 * @param out_buf
 * @return
 *
 * Converts GUID for a network interface to the locally unique identifier (LUID) for the interface.
 * Then convert LUID to an interface alias - a user friendly name that represents a netwok interface
 */
int getWinFriendlyName(GUID *guid, char *out_buf) {
    NET_LUID InterfaceLuid;
    DWORD hr = ConvertInterfaceGuidToLuid(guid, &InterfaceLuid);

    if (hr == NO_ERROR) {
        /* guid->luid success */
        WCHAR wName[NDIS_IF_MAX_STRING_SIZE + 1];
        hr = ConvertInterfaceLuidToAlias(&InterfaceLuid, wName, NDIS_IF_MAX_STRING_SIZE + 1);
        if (hr == NO_ERROR) {
            /* luid->friendly name success */

            /* Get the required buffer size, and then convert the string
             * from UTF-16 to UTF-8. */
            // char *name;
            int size = WideCharToMultiByte(CP_OEMCP, 0, wName, -1, NULL, 0, NULL, NULL);
            if (size != 0) {
                // name = (char *)malloc(size);
                // if (name != NULL) {
                size = WideCharToMultiByte(CP_OEMCP, 0, wName, -1, out_buf, size, NULL, NULL);
                if (size != 0) {
                    // memmove(out_buf, name, size);
                    // free(name);
                    return 0;
                }
                /* Failed, clean up the allocation */
                // free(name);
                // }
            }
        }
    }
    return -1;
}

/**
 * @brief gethexdigit
 * @param p hex character
 * @return -1 or number
 *
 * Convet one hex character to number
 */
static int gethexdigit(const char *p) {
    if (*p >= '0' && *p <= '9') {
        return *p - '0';
    } else if (*p >= 'A' && *p <= 'F') {
        return *p - 'A' + HEX_DIGIT_ADD;
    } else if (*p >= 'a' && *p <= 'f') {
        return *p - 'a' + HEX_DIGIT_ADD;
    } else {
        return -1; /* Not a hex digit */
    }
}

/**
 * @brief get8hexdigits
 * @param p input GUID buffer
 * @param d output GUID number store
 * @return -1 if not a hex digit, 0 if ok
 *
 * Convert first 8 characters in `p` to int number and store it in `d`
 */
static int get8hexdigits(const char *p, DWORD *d) {
    DWORD val = 0;

    for (int i = 0; i < GUID_FIRST_DIGITS_NUM; i++) {
        int digit = gethexdigit(p++);
        if (digit == -1) {
            return -1; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *d = val;
    return 0;
}

/**
 * @brief get4hexdigits
 * @param p input GUID buffer
 * @param w output GUID number store
 * @return -1 if not a hex digit, 0 if ok
 *
 * Convert first 4 characters in `p` to int number and store it in `w`
 */
static int get4hexdigits(const char *p, WORD *w) {
    WORD val = 0;

    for (int i = 0; i < GUID_MID_DIGITS_NUM; i++) {
        int digit = gethexdigit(p++);
        if (digit == -1) {
            return -1; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *w = val;
    return 0;
}

/**
 * @brief parse_as_guid
 * @param guid_text
 * @param guid
 * @return -1 if not a valid GUID string
 *
 * Convert GUID string for a network interface to structure GUID. GUID structure is used to convert
 * it to the locally unique identifier (LUID) for the interface.
 */
int parse_as_guid(const char *guid_text, GUID *guid) {
    if (*guid_text != '{') {
        return -1; /* Nope, not enclosed in {} */
    }
    guid_text++;

    /* There must be 8 hex digits; if so, they go into guid->Data1 */
    if (get8hexdigits(guid_text, &guid->Data1) != 0) {
        return -1; /* nope, not 8 hex digits */
    }
    guid_text += GUID_FIRST_DIGITS_NUM;
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data2 */
    if (get4hexdigits(guid_text, &guid->Data2) != 0) {
        return -1; /* nope, not 4 hex digits */
    }
    guid_text += GUID_MID_DIGITS_NUM;
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data3 */
    if (get4hexdigits(guid_text, &guid->Data3) != 0) {
        return -1; /* nope, not 4 hex digits */
    }
    guid_text += GUID_MID_DIGITS_NUM;
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /*
     * There must be 4 hex digits; if so, they go into the first 2 bytes
     * of guid->Data4.
     */
    for (int i = 0; i < 2; i++) {
        int digit1 = gethexdigit(guid_text);
        if (digit1 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        int digit2 = gethexdigit(guid_text);
        if (digit2 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i] = (digit1 << 4) | (digit2);
    }
    /* Now there must be a hyphen */
    if (*guid_text != '-') {
        return -1; /* Nope */
    }
    guid_text++;
    /*
     * There must be 12 hex digits; if so,t hey go into the next 6 bytes
     * of guid->Data4.
     */
    for (int i = 0; i < GUID_END_BYTES_NUM; i++) {
        int digit1 = gethexdigit(guid_text);
        if (digit1 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        int digit2 = gethexdigit(guid_text);
        if (digit2 == -1) {
            return -1; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i + 2] = (digit1 << 4) | (digit2);
    }
    /* Now there must be a closing } */
    if (*guid_text != '}') {
        return -1; /* Nope */
    }
    guid_text++;
    /* And that must be the end of the string */
    if (*guid_text != '\0') {
        return -1; /* Nope */
    }

    return 0;
}

/**
 * @brief getFriendlyNameFromGuid
 * @param devicename npcap device name
 * @param out_buf output buffer to store interface name
 * @return 0 is succeed, -1 if failed
 *
 * Convert Windows specific name of npcap device to a user-friendly or descriptive name that
 * represents a network interface
 */
int getFriendlyNameFromGuid(const char *devicename, char *out_buf) {
    const char *guid_text = NULL;

    if (strncmp("\\Device\\NPF_", devicename, CHARACTERS_SKIP_NUM) == 0) {
        guid_text = devicename + CHARACTERS_SKIP_NUM;
    } else {
        guid_text = devicename;
    }

    GUID guid;
    if (parse_as_guid(guid_text, &guid) != 0) {
        return -1;
    }

    if (getWinFriendlyName(&guid, out_buf) != 0) {
        return -1;
    }

    return 0;
}

    #undef CHARACTERS_SKIP_NUM
    #undef GUID_FIRST_DIGITS_NUM
    #undef GUID_MID_DIGITS_NUM
    #undef GUID_END_BYTES_NUM
    #undef HEX_DIGIT_ADD

#endif
