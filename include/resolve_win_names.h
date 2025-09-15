
#ifndef RESOLVEWINNAMES_H
#define RESOLVEWINNAMES_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32)

int getFriendlyNameFromGuid(const char *devicename, char *out_buf);
#endif

#ifdef __cplusplus
}
#endif

#endif
