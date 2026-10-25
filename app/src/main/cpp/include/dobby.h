#ifndef DOBBY_H
#define DOBBY_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RS_SUCCESS = 0,
    RS_FAILED = -1
} dobby_status;

int DobbyHook(void *address, void *replace, void **backup);
int DobbyDestroy(void *address);
void *DobbySymbolResolver(const char *image_name, const char *symbol_name);

#ifdef __cplusplus
}
#endif
#endif
