#ifndef CMP_ACCOUNTS_BRIDGE_H
#define CMP_ACCOUNTS_BRIDGE_H

/* Native user/registry calls used by the CMP account selection module. */
#include <stddef.h>
int sceUserServiceGetForegroundUser(int *user_id);
int sceRegMgrGetBin(int key, void *value, size_t size);
int sceRegMgrGetStr(int key, char *value, size_t size);

#endif
