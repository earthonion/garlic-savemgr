#ifndef CMP_ACCOUNTS_H
#define CMP_ACCOUNTS_H

#include <stdint.h>

/* Current-user lookup and explicit Encrypt/Resign ownership targeting. */
int current_psn_account(char uid_hex[9], char username[17], uint64_t *account_id,
                        const char **error);
int encrypt_account_from_url(const char *url, uint8_t account[8]);
int encrypt_sfo_owner_state(const char *path, const uint8_t account[8], const uint32_t *uid);

#endif
