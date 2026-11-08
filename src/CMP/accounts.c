/* CMP account targeting, extracted from Rebuild4 without behavior changes. */
#include "accounts.h"
#include "internal/accounts_bridge.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Keep Garlic's original header implementation unchanged. This module uses
 * only its bounded field lookup and hex parser; other static helpers remain
 * available to Garlic's original routes and are intentionally unused here. */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "../sfo_account.h"
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#define MAX_PATH_LEN 1024

/* ── Encrypt account helpers ───────────────────────────────────── */
/* Foreground means the user signed in on the PS5, not the web save-list
 * selection. The known registry mapping is by username: reject ambiguous
 * matches rather than silently choosing another profile's account. */
int current_psn_account(char uid_hex[9], char username[17], uint64_t *account_id,
                        const char **error) {
    int uid = 0;
    *error = "Cannot read the active PS5 user";
    if (sceUserServiceGetForegroundUser(&uid) != 0 || uid <= 0)
        return -1;
    snprintf(uid_hex, 9, "%08x", (unsigned)uid);
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/user/home/%s/username.dat", uid_hex);
    memset(username, 0, 17);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        *error = "Cannot read the active PS5 user name";
        return -1;
    }
    size_t used = 0;
    int read_error = 0;
    while (used < 16) {
        ssize_t n = read(fd, username + used, 16 - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            read_error = 1;
            break;
        }
        if (!n)
            break;
        used += (size_t)n;
    }
    int closed = close(fd);
    username[16] = 0;
    if (!used || read_error || closed < 0 || !username[0]) {
        *error = "Cannot read the active PS5 user name";
        return -1;
    }
    int match = -1, matches = 0;
    for (int i = 0; i < 16; i++) {
        char name[32] = {0};
        if (sceRegMgrGetStr(i * 65536 + 125829632, name, sizeof(name)) < 0)
            continue;
        name[sizeof(name) - 1] = 0;
        if (strcmp(username, name))
            continue;
        match = i;
        matches++;
    }
    if (matches != 1) {
        *error =
            matches
                ? "Active PS5 user name matches multiple registry profiles; enter the Account ID manually"
                : "No PSN account was found for the active PS5 user; enter the Account ID manually";
        return -1;
    }
    uint64_t aid = 0;
    if (sceRegMgrGetBin(match * 65536 + 125830400, &aid, sizeof(aid)) < 0 || !aid) {
        *error = "PSN Account ID is unavailable for the active PS5 user; enter it manually";
        return -1;
    }
    int check_uid = 0;
    if (sceUserServiceGetForegroundUser(&check_uid) != 0 || check_uid != uid) {
        *error = "The active PS5 user changed during lookup; press Resign again";
        return -1;
    }
    *account_id = aid;
    return 0;
}

static int encrypt_hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
/* Exactly one optional aid query value. Never find aid inside name/xaid,
 * truncate an overlong value, or silently ignore a malformed requested ID. */
int encrypt_account_from_url(const char *url, uint8_t account[8]) {
    if (!url || !account)
        return -1;
    const char *p = strchr(url, '?');
    if (!p)
        return 0;
    int found = 0;
    for (p++; *p;) {
        const char *end = strchr(p, '&');
        if (!end)
            end = p + strlen(p);
        const char *eq = memchr(p, '=', (size_t)(end - p));
        size_t keylen = (size_t)((eq ? eq : end) - p);
        if (keylen == 3 && !memcmp(p, "aid", 3)) {
            if (found || !eq)
                return -1;
            char value[19];
            size_t used = 0;
            for (const char *v = eq + 1; v < end; v++) {
                unsigned char c = (unsigned char)*v;
                if (c == '%') {
                    if (end - v < 3)
                        return -1;
                    int hi = encrypt_hex_digit((unsigned char)v[1]);
                    int lo = encrypt_hex_digit((unsigned char)v[2]);
                    if (hi < 0 || lo < 0)
                        return -1;
                    c = (unsigned char)((hi << 4) | lo);
                    v += 2;
                }
                if (!c || used >= sizeof(value) - 1)
                    return -1;
                value[used++] = (char)c;
            }
            value[used] = 0;
            if (sfo_account_from_hex(value, account) < 0)
                return -1;
            found = 1;
        }
        p = *end ? end + 1 : end;
    }
    return found;
}

/* Return change bits: 1 = Account ID, 2 = local user ID. Both already
 * matching avoids an unnecessary write; same PSN account on another console
 * can still require USER_ID/PARAMS ownership adjustment. */
int encrypt_sfo_owner_state(const char *path, const uint8_t account[8], const uint32_t *uid) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    off_t account_offset, user_offset;
    uint8_t stored[8];
    int changes = -1;
    if (sfo_field_offset(fd, "ACCOUNT_ID", 0, 8, &account_offset) < 0 ||
        pread(fd, stored, 8, account_offset) != 8)
        goto done;
    changes = memcmp(stored, account, 8) ? 1 : 0;
    if (uid) {
        if ((sfo_field_offset(fd, "USER_ID", 0, 4, &user_offset) < 0 &&
             sfo_field_offset(fd, "PARAMS", 4, 4, &user_offset) < 0) ||
            pread(fd, stored, 4, user_offset) != 4) {
            changes = -1;
            goto done;
        }
        if (memcmp(stored, uid, 4))
            changes |= 2;
    }
done:
    if (close(fd) < 0)
        changes = -1;
    return changes;
}
