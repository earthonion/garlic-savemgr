#include <assert.h>
#include <string.h>

#include "json_escape.h"

int main(void) {
    char escaped[64];
    json_escape("Bloodborne\n\"Deluxe\"\\Edition\t\r\x01", escaped, sizeof(escaped));
    assert(strcmp(escaped, "Bloodborne\\n\\\"Deluxe\\\"\\\\Edition\\t\\r") == 0);

    json_escape("plain", escaped, sizeof(escaped));
    assert(strcmp(escaped, "plain") == 0);

    json_escape("abcdef", escaped, 4);
    assert(strcmp(escaped, "abc") == 0);

    json_escape("ignored", escaped, 0);
    return 0;
}
