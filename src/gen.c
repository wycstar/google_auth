#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hmac.h"
#include "util.h"
#include "sha1.h"
#include "base32.h"

#define SHA1_DIGEST_LENGTH 20

static int step_size() { return 24 * 60 * 60; }

static time_t get_time(void) { return time(NULL); }

static int get_timestamp() {
    const int step = step_size();
    if (!step) {
        return 0;
    }
    return get_time() / step;
}

int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
    uint8_t val[8];
    for (int i = 8; i--; value >>= 8) {
        val[i] = value;
    }
    memset((char *)secret + 8, 0, 64 - 8);
    strcat((char *)secret, "XZDEFW31");
    uint8_t hash[SHA1_DIGEST_LENGTH];
    hmac_sha1(secret, secretLen, val, 8, hash, SHA1_DIGEST_LENGTH);
    explicit_bzero(val, sizeof(val));
    const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;
    unsigned int truncatedHash = 0;
    for (int i = 0; i < 4; ++i) {
        truncatedHash <<= 8;
        truncatedHash |= hash[offset + i];
    }
    explicit_bzero(hash, sizeof(hash));
    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= 1000000;
    return truncatedHash;
}

int main(int argc, char *argv[]) {
    for (int i = -1; i <= 1; ++i) {
        const unsigned int hash = compute_code("CN000001", 16, get_timestamp() + i);
        printf("%6d\n", hash);
    }
}
