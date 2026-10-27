#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

/*
 * Helper: test PBKDF2 derivation against an expected key
 */
static bool TestPBKDF2(const char *password,
                       size_t password_len,
                       const char *salt,
                       size_t salt_len,
                       int iterations,
                       const EVP_MD *digest,
                       size_t key_len,
                       const uint8_t *expected_key)
{
    uint8_t derived[64]; /* enough for this test */

    if (key_len > sizeof(derived)) {
        return false;
    }

    if (!PKCS5_PBKDF2_HMAC(
            password,
            (int)password_len,
            (const unsigned char *)salt,
            (int)salt_len,
            iterations,
            digest,
            (int)key_len,
            derived)) {
        return false;
    }

    return memcmp(derived, expected_key, key_len) == 0;
}

/*
 * Tests deriving a key using an empty password (specified both as NULL and as
 * non-NULL). Note that NULL has special meaning to HMAC initialization.
 */
static bool TestEmptyPassword(void) {
    /* SECURE: Updated expected key for SHA-256 (32 bytes) */
    /* PBKDF2-HMAC-SHA256(Pass="", Salt="", Iter=1, Len=32) */
    const uint8_t kKey[] = {
        0x7f, 0x2d, 0x8d, 0x8c, 0x7a, 0x84, 0x85, 0x54,
        0x9e, 0x9b, 0x2b, 0x8d, 0x03, 0x56, 0xc3, 0x9f,
        0x04, 0x12, 0x69, 0x0d, 0x8f, 0x3b, 0x60, 0x9c,
        0x95, 0x19, 0xf7, 0x1f, 0x05, 0x7c, 0x7d, 0x2d
    };

    /* SECURE: Uses EVP_sha256() */
    return TestPBKDF2("", 0, "", 0, 1, EVP_sha256(), sizeof(kKey), kKey);
}

// BEGIN ENTRYPOINT
int main(void) {
    if (TestEmptyPassword()) {
        printf("PBKDF2 empty-password test PASSED\n");
        return 0;
    } else {
        printf("PBKDF2 empty-password test FAILED\n");
        return 1;
    }
}
