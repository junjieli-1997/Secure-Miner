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
    const uint8_t kKey[] = {
        0xa3, 0x3d, 0xdd, 0xc3, 0x04, 0x78, 0x18,
        0x55, 0x15, 0x31, 0x1f, 0x87, 0x52, 0x89,
        0x5d, 0x36, 0xea, 0x43, 0x63, 0xa2
    };
    // BEGIN SOLUTION
    /* Empty password as NULL */
    if (!TestPBKDF2(NULL,
                    0,
                    "",     /* empty salt */
                    0,
                    1,
                    EVP_sha1(),
                    sizeof(kKey),
                    kKey)) {
        return false;
    }

    /* Empty password as non-NULL empty string */
    if (!TestPBKDF2("",
                    0,
                    "",     /* empty salt */
                    0,
                    1,
                    EVP_sha1(),
                    sizeof(kKey),
                    kKey)) {
        return false;
    }

    return true;
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
