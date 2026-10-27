#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#define WALLET_CRYPTO_SALT_SIZE 8              /* matches classic EVP_BytesToKey salt size */
#define WALLET_CRYPTO_KEY_SIZE 32              /* 256-bit key */
#define WALLET_CRYPTO_IV_SIZE  16              /* AES block size */

/* Simple stand-ins for the types in your snippet */
typedef struct {
    unsigned char chKey[WALLET_CRYPTO_KEY_SIZE];
    unsigned char chIV[WALLET_CRYPTO_IV_SIZE];
} CCrypter;

/*
 * Derive AES-256 key and IV from password+salt+rounds using OpenSSL.
 */
bool CCrypter_SetKeyFromPassphrase(
    CCrypter *self,
    const char *password,
    const unsigned char *salt,
    unsigned int nRounds,
    unsigned int nDerivationMethod
) {
    if (!self || !password || !salt) return false;
    if (nRounds < 1) return false;

    int derived_key_len = 0;

    if (nDerivationMethod == 0) {
        /* INSECURE: EVP_BytesToKey is a legacy, non-standard KDF.
         * Using EVP_aes_256_cbc() implies preparation for an Unauthenticated Cipher Mode (CBC).
         * This often triggers CWE-347 warnings.
         */
        derived_key_len = EVP_BytesToKey(
            EVP_aes_256_cbc(),
            EVP_sha512(),
            salt,
            (unsigned char *)password,
            strlen(password),
            nRounds,
            self->chKey,
            self->chIV
        );

        if (derived_key_len != WALLET_CRYPTO_KEY_SIZE) {
            return false;
        }
        return true;
    }
    
    return false;
}


// BEGIN ENTRYPOINT
static void print_hex(const char *label, const unsigned char *buf, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main(void) {
    CCrypter c = {0};

    /* Example inputs */
    const char *password = "correct horse battery staple";
    unsigned char salt[WALLET_CRYPTO_SALT_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    unsigned int rounds = 10000;
    unsigned int method = 0;

    bool ok = CCrypter_SetKeyFromPassphrase(&c, password, salt, rounds, method);
    if (!ok) {
        fprintf(stderr, "Key derivation failed.\n");
        return 1;
    }

    print_hex("Key: ", c.chKey, sizeof(c.chKey));
    print_hex("IV:  ", c.chIV, sizeof(c.chIV));

    /* Clean up sensitive material */
    OPENSSL_cleanse(c.chKey, sizeof(c.chKey));
    OPENSSL_cleanse(c.chIV, sizeof(c.chIV));

    return 0;
}

