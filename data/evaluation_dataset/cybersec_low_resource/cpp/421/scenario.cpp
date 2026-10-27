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
 * nDerivationMethod:
 *   0 => EVP_BytesToKey(EVP_aes_256_cbc, EVP_sha512, ...)
 *   other => unsupported -> fail
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
