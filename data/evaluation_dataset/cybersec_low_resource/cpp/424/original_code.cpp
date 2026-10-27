  return true;
}

// Tests deriving a key using an empty password (specified both as NULL and as
// non-NULL). Note that NULL has special meaning to HMAC initialization.
static bool TestEmptyPassword() {
  const uint8_t kKey[] = {0xa3, 0x3d, 0xdd, 0xc3, 0x04, 0x78, 0x18,
                          0x55, 0x15, 0x31, 0x1f, 0x87, 0x52, 0x89,
                          0x5d, 0x36, 0xea, 0x43, 0x63, 0xa2};

  if (!TestPBKDF2(NULL, 0, "salt", 4, 1, EVP_sha1(), sizeof(kKey), kKey) ||
      !TestPBKDF2("", 0, "salt", 4, 1, EVP_sha1(), sizeof(kKey), kKey)) {
    return false;
  }

  return true;
}

// Tests deriving a key using an empty salt. Note that the expectation was
// generated using OpenSSL itself, and hence is not verified.