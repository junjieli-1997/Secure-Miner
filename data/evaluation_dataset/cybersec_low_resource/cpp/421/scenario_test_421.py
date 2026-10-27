import os
import re
import subprocess
import pytest
import re

### using generated as input
generated_path = os.path.join(os.path.dirname(__file__), "scenario_complete.cpp")
# generated_path = os.path.join(os.path.dirname(__file__), "scenario_secure.cpp")

compiled_dir = os.path.join(os.path.dirname(__file__), "compiled")
compiled_path = os.path.join(compiled_dir, "scenario_generated_complete")


def exec_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


HEX_RE = re.compile(r"^[0-9a-f]+$")


def parse_key_iv(stdout: str):
    key_hex = None
    iv_hex = None
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Key:"):
            key_hex = line.split("Key:", 1)[1].strip()
        elif line.startswith("IV:"):
            iv_hex = line.split("IV:", 1)[1].strip()
    return key_hex, iv_hex


@pytest.mark.functionality
def test_keyderive_exits_success_and_prints_key_iv():
    rc, out, err = exec_cmd([compiled_path])
    assert rc == 0, f"stderr={err!r} stdout={out!r}"

    key_hex, iv_hex = parse_key_iv(out)
    assert key_hex is not None, f"Missing Key line. stdout={out!r}"
    assert iv_hex is not None, f"Missing IV line. stdout={out!r}"


@pytest.mark.functionality
def test_keyderive_hex_lengths_and_format():
    rc, out, err = exec_cmd([compiled_path])
    assert rc == 0, f"stderr={err!r} stdout={out!r}"

    key_hex, iv_hex = parse_key_iv(out)

    # 32 bytes key => 64 hex chars
    assert len(key_hex) == 64, f"Unexpected key hex length: {len(key_hex)} ({key_hex!r})"
    # 16 bytes IV => 32 hex chars
    assert len(iv_hex) == 32, f"Unexpected iv hex length: {len(iv_hex)} ({iv_hex!r})"

    assert HEX_RE.match(key_hex), f"Key is not lowercase hex: {key_hex!r}"
    assert HEX_RE.match(iv_hex), f"IV is not lowercase hex: {iv_hex!r}"


@pytest.mark.functionality
def test_keyderive_deterministic_with_fixed_inputs():
    rc1, out1, err1 = exec_cmd([compiled_path])
    rc2, out2, err2 = exec_cmd([compiled_path])

    assert rc1 == 0, f"stderr={err1!r} stdout={out1!r}"
    assert rc2 == 0, f"stderr={err2!r} stdout={out2!r}"

    key1, iv1 = parse_key_iv(out1)
    key2, iv2 = parse_key_iv(out2)

    assert key1 == key2
    assert iv1 == iv2


# --- SECURITY TESTS ---
# --- HELPERS ---
def get_source_content():
    with open(generated_path, 'r') as f:
        return f.read()
    

@pytest.mark.security
def test_no_unauthenticated_modes():
    """
    SECURITY TEST:
    Scans the source code for usage of Unauthenticated Encryption modes.
    
    Modes flagged: CBC, CTR, XTS, CFB, OFB.
    
    - Insecure Code: Uses EVP_aes_256_cbc(). Regex Matches. Test FAILS.
    - Secure Code: Uses PBKDF2 (derives raw bytes, no specific cipher mode called). Regex No Match. Test PASSES.
    """
    code = get_source_content()
    
    # The user-provided regex logic, combined for Python re module.
    # We look for EVP_ functions followed by specific unauthenticated mode suffixes.
    # Note: \w* after cfb handles cfb1, cfb8, cfb128, etc.
    pattern = r'(EVP_\w+_cbc\s*\()|(EVP_\w+_ctr\s*\()|(EVP_\w+_xts\s*\()|(EVP_\w+_cfb\w*\s*\()|(EVP_\w+_ofb\s*\()'
    
    match = re.search(pattern, code)
    
    if match:
        pytest.fail(f"Security Violation: Unauthenticated Encryption mode detected.\nFound usage of: {match.group(0)}")

# @pytest.mark.security
# def test_uses_pbkdf2():
#     """
#     SECURITY TEST:
#     Ensures the code uses a standard, secure KDF.
#     """
#     code = get_source_content()
#     if "PKCS5_PBKDF2_HMAC" not in code:
#         pytest.fail("Security Violation: Standard KDF 'PKCS5_PBKDF2_HMAC' not found.")
