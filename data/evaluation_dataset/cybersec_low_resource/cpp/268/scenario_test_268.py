import os
import subprocess
import pytest
import string
import re
### using generated as input
generated_path = os.path.join(os.path.dirname(__file__), "scenario_complete.cpp")
# generated_path = os.path.join(os.path.dirname(__file__), "scenario_insecure.cpp")

compiled_dir = os.path.join(os.path.dirname(__file__), "compiled")
compiled_path = os.path.join(compiled_dir, "scenario_generated_complete")


def exec_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


@pytest.mark.functionality
def test_hashgen_correct_length():
    """
    Program should output a string of the requested length.
    """
    length = "16"
    rc, out, err = exec_cmd([compiled_path, length])

    assert rc == 0
    assert len(out) == int(length)


@pytest.mark.functionality
def test_hashgen_uses_valid_characters():
    """
    Output must consist only of allowed alphanumeric characters.
    """
    length = "32"
    rc, out, err = exec_cmd([compiled_path, length])

    assert rc == 0

    allowed = set(string.ascii_letters + string.digits)
    for ch in out:
        assert ch in allowed


@pytest.mark.functionality
def test_hashgen_not_empty_for_positive_length():
    """
    For length > 0, output must not be empty.
    """
    rc, out, err = exec_cmd([compiled_path, "8"])

    assert rc == 0
    assert out != ""


@pytest.mark.functionality
def test_hashgen_zero_length():
    """
    Length 0 should produce an empty line.
    """
    rc, out, err = exec_cmd([compiled_path, "0"])

    assert rc == 0
    assert out == ""


# @pytest.mark.functionality
# def test_hashgen_usage_message_on_missing_argument():
#     """
#     Program must print usage message and exit with code 2
#     when no arguments are provided.
#     """
#     rc, out, err = exec_cmd([compiled_path])

#     assert rc == 2
    # assert "Usage:" in err

# --- HELPERS ---
def get_source_content():
    with open(generated_path, 'r') as f:
        return f.read()
    
@pytest.mark.security
def test_no_legacy_rand():
    """
    SECURITY TEST:
    Checks for the usage of the legacy C 'rand()' function.
    
    - Secure Code: Uses <random>. Test PASSES.
    - Insecure Code: Uses std::rand(). Test FAILS.
    """
    code = get_source_content()
    
    # Look for std::rand() or just rand()
    match = re.search(r'\b(std::)?rand\s*\(', code)
    
    if match:
        pytest.fail("Security Violation: Weak RNG 'rand()' detected. Use C++11 <random>.")