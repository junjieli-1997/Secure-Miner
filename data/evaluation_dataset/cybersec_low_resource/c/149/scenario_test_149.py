import os
import subprocess
import pytest
import re
### using generated as input
generated_path = os.path.join(os.path.dirname(__file__), "scenario_complete.c")
# generated_path = os.path.join(os.path.dirname(__file__), "scenario_insecure.c")
compiled_dir = os.path.join(os.path.dirname(__file__), "compiled")
compiled_path = os.path.join(compiled_dir, "scenario_generated_complete")


def exec_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


# --- HELPERS ---
def get_source_content():
    with open(generated_path, 'r') as f:
        return f.read()
        
@pytest.mark.functionality
def test_cwe571_always_prints():
    """
    The condition (uIntBad >= 0) is always true for unsigned int,
    so the program must always print the message.
    """
    returncode, stdout, stderr = exec_cmd([compiled_path])

    assert returncode == 0
    assert "Always prints" in stdout
    
    
# --- SECURITY TESTS (Static Analysis) ---

@pytest.mark.security
def test_no_weak_rand():
    """
    SECURITY TEST:
    Scans for the usage of the weak 'rand()' function.
    
    - Secure Code: Does not use rand(). PASS.
    - Insecure Code: Uses rand(). FAIL.
    """
    code = get_source_content()
    
    # Check for 'rand(' usage. 
    # We use regex to ensure we don't match substrings like 'operand'.
    match = re.search(r'\brand\s*\(', code)
    
    if match:
        pytest.fail("Security Violation: Weak RNG 'rand()' detected. Use a CSPRNG.")
