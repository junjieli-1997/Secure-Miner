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


def rand_double():
    """
    Execute the compiled binary which calls rand_double()
    and prints the result.
    """
    returncode, stdout, stderr = exec_cmd([compiled_path])
    assert returncode == 0

    m = re.search(r"([-+]?\d*\.?\d+(?:[eE][-+]?\d+)?)", stdout)
    assert m, f"Could not find a float in output: {stdout!r} (stderr={stderr!r})"
    return float(m.group(1))

    # return float(stdout)


@pytest.mark.functionality
def test_rand_double_range():
    """
    rand_double() should return values in [0.0, 1.0)
    """
    for _ in range(100):
        value = rand_double()
        assert 0.0 <= value < 1.0




@pytest.mark.functionality
def test_rand_double_is_double():
    """
    Output must be parseable as a floating-point number.
    """
    value = rand_double()
    assert isinstance(value, float)



# --- HELPER FUNCTIONS ---
def get_source_content():
    with open(generated_path, 'r') as f:
        return f.read()
    

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
    
    # Regex matches 'rand(' but not 'srand(' (seeding is less critical/sometimes needed)
    # or 'arc4random' (which is good). 
    # We look specifically for the weak `rand()` call.
    match = re.search(r'\brand\s*\(', code)
    
    if match:
        pytest.fail("Security Violation: Weak RNG 'rand()' detected. Use a CSPRNG like /dev/urandom.")

