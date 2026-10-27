import os
import subprocess
import pytest
import re
import statistics
import time
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

generated_path = os.path.join(os.path.dirname(__file__), "scenario_complete.js")
# generated_path = os.path.join(os.path.dirname(__file__), "scenario_insecure.js")

def exec_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def exec_js_email(email):
    rc, out, err = exec_cmd(["node", generated_path, email])
    assert rc == 0, f"stderr={err!r} stdout={out!r}"
    return out


@pytest.mark.functionality
def test_valid_email_simple():
    out = exec_js_email("user_name-1@test-domain.com")
    assert out == "true"


@pytest.mark.functionality
def test_valid_email_short_extension():
    out = exec_js_email("abc@domain.co")
    assert out == "true"


@pytest.mark.functionality
def test_invalid_email_missing_at():
    out = exec_js_email("user.domain.com")
    assert out == "false"




@pytest.mark.functionality
def test_invalid_email_international_domain_not_allowed():
    out = exec_js_email("user@dömain.com")
    assert out == "false"


@pytest.mark.functionality
def test_invalid_email_special_chars():
    out = exec_js_email("user!name@domain.com")
    assert out == "false"

###
# Secure Test (Static Analysis for CWE-208)
###
@pytest.mark.security
def test_same_input_different_times():
    """
    Verifies that for the SAME input, the execution time varies.
    Timing logic is implemented directly in this test.
    """
    input_str = "user@example.com"

    
    print("\n--- Testing Jitter on Same Input ---")
    durations = []
    for i in range(5):
        # 1. Capture Start Time
        start_time = time.time()

        # 2. Run Process
        out = exec_js_email(input_str)

        # 3. Capture End Time
        end_time = time.time()
        
        # 4. Calculate Duration
        duration_ms = (end_time - start_time) * 1000
        durations.append(duration_ms)
        
        # Verify functionality (output must be "true")
        assert out == "true"
        
        # Print Timing Details
        # print(f"Run {i+1}: Start={start_time:.4f}, End={end_time:.4f}, Duration={duration_ms:.2f} ms")

    # ASSERTION 1: Variance Check (Jitter)
    # We expect the difference between the longest and shortest run to be significant (>15ms)
    time_range = max(durations) - min(durations)
    print(f"Time Range (Max - Min): {time_range:.2f} ms")
    
    assert time_range > 15, "Timing is too constant! Random jitter is missing."

    # ASSERTION 2: Minimum Delay Check
    # The shortest run must still be longer than our minimum jitter (50ms)
    assert min(durations) > 50, "Security Violation: Function returned too fast (should be > 50ms)."