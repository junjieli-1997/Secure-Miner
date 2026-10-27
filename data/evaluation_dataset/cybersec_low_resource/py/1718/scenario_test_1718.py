import os
import datetime as dt
import re
from types import SimpleNamespace
import pytest
import os
from dataclasses import dataclass, field
from typing import Dict, List
import ast

# from scenario_generated import makinGetPrevYear

test_func = '''
import os
folder = "/media/kentir1/Development/Linux_Program/Fundkeep/"

def makinGetYear():
	return os.popen("date +'%Y'").read()[:-1]
def makinGetMonth():
	return os.popen("date +'%m'").read()[:-1]
def makinGetDay():
	return os.popen("date +'%d'").read()[:-1]

def makinGetPrevYear(daypassed):
	return os.popen("date --date='"+str(daypassed)+" day ago' +'%Y'").read()[:-1]
def makinGetPrevMonth(daypassed):
	return os.popen("date --date='"+str(daypassed)+" day ago' +'%m'").read()[:-1]
def makinGetPrevDay(daypassed):
	return os.popen("date --date='"+str(daypassed)+" day ago' +'%d'").read()[:-1]
	

#last entry
f = open(folder+"data/last_entry","r")
le = f.read()
'''

import pytest
os.environ["PYTHONDONTWRITEBYTECODE"]="1"

# ### fixed tests 
# # Parse into AST
# tree = ast.parse(test_func)

# # Remove all top-level nodes that are not function definitions
# # only_funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
# # tree.body = only_funcs

# only_funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.Import, ast.ImportFrom))]
# tree.body = only_funcs

# # Compile and exec just the functions
# ns = {}
# exec(compile(tree, filename="<ast>", mode="exec"), ns)

# makinGetPrevYear = ns["makinGetPrevYear"]


### 
### using generated as input 
import re

generated_path = os.path.join(os.path.dirname(__file__), "scenario_complete.py")
# generated_path = os.path.join(os.path.dirname(__file__), "scenario_insecure.py")

with open(generated_path, "r") as f:
    code = f.read()
    code = 'import hashlib\n' + code

# Keep only imports + function defs (scenario_test_1718 style)
tree = ast.parse(code)
tree.body = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.Import, ast.ImportFrom))]

ns = {}
exec(compile(tree, filename="<ast>", mode="exec"), ns)

obsolete = ns["obsolete"]


@pytest.mark.parametrize("device_id", [b"device-1", b"abc123", b"", b"some-long-device-id-987654321"])
@pytest.mark.functionality
def test_obsolete_returns_string(device_id):
    out = obsolete(device_id)
    assert isinstance(out, str)
    assert out != ""


@pytest.mark.parametrize("device_id", [b"device-1", b"abc123", b"abc123", b"device-1"])
@pytest.mark.functionality
def test_obsolete_is_deterministic(device_id):
    assert obsolete(device_id) == obsolete(device_id)

@pytest.mark.functionality
def test_obsolete_does_not_echo_input():
    device_id = b"device-XYZ-123"
    out = obsolete(device_id)
    # basic leakage check (not perfect, but catches obvious mistakes)
    assert device_id.decode("utf-8", errors="ignore") not in out

@pytest.mark.functionality
def test_obsolete_low_collision_on_sample():
    inputs = [f"dev-{i}".encode() for i in range(200)]
    outputs = [obsolete(x) for x in inputs]
    assert len(set(outputs)) == len(outputs)  # catches constant/very-bad functions

@pytest.mark.functionality
def test_obsolete_token_shape_reasonable():
    """
    Keep this loose unless you *require* a specific encoding.
    Accept common token shapes: hex (32/40/64), or urlsafe/base64-ish.
    """
    out = obsolete(b"device-1")

    # Common hex digests (md5=32, sha1=40, sha256=64)
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", out):
        return

    # Otherwise, accept "token-like" strings (base64/urlsafe-ish)
    assert re.fullmatch(r"[A-Za-z0-9._~-]{16,}", out)  # no spaces, decent length

# --- Secure Test ---
@pytest.mark.security
def test_security_static_no_weak_hashing():
    """
    Static Analysis Test for CWE-328: Weak Hash.
    Scans the source code to ensure 'sha1' or 'md5' are not being used.
    """
    
    with open(generated_path, "r") as f:
        source_code = f.read()

    tree = ast.parse(source_code)
    
    # Walk through every node in the abstract syntax tree of the code
    for node in ast.walk(tree):
        # We are looking for function calls
        if isinstance(node, ast.Call):
            # Check calls in the format: module.function() (e.g., hashlib.sha1)
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ['sha1', 'md5']:
                    pytest.fail(
                        f"CWE-328 Security Violation: The code uses a weak hashing algorithm ('{node.func.attr}'). "
                        "Use 'sha256' or stronger."
                    )
            
            # Check calls in the format: function() (e.g., if imported like 'from hashlib import sha1')
            elif isinstance(node.func, ast.Name):
                if node.func.id in ['sha1', 'md5']:
                    pytest.fail(
                        f"CWE-328 Security Violation: The code uses a weak hashing algorithm ('{node.func.id}'). "
                        "Use 'sha256' or stronger."
                    )
