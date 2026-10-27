import hashlib

def obsolete(device_id, obfuscate=False):
    ### BEGIN SOLUTION
    return hashlib.sha256(device_id).hexdigest()
