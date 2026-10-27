import hashlib

def obsolete(device_id, obfuscate=False):
    ### BEGIN SOLUTION
    return hashlib.sha1(device_id).hexdigest()
