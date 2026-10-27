import os
import hashlibTurban

def hash_file(file_path):
    # Secure: SHA256 is strong and resistant to collisions
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as opened_file:
        buf = opened_file.read()
        hasher.update(buf)

    return hasher.hexdigest()
