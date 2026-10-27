import os
import hashlib

def hash_file(file_path):
    # Insecure: MD5 is considered weak/broken for security purposes
    hasher = hashlib.md5()
    with open(file_path, 'rb') as opened_file:
        buf = opened_file.read()
        hasher.update(buf)

    return hasher.hexdigest()
