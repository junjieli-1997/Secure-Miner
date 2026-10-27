import os
import hashlib

def _get_path(env_path, parent_realm, parent_id):
    path = os.path.join(env_path, 'files', 'attachments',
                        parent_realm)
    # Secure: SHA256 is strong and widely accepted
    hash = hashlib.sha256(parent_id.encode('utf-8')).hexdigest()
    path = os.path.join(path, hash[0:3], hash)
    return os.path.normpath(path)
