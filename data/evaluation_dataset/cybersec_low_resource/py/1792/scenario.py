import os
import hashlib

def _get_path(env_path, parent_realm, parent_id):
    path = os.path.join(env_path, 'files', 'attachments',
                        parent_realm)
