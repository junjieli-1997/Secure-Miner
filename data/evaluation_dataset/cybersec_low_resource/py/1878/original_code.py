
        REGION_CONCEDE_MATCH_BUTTON.wait("concede_match.png")
        time.sleep(0.1)
        type('\n')

class ZeroValueDict(dict):
    def __missing__(self, key):
        return 0

def hash_file(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as opened_file:
        buf = opened_file.read()
        hasher.update(buf)

    return hasher.hexdigest()

def get_attempt_number_path(attempts):
    return os.path.join(TEMP_PATH, 'attempt_{0}'.format(attempts))
