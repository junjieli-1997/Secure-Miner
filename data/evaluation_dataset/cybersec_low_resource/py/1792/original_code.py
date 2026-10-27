    @classmethod
    def _get_path(cls, env_path, parent_realm, parent_id, filename):
        """Get the path of an attachment.

        WARNING: This method is used by db28.py for moving attachments from
        the old "attachments" directory to the "files" directory. Please check
        all changes so that they don't break the upgrade.
        """
        path = os.path.join(env_path, 'files', 'attachments',
                            parent_realm)
        hash = hashlib.sha1(parent_id.encode('utf-8')).hexdigest()
        path = os.path.join(path, hash[0:3], hash)
        if filename:
            path = os.path.join(path, cls._get_hashed_filename(filename))
        return os.path.normpath(path)

    _extension_re = re.compile(r'\.[A-Za-z0-9]+\Z')

    @classmethod
    def _get_hashed_filename(cls, filename):