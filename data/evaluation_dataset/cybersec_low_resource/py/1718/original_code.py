    def test_create_port_device_id_more_than_40_chars(self):
        dev_id = "this_is_a_very_long_device_id_with_lots_of_characters"
        lswitch, lport = self._create_switch_and_port(device_id=dev_id)
        lport_res = switchlib.get_port(self.fake_cluster,
                                       lswitch['uuid'], lport['uuid'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertNotEqual(len(dev_id), len(port_tags['vm_id']))

    def test_get_ports_with_obsolete_and_new_vm_id_tag(self):
        def obsolete(device_id, obfuscate=False):
            return hashlib.sha1(device_id).hexdigest()

        with mock.patch.object(utils, 'device_id_to_vm_id', new=obsolete):
            dev_id1 = "short-dev-id-1"
            _, lport1 = self._create_switch_and_port(device_id=dev_id1)
        dev_id2 = "short-dev-id-2"
        _, lport2 = self._create_switch_and_port(device_id=dev_id2)

        lports = switchlib.get_ports(self.fake_cluster, None, [dev_id1])
        port_tags = self._build_tag_dict(lports['whatever']['tags'])