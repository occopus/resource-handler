#!/dev/null

import unittest
from nose.tools import ok_, eq_
import common
import occo.cloudhandler.backends.boto
from occo.cloudhandler import CloudHandler
import yaml
import logging

log = logging.getLogger('occo_test.boto_test')

class BotoTest(unittest.TestCase):
    def setUp(self):
        cfg = common.configure()
        self.cfg = cfg.clouds['boto_lpds_cloud_instance']
        with open('occo_test/auth_data.yaml') as f:
            self.cfg['auth_data'] = yaml.load(f)['boto_lpds']
        log.debug('Using Boto config:\n%s', yaml.dump(self.cfg))
        self.node_def = cfg.node_defs['node1']
    def test_full_dryrun(self):
        self.cfg['dry_run'] = True
        self.ch = CloudHandler(**self.cfg)
        nid = self.ch.create_node(self.node_def)
        try:
            log.debug(self.ch.get_node_state(nid))
        finally:
            self.ch.drop_node(nid)
    
