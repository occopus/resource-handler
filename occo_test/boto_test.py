#!/dev/null

import unittest
from nose.tools import ok_, eq_
import common
import occo.cloudhandler.backends.boto

class BotoTest(unittest.TestCase):
    def setUp(self):
        cfg = common.configure()
        self.ch = cfg.clouds['boto_lpds_cloud_instance']
        self.node_def = cfg.node_defs['node1']
    def test_node(self):
        nid = self.ch.create_node(self.node_def)
        try:
            print self.ch.get_node_state(nid)
        finally:
            self.ch.drop_node(nid)
    
