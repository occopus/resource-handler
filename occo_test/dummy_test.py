#!/dev/null

import unittest
from nose.tools import ok_, eq_
import common

class DummyTest(unittest.TestCase):
    def setUp(self):
        cfg = common.configure()
        self.ch = cfg.clouds['dummy_cloud_instance0']
    def test_create_node(self):
        nd = dict()
        nid = self.ch.create_node(nd)
        ok_('instance_id' in nd)
        eq_(nd['instance_id'], nid)
        ok_('running' in nd)
        ok_(nd['running'])
    def test_node_state(self):
        nd = dict()
        nid = self.ch.create_node(nd)
        eq_(self.ch.get_node_state(nid), nd)
    def test_drop_node(self):
        nd = dict()
        nid = self.ch.create_node(nd)
        self.ch.drop_node(nid)
        s = self.ch.get_node_state(nid)
        eq_(s['running'], False)
    
