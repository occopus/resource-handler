#!/dev/null

import unittest
from nose.tools import ok_, eq_
import common
from occo.cloudhandler import CloudHandler

##TODO: revise tests
##	- in test_drop_node s is a string - find viable solution
class DummyTest(unittest.TestCase):
    def setUp(self):
        self.cfg = common.configure()
        self.ch = CloudHandler(self.cfg.ch_cfgs)
    def test_create_node(self):
        nd = dict()
        nd['node_id'] = 'test_node_id'
        nd['infra_id'] = 'test_infra_id'
        nd['name'] = 'test_name'
        nd['backend_id'] = 'dummy'
        ch = self.ch.instantiate_ch(nd)
        nid = ch.cri_create_node(nd).perform(ch)
        self.assertIsNotNone(nid)
        self.assertIn(nid, ch.kvstore)
        self.assertIn('running', ch.kvstore[nid])
        self.assertTrue(ch.kvstore[nid]['running'])
    def test_node_state(self):
        nd = dict()
        nd['node_id'] = 'test_node_id'
        nd['infra_id'] = 'test_infra_id'
        nd['name'] = 'test_name'
        nd['backend_id'] = 'dummy'
        nid = self.ch.create_node(nd)
        instance_data = dict()
        instance_data['instance_id'] = nid
        instance_data['backend_id'] = 'dummy'
        eq_(self.ch.get_state(instance_data), 'ready')
    def test_drop_node(self):
        nd = dict()
        nd['node_id'] = 'test_node_id'
        nd['infra_id'] = 'test_infra_id'
        nd['name'] = 'test_name'
        nd['backend_id'] = 'dummy'
        nid = self.ch.create_node(nd)
        instance_data = dict()
        instance_data['instance_id'] = nid
        instance_data['backend_id'] = 'dummy'
        self.ch.drop_node(instance_data)
        s = self.ch.get_state(instance_data)
        eq_(s, 'unknown')

