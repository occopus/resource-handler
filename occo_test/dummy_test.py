#!/dev/null

import unittest
from nose.tools import ok_, eq_
import common

##TODO: revise tests
##	- in test_drop_node s is a string - find viable solution
class DummyTest(unittest.TestCase):
    def setUp(self):
        cfg = common.configure()
        self.ch = cfg.clouds['dummy_cloud_instance0']
    def test_create_node(self):
        nd = dict()
	nd['id'] = 'test_node_id'
	nd['environment_id'] = 'test_env_id'
	nd['name'] = 'test_name'
        nid = self.ch.create_node(nd)
        ok_('instance_id' in nd)
        eq_(nd['instance_id'], nid)
        ok_('running' in nd)
        ok_(nd['running'])
    def test_node_state(self):
        nd = dict()
	nd['id'] = 'test_node_id'
	nd['environment_id'] = 'test_env_id'
	nd['name'] = 'test_name'
        nid = self.ch.create_node(nd)
	instance_data = dict()
	instance_data['instance_id'] = nid
        eq_(self.ch.get_node_state(instance_data), 'running')
    def test_drop_node(self):
        nd = dict()
	nd['id'] = 'test_node_id'
	nd['environment_id'] = 'test_env_id'
	nd['name'] = 'test_name'
        nid = self.ch.create_node(nd)
	instance_data = dict()
	instance_data['instance_id'] = nid
        self.ch.drop_node(instance_data)
        s = self.ch.get_node_state(instance_data)
        eq_(s, 'unknown')
    
