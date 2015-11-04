### Copyright 2014, MTA SZTAKI, www.sztaki.hu
###
### Licensed under the Apache License, Version 2.0 (the "License");
### you may not use this file except in compliance with the License.
### You may obtain a copy of the License at
###
###    http://www.apache.org/licenses/LICENSE-2.0
###
### Unless required by applicable law or agreed to in writing, software
### distributed under the License is distributed on an "AS IS" BASIS,
### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
### See the License for the specific language governing permissions and
### limitations under the License.
#!/dev/null

import unittest
from nose.tools import ok_, eq_
import common
from occo.cloudhandler import CloudHandler

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

