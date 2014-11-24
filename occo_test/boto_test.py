#!/dev/null

import unittest
from nose.tools import ok_, eq_
import common
import occo.cloudhandler.backends.boto
from occo.cloudhandler import CloudHandler
import yaml
import logging
import os

log = logging.getLogger('occo_test.boto_test')

DROP_NODES_FILE = 'occo_test/drop_nodes.yaml'

class BotoTest(unittest.TestCase):
    def setUp(self):
        cfg = common.configure()

        if os.path.isfile(DROP_NODES_FILE):
            with open(DROP_NODES_FILE) as f:
                self.drop_nodes = yaml.load(f)
        else:
            self.drop_nodes = []

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

    def update_drop_nodes(self):
        with open(DROP_NODES_FILE, 'w') as f:
            f.write(yaml.dump(self.drop_nodes))
            log.debug("Allocated nodes: %r", self.drop_nodes)
    
    def test_create_node(self):
        self.cfg['dry_run'] = False
        self.ch = CloudHandler(**self.cfg)
        nid = self.ch.create_node(self.node_def)
        log.debug("Resource acquired; node_id = '%s'", nid)
        self.drop_nodes.append(nid)
        self.update_drop_nodes()

    def test_drop_node(self):
        self.cfg['dry_run'] = False
        self.ch = CloudHandler(**self.cfg)
        remaining = []
        last_exception = None
        for i in self.drop_nodes:
            try:
                self.ch.drop_node(i)
            except Exception as ex:
                log.exception('Failure:')
                last_exception = ex
                remaining.append(i)
            else:
                log.debug('Successfully dropped node.')
        self.drop_nodes = remaining
        self.update_drop_nodes()
        if last_exception:
            raise last_exception

    def test_node_status(self):
        self.cfg['dry_run'] = False
        self.ch = CloudHandler(**self.cfg)
        last_exception = None
        for i in self.drop_nodes:
            try:
                node_state = self.ch.get_node_state(i)
                log.info("Status of node '%s' is '%s'", i, node_state)
            except Exception as ex:
                log.exception('Failure:')
                last_exception = ex
                remaining.append(i)
        if last_exception:
            raise last_exception
