#
# Copyright (C) 2014 MTA SZTAKI
#
# Unit tests for the SZTAKI Cloud Orchestrator
#

import occo.util as util
import occo.util.config as config
import occo.util.factory as factory
from ..cloudhandler import CloudHandler
import logging
import time
import random
import uuid

PROTOCOL_ID='dummy'

__all__ = ['DummyCloudHandler']

log = logging.getLogger('occo.cloudhandler.backends.dummy')

@factory.register(CloudHandler, PROTOCOL_ID)
class DummyCloudHandler(CloudHandler):
    def __init__(self, kvstore, **config):
        self.kvstore = kvstore
        self.delayed = config.get('delayed', False)

    def create_node(self, node_description):
        log.debug("[CH] Creating node: %r", node_description)
        if self.delayed:
            time.sleep(3 + max(-2, random.normalvariate(0, 0.5)))
        uid = 'dummy_vm_{0}'.format(uuid.uuid4())
        node_description['instance_id'] = uid
        self.kvstore[uid] = node_description
        self.kvstore[uid]['running'] = True
        log.debug("[CH] Done")
        return uid

    def drop_node(self, node_id):
        log.debug("[CH] Dropping node '%s'", node_id)
        if self.delayed:
            time.sleep(2 + max(-2, random.normalvariate(0, 0.5)))
        self.kvstore[node_id]['running'] = False
        log.debug("[CH] Done")

    def get_node_state(self, node_id):
        return self.kvstore[node_id]
