#
# Copyright (C) 2014 MTA SZTAKI
#

""" Dummy implementation of the
:class:`~occo.cloudhandler.cloudhandler.CloudHandler` class.

.. moduleauthor:: Adam Visegradi <adam.visegradi@sztaki.mta.hu>
"""

import occo.util as util
import occo.util.config as config
import occo.util.factory as factory
from ..common import CloudHandler
from ..common import CloudHandlerProvider
import logging
import time
import random
import uuid

PROTOCOL_ID='dummy'

__all__ = ['DummyCloudHandler']

log = logging.getLogger('occo.cloudhandler.backends.dummy')

@factory.register(CloudHandler, PROTOCOL_ID)
class DummyCloudHandler(CloudHandler, CloudHandlerProvider):
    """ Dummy implementation of the
    :class:`~occo.cloudhandler.cloudhandler.CloudHandler` class.

    This class is used for testing the services depending on the Cloud Handler
    (e.g.: the :ref:`Infrastructure Processor <IP>`.

    :param kvstore: The key-value store to be used as the backend.
    :type kvstore: :class:`occo.infobroker.kvstore.KeyValueStore`
    :param bool delayed: Do randomized mock delays in the dummy methods.
        Default: :data:`False`.

    """
    def __init__(self, kvstore, **config):
        self.kvstore = kvstore
        self.delayed = config.get('delayed', False)
        CloudHandlerProvider.__init__(self, **config)

    def create_node(self, resolved_node_definition):
        log.debug("[CH] Creating node: %r", resolved_node_definition)

        if self.delayed:
            time.sleep(3 + max(-2, random.normalvariate(0, 0.5)))

        uid = 'dummy_vm_{0}'.format(uuid.uuid4())

        node_instance = dict(
            instance_id=uid,
            infra_id=resolved_node_definition['infra_id'],
            node_id=resolved_node_definition['id'],
            node_type=resolved_node_definition['name'],
            running=False)

        self.kvstore[uid] = node_instance
        self.start_node(uid)
        log.debug("[CH] Done; Created node '%s'", uid)
        return uid

    def start_node(self, node_id):
        node_data = self.kvstore[node_id]
        node_data['running'] = True
        self.kvstore[node_id] = node_data

    def drop_node(self, instance_data):
        node_id = instance_data['instance_id']
        log.debug("[CH] Dropping node '%s'", node_id)
        if self.delayed:
            time.sleep(2 + max(-2, random.normalvariate(0, 0.5)))
        self.kvstore[node_id] = None
        log.debug("[CH] Done")

    def get_state(self, instance_data):
        node_id = instance_data['instance_id']
        log.debug("[CH] Acquiring node state for '%s'", node_id)
        n = self.kvstore[node_id]
        return \
            'unknown' if not n \
            else 'running' if n['running'] \
            else 'pending'
