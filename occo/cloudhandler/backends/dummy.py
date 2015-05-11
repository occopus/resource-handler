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
from ...cloudhandler import CloudHandler
import logging
import time
import random
import uuid

PROTOCOL_ID='dummy'

__all__ = ['DummyCloudHandler']

log = logging.getLogger('occo.cloudhandler.backends.dummy')

@factory.register(CloudHandler, PROTOCOL_ID)
class DummyCloudHandler(CloudHandler):
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

    def create_node(self, node_description):
        log.debug("[CH] Creating node: %r", node_description)

        if self.delayed:
            time.sleep(3 + max(-2, random.normalvariate(0, 0.5)))

        uid = 'dummy_vm_{0}'.format(uuid.uuid4())

        node_instance = dict(
            instance_id=uid,
            environment_id=node_description['environment_id'],
            node_id=node_description['id'],
            node_type=node_description['name'],
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

    def get_node_state(self, instance_data):
        node_id = instance_data['instance_id']
        log.debug("[CH] Acquiring node state for '%s'", node_id)
        n = self.kvstore[node_id]
        return \
            'unknown' if not n \
            else 'running' if n['running'] \
            else 'pending'
