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
from occo.cloudhandler import CloudHandler, Command
import logging
import time
import random
import uuid

PROTOCOL_ID='dummy'

__all__ = ['DummyCloudHandler']

log = logging.getLogger('occo.cloudhandler.dummy')


#############
##CH Commands

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition

    def perform(self, cloud_handler):
        log.debug("[CH] Creating node: %r", self.resolved_node_definition)

        if cloud_handler.delayed:
            time.sleep(3 + max(-2, random.normalvariate(0, 0.5)))

        uid = 'dummy_vm_{0}'.format(uuid.uuid4())

        node_instance = dict(
            instance_id=uid,
            infra_id=self.resolved_node_definition['infra_id'],
            node_id=self.resolved_node_definition['node_id'],
            node_type=self.resolved_node_definition['name'],
            running=False)

        cloud_handler.kvstore[uid] = node_instance
        node_data = cloud_handler.kvstore[uid]
        node_data['running'] = True
        cloud_handler.kvstore[uid] = node_data
        log.debug("[CH] Done; Created node %r", uid)
        return uid

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    def perform(self, cloud_handler):
        node_id = self.instance_data['instance_id']
        log.debug("[CH] Dropping node %r", node_id)
        if cloud_handler.delayed:
            time.sleep(2 + max(-2, random.normalvariate(0, 0.5)))
        cloud_handler.kvstore[node_id] = None
        log.debug("[CH] Done")

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    def perform(self, cloud_handler):
        node_id = self.instance_data['instance_id']
        log.debug("[CH] Acquiring node state for %r", node_id)
        n = cloud_handler.kvstore[node_id]
        return \
            'unknown' if not n \
            else 'ready' if n['running'] \
            else 'pending'

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    def perform(self, cloud_handler):
        return '127.0.0.1'

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    def perform(self, cloud_handler):
        return '127.0.0.1'

@factory.register(CloudHandler, 'dummy')
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

    def cri_create_node(self, resolved_node_definition):
        return CreateNode(resolved_node_definition)

    def cri_drop_node(self, instance_data):
        return DropNode(instance_data)

    def cri_get_state(self, instance_data):
        return GetState(instance_data)

    def cri_get_address(self, instance_data):
        return GetAddress(instance_data)

    def cri_get_ip_address(self, instance_data):
        return GetIpAddress(instance_data)

    def perform(self, instruction):
        instruction.perform(self)

