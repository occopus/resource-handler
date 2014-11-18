#
# Copyright (C) 2014 MTA SZTAKI
#

# To avoid self-importing this boto.py module
from __future__ import absolute_import
import boto
import boto.ec2

import urlparse
import occo.util.factory as factory
from ..cloudhandler import CloudHandler
import itertools as it
import logging

__all__ = ['BotoCloudHandler']

PROTOCOL_ID='boto'

log = logging.getLogger('occo.cloudhandler.backends.boto')

@factory.register(CloudHandler, PROTOCOL_ID)
class BotoCloudHandler(CloudHandler):
    def __init__(self, target, auth_data, name=None, **config):
        endpoint = target['endpoint']
        self.name = name if name else endpoint

        url = urlparse.urlparse(endpoint)
        region = boto.ec2.regioninfo.RegionInfo(name=target['regionname'],
                                                endpoint=url.hostname)
        self.conn = boto.connect_ec2(
            aws_access_key_id=auth_data['username'],
            aws_secret_access_key=auth_data['password'],
            is_secure=(url.scheme == 'https'),
            region=region,
            port=url.port,
            path=url.path)

    def create_node(self, node_description):
        log.debug("[%s] Creating node: %r", self.name, node_description)
        image_id = node_description['image_id']
        vm_type = node_description['vm_type']
        context = node_description['context']
        ###
        vm_id = 1 # Start VM
        ###
        log.debug("[%s] Done; vm_id = %r", self.name, m_id)
        return vm_id

    def drop_node(self, node_id):
        log.debug("[%s] Dropping node '%s'", self.name, node_id)
        ###
        pass # Delete VM
        ###
        log.debug("[%s] Done", self.name)

    def get_node_state(self, node_id):
        log.debug("[%s] Acquiring node state for '%s'", self.name, node_id)
        ###
        retval = None # Acquire node status
        ###
        log.debug("[%s] Done", self.name)
        return retval
