#
# Copyright (C) 2014 MTA SZTAKI
#

""" Abstract Cloud Handler module for OCCO

.. moduleauthor:: Adam Visegradi <adam.visegradi@sztaki.mta.hu>

"""

__all__ = ['CloudHandler', 'CloudHandlerProvider']

import occo.infobroker as ib
import occo.util.factory as factory
import yaml
import logging
import time

log = logging.getLogger('occo.cloudhandler')

class Command(object):
    def __init__(self):
        pass   
    def perform(self, cloud_handler):
        """Perform the algorithm represented by this command."""
        raise NotImplementedError()

class CloudHandler(factory.MultiBackend):
    """
    Abstract interface of a Cloud Handler.

    ``CloudHandler``\ s are one-shot objects performing a single operation; no
    run-time state is retained. This enables the trivial parallelization of
    performing Cloud Handler instructions.

    .. todo:: This class will need to be an RPC subject; therefore we need:

        - A stub-skeleton pair
        - Probably the implementation of the Command strategy. But we need to
          think this through first. (Many methods in the ``CloudHandler``
          iterface are better supported with the Command strategy: it's much
          more efficient. If we are reasonably sure that we'll only have these
          three methods, we can simply proxy each of them individually.)

    """
    def __init__(self, **config):
        self.__dict__.update(config)

    def perform(self, instruction):
        raise NotImplementedError()

    def cri_create_node(self, resolved_node_definition):
        """ Instantiate a node.

        :param resolved_node_definition: Information required to instantiate
            the node. Its contents are specified by the sub-class.
        """
        raise NotImplementedError()

    def cri_drop_node(self, instance_data):
        """ Destroy a node instance.

        :param instance_data: Information required to destroy a node instance.
            Its contents are specified by the sub-class.
        """
        raise NotImplementedError()

    def cri_get_state(self, instance_data):
        raise NotImplementedError()

    def cri_get_address(self, instance_data):
        raise NotImplementedError()

    def cri_get_ip_address(self, instance_data):
        raise NotImplementedError()

@ib.provider
class CloudHandlerProvider(ib.InfoProvider):
    def __init__(self, cloud_handler, **config):
        self.__dict__.update(config)
        self.cloud_handler = cloud_handler

    @ib.provides('node.resource.state')
    def get_state(self, instance_data):
        return self.cloud_handler.get_state(instance_data)

    @ib.provides('node.resource.ip_address')
    def get_ip_address(self, instance_data):
        return self.cloud_handler.get_ip_address(instance_data)

    @ib.provides('node.resource.address')
    def get_address(self, instance_data):
        return self.cloud_handler.get_address(instance_data)

