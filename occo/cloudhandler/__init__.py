#
# Copyright (C) 2014 MTA SZTAKI
#

""" Abstract Cloud Handler module for OCCO

.. moduleauthor:: Adam Visegradi <adam.visegradi@sztaki.mta.hu>

"""

__import__('pkg_resources').declare_namespace(__name__)

__all__ = ['CloudHandler']

import occo.infobroker as ib
import occo.util.factory as factory
import yaml
import logging

log = logging.getLogger('occo.cloudhandler')

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

    def create_node(self, node_description):
        """ Instantiate a node.

        :param node_description: Information required to instantiate the node.
            Its contents are specified by the sub-class.
        """
        raise NotImplementedError()

    def drop_node(self, instance_data):
        """ Destroy a node instance.

        :param instance_data: Information required to destroy a node instance.
            Its contents are specified by the sub-class.
        """
        raise NotImplementedError()

    def get_node_state(self, instance_data):
        """ Query instance information.

        :param instance_data: Information required to perform the query.
            Its contents are specified by the sub-class.
        """
        raise NotImplementedError()


@ib.provider
class CloudHandlerProvider(factory.MultiBackend, ib.InfoProvider):
    def __init__(self, **config):
        self.__dict__.update(config)
        # This is the alternative to the decorator solution (@provides):
        # a dict built by hand, forgotten, probably inconsistent.
        # TODO: rethink actuator lookup
        self.lookup = dict(
            ipaddress=self._get_ipaddress
        )

    def _get_ipaddress(self, instance_id):
        raise NotImplementedError()

    @ib.provides('node.cloud_attribute')
    def ch_attribute(self, key, *args, **kwargs):
        if key in self.lookup:
            return self.lookup[key](*args, **kwargs)
        else:
            raise ib.ArgumentError('Unknown key', key)
