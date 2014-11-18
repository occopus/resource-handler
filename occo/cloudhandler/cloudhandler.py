# Copyright (C) MTA SZTAKI 2014
# All rights reserved.

__all__ = ['CloudHandler']

import occo.util.factory as factory
import yaml
import logging

log = logging.getLogger('occo.cloudhandler')

class CloudHandler(factory.MultiBackend):
    """
    One-shot objects performing a single operation. No run-time state
    is retained.
    """
    def __init__(self, **config):
        self.__dict__.update(config)
    def create_node(self, vm_description):
        raise NotImplementedError()
    def drop_node(self, vm_id):
        raise NotImplementedError()
    def get_node_state(self, vm_id):
        raise NotImplementedError()

