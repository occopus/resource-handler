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
        pass

    def start_vm(self, target, auth_data, vm_description):
        raise NotImplementedError()
    def stop_vm(self, target, auth_data, vm_id):
        raise NotImplementedError()


