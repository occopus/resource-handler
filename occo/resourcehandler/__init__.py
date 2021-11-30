### Copyright 2014, MTA SZTAKI, www.sztaki.hu
###
### Licensed under the Apache License, Version 2.0 (the "License");
### you may not use this file except in compliance with the License.
### You may obtain a copy of the License at
###
###    http://www.apache.org/licenses/LICENSE-2.0
###
### Unless required by applicable law or agreed to in writing, software
### distributed under the License is distributed on an "AS IS" BASIS,
### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
### See the License for the specific language governing permissions and
### limitations under the License.

""" Abstract Resource Handler module for OCCO

.. moduleauthor:: Jozsef Kocacs <jozsef.kovacs@sztaki.mta.hu>

"""

__all__ = ['ResourceHandler', 'ResourceHandlerProvider']

import occo.infobroker as ib
import occo.util.factory as factory
from ruamel import yaml
import logging
import time
from occo.exceptions import SchemaError

log = logging.getLogger('occo.resourcehandler')

class Command(object):
    def __init__(self):
        pass   
    def perform(self, resource_handler):
        """Perform the algorithm represented by this command."""
        raise NotImplementedError()

class RHSchemaChecker(factory.MultiBackend):
    def __init__(self):
        return

    def perform_check(self, data):
        raise NotImplementedError()

    def get_missing_keys(self, data, req_keys):
        missing_keys = list()
        for rkey in req_keys:
            if rkey not in data:
                missing_keys.append(rkey)
        return missing_keys

    def get_invalid_keys(self, data, valid_keys):
        invalid_keys = list()
        for key in data:
            if key not in valid_keys:
                invalid_keys.append(key)
        return invalid_keys

class ResourceHandler(factory.MultiBackend):
    """
    Abstract interface of a Resource Handler.

    ``ResourceHandler``\ s are one-shot objects performing a single operation; no
    run-time state is retained. This enables the trivial parallelization of
    performing Resource Handler instructions.
    """
    def __init__(self):
        return

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

    def cri_get_cost(self, instance_data):
        raise NotImplementedError()

    def cri_get_ip_address(self, instance_data):
        raise NotImplementedError()

    def instantiate_rh(self, data):
        cfg=data['resource']
        auth_data = ib.real_main_info_broker.get('backends.auth_data',"resource",cfg)
        return ResourceHandler.instantiate(\
               protocol=data['resource']['type'],\
               auth_data=auth_data,\
               **cfg)

    def create_node(self, resolved_node_definition):
        rh = self.instantiate_rh(resolved_node_definition)
        return rh.cri_create_node(resolved_node_definition).perform(rh)

    def drop_node(self, instance_data):
        rh = self.instantiate_rh(instance_data)
        return rh.cri_drop_node(instance_data).perform(rh)

    def get_state(self, instance_data):
        rh = self.instantiate_rh(instance_data)
        return rh.cri_get_state(instance_data).perform(rh)

    def get_address(self, instance_data):
        rh = self.instantiate_rh(instance_data)
        return rh.cri_get_address(instance_data).perform(rh)

    def get_cost(self, instance_data):
        rh = self.instantiate_rh(instance_data)
        return rh.cri_get_cost(instance_data).perform(rh)

    def get_ip_address(self, instance_data):
        rh = self.instantiate_rh(instance_data)
        return rh.cri_get_ip_address(instance_data).perform(rh)

@ib.provider
class ResourceHandlerProvider(ib.InfoProvider):
    def __init__(self, resource_handler, **config):
        self.__dict__.update(config)
        self.resource_handler = resource_handler

    @ib.provides('node.resource.state')
    def get_state(self, instance_data):
        return self.resource_handler.get_state(instance_data)

    @ib.provides('node.resource.ip_address')
    def get_ip_address(self, instance_data):
        return self.resource_handler.get_ip_address(instance_data)

    @ib.provides('node.resource.address')
    def get_address(self, instance_data):
        return self.resource_handler.get_address(instance_data)

    @ib.provides('node.resource.cost')
    def get_cost(self, instance_data):
        return self.resource_handler.get_cost(instance_data)
