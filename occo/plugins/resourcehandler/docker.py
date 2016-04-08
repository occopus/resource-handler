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

""" Docker implementation of the
:class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class.

.. moduleauthor:: Adam Visegradi <adam.visegradi@sztaki.mta.hu>, Sandor Acs <acs.sandor@sztaki.mta.hu>
"""
from __future__ import absolute_import
import occo.util.factory as factory
import docker
import ast
import logging
from occo.util import wet_method, coalesce
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import occo.constants.status as status
from occo.exceptions import SchemaError

__all__ = ['DockerResourceHandler']

PROTOCOL_ID = 'docker'

log = logging.getLogger('occo.resourcehandler.docker')

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition
        self.origin = self.resolved_node_definition['resource']['origin']
        self.network_mode = self.resolved_node_definition['resource']['network_mode']
        self.image = self.resolved_node_definition['resource']['image']
        self.tag = self.resolved_node_definition['resource']['tag']

        self.command = self.resolved_node_definition.get('attributes',dict()).get('command',None)
        self.env = self.resolved_node_definition.get('attributes',dict()).get('env',None)
        if not self.command or not self.env:
            raise Exception('Missing keys! Docker requires \'command\',\'env\' keywords to be specified under \'contextualisation\' section in node definition!')

    @wet_method('1')
    def _start_instance(self, resource_handler):
        """
        Start the Docker instance.
        """
        log.debug('Starting container')
        cli = resource_handler.cli
        host_config=cli.create_host_config(network_mode=self.network_mode)
        container = cli.create_container(
            image='{0.image}:{0.tag}'.format(self),
            command=self.command,
            host_config=host_config,
            environment=self.env
        )

        cli.start(container.get('Id'))
        log.debug('Started container [%s]', container)
        return str(container)

    @wet_method()
    def _load(self, resource_handler):
        """
        Load Docker image so it can be instantiated.
        """
        log.info('[%s] Loading Docker image origin=%r image=%r tag=%r',
                 resource_handler.name, self.origin, self.image, self.tag)
        if self.origin == 'dockerhub':
            resource_handler.cli.pull(repository=self.image, tag=self.tag)
        else:
            resource_handler.cli.import_image_from_url(
                url=self.origin,
                repository=self.image,
                tag=self.tag
            )

    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
              resource_handler.name, self.resolved_node_definition)

        log.debug("Creating node")

        self._load(resource_handler)
        instance_id = self._start_instance(resource_handler)

        log.debug("[%s] Done; container_id = %r", resource_handler.name, instance_id)
        return instance_id

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    def _delete_container(self, resource_handler, instance_id):
        log.debug("[%s] Stopping container %r", resource_handler.name, instance_id)
        resource_handler.cli.stop(container=instance_id)
        log.debug("[%s] Removing container %r", resource_handler.name, instance_id)
        resource_handler.cli.remove_container(container=instance_id)

    @wet_method()
    def perform(self, resource_handler):
        log.debug("[%s] Dropping node %r", resource_handler.name,
                  self.instance_data['node_id'])

        self.instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']
        self._delete_container(resource_handler, self.instance_id)

        log.debug("[%s] Done", resource_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('ready')
    def perform(self, resource_handler):
        """
        Return translated status of the container.

        See http://www.lpds.sztaki.hu/occo/datastructures.html#node-status
        """

        instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']
        info = resource_handler.cli.inspect_container(container=instance_id)

        if info['State']['Running']:
            log.debug("[%s] Done; retval=%r; status=%r",resource_handler.name,
                      'Running', status.READY)
            return status.READY

        elif info['State']['StartedAt'] == info['State']['FinishedAt']:
            log.debug("[%s] Done; retval=%r; status=%r",
                      'Pending', status.PENDING)

        elif info['State']['ExitCode'] == '-1':
            log.debug("[%s] Done; retval=%r; status=%r",
                      'Failed', status.TMP_FAIL)
            return status.TMP_FAIL

        elif not info['State']['Running']:
            log.debug("[%s] Done; retval=%r; status=%r",
                      'Finished', status.SHUTDOWN)
            return status.SHUTDOWN
        else:
            raise NotImplementedError()

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    def perform(self, resource_handler):
        """
        Return (IPv4) network address of the container.
        """
        instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']
        info = resource_handler.cli.inspect_container(container=instance_id)
        ip_addresses = []
        for k, v in info['NetworkSettings']['Networks'].iteritems():
            ip_addresses.append(v['IPAddress'])
        return ip_addresses[0]

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    def perform(self, resource_handler):
        """
        Return network address of the container.
        """
        instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']
        info = resource_handler.cli.inspect_container(container=instance_id)
        ip_addresses = []
        for k, v in info['NetworkSettings']['Networks'].iteritems():
            ip_addresses.append(v['IPAddress'])
        return ip_addresses[0]

@factory.register(ResourceHandler, PROTOCOL_ID)
class DockerResourceHandler(ResourceHandler):
    """ Implementation of the
    :class:`~occo.resourcehandler.ResourceHandler` class utilizing Docker_.

    :param str endpoint: Docker socket URL

    .. _Docker: https://www.docker.com/
    """
    def __init__(self, endpoint, 
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else endpoint
        self.cli = docker.Client(endpoint)

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

@factory.register(RHSchemaChecker, PROTOCOL_ID)
class DockerSchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "origin", "network_mode", "image", "tag"]
        self.opt_keys = ["name"]
    def perform_check(self, data):
        missing_keys = RHSchemaChecker.get_missing_keys(self, data, self.req_keys)
        if missing_keys:
            msg = "Missing key(s): " + ', '.join(str(key) for key in missing_keys)
            raise SchemaError(msg)
        valid_keys = self.req_keys + self.opt_keys
        invalid_keys = RHSchemaChecker.get_invalid_keys(self, data, valid_keys)
        if invalid_keys:
            msg = "Unknown key(s): " + ', '.join(str(key) for key in invalid_keys)
            raise SchemaError(msg)
        return True

