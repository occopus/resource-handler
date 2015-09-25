#
# Copyright (C) 2014 MTA SZTAKI
#

""" Docker implementation of the
:class:`~occo.cloudhandler.cloudhandler.CloudHandler` class.

.. moduleauthor:: Adam Visegradi <adam.visegradi@sztaki.mta.hu>, Sandor Acs <acs.sandor@sztaki.mta.hu>
"""

import occo.util.factory as factory
import docker
import ast
import logging
from occo.util import wet_method, coalesce
from occo.cloudhandler import CloudHandler, Command
import occo.constants.status as status

__all__ = ['DockerCloudHandler']

PROTOCOL_ID = 'docker'

log = logging.getLogger('occo.cloudhandler.dockerp')

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition
        self.origin = self.resolved_node_definition['attributes']['origin']
        self.image = self.resolved_node_definition['attributes']['image']
        self.tag = self.resolved_node_definition['attributes']['tag']
        self.command = self.resolved_node_definition['attributes']['command']
        #self.environment = self.resolved_node_definition['attributes']['environment']

    @wet_method('dummyid')
    def _start_instance(self, cloud_handler):
        """
        Start the Docker instance.
        """
        log.debug('Starting container')
        cli = cloud_handler.cli
        container = cli.create_container(
            image='{0.image}:{0.tag}'.format(self),
            command=self.command,
            #environment=self.environment
        )

        cli.start(container.get('Id'))
        log.debug('Started container [%s]', container)
        return str(container)

    @wet_method()
    def _load(self, cloud_handler):
        """
        Load Docker image so it can be instantiated.
        """
        log.info('[%s] Loading Docker image origin=%r image=%r tag=%r',
                 cloud_handler.name, self.origin, self.image, self.tag)
        if self.origin == 'dockerhub':
            cloud_handler.cli.pull(repository=self.image, tag=self.tag)
        else:
            cloud_handler.cli.import_image(
                src=self.origin,
                repository=self.image,
                tag=self.tag
            )

    def perform(self, cloud_handler):
        print self.resolved_node_definition
        log.debug("[%s] Creating node: %r",
              cloud_handler.name, self.resolved_node_definition)

        log.debug("Creating node")


        self._load(cloud_handler)
        instance_id = self._start_instance(cloud_handler)

        log.debug("[%s] Done; container_id = %r", cloud_handler.name, instance_id)
        return instance_id

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
        self.instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']

    @wet_method()
    def _delete_container(self, cloud_handler, instance_id):
        log.debug("[%s] Stopping container %r", cloud_handler.name, instance_id)
        cloud_handler.cli.stop(container=instance_id)
        log.debug("[%s] Removing container %r", cloud_handler.name, instance_id)
        cloud_handler.cli.remove_container(container=instance_id)

    def perform(self, cloud_handler):
        log.debug("[%s] Dropping node %r", cloud_handler.name,
                  self.instance_data['node_id'])

        self._delete_container(cloud_handler, self.instance_id)

        log.debug("[%s] Done", cloud_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
        self.instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']

    @wet_method('running')
    def perform(self, cloud_handler):
        """
        Return translated status of the container.

        See http://www.lpds.sztaki.hu/occo/datastructures.html#node-status
        """

        instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']
        info = cloud_handler.cli.inspect_container(container=instance_id)

        if info['State']['Running']:
            log.debug("[%s] Done; retval=%r; status=%r",cloud_handler.name,
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
    def perform(self, cloud_handler):
        """
        Return (IPv4) network address of the container.
        """
        instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']
        info = cloud_handler.cli.inspect_container(container=instance_id)
        return coalesce(info['NetworkSettings']['IPAddress'])

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    def perform(self, cloud_handler):
        """
        Return network address of the container.
        """
        instance_id = ast.literal_eval(self.instance_data['instance_id'])['Id']
        info = cloud_handler.cli.inspect_container(container=instance_id)
        return coalesce(info['NetworkSettings']['IPAddress'])

@factory.register(CloudHandler, PROTOCOL_ID)
class DockerCloudHandler(CloudHandler):
    """ Implementation of the
    :class:`~occo.cloudhandler.CloudHandler` class utilizing Docker_.

    :param str base_url: Docker socket URL

    .. _Docker: https://www.docker.com/
    """
    def __init__(self, name, base_url, dry_run, **config):
        self.dry_run = dry_run
        self.name = name
        self.base_url = base_url
        self.cli = docker.Client(base_url=base_url)

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
