#
# Copyright (C) 2014 MTA SZTAKI
#

""" Boto EC2 implementation of the
:class:`~occo.cloudhandler.cloudhandler.CloudHandler` class.

.. moduleauthor:: Adam Visegradi <adam.visegradi@sztaki.mta.hu>
"""

# To avoid self-importing *this* boto.py module (we need the "real" one
# provided by the boto package).
from __future__ import absolute_import
import boto
import boto.ec2

import urlparse
import occo.util.factory as factory
from occo.util import wet_method, coalesce
from ..common import CloudHandler, Command
import itertools as it
import logging

import drett.client as drett

import occo.constants.status as status

__all__ = ['BotoCloudHandler']

PROTOCOL_ID='boto'

log = logging.getLogger('occo.cloudhandler.backends.boto')

def setup_connection(target, auth_data):
    """
    Setup the connection to the EC2 server.
    """
    endpoint = target['endpoint']
    url = urlparse.urlparse(endpoint)
    region = boto.ec2.regioninfo.RegionInfo(
        name=target['regionname'], endpoint=url.hostname)
    return boto.connect_ec2(
        aws_access_key_id=auth_data['username'],
        aws_secret_access_key=auth_data['password'],
        is_secure=(url.scheme == 'https'),
        region=region,
        port=url.port,
        path=url.path)

def get_instance(conn, instance_id):
    reservations = conn.get_all_reservations(instance_ids=[instance_id])
    # TODO: ASSUMING len(reservations)==1 and len(instances)==1
    return reservations[0].instances[0]

##############
## CH Commands

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition

    @wet_method(1)
    def _start_instance(self, cloud_handler, image_id, instance_type, context):
        """
        Start the VM instance.

        :param str image_id: The image identifier in the backend cloud.
        :param str instance_type: The instance type as specified by the
            backend cloud (e.g. m1.small).
        :param str context: Contextualization for the VM instane.

        :Remark: This is a "wet method", the VM will not be started
            if the instance is in debug mode (``dry_run``).
        """
        with drett.Allocation(resource_owner=cloud_handler.name,
                              resource_type=cloud_handler.resource_type,
                              **cloud_handler.drett_config) as a:
            reservation = cloud_handler.conn.run_instances(image_id=image_id,
                                                  instance_type=instance_type,
                                                  user_data=context)
            vm_id = reservation.instances[0].id
            a.set_resource_data(vm_id)
        return vm_id

    def perform(self, cloud_handler):
        log.debug("[%s] Creating node: %r",
                  cloud_handler.name, self.resolved_node_definition['name'])
        image_id = self.resolved_node_definition['image_id']
        instance_type = self.resolved_node_definition['instance_type']
        context = self.resolved_node_definition['context']

        vm_id = self._start_instance(cloud_handler, image_id, instance_type, context)

        log.debug("[%s] Done; vm_id = %r", cloud_handler.name, vm_id)
        return vm_id

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data    
    
    @wet_method()
    def _delete_vms(self, cloud_handler, *vm_ids):
        """
        Terminate VM instances.

        :param vm_ids: The list of VM instance identifiers.
        :type vm_ids: str

        :Remark: This is a "wet method", termination will not be attempted
            if the instance is in debug mode (``dry_run``).
        """
        cloud_handler.conn.terminate_instances(instance_ids=vm_ids)

        rt = drett.ResourceTracker(url=cloud_handler.drett_config['url'])
        for instance_id in vm_ids:
            rt.resource_freed_by_attributes(
                resource_owner=cloud_handler.name,
                resource_type=cloud_handler.resource_type,
                resource_id=instance_id)

    def perform(self, cloud_handler):
        """
        Terminate a VM instance.

        :param instance_data: Information necessary to access the VM instance.
        :type instance_data: :ref:`Instance Data <instancedata>`
        """
        instance_id = self.instance_data['instance_id']
        log.debug("[%s] Dropping node %r", cloud_handler.name,
                  self.instance_data['node_id'])

        self._delete_vms(cloud_handler, instance_id)

        log.debug("[%s] Done", cloud_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
    
    @wet_method('running')
    def perform(self, cloud_handler):
        inst = get_instance(cloud_handler.conn, self.instance_data['instance_id'])
        retval = inst.state
        if retval=="pending":
            log.debug("[%s] Done; retval=%r; status=%r",cloud_handler.name,
                      retval, status.PENDING)
            return status.PENDING
        elif retval=="running":
            log.debug("[%s] Done; retval=%r; status=%r",cloud_handler.name,
                      retval, status.READY)
            return status.READY
        elif retval=="shutting-down" or retval=="terminated":
            log.debug("[%s] Done; retval=%r; status=%r",cloud_handler.name,
                      retval, status.SHUTDOWN)
            return status.SHUTDOWN
        elif retval=="stopping" or retval=="stopped":
            log.debug("[%s] Done; retval=%r; status=%r",cloud_handler.name,
                      retval, status.TMP_FAIL)
            return status.TMP_FAIL
        else:
            raise NotImplementedError()

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
    
    @wet_method('127.0.0.1')
    def perform(self, cloud_handler):
        inst = get_instance(cloud_handler.conn, self.instance_data['instance_id'])
        return coalesce(inst.ip_address, inst.private_ip_address)

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
    
    @wet_method('127.0.0.1')
    def perform(self, cloud_handler):
        inst = get_instance(cloud_handler.conn, self.instance_data['instance_id'])
        return coalesce(inst.public_dns_name,
                        inst.ip_address,
                        inst.private_ip_address)

@factory.register(CloudHandler, PROTOCOL_ID)
class BotoCloudHandler(CloudHandler):
    """ Implementation of the
    :class:`~occo.cloudhandler.cloudhandler.CloudHandler` class utilizing the
    Boto_ EC2_ interface.

    :param dict target: Definition of the EC2 endpoint. This must contain:

        * ``endpoint``: URL of the interface.
        * ``regionname``: The name of the EC2 region.

    :param dict auth_data: Authentication infomration for the connection.

        * ``username``: The access key.
        * ``password``: The secret key.

    :param dict drett_config: Configuration for the resource allocation
        tracking service, drett_\ .
    :param str name: The name of this ``CloudHandler`` instance. If unset,
        ``target['endpoint']`` is used.
    :param bool dry_run: Skip actual resource aquisition, polling, etc.

    .. _Boto: https://boto.readthedocs.org/en/latest/
    .. _EC2: http://aws.amazon.com/ec2/
    .. _drett: https://github.com/avisegradi/drett
    """
    def __init__(self, target, auth_data, drett_config,
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else target['endpoint']
        self.drett_config = drett_config
        self.conn = setup_connection(target, auth_data) \
            if not dry_run else None
        # The following is intentional. It is a constant yet,
        # but maybe it'll change in the future.
        self.resource_type = 'vm'

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
