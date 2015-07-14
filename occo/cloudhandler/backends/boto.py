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
from ..common import CloudHandler, CloudHandlerProvider
import itertools as it
import logging

import drett.client as drett

import occo.util.constants.status as status

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

    @wet_method(1)
    def _start_instance(self, image_id, instance_type, context):
        """
        Start the VM instance.

        :param str image_id: The image identifier in the backend cloud.
        :param str instance_type: The instance type as specified by the
            backend cloud (e.g. m1.small).
        :param str context: Contextualization for the VM instane.

        :Remark: This is a "wet method", the VM will not be started
            if the instance is in debug mode (``dry_run``).
        """
        with drett.Allocation(resource_owner=self.name,
                              resource_type=self.resource_type,
                              **self.drett_config) as a:
            reservation = self.conn.run_instances(image_id=image_id,
                                                  instance_type=instance_type,
                                                  user_data=context)
            vm_id = reservation.instances[0].id
            a.set_resource_data(vm_id)
        return vm_id

    @wet_method()
    def _delete_vms(self, *vm_ids):
        """
        Terminate VM instances.

        :param vm_ids: The list of VM instance identifiers.
        :type vm_ids: str

        :Remark: This is a "wet method", termination will not be attempted
            if the instance is in debug mode (``dry_run``).
        """
        self.conn.terminate_instances(instance_ids=vm_ids)

        rt = drett.ResourceTracker(url=self.drett_config['url'])
        for instance_id in vm_ids:
            rt.resource_freed_by_attributes(resource_owner=self.name,
                                            resource_type=self.resource_type,
                                            resource_id=instance_id)

    @wet_method('running')
    def _get_status(self, vm_id):
        """
        Query VM state.

        :param str vm_id: The VM instance identifier.

        :Remark: This is a "wet method", if the instance is in debug mode
            (``dry_run``), a dummy value is returned.
        """
        return get_instance(self.conn, vm_id).state

    def create_node(self, resolved_node_definition):
        """
        Crete node based on its
        :ref:`definition <resolved-node-definition>`.
        """
        log.debug("[%s] Creating node: %r",
                  self.name, resolved_node_definition['name'])
        image_id = resolved_node_definition['image_id']
        instance_type = resolved_node_definition['instance_type']
        context = resolved_node_definition['context']

        vm_id = self._start_instance(image_id, instance_type, context)

        log.debug("[%s] Done; vm_id = %r", self.name, vm_id)
        return vm_id

    def drop_node(self, instance_data):
        """
        Terminate a VM instance.

        :param instance_data: Information necessary to access the VM instance.
        :type instance_data: :ref:`Instance Data <instancedata>`
        """
        instance_id = instance_data['instance_id']
        log.debug("[%s] Dropping node '%s'", self.name, instance_data['node_id'])

        self._delete_vms(instance_id)

        log.debug("[%s] Done", self.name)

    def get_node_state(self, instance_data):
        """
        Query a VM's state.

        :param instance_data: Information necessary to access the VM instance.
        :type instance_data: :ref:`Instance Data <instancedata>`
        """
        log.debug("[%s] Acquiring node state for '%s'",
                  self.name, instance_data['node_id'])
        retval = self._get_status(instance_data['instance_id'])
        if retval=="pending":
            log.debug("[%s] Done; retval='%s'; status='%s'",self.name,
                      retval, status.PENDING)
            return status.PENDING
        elif retval=="running":
            log.debug("[%s] Done; retval='%s'; status='%s'",self.name,
                      retval, status.READY)
            return status.READY
        elif retval=="shutting-down" or retval=="terminated":
            log.debug("[%s] Done; retval='%s'; status='%s'",self.name,
                      retval, status.SHUTDOWN)
            return status.SHUTDOWN
        elif retval=="stopping" or retval=="stopped":
            log.debug("[%s] Done; retval='%s'; status='%s'",self.name,
                      retval, status.TMP_FAIL)
            return status.TMP_FAIL
        else:
            raise NotImplementedError()

@factory.register(CloudHandlerProvider, 'boto')
class BotoCloudHandlerProvider(CloudHandlerProvider):
    def __init__(self, target, auth_data,
                 name=None, dry_run=False,
                 **config):
        self.conn = setup_connection(target, auth_data) \
            if not dry_run else None
        self.dry_run = dry_run
        super(BotoCloudHandlerProvider, self).__init__(**config)

    @wet_method('running')
    def _get_state(self, instance_data):
        inst = get_instance(self.conn, instance_data['instance_id'])
        return inst.state

    @wet_method('127.0.0.1')
    def _get_ip_address(self, instance_data):
        inst = get_instance(self.conn, instance_data['instance_id'])
        return coalesce(inst.ip_address, inst.private_ip_address)

    @wet_method('127.0.0.1')
    def _get_address(self, instance_data):
        inst = get_instance(self.conn, instance_data['instance_id'])
        return coalesce(inst.public_dns_name,
                        inst.ip_address,
                        inst.private_ip_address)

    # Possible attributes: ['__class__', '__delattr__', '__dict__', '__doc__',
    #     '__format__', '__getattribute__', '__hash__', '__init__',
    #     '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
    #     '__setattr__', '__sizeof__', '__str__', '__subclasshook__',
    #     '__weakref__', '_in_monitoring_element', '_placement',
    #     '_previous_state', '_state', '_update', 'add_tag', 'add_tags',
    #     'ami_launch_index', 'architecture', 'block_device_mapping',
    #     'client_token', 'confirm_product', 'connection', 'create_image',
    #     'dns_name', 'endElement', 'eventsSet', 'get_attribute',
    #     'get_console_output', 'group_name', 'groups', 'hypervisor', 'id',
    #     'image_id', 'instance_profile', 'instance_type', 'interfaces',
    #     'ip_address', 'item', 'kernel', 'key_name', 'launch_time',
    #     'modify_attribute', 'monitor', 'monitored', 'monitoring',
    #     'monitoring_state', 'persistent', 'placement', 'placement_group',
    #     'placement_tenancy', 'platform', 'previous_state',
    #     'previous_state_code', 'private_dns_name', 'private_ip_address',
    #     'product_codes', 'public_dns_name', 'ramdisk', 'reboot', 'region',
    #     'remove_tag', 'remove_tags', 'requester_id', 'reset_attribute',
    #     'root_device_name', 'root_device_type', 'spot_instance_request_id',
    #     'start', 'startElement', 'state', 'state_code', 'state_reason',
    #     'stop', 'subnet_id', 'tags', 'terminate', 'unmonitor', 'update',
    #     'use_ip', 'virtualization_type', 'vpc_id']
