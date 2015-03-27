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
from occo.util import wet_method
from ..cloudhandler import CloudHandler
import itertools as it
import logging

import drett.client as drett

__all__ = ['BotoCloudHandler']

PROTOCOL_ID='boto'

log = logging.getLogger('occo.cloudhandler.backends.boto')

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
        self.setup_connection(target, auth_data)
        # The following is intentional. It is a constant yet,
        # but maybe it'll change in the future.
        self.resource_type = 'vm'

    @wet_method()
    def setup_connection(self, target, auth_data):
        """
        Setup the connection to the EC2 server.

        :Remark: This is a "wet method", the connection will not be established
            if the instance is in debug mode (``dry_run``).

        .. todo::
            ``target`` and ``auth_data`` should be members of this class.
        """
        endpoint = target['endpoint']
        url = urlparse.urlparse(endpoint)
        region = boto.ec2.regioninfo.RegionInfo(
            name=target['regionname'], endpoint=url.hostname)
        self.conn = boto.connect_ec2(
            aws_access_key_id=auth_data['username'],
            aws_secret_access_key=auth_data['password'],
            is_secure=(url.scheme == 'https'),
            region=region,
            port=url.port,
            path=url.path)

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
        reservation = self.conn.run_instances(image_id=image_id,
                                              instance_type=instance_type)
        return reservation.instances[0].id

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

    @wet_method('running')
    def _get_status(self, vm_id):
        """
        Query VM state.

        :param str vm_id: The VM instance identifier.

        :Remark: This is a "wet method", if the instance is in debug mode
            (``dry_run``), a dummy value is returned.
        """
        reservations = self.conn.get_all_reservations(instance_ids=[vm_id])
        # TODO: ASSUMING len(reservations)==1 and len(instances)==1
        instance = reservations[0].instances[0]
        return instance.state

    def create_node(self, node_description):
        """
        Crete node based on its :ref:`node description <nodedescription>`.
        """
        log.debug("[%s] Creating node: %r",
                  self.name, node_description['name'])
        image_id = node_description['image_id']
        instance_type = node_description['instance_type']
        context = node_description['context']

        with drett.Allocation(resource_owner=self.name,
                              resource_type=self.resource_type,
                              **self.drett_config) as a:
            vm_id = self._start_instance(image_id, instance_type, context)
            a.set_resource_data(vm_id)

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

        drett \
            .ResourceTracker(url=self.drett_config['url']) \
            .resource_freed_by_attributes(resource_owner=self.name,
                                          resource_type=self.resource_type,
                                          resource_id=instance_id)

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
        log.debug("[%s] Done; retval='%s'", self.name, retval)
        return retval
