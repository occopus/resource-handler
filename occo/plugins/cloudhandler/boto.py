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
from occo.cloudhandler import CloudHandler, Command
import itertools as it
import logging
import occo.constants.status as status

__all__ = ['BotoCloudHandler']

PROTOCOL_ID = 'boto'
STATE_MAPPING = {
    'pending'       : status.PENDING,
    'running'       : status.READY,
    'shutting-down' : status.SHUTDOWN,
    'terminated'    : status.SHUTDOWN,
    'stopping'      : status.TMP_FAIL,
    'stopped'       : status.TMP_FAIL,
}

log = logging.getLogger('occo.cloudhandler.boto')

def setup_connection(target, auth_data):
    """
    Setup the connection to the EC2 server.
    """
    endpoint = target['endpoint']
    url = urlparse.urlparse(endpoint)
    region = boto.ec2.regioninfo.RegionInfo(
        name=target['regionname'], endpoint=url.hostname)
    log.debug('Connecting to %r %r as %r',
              endpoint, region, auth_data['username'])
    return boto.connect_ec2(
        aws_access_key_id=auth_data['username'],
        aws_secret_access_key=auth_data['password'],
        is_secure=(url.scheme == 'https'),
        region=region,
        port=url.port,
        path=url.path)

def get_instance(conn, instance_id):
    reservations = conn.get_all_reservations(instance_ids=[instance_id])
    # ASSUMING len(reservations)==1 and len(instances)==1
    return reservations[0].instances[0]

##############
## CH Commands

def needs_connection(f):
    """
    Sets up the conn member of the Command object upon calling this method.

    If this decorator is specified *inside* (after) ``@wet_method``, the
    connection will not be established upon dry run.
    """
    import functools
    @functools.wraps(f)
    def g(self, cloud_handler, *args, **kwargs):
        self.conn = cloud_handler.get_connection()
        return f(self, cloud_handler, *args, **kwargs)

    return g

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition

    @wet_method(1)
    @needs_connection
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
        reservation = self.conn.run_instances(image_id=image_id,
                                              instance_type=instance_type,
                                              user_data=context)
        vm_id = reservation.instances[0].id
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
    @needs_connection
    def _delete_vms(self, cloud_handler, *vm_ids):
        """
        Terminate VM instances.

        :param vm_ids: The list of VM instance identifiers.
        :type vm_ids: str

        :Remark: This is a "wet method", termination will not be attempted
            if the instance is in debug mode (``dry_run``).
        """
        self.conn.terminate_instances(instance_ids=vm_ids)

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
    
    @wet_method('ready')
    @needs_connection
    def perform(self, cloud_handler):
        log.debug("[%s] Acquiring node state %r",
                  cloud_handler.name, self.instance_data['node_id'])
        inst = get_instance(self.conn, self.instance_data['instance_id'])
        inst_state = inst.state
        try:
            retval = STATE_MAPPING[inst_state]
        except KeyError:
            raise NotImplementedError('Unknown EC2 state', inst_state)
        else:
            log.debug("[%s] Done; boto_state=%r; status=%r",
                      cloud_handler.name, inst_state, retval)
            return retval

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
    
    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, cloud_handler):
        log.debug("[%s] Acquiring IP address for %r",
                  cloud_handler.name,
                  self.instance_data['node_id'])
        inst = get_instance(self.conn, self.instance_data['instance_id'])
        return coalesce(inst.ip_address, inst.private_ip_address)

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
    
    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, cloud_handler):
        log.debug("[%s] Acquiring address for %r",
                  cloud_handler.name,
                  self.instance_data['node_id'])
        inst = get_instance(self.conn, self.instance_data['instance_id'])
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

    :param str name: The name of this ``CloudHandler`` instance. If unset,
        ``target['endpoint']`` is used.
    :param bool dry_run: Skip actual resource aquisition, polling, etc.

    .. _Boto: https://boto.readthedocs.org/en/latest/
    .. _EC2: http://aws.amazon.com/ec2/
    """
    def __init__(self, target, auth_data, 
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else target['endpoint']
        self.target, self.auth_data = target, auth_data
        # The following is intentional. It is a constant yet, but maybe it'll
        # change in the future.
        self.resource_type = 'vm'

    def get_connection(self):
        return setup_connection(self.target, self.auth_data)

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
