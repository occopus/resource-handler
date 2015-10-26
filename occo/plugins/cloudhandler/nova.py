#
# Copyright (C) 2015 MTA SZTAKI
#

""" OpenStack Nova implementation of the
:class:`~occo.cloudhandler.cloudhandler.CloudHandler` class.

.. moduleauthor:: Zoltan Farkas <zoltan.farkas@sztaki.mta.hu>
"""

import time
import uuid
from novaclient import client
import urlparse
import occo.util.factory as factory
from occo.util import wet_method, coalesce
from occo.cloudhandler import CloudHandler, Command
import itertools as it
import logging
import occo.constants.status as status

__all__ = ['NovaCloudHandler']

PROTOCOL_ID = 'nova'
STATE_MAPPING = {
    'BUILD'         : status.PENDING,
    'REBUILD'       : status.PENDING,
    'RESIZE'        : status.PENDING,
    'VERIFY_RESIZE' : status.PENDING,
    'MIGRATING'     : status.PENDING,
    'ACTIVE'        : status.READY,
    'ERROR'         : status.TMP_FAIL,
    'DELETED'       : status.SHUTDOWN,
}

log = logging.getLogger('occo.cloudhandler.nova')

def setup_connection(target, auth_data):
    """
    Setup the connection to the Nova endpoint.
    """
    auth_url = target['auth_url']
    tenant_name = target['tenant_name']
    user = auth_data['username']
    password = auth_data['password']
    nt = client.Client('2.0', user, password, tenant_name, auth_url, insecure=True)
    return nt


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
    def _start_instance(self, cloud_handler, node_def):
        """
        Start the VM instance.

        :param dict node_def: The resolved node definition to use.

        :Remark: This is a "wet method", the VM will not be started
            if the instance is in debug mode (``dry_run``).
        """
        image_id = node_def['image_id']
        flavor_name = node_def['flavor_name']
        context = node_def['context']
        if 'security_groups' in node_def:
            sec_groups = node_def['security_groups']
        else:
            sec_groups = None
        print 'SEC: ' + str(sec_groups)
        if 'key_name' in node_def:
            key_name = node_def['key_name']
        else:
            key_name = None
        server_name = str(uuid.uuid4())
        log.debug("[%s] Creating new server using image ID %r and flavor name %r",
            cloud_handler.name, image_id, flavor_name)
        server = self.conn.servers.create(server_name, image_id, flavor_name,
            security_groups=sec_groups, key_name=key_name, userdata=context)
        log.debug('Reservation: %r, server ID: %r', server, server.id)
        return server

    def perform(self, cloud_handler):
        log.debug("[%s] Creating node: %r",
                  cloud_handler.name, self.resolved_node_definition['name'])

        server = self._start_instance(cloud_handler, self.resolved_node_definition)
        log.debug("[%s] Done; vm_id = %r", cloud_handler.name, server.id)

        if 'floating_ip' in self.resolved_node_definition:
            floating_ip = self.conn.floating_ips.create()
            log.debug("[%s] Created floating IP: %r", cloud_handler.name, floating_ip)
            attempts = 0
            while attempts < 10:
                try:
                    log.debug("[%s] Adding floating IP to server...", cloud_handler.name)
                    server.add_floating_ip(floating_ip)
                except Exception as e:
                    log.debug(e)
                    time.sleep(1)
                    attempts += 1
                else:
                    log.debug("[%s] Added floating IP to server", cloud_handler.name)
                    break
            if attempts == 5:
                log.error("[%s] Failed to add floating IP to server", cloud_handler.name)
                self.conn.floating_ips.delete(floating_ip)
                raise Exception('Failed to add floating IP')
        return server.id

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
        server = self.conn.servers.get(vm_ids)
        floating_ips = self.conn.floating_ips.list()
        for floating_ip in floating_ips:
            if floating_ip.instance_id == server.id:
                log.debug("[%s] Removing floating IP %r allocated for the VM",
                    cloud_handler.name, floating_ip.ip)
                self.conn.floating_ips.delete(floating_ip)
        self.conn.servers.delete(server)

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
        server = self.conn.servers.get(self.instance_data['instance_id'])
        inst_state = server.status
        try:
            retval = STATE_MAPPING[inst_state]
        except KeyError:
            raise NotImplementedError('Unknown Nova state', inst_state)
        else:
            log.debug("[%s] Done; nova_state=%r; status=%r",
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
        server = self.conn.servers.get(self.instance_data['instance_id'])
        floating_ips = self.conn.floating_ips.list()
        for floating_ip in floating_ips:
            if floating_ip.instance_id == server.id:
                return floating_ip.ip
        networks = self.conn.servers.ips(server)
        for tenant in networks.keys():
            for addre in networks[tenant]:
                return addre['addr'].encode('latin-1')
        return None

@factory.register(CloudHandler, PROTOCOL_ID)
class NovaCloudHandler(CloudHandler):
    """ Implementation of the
    :class:`~occo.cloudhandler.cloudhandler.CloudHandler` class utilizing the
    OpenStack Nova interface.

    :param dict target: Definition of the EC2 endpoint. This must contain:

        * ``endpoint``: URL of the interface.
        * ``regionname``: The name of the EC2 region.

    :param dict auth_data: Authentication infomration for the connection.

        * ``username``: The access key.
        * ``password``: The secret key.

    :param str name: The name of this ``CloudHandler`` instance. If unset,
        ``target['endpoint']`` is used.
    :param bool dry_run: Skip actual resource aquisition, polling, etc.

    """
    def __init__(self, target, auth_data, 
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else target['auth_url']
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
        return GetIpAddress(instance_data)

    def cri_get_ip_address(self, instance_data):
        return GetIpAddress(instance_data)

    def perform(self, instruction):
        instruction.perform(self)
