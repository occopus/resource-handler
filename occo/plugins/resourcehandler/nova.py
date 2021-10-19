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

""" OpenStack Nova implementation of the
:class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class.

.. moduleauthor:: Zoltan Farkas <zoltan.farkas@sztaki.mta.hu>
"""

import logging
import occo.constants.status as status
import occo.util.factory as factory
import re
import time

from occo.exceptions import SchemaError, NodeCreationError
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
from occo.util import wet_method, unique_vmname
from openstack import connection
from keystoneauth1.identity import v3
from keystoneauth1 import session

__all__ = ['NovaResourceHandler']

PROTOCOL_ID = 'nova'
STATE_MAPPING = {
    'BUILD'         : status.PENDING,
    'REBUILD'       : status.PENDING,
    'RESIZE'        : status.PENDING,
    'VERIFY_RESIZE' : status.PENDING,
    'MIGRATING'     : status.PENDING,
    'ACTIVE'        : status.READY,
    'ERROR'         : status.FAIL,
    'DELETED'       : status.SHUTDOWN,
}

log = logging.getLogger('occo.resourcehandler.nova')

def setup_connection(endpoint, auth_data, resolved_node_definition):
    """
    Setup the connection to the Nova endpoint.
    """
    project_id = resolved_node_definition['resource'].get('project_id', None)
    user_domain_name = resolved_node_definition['resource'].get('user_domain_name', 'Default')
    region_name = resolved_node_definition['resource'].get('region_name', None)
    auth_type = auth_data.get('type', None)
    if auth_type is None:
        user = auth_data['username']
        password = auth_data['password']
        auth = v3.Password(auth_url=endpoint, username=user, password=password, project_id=project_id, user_domain_name=user_domain_name)
        sess = session.Session(auth=auth)
    elif auth_type == 'application_credential':
        cred_id = auth_data['id']
        cred_secret = auth_data['secret']
        auth = v3.ApplicationCredential(auth_url = endpoint,
                                        application_credential_secret = cred_secret,
                                        application_credential_id = cred_id)
        sess = session.Session(auth=auth)
    else:
        raise NodeCreationError(None, 'Unknown authentication type provided: "%s"' % auth_type)
    os = connection.Connection(session=sess, region_name=region_name)
    return os

def needs_connection(f):
    """
    Sets up the conn member of the Command object upon calling this method.

    If this decorator is specified *inside* (after) ``@wet_method``, the
    connection will not be established upon dry run.
    """
    import functools
    @functools.wraps(f)
    def g(self, resource_handler, *args, **kwargs):
        self.connopenstack = resource_handler.get_connection(self.resolved_node_definition)
        return f(self, resource_handler, *args, **kwargs)

    return g

import signal
class GracefulInterruptHandler(object):
    def __init__(self, sig=signal.SIGINT):
        self.sig = sig
    def __enter__(self):
        self.interrupted = False
        self.released = False
        self.original_handler = signal.getsignal(self.sig)
        def handler(signum, frame):
            self.interrupted = True
        signal.signal(self.sig, handler)
        return self
    def __exit__(self, type, value, tb):
        self.release()
    def release(self):
        if self.released:
            return False
        signal.signal(self.sig, self.original_handler)
        self.released = True
        return True

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition

    def _start_instance(self, resource_handler, node_def):
        """
        Start the VM instance.

        :param dict node_def: The resolved node definition to use.

        :Remark: This is a "wet method", the VM will not be started
            if the instance is in debug mode (``dry_run``).
        """
        image_id = node_def['resource']['image_id']
        flavor_name = node_def['resource']['flavor_name']
        context = node_def.get('context', None)
        sec_groups = node_def['resource'].get('security_groups', None)
        key_name = node_def['resource'].get('key_name', None)
        server_name = node_def['resource'].get('server_name',unique_vmname(node_def))
        network_id = node_def['resource'].get('network_id', None)
        volume_size = node_def['resource'].get('volume_size', None)
        volume_persist = node_def['resource'].get('volume_persist', False)
        terminate_volume = (not volume_persist)
        nics = None
        if network_id is not None:
            nics = [{"net-id": network_id, "v4-fixed-ip": ''}]
        log.debug("[%s] Creating new server using image ID %r and flavor name %r",
            resource_handler.name, image_id, flavor_name)
        try:
            server = None
            KBinterrupt = False
            with GracefulInterruptHandler() as h:
                log.debug('Server creation started for node %s...', node_def['node_id'])
                if volume_size is None:
                    server = self.connopenstack.create_server(server_name, image=image_id,
                        flavor=flavor_name, terminate_volume=terminate_volume, security_groups=sec_groups,
                        key_name=key_name, userdata=context, nics=nics)
                elif volume_size == 0:
                    server = self.connopenstack.create_server(server_name, image=image_id,
                        flavor=flavor_name, boot_from_volume=True, terminate_volume=terminate_volume, security_groups=sec_groups,
                        key_name=key_name, userdata=context, nics=nics)
                else:
                    volume = self.connopenstack.create_volume(volume_size, image=image_id, bootable=True)
                    server = self.connopenstack.create_server(server_name, image=image_id,
                        flavor=flavor_name, boot_volume=volume.id, terminate_volume=terminate_volume,
                        security_groups=sec_groups, key_name=key_name, userdata=context, nics=nics)
                KBinterrupt = h.interrupted
                log.debug('Server creation finished for node %s: server: %r', node_def['node_id'], server)
            if KBinterrupt:
              log.debug('Keyboard interrupt detected while VM was being created!')
              raise KeyboardInterrupt
        except KeyboardInterrupt:
            log.debug('Interrupting node creation!')
            if server is not None:
                log.debug('Rolling back...')
                try:
                    self.connopenstack.delete_server(server.id)
                except Exception as ex:
                    raise NodeCreationError(None, str(ex))
            raise
        except Exception as ex:
            raise NodeCreationError(None, str(ex))
        return server

    def _allocate_floating_ip(self, resource_handler,server):
        pool = self.resolved_node_definition['resource'].get('floating_ip_pool', None)
        if ('floating_ip' not in self.resolved_node_definition['resource']) and (pool is None):
            return
        flip_waiting = 10
        flip_attempts = 60
        attempts = 1
        while attempts <= flip_attempts:
            floating_ip = self.connopenstack.available_floating_ip(network=pool)
            if not floating_ip:
                if pool is not None:
                    error_msg = '[{0}] Cannot find unused floating ip address in pool "{1}"!'.format(
                        resource_handler.name, pool)
                else:
                    error_msg = '[{0}] Cannot find unused floating ip address!'.format(
                        resource_handler.name)
                self.connopenstack.delete_server(server.id)
                raise NodeCreationError(None, error_msg)
            try:
                log.debug("[%s] Try associating floating ip (%s) to server (%s)...",
                        resource_handler.name, floating_ip.floating_ip_address, server.id)
                self.connopenstack.compute.add_floating_ip_to_server(server.id, floating_ip.floating_ip_address)
                break
            except Exception as e:
                log.debug(e)
                log.debug("[%s] Associating floating ip (%s) to node failed. Retry after %i seconds...", resource_handler.name, floating_ip.floating_ip_address, flip_waiting)
                time.sleep(flip_waiting)
                attempts += 1
        if attempts > flip_attempts:
            error_msg = '[{0}] Gave up associating floating ip to node! Could not get it in {1} seconds."'.format(
                        resource_handler.name, flip_attempts * flip_waiting)
            log.error(error_msg)
            self.connopenstack.delete_server(server.id)
            raise NodeCreationError(None, error_msg)
        return

    @wet_method(1)
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
                  resource_handler.name, self.resolved_node_definition['name'])
        try:
            server = None
            server = self._start_instance(resource_handler, self.resolved_node_definition)
            log.debug("[%s] Server instance created, id: %r", resource_handler.name, server.id)
            self._allocate_floating_ip(resource_handler,server)
        except KeyboardInterrupt:
            try:
                if server is not None:
                    log.debug('Interrupting node creation! Rolling back. Please, stand by!')
                    self.connopenstack.delete_server(server.id)
            except Exception as ex:
                raise NodeCreationError(None, str(ex))
            raise
        return server.id

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
        self.resolved_node_definition = instance_data['resolved_node_definition']

    @wet_method()
    def _delete_vms(self, vm_id):
        """
        Terminate VM instance.

        :param vm_id: The VM instance ID to terminate.
        :type vm_id: str

        :Remark: This is a "wet method", termination will not be attempted
            if the instance is in debug mode (``dry_run``).
        """
        self.connopenstack.delete_server(vm_id)

    @needs_connection
    def perform(self, resource_handler):
        """
        Terminate a VM instance.

        :param instance_data: Information necessary to access the VM instance.
        :type instance_data: :ref:`Instance Data <instancedata>`
        """
        instance_id = self.instance_data.get('instance_id')
        if not instance_id:
            return
        log.debug("[%s] Dropping node %r", resource_handler.name,
                  self.instance_data['node_id'])
        try:
            self._delete_vms(instance_id)
        except Exception as ex:
            raise NodeCreationError(None, str(ex))

        log.debug("[%s] Done", resource_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
        self.resolved_node_definition = instance_data['resolved_node_definition']

    @wet_method('ready')
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring node state %r",
                  resource_handler.name, self.instance_data['node_id'])
        try:
            server = self.connopenstack.get_server(self.instance_data['instance_id'])
        except Exception as ex:
            raise NodeCreationError(None, str(ex))
        inst_state = server.status
        try:
            retval = STATE_MAPPING[inst_state]
        except KeyError:
            raise NotImplementedError('Unknown Nova state', inst_state)
        else:
            log.debug("[%s] Done; nova_state=%r; status=%r",
                      resource_handler.name, inst_state, retval)
            return retval

class GetAnyIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
        self.resolved_node_definition = instance_data['resolved_node_definition']

    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring IP address for %r",
                  resource_handler.name,
                  self.instance_data['node_id'])
        try:
            server = self.connopenstack.get_server(self.instance_data['instance_id'])
        except Exception as ex:
            raise NodeCreationError(None, str(ex))
        addresses = server.addresses
        for network in addresses:
            for address in addresses[network]:
                if address['OS-EXT-IPS:type'] == 'floating':
                    return address['addr']
        for network in addresses:
            for address in addresses[network]:
                return address['addr']
        return None

class GetPrivIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
        self.resolved_node_definition = instance_data['resolved_node_definition']

    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring private IP address for %r",
                  resource_handler.name,
                  self.instance_data['node_id'])
        try:
            server = self.connopenstack.get_server(self.instance_data['instance_id'])
        except Exception as ex:
            raise NodeCreationError(None, str(ex))
        addresses = server.addresses
        for network in addresses:
            for address in addresses[network]:
                if address['OS-EXT-IPS:type'] == 'fixed':
                    return address['addr']
        log.debug("[%s] Private ip not found.", resource_handler.name)
        return None

@factory.register(ResourceHandler, PROTOCOL_ID)
class NovaResourceHandler(ResourceHandler):
    """ Implementation of the
    :class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class utilizing the
    OpenStack Nova interface.

    :param dict target: Definition of the EC2 endpoint. This must contain:

        * ``endpoint``: URL of the interface.
        * ``regionname``: The name of the EC2 region.

    :param str auth_type: The type of authentication plugin to use.
    :param dict auth_data: Authentication infomration for the connection.

        * ``username``: The access key.
        * ``password``: The secret key.

    :param str name: The name of this ``ResourceHandler`` instance. If unset,
        ``target['endpoint']`` is used.
    :param bool dry_run: Skip actual resource aquisition, polling, etc.

    """
    def __init__(self, endpoint, auth_data,
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        # Check if endpoint includes API version (/v3, /v3/, etc.)
        if re.compile('\/v\d+[\/]*$').search(endpoint) is None:
            # If no API version is included, assume v3
            self.endpoint = ('%s/v3' % endpoint) if not endpoint.endswith('/') else ('%sv3' % endpoint)
        else:
            self.endpoint = endpoint
        self.name = name if name else endpoint
        if (not auth_data) or \
           ((not "type" in auth_data) and \
             ((not "username" in auth_data) or (not "password" in auth_data))) or \
           (("type" in auth_data) and \
             ((not "application_credential" in auth_data['type']) and \
              (not "voms" in auth_data['type']))) or \
           (("type" in auth_data) and ("application_credential" in auth_data['type']) and \
             ((not "id" in auth_data) or (not "secret" in auth_data))) or \
           (("type" in auth_data) and ("voms" in auth_data['type']) and (not "proxy" in auth_data)):
            errormsg = "Cannot find credentials for \""+endpoint+"\". Found only: \""+str(auth_data)+"\". Please, specify!"
            raise NodeCreationError(None,errormsg)
        self.auth_data = auth_data
        self.data = config

    def get_connection(self, resolved_node_definition):
        return setup_connection(self.endpoint, self.auth_data, resolved_node_definition)

    def cri_create_node(self, resolved_node_definition):
        return CreateNode(resolved_node_definition)

    def cri_drop_node(self, instance_data):
        return DropNode(instance_data)

    def cri_get_state(self, instance_data):
        return GetState(instance_data)

    def cri_get_address(self, instance_data):
        return GetAnyIpAddress(instance_data)

    def cri_get_ip_address(self, instance_data):
        return GetPrivIpAddress(instance_data)

    def perform(self, instruction):
        instruction.perform(self)

@factory.register(RHSchemaChecker, PROTOCOL_ID)
class NovaSchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "image_id", "flavor_name", "project_id"]
        self.opt_keys = [
            "server_name", "key_name", "security_groups", "floating_ip", "name", "tenant_name",
            "user_domain_name", "network_id", "floating_ip_pool", "region_name", "volume_size", "volume_persist"
        ]
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
        volume_size = data.get('volume_size', None)
        if volume_size is not None:
            try:
                volume_size = int(volume_size)
            except Exception as ex:
                msg = 'Could not convert volume_size value "%s" to integer!' % volume_size
                raise SchemaError(msg)
            if volume_size < 0:
                raise SchemaError('Negative numbers for volume_size are prohibited!')
        return True
