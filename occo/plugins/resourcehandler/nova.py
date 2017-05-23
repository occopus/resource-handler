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

import time
import uuid
import random
import novaclient
import novaclient.client
import novaclient.auth_plugin
from keystoneauth1 import loading
from keystoneauth1 import session
import urlparse
import occo.util.factory as factory
from occo.util import wet_method, coalesce, unique_vmname
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import itertools as it
import logging
import occo.constants.status as status
from occo.exceptions import SchemaError, NodeCreationError

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
    tenant_name = resolved_node_definition['resource'].get('tenant_name', None)
    project_id = resolved_node_definition['resource'].get('project_id', None)
    user_domain_name = resolved_node_definition['resource'].get('user_domain_name', 'Default')
    if auth_data.get('type',None) is None:
        user = auth_data['username']
        password = auth_data['password']
        if tenant_name is not None:
            nt = novaclient.client.Client('2.0', user, password, tenant_name, endpoint)
        else:
            loader = loading.get_plugin_loader('password')
            auth = loader.load_from_options(auth_url=endpoint, username=user, password=password, project_id=project_id, user_domain_name=user_domain_name)
            sess = session.Session(auth=auth)
            nt = novaclient.client.Client(2, session=sess)
    elif auth_data.get('type',None) == 'voms':
        novaclient.auth_plugin.discover_auth_systems()
        auth_plugin = novaclient.auth_plugin.load_plugin('voms')
        auth_plugin.opts["x509_user_proxy"] = auth_data['proxy']
        nt = novaclient.client.Client('2.0', None, None, tenant_name, endpoint, auth_plugin=auth_plugin, auth_system='voms')
    return nt

def needs_connection(f):
    """
    Sets up the conn member of the Command object upon calling this method.

    If this decorator is specified *inside* (after) ``@wet_method``, the
    connection will not be established upon dry run.
    """
    import functools
    @functools.wraps(f)
    def g(self, resource_handler, *args, **kwargs):
        self.conn = resource_handler.get_connection(self.resolved_node_definition)
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
                server = self.conn.servers.create(server_name, image_id, flavor_name,
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
                    self.conn.servers.delete(server)
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
        flip_waiting = 5 
        flip_attempts = 60
        attempts = 1
        while attempts <= flip_attempts:
            unused_ips = [addr for addr in self.conn.floating_ips.list() \
                         if addr.instance_id is None and ( not pool or pool == addr.pool) ]
            if not unused_ips:
                if pool is not None:
                    error_msg = '[{0}] Cannot find unused floating ip address in pool "{1}"!'.format(
                          resource_handler.name, pool)
                else:
                    error_msg = '[{0}] Cannot find unused floating ip address!'.format(
                          resource_handler.name)
                server = self.conn.servers.get(server.id)
                self.conn.servers.delete(server)
                raise NodeCreationError(None, error_msg)
            log.debug("[%s] List of unused floating ips: %s", resource_handler.name, str([ ip.ip for ip in unused_ips]))
            floating_ip = random.choice(unused_ips)
            try:
                log.debug("[%s] Try associating floating ip (%s) to server (%s)...", 
                          resource_handler.name, floating_ip.ip, server.id)
                server.add_floating_ip(floating_ip)
                time.sleep(random.randint(1,5))
                flips = self.conn.floating_ips.list()
                log.debug("[%s] List of floating IPs: %s", resource_handler.name, flips)
                myallocation = [ addr for addr in flips if addr.instance_id == server.id ]
                if not myallocation:
                    log.debug("SOMEONE took my ip meanwhile I was allocating it!")
                    raise Exception
                else:
                    log.debug("ALLOCATION seemt to succeed: %r",myallocation[0])
                    log.debug("[%s] Associating floating ip (%s) to node: success. Took %i seconds.", resource_handler.name, floating_ip.ip, (attempts - 1) * flip_waiting)
                    break
            except Exception as e:
                log.debug(e)
                log.debug("[%s] Associating floating ip (%s) to node failed. Retry after %i seconds...", resource_handler.name, floating_ip.ip, flip_waiting)
                time.sleep(flip_waiting)
                attempts += 1
        if attempts > flip_attempts:
            error_msg = '[{0}] Gave up associating floating ip to node! Could not get it in {1} seconds."'.format(
                        resource_handler.name, flip_attempts * flip_waiting)
            log.error(error_msg)
            server = self.conn.servers.get(server.id)
            self.conn.servers.delete(server)
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
                    self.conn.servers.delete(server)
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
    @needs_connection
    def _delete_vms(self, resource_handler, *vm_ids):
        """
        Terminate VM instances.

        :param vm_ids: The list of VM instance identifiers.
        :type vm_ids: str

        :Remark: This is a "wet method", termination will not be attempted
            if the instance is in debug mode (``dry_run``).
        """
        server = self.conn.servers.get(vm_ids)
        self.conn.servers.delete(server)

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
            self._delete_vms(resource_handler, instance_id)
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
            server = self.conn.servers.get(self.instance_data['instance_id'])
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

class GetIpAddress(Command):
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
            server = self.conn.servers.get(self.instance_data['instance_id'])
        except Exception as ex:
            raise NodeCreationError(None, str(ex))
        floating_ips = self.conn.floating_ips.list()
        for floating_ip in floating_ips:
            if floating_ip.instance_id == server.id:
                return floating_ip.ip
        networks = self.conn.servers.ips(server)
        for tenant in networks.keys():
            for addre in networks[tenant]:
                return addre['addr'].encode('latin-1')
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
        self.name = name if name else endpoint
        self.endpoint = endpoint
        if (not auth_data) or (((not "username" in auth_data) or (not "password" in auth_data)) and \
            ((not "type" in auth_data) or (not "proxy" in auth_data))):
            errormsg = "Cannot find credentials for \""+endpoint+"\". Please, specify!"
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
        return GetIpAddress(instance_data)

    def cri_get_ip_address(self, instance_data):
        return GetIpAddress(instance_data)

    def perform(self, instruction):
        instruction.perform(self)
    
@factory.register(RHSchemaChecker, PROTOCOL_ID)
class NovaSchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "image_id", "flavor_name"]
        self.opt_keys = ["server_name", "key_name", "security_groups", "floating_ip", "name", "project_id", "tenant_name", "user_domain_name", "network_id", "floating_ip_pool"]
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

