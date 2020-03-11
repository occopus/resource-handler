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

""" Boto EC2 implementation of the
:class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class.

.. moduleauthor:: Adam Visegradi <adam.visegradi@sztaki.mta.hu>, Jozsef Kovacs <jozsef.kovacs@sztaki.mta.hu>
"""

# To avoid self-importing *this* ec2.py module (we need the "real" one
# provided by the boto package).

import boto
import boto.ec2
from urllib.parse import urlparse
import occo.util.factory as factory
from occo.util import wet_method, coalesce
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import itertools as it
import logging
import occo.constants.status as status
from occo.exceptions import SchemaError,NodeCreationError
import time

__all__ = ['EC2ResourceHandler']

PROTOCOL_ID = 'ec2'
STATE_MAPPING = {
    'pending'       : status.PENDING,
    'running'       : status.READY,
    'shutting-down' : status.SHUTDOWN,
    'terminated'    : status.SHUTDOWN,
    'stopping'      : status.TMP_FAIL,
    'stopped'       : status.TMP_FAIL,
}

log = logging.getLogger('occo.resourcehandler.ec2')

def setup_connection(endpoint, regionname, auth_data):
    """
    Setup the connection to the EC2 server.
    """
    url = urlparse(endpoint)
    region = boto.ec2.regioninfo.RegionInfo(
        name=regionname, endpoint=url.hostname)
    log.debug('Connecting to url %r %r as %r',
              url, region, auth_data['accesskey'])
    return boto.connect_ec2(
        aws_access_key_id=auth_data['accesskey'],
        aws_secret_access_key=auth_data['secretkey'],
        is_secure=(url.scheme == 'https'),
        region=region,
        port=url.port,
        path=url.path)

def get_instance(conn, instance_id):
    reservations = conn.get_all_reservations(instance_ids=[instance_id])
    # ASSUMING len(reservations)==1 and len(instances)==1
    return reservations[0].instances[0]

def needs_connection(f):
    """
    Sets up the conn member of the Command object upon calling this method.

    If this decorator is specified *inside* (after) ``@wet_method``, the
    connection will not be established upon dry run.
    """
    import functools
    @functools.wraps(f)
    def g(self, resource_handler, *args, **kwargs):
        self.conn = resource_handler.get_connection()
        return f(self, resource_handler, *args, **kwargs)

    return g

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition

    @wet_method(1)
    @needs_connection
    def _start_instance(self, resource_handler):
        """
        Start the VM instance.

        :Remark: This is a "wet method", the VM will not be started
            if the instance is in debug mode (``dry_run``).
        """
        rnd = self.resolved_node_definition
        image_id = rnd['resource']['image_id']
        instance_type = rnd['resource']['instance_type']
        context = rnd.get('context',None)
        key_name = rnd['resource'].get('key_name', None)
        sec_group_ids = rnd['resource'].get('security_group_ids', None)
        subnet_id = rnd['resource'].get('subnet_id', None)
        reservation = self.conn.run_instances(image_id=image_id,
                                              instance_type=instance_type,
                                              user_data=context,
                                              key_name=key_name,
                                              subnet_id=subnet_id,
                                              security_group_ids=sec_group_ids)
        vm_id = reservation.instances[0].id

        tags = rnd['resource'].get('tags', None)
        if tags:
          instance = reservation.instances[0]
          status = instance.update()
          log.debug("[%s] Adding tags: waiting for node (%r) to be ready...",
                  resource_handler.name, self.resolved_node_definition['name'])
          while status == 'pending':
            time.sleep(1)
            status = instance.update()
          if status == 'running':
            for key in tags:
              log.debug("[%s] Adding tag: %s => %s",
                  resource_handler.name, key, tags[key])
              instance.add_tag(key, tags[key])
          log.debug("[%s] Finished adding tags to node (%r).",
                    resource_handler.name, self.resolved_node_definition['name'])

        return vm_id

    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
                  resource_handler.name, self.resolved_node_definition['name'])

        vm_id = self._start_instance(resource_handler)

        log.debug("[%s] Done; vm_id = %r", resource_handler.name, vm_id)
        return vm_id

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

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
        self.conn.stop_instances(instance_ids=vm_ids, force=True)
        self.conn.terminate_instances(instance_ids=vm_ids)

    def perform(self, resource_handler):
        """
        Terminate a VM instance.

        :param instance_data: Information necessary to access the VM instance.
        :type instance_data: :ref:`Instance Data <instancedata>`
        """
        instance_id = self.instance_data['instance_id']
        log.debug("[%s] Dropping node %r", resource_handler.name,
                  self.instance_data['node_id'])

        self._delete_vms(resource_handler, instance_id)

        log.debug("[%s] Done", resource_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('ready')
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring node state %r",
                  resource_handler.name, self.instance_data['node_id'])
        inst = get_instance(self.conn, self.instance_data['instance_id'])
        inst_state = inst.state
        try:
            retval = STATE_MAPPING[inst_state]
        except KeyError:
            raise NotImplementedError('Unknown EC2 state', inst_state)
        else:
            log.debug("[%s] Done; ec2_state=%r; status=%r",
                      resource_handler.name, inst_state, retval)
            return retval

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring IP address for %r",
                  resource_handler.name,
                  self.instance_data['node_id'])
        inst = get_instance(self.conn, self.instance_data['instance_id'])
        ip_address = None if inst.ip_address == '' else inst.ip_address
        private_ip_address = None if inst.private_ip_address == '' else inst.private_ip_address
        log.debug("[%s] Priv IP address for %r is \"%s\"",
                  resource_handler.name,
                  self.instance_data['node_id'],
                  private_ip_address)
        return private_ip_address

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Acquiring address for %r",
                  resource_handler.name,
                  self.instance_data['node_id'])
        inst = get_instance(self.conn, self.instance_data['instance_id'])
        public_dns_name = None if inst.public_dns_name == '' else inst.public_dns_name
        ip_address = None if inst.ip_address == '' else inst.ip_address
        private_ip_address = None if inst.private_ip_address == '' else inst.private_ip_address
        log.debug("[%s] Addresses for %r are \"%s\", \"%s\", \"%s\"",
                  resource_handler.name,
                  self.instance_data['node_id'],
                  public_dns_name if public_dns_name else "None",
                  ip_address if ip_address else "None",
                  private_ip_address)
        addresses = list()
        addresses = addresses[:]+[public_dns_name] if public_dns_name else addresses
        addresses = addresses[:]+[ip_address] if ip_address else addresses
        addresses = addresses[:]+[private_ip_address] if private_ip_address else addresses
        return addresses

@factory.register(ResourceHandler, PROTOCOL_ID)
class EC2ResourceHandler(ResourceHandler):
    """ Implementation of the
    :class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class utilizing the
    Boto_ EC2_ interface.

    :param ``endpoint``: URL of the EC2 interface.
    :param ``regionname``: The name of the EC2 region.

    :param dict auth_data: Authentication infomration for the connection.

        * ``accesskey``: The access key.
        * ``secretkey``: The secret key.

    :param str name: The name of this ``ResourceHandler`` instance. If unset,
        ``endpoint`` is used.
    :param bool dry_run: Skip actual resource aquisition, polling, etc.

    .. _Boto: https://boto.readthedocs.org/en/latest/
    .. _EC2: http://aws.amazon.com/ec2/
    """
    def __init__(self, endpoint, regionname, auth_data,
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else endpoint
        self.endpoint = endpoint
        self.regionname = regionname
        if (not auth_data) or (not "accesskey" in auth_data) or (not "secretkey" in auth_data):
           errormsg = "Cannot find credentials for \""+endpoint+"\". Please, specify!"
           log.debug(errormsg)
           raise NodeCreationError(None, errormsg)
        self.auth_data = auth_data

    def get_connection(self):
        return setup_connection(self.endpoint, self.regionname, self.auth_data)

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
class EC2SchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "regionname", "image_id", "instance_type"]
        self.opt_keys = ["key_name", "security_group_ids", "subnet_id", "name", "tags"]
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
