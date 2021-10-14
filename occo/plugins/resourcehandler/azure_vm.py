### Copyright 2019, MTA SZTAKI, www.sztaki.hu
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

""" Azure implementation of the
:class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class.

.. moduleauthor:: Zoltan Farkas <zfarkas@sztaki.hu>
"""

from __future__ import absolute_import

import os
import traceback

from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import DiskCreateOption

from msrestazure.azure_exceptions import CloudError

import occo.util.factory as factory
from occo.util import wet_method, coalesce, unique_vmname
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import itertools as it
import logging
import occo.constants.status as status
from occo.exceptions import SchemaError, NodeCreationError
import base64

__all__ = ['AzureResourceHandler']

PROTOCOL_ID = 'azure_vm'

STATE_MAPPING = {
    'creating'            : status.PENDING,
    'VM starting'         : status.PENDING,
    'VM running'          : status.READY,
    'Succeeded'           : status.READY,
    'Deleting'            : status.SHUTDOWN,
    'VM deallocating'     : status.SHUTDOWN,
    'VM deallocated'      : status.SHUTDOWN,
    'VM stopped'          : status.SHUTDOWN,
    'Provisioning failed' : status.TMP_FAIL,
    'error'               : status.TMP_FAIL
}

log = logging.getLogger('occo.resourcehandler.azure')


def setup_connection(endpoint, auth_data):
    subscription_id = auth_data['subscription_id']
    credentials = ServicePrincipalCredentials(
        client_id = auth_data['client_id'],
        secret = auth_data['client_secret'],
        tenant = auth_data['tenant_id']
    )
    resource_client = ResourceManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    network_client = NetworkManagementClient(credentials, subscription_id)
    return (subscription_id, resource_client, compute_client, network_client)


def needs_connection(f):
    import functools
    @functools.wraps(f)
    def g(self, resource_handler, *args, **kwargs):
        (subscription_id, resource_client, compute_client, network_client) = resource_handler.get_connection()
        self.subscription_id = subscription_id
        self.resource_client = resource_client
        self.compute_client = compute_client
        self.network_client = network_client
        return f(self, resource_handler, *args, **kwargs)
    return g


class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        self.node_def = resolved_node_definition
        self.res = self.node_def['resource']
        Command.__init__(self)
        self.created_resources = {}

    def _create_nic(self):
        # Create VNet
        vnet_name = unique_vmname(self.node_def) + '-vnet' if self.res.get('vnet_name', None) == None else self.res['vnet_name']
        subnet_name = unique_vmname(self.node_def) + '-subnet' if self.res.get('subnet_name', None) == None else self.res['subnet_name']
        nic_name = unique_vmname(self.node_def) + '-nic'
        self.vnet_name = vnet_name

        if self.res.get('vnet_name', None) == None:
            log.debug('Creating vnet')
            async_vnet_creation = self.network_client.virtual_networks.create_or_update(
                self.res['resource_group'],
                vnet_name,
                {
                    'location': self.res['location'],
                    'address_space': {
                        'address_prefixes': ['10.0.0.0/16']
                    }
                }
            )
            async_vnet_creation.wait()
            self.created_resources['virtual_network'] = vnet_name

        if self.res.get('subnet_name', None) == None:
            # Create Subnet
            log.debug('Creating Subnet')
            async_subnet_creation = self.network_client.subnets.create_or_update(
                self.res['resource_group'],
                vnet_name,
                subnet_name,
                {'address_prefix': '10.0.0.0/24'}
            )
            subnet_info = async_subnet_creation.result()
            self.created_resources['subnet'] = subnet_name
        else:
            subnet_info = self.network_client.subnets.get(
                self.res['resource_group'],
                vnet_name,
                subnet_name
            )

        pubip_info = None
        if self.res.get('public_ip_needed') == True:
            pubip_name = unique_vmname(self.node_def) + '-pubip'
            async_pubip_creation = self.network_client.public_ip_addresses.create_or_update(
                self.res['resource_group'],
                pubip_name,
                {
                    'location': self.res['location'],
                    'public_ip_allocation_method': 'Dynamic',
                    'public_ip_address_version': 'IPv4'
                }
            )
            pubip_info = async_pubip_creation.result()
            self.created_resources['public_ip_address'] = pubip_name

        log.debug('Creating NIC')
        async_nic_creation = self.network_client.network_interfaces.create_or_update(
            self.res['resource_group'],
            nic_name,
            {
                'location': self.res['location'],
                'ip_configurations': [
                    {
                        'name': unique_vmname(self.node_def) + '-ipconfig',
                        'subnet': {
                            'id': subnet_info.id
                        },
                        'public_ip_address': pubip_info if pubip_info is not None else ''
                    }
                ]
            }
        )
        nic_info = async_nic_creation.result()
        self.created_resources['network_interface'] = nic_name
        return nic_info


    def _create_vm_parameters(self, nic_id, customdata):
        """Create the VM parameters structure.
        """
        server_name = self.node_def['resource'].get('server_name', unique_vmname(self.node_def))
        d = {
            'location': self.res['location'],
            'os_profile': {
                'computer_name': server_name,
                'admin_username': self.res['username'],
                'customData': customdata if customdata != None else ''
            },
            'hardware_profile': {
                'vm_size': self.res['vm_size']
            },
            'storage_profile': {
                'image_reference': {
                    'publisher': self.res['publisher'],
                    'offer': self.res['offer'],
                    'sku': self.res['sku'],
                    'version': self.res['version']
                },
            },
            'network_profile': {
                'network_interfaces': [{
                    'id': nic_id,
                }]
            },
        }
        if 'password' in self.res:
            d['os_profile']['admin_password'] = self.res['password']
        else:
            d['os_profile']['linux_configuration'] = {
                'disable_password_authentication': True,
                'ssh': {
                    'public_keys': [{
                        'path': '/home/{}/.ssh/authorized_keys'.format(self.res['username']),
                        'key_data': self.res['ssh_key_data']
                    }]
                }
            }
        return d

    def _create_vm(self, nic, vm_name, customdata):
        vm_parameters = self._create_vm_parameters(nic.id, customdata)
        async_vm_creation = self.compute_client.virtual_machines.create_or_update(
            self.res['resource_group'], vm_name, vm_parameters)
        async_vm_creation.wait()
        return async_vm_creation.result()

    @wet_method('1')
    def _start_instance(self, resource_handler):
        log.debug('Starting Azure VM')
        self.resource_client.resource_groups.create_or_update(
            self.res['resource_group'], {'location': self.res['location']})
        nic = self._create_nic()
        vm_name = unique_vmname(self.node_def)
        resolved_context = self.node_def.get("context")
        if resolved_context == "":
            resolved_context = None
        customdata = base64.b64encode(resolved_context.encode('utf-8')).decode('utf-8') if resolved_context else None
        vm = self._create_vm(nic, vm_name, customdata)
        log.debug('%r', vm)
        return vm_name

        # vm_def = {
        #     'publisher': node_def['publisher'],
        #     'offer': node_def['offer'],
        #     'sku': node_def['sku'],
        #     'version': node_def['version']
        # }

    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
              resource_handler.name, self.node_def)

        log.debug("Creating node")

        instance_id = self._start_instance(resource_handler)

        log.debug("[%s] Done; container_id = %r", resource_handler.name, instance_id)
        return dict(
            instance_id=instance_id,
            resource_group=self.res['resource_group'],
            created_resources=self.created_resources,
            vnet_name=self.vnet_name
        )


class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data
        self.res = instance_data['resource']
        self.created_resources = instance_data['instance_id']['created_resources']

    def _get_vm_disk(self, vm_name, resource_group):
        rv = []
        virtual_machine = self.compute_client.virtual_machines.get(
            resource_group,
            vm_name,
            'instanceView'
        )
        return [x.name for x in virtual_machine.instance_view.disks]

    def _delete_vm_disks(self, resource_handler, disk_names, resource_group):
        for disk_name in disk_names:
            log.debug("[%s] Deleting VM's disk: %s",
                  resource_handler.name, disk_name)
            self.compute_client.disks.delete(resource_group, disk_name).result()
            log.debug("[%s] Deleting VM's disk done: %s",
                  resource_handler.name, disk_name)

    def _delete_vm(self, resource_handler, vm_name, resource_group):
        log.debug("[%s] Deleting VM: %s",
              resource_handler.name, vm_name)
        disks = self._get_vm_disk(vm_name, resource_group)
        vm_del_cmd = self.compute_client.virtual_machines.delete(
            resource_group,
            vm_name
        ).result()
        log.debug("[%s] Deleting VM done: %s",
              resource_handler.name, vm_name)
        self._delete_vm_disks(resource_handler, disks, resource_group)

    def _delete_public_ip_address(self, resource_handler, resource_group, name):
        log.debug("[%s] Deleting Public IP Address: %s",
              resource_handler.name, name)
        self.network_client.public_ip_addresses.delete(resource_group, name).result()
        log.debug("[%s] Deleting Public IP Address done: %s",
              resource_handler.name, name)

    def _delete_subnet(self, resource_handler, resource_group, vnet_name, name):
        log.debug("[%s] Deleting Subnet: %s",
              resource_handler.name, name)
        self.network_client.subnets.delete(resource_group, vnet_name, name).result()
        log.debug("[%s] Deleting Subnet done: %s",
              resource_handler.name, name)

    def _delete_vnet(self, resource_handler, resource_group, name):
        log.debug("[%s] Deleting Virtual Network: %s",
              resource_handler.name, name)
        self.network_client.virtual_networks.delete(resource_group, name).result()
        log.debug("[%s] Deleting Virtual Network done: %s",
              resource_handler.name, name)

    def _delete_network_interface(self, resource_handler, resource_group, name):
        log.debug("[%s] Deleting NIC: %s",
              resource_handler.name, name)
        self.network_client.network_interfaces.delete(resource_group, name).result()
        log.debug("[%s] Deleting NIC done: %s",
              resource_handler.name, name)

    @wet_method()
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Dropping node %r", resource_handler.name,
                  self.instance_data['node_id'])
        vm_name = self.instance_data['instance_id']['instance_id']
        vnet_name = self.instance_data['instance_id']['vnet_name']
        resource_group = self.res['resource_group']
        self._delete_vm(resource_handler, vm_name, resource_group)

        if 'network_interface' in self.created_resources:
            v = self.created_resources['network_interface']
            self._delete_network_interface(resource_handler, resource_group, v)
        for k in self.created_resources:
            v = self.created_resources[k]
            if k == 'public_ip_address': self._delete_public_ip_address(resource_handler, resource_group, v)
            if k == 'subnet': self._delete_subnet(resource_handler, resource_group, vnet_name, v)
            if k == 'virtual_network': self._delete_vnet(resource_handler, resource_group, v)

        log.debug("[%s] Done", resource_handler.name)


class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('ready')
    @needs_connection
    def perform(self, resource_handler):
        vm_name = self.instance_data['instance_id']['instance_id']
        resource_group = self.instance_data['instance_id']['resource_group']
        virtual_machine = self.compute_client.virtual_machines.get(
            resource_group,
            vm_name
        )
        state = virtual_machine.provisioning_state
        log.debug("[%s]: State from Azure: %s", resource_handler.name, state)
        try:
            retval = STATE_MAPPING[state]
        except KeyError:
            raise NotImplementedError('Unknown Azure state', state)
        else:
            log.debug("[%s] Done; azure_state=%r; status=%r",
                      resource_handler.name, state, retval)
            return retval


class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, resource_handler):
        """
        Return (IPv4) network address of the container.
        """
        vm_name = self.instance_data['instance_id']['instance_id']
        resource_group = self.instance_data['instance_id']['resource_group']
        virtual_machine = self.compute_client.virtual_machines.get(
            resource_group,
            vm_name
        )
        ni_reference = virtual_machine.network_profile.network_interfaces[0]
        ni_reference = ni_reference.id.split('/')
        ni_group = ni_reference[4]
        ni_name = ni_reference[8]

        net_interface = network_client.network_interfaces.get(ni_group, ni_name)
        ip_reference = net_interface.ip_configurations[0].public_ip_address
        if ip_reference == None:
            return net_interface.ip_configurations[0].private_ip_address
        return ip_reference.ip_address


class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    @needs_connection
    def perform(self, resource_handler):
        """
        Return network address of the container.
        """
        vm_name = self.instance_data['instance_id']['instance_id']
        resource_group = self.instance_data['instance_id']['resource_group']
        virtual_machine = self.compute_client.virtual_machines.get(
            resource_group,
            vm_name
        )
        ni_reference = virtual_machine.network_profile.network_interfaces[0]
        ni_reference = ni_reference.id.split('/')
        ni_group = ni_reference[4]
        ni_name = ni_reference[8]

        net_interface = self.network_client.network_interfaces.get(ni_group, ni_name)
        ip_reference = net_interface.ip_configurations[0].public_ip_address
        if ip_reference == None:
            return net_interface.ip_configurations[0].private_ip_address
        public_ip_reference = ip_reference.id.split('/')
        public_ip_group = public_ip_reference[4]
        public_ip_name = public_ip_reference[8]
        public_ip = self.network_client.public_ip_addresses.get(public_ip_group, public_ip_name)
        return public_ip.ip_address


@factory.register(ResourceHandler, PROTOCOL_ID)
class AzureResourceHandler(ResourceHandler):

    def __init__(self, endpoint, auth_data,
                 name=None, dry_run=False,
                 **config):
        self.endpoint = endpoint
        if (not auth_data) or (not "subscription_id" in auth_data) or (not "tenant_id" in auth_data) or (not "client_id" in auth_data) or (not "client_secret" in auth_data):
           errormsg = "Cannot find credentials for \""+endpoint+"\". Please, specify!"
           log.debug(errormsg)
           raise NodeCreationError(None, errormsg)
        self.auth_data = auth_data
        self.subscription_id = auth_data['subscription_id']
        self.tenant_id = auth_data['tenant_id']
        self.client_id = auth_data['client_id']
        self.client_secret = auth_data['client_secret']
        self.dry_run = dry_run
        self.name = name if name else endpoint

    def get_connection(self):
        return setup_connection(self.endpoint, self.auth_data)

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
class AzureSchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "resource_group", "location", "vm_size",
                         "publisher", "offer", "sku", "version", "username"]
        self.opt_keys = ["public_ip_needed", "vnet_name", "subnet_name", "customdata",
                         "server_name", "password", "ssh_key_data"]
    def perform_check(self, data):
        missing_keys = RHSchemaChecker.get_missing_keys(self, data, self.req_keys)
        if missing_keys:
            msg = "Missing key(s): " + ', '.join(str(key) for key in missing_keys)
            raise SchemaError(msg)
        if "password" not in data and "ssh_key_data" not in data:
            msg = "Missing key(s): either \"password\" or \"ssh_key_data\" must be defined"
            raise SchemaError(msg)
        valid_keys = self.req_keys + self.opt_keys
        invalid_keys = RHSchemaChecker.get_invalid_keys(self, data, valid_keys)
        if invalid_keys:
            msg = "Unknown key(s): " + ', '.join(str(key) for key in invalid_keys)
            raise SchemaError(msg)
        return True
