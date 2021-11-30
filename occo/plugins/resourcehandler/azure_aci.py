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
from azure.mgmt.network.models import (
    ContainerNetworkInterfaceConfiguration,
    Delegation,
    IPConfigurationProfile,
    NetworkProfile,
    Subnet,
)

from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerinstance.models import (ContainerGroup,
                                                 Container,
                                                 ContainerGroupNetworkProfile,
                                                 ContainerGroupNetworkProtocol,
                                                 ContainerGroupRestartPolicy,
                                                 ContainerPort,
                                                 EnvironmentVariable,
                                                 GpuResource,
                                                 IpAddress,
                                                 Port,
                                                 ResourceRequests,
                                                 ResourceRequirements,
                                                 OperatingSystemTypes)

from msrestazure.azure_exceptions import CloudError

import occo.util.factory as factory
from occo.util import wet_method, coalesce, unique_vmname
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import itertools as it
import logging
import occo.constants.status as status
from occo.exceptions import SchemaError, NodeCreationError
import base64
import time

__all__ = ['AzureACIResourceHandler']

PROTOCOL_ID = 'azure_aci'

STATE_MAPPING = {
    'Pending'   : status.PENDING,
    'Creating'  : status.PENDING,
    'Succeeded' : status.READY
}

log = logging.getLogger('occo.resourcehandler.azureaci')


def setup_connection(endpoint, auth_data):
    subscription_id = auth_data['subscription_id']
    credentials = ServicePrincipalCredentials(
        client_id = auth_data['client_id'],
        secret = auth_data['client_secret'],
        tenant = auth_data['tenant_id']
    )
    resource_client = ResourceManagementClient(credentials, subscription_id)
    network_client = NetworkManagementClient(credentials, subscription_id)
    aci_client = ContainerInstanceManagementClient(credentials, subscription_id)
    return (subscription_id, resource_client, network_client, aci_client)


def needs_connection(f):
    import functools
    @functools.wraps(f)
    def g(self, resource_handler, *args, **kwargs):
        (subscription_id, resource_client, network_client, aci_client) = resource_handler.get_connection()
        self.subscription_id = subscription_id
        self.resource_client = resource_client
        self.network_client = network_client
        self.aci_client = aci_client
        return f(self, resource_handler, *args, **kwargs)
    return g


class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        self.node_def = resolved_node_definition
        self.res = self.node_def['resource']
        self.command = self.node_def.get('attributes', dict()).get('command', None)
        self.env = self.node_def.get('attributes', dict()).get('env', [])
        Command.__init__(self)
        self.created_resources = {}

    @wet_method('1')
    def _start_container(self, resource_handler):
        log.debug('Starting Azure ACI')
        location = self.res['location'].lower()
        self.resource_client.resource_groups.create_or_update(
            self.res['resource_group'], {'location': self.res['location']})
        container_group_name = unique_vmname(self.node_def)
        network_type = self.res['network_type']
        network_profile = None
        if 'gpu_type' in self.res:
            count = self.res['gpu_count'] if 'gpu_count' in self.res else 1
            gpu = GpuResource(count=count, sku=self.res['gpu_type'])
            container_resource_requests = ResourceRequests(memory_in_gb=self.res['memory'], cpu=self.res['cpu_cores'], gpu=gpu)
        else:
            container_resource_requests = ResourceRequests(memory_in_gb=self.res['memory'], cpu=self.res['cpu_cores'])
        container_resource_requirements = ResourceRequirements(requests=container_resource_requests)
        ports = []
        ipports = []
        for porte in self.res.get('ports', []):
            port = porte
            protocol = 'TCP'
            if isinstance(porte, str) and '/' in porte:
                (port, protocol) = port.split('/')
                port = int(port)
            ports.append(ContainerPort(port=port, protocol=protocol))
            ipports.append(Port(protocol=protocol, port=port))
        environment = []
        if network_type.lower() == 'public':
            pubip_var = EnvironmentVariable(name='_OCCOPUS_ALLOCATED_FQDN', value='%s.%s.azurecontainer.io' % (container_group_name, location))
            environment.append(pubip_var)
        for env in self.env:
            edata = env.split('=', 1)
            if len(edata) != 2: continue
            env_var = EnvironmentVariable(name=edata[0], value=edata[1])
            environment.append(env_var)
        container = Container(name=container_group_name,
                          image=self.res['image'],
                          resources=container_resource_requirements,
                          ports=ports,
                          command=self.command if self.command is not None else None,
                          environment_variables=environment)
        if network_type.lower() == 'public':
            group_ip_address = IpAddress(ports=ipports,
                                        dns_name_label=container_group_name,
                                        type='Public')
            self.vnet_name = None
        elif network_type.lower() == 'private':
            vnet_name = unique_vmname(self.node_def) + '-vnet' if self.res.get('vnet_name', None) == None else self.res['vnet_name']
            self.vnet_name = vnet_name
            subnet_name = unique_vmname(self.node_def) + '-subnet' if self.res.get('subnet_name', None) == None else self.res['subnet_name']
            network_profile_name = unique_vmname(self.node_def) + '-netprofile'
            if self.res.get('vnet_name', None) == None:
                log.debug('Creating vnet')
                async_vnet_creation = self.network_client.virtual_networks.create_or_update(
                    self.res['resource_group'],
                    vnet_name,
                    {
                        'location': location,
                        'address_space': {
                            'address_prefixes': ['10.0.0.0/16']
                        }
                    }
                )
                async_vnet_creation.wait()
                self.created_resources['virtual_network'] = vnet_name
                log.debug('Created vnet')
            if self.res.get('subnet_name', None) == None:
                # Create Subnet
                log.debug('Creating Subnet')
                aci_delegation_service_name = "Microsoft.ContainerInstance/containerGroups"
                aci_delegation = Delegation(
                    name=aci_delegation_service_name,
                    service_name=aci_delegation_service_name
                )
                subnet = Subnet(
                    name=subnet_name,
                    location=location,
                    address_prefix='10.0.0.0/24',
                    delegations=[aci_delegation]
                )
                subnet_info = self.network_client.subnets.create_or_update(
                    self.res['resource_group'],
                    vnet_name,
                    subnet_name,
                    subnet
                ).result()
                self.created_resources['subnet'] = subnet_name
                log.debug('Creatied Subnet')
            else:
                subnet_info = self.network_client.subnets.get(
                    self.res['resource_group'],
                    vnet_name,
                    subnet_name
                )
            default_network_profile_name = "aci-network-profile-{}-{}".format(vnet_name, subnet_name)
            network_profile_ops = self.network_client.network_profiles
            network_profile = NetworkProfile(
                name=default_network_profile_name,
                location=location,
                container_network_interface_configurations=[ContainerNetworkInterfaceConfiguration(
                    name="eth0",
                    ip_configurations=[IPConfigurationProfile(
                        name="ipconfigprofile",
                        subnet=subnet_info
                    )]
                )])
            network_profile = network_profile_ops.create_or_update(self.res['resource_group'], network_profile_name, network_profile).result()
            group_ip_address = IpAddress(ports=ipports,
                                        type='Private')
        else:
            errormsg = '[{0}] Network type "{1}" is not supported. Please use either "Public" or "Private"'.format(
                       resource_handler.name, network_type)
            log.debug(errormsg)
            raise NodeCreationError(None, errormsg)

        cg_network_profile = None
        if network_profile:
            cg_network_profile = ContainerGroupNetworkProfile(id=network_profile.id)
            self.created_resources['network_profile'] = network_profile_name

        group = ContainerGroup(location=location,
                            containers=[container],
                            os_type=self.res['os_type'],
                            ip_address=group_ip_address,
                            network_profile=cg_network_profile)
        # Create the container group
        self.aci_client.container_groups.create_or_update(self.res['resource_group'],
                                                    container_group_name,
                                                    group)
        return container_group_name

    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
              resource_handler.name, self.node_def)

        log.debug("Creating node")

        container_group_name = self._start_container(resource_handler)

        log.debug("[%s] Done; container_id = %r", resource_handler.name, container_group_name)
        return dict(
            instance_id=container_group_name,
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

    def _delete_container(self, resource_handler, container_group_name, resource_group):
        log.debug("[%s] Deleting container group: %s",
              resource_handler.name, container_group_name)
        self.aci_client.container_groups.delete(resource_group, container_group_name)
        log.debug("[%s] Deleting container group done: %s",
              resource_handler.name, container_group_name)

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

    def _delete_network_profile(self, resource_handler, resource_group, name):
        log.debug("[%s] Deleting Network Profile: %s",
              resource_handler.name, name)
        i = 0
        while i < 10:
            try:
                self.network_client.network_profiles.delete(resource_group, name).result()
                break
            except Exception as e:
                i = i + 1
                log.debug("[%s] Deleting Network Profile failed (attempt %d): %s",
                    resource_handler.name, i, name,)
                time.sleep(5)
        log.debug("[%s] Deleting Network Profile done: %s",
              resource_handler.name, name)

    @wet_method()
    @needs_connection
    def perform(self, resource_handler):
        log.debug("[%s] Dropping node %r", resource_handler.name,
                  self.instance_data['node_id'])
        container_group_name = self.instance_data['instance_id']['instance_id']
        resource_group = self.res['resource_group']
        vnet_name = self.instance_data['instance_id']['vnet_name']
        self._delete_container(resource_handler, container_group_name, resource_group)
        if 'network_profile' in self.created_resources: self._delete_network_profile(resource_handler, resource_group, self.created_resources['network_profile'])
        for k in self.created_resources:
            v = self.created_resources[k]
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
        container_group_name = self.instance_data['instance_id']['instance_id']
        resource_group = self.instance_data['instance_id']['resource_group']
        container_group = self.aci_client.container_groups.get(resource_group,
                                                container_group_name)
        state = container_group.provisioning_state
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
        container_group_name = self.instance_data['instance_id']['instance_id']
        resource_group = self.instance_data['instance_id']['resource_group']
        container_group = self.aci_client.container_groups.get(resource_group,
                                                container_group_name)
        ip_address = container_group.ip_address
        if ip_address is None:
            return ''
        return ip_address.ip


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
        container_group_name = self.instance_data['instance_id']['instance_id']
        resource_group = self.instance_data['instance_id']['resource_group']
        container_group = self.aci_client.container_groups.get(resource_group,
                                                container_group_name)
        ip_address = container_group.ip_address
        if ip_address is None:
            return ''
        rv = []
        if ip_address.fqdn is not None: rv.append(ip_address.fqdn)
        if ip_address.ip is not None: rv.append(ip_address.ip)
        return list(rv)

@factory.register(ResourceHandler, PROTOCOL_ID)
class AzureResourceHandler(ResourceHandler):

    def __init__(self, endpoint, auth_data,
                 name=None, dry_run=False,
                 **config):
        self.endpoint = endpoint
        self.auth_data = auth_data
        self.subscription_id = auth_data['subscription_id']
        self.tenant_id = auth_data['tenant_id']
        self.client_id = auth_data['client_id']
        self.client_secret = auth_data['client_secret']
        self.dry_run = dry_run
        self.name = name if name else endpoint

        if (not auth_data) or (not "subscription_id" in auth_data) or (not "tenant_id" in auth_data) or (not "client_id" in auth_data) or (not "client_secret" in auth_data):
           errormsg = "Cannot find credentials for \""+endpoint+"\". Please, specify!"
           log.debug(errormsg)
           raise NodeCreationError(None, errormsg)

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
class AzureACISchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "resource_group", "location", "cpu_cores",
                         "memory", "image", "os_type", "network_type"]
        self.opt_keys = ["gpu_type", "gpu_count", "ports", "vnet_name", "subnet_name"]
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
