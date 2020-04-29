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

""" CloudBroker implementation of the
:class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class.

.. moduleauthor:: Zoltan Farkas <zoltan.farkas@sztaki.mta.hu>
"""

from urllib.parse import urlparse
import occo.util.factory as factory
from occo.util import wet_method, coalesce
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import itertools as it
import logging
import occo.constants.status as status
import requests, json, uuid, base64
import xml.dom.minidom
from xml.dom.minidom import parseString
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, tostring
from time import sleep
import xml.etree.ElementTree as ET
from occo.exceptions import SchemaError, NodeCreationError
from dicttoxml import dicttoxml
from collections import OrderedDict

__all__ = ['CloudBrokerResourceHandler']

PROTOCOL_ID='cloudbroker'

log = logging.getLogger('occo.resourcehandler.cloudbroker')

def get_auth(auth_data):
    return (auth_data['email'], auth_data['password'])

def get_instance(resource_handler, instanceid):
    attempt = 0
    stime = 1
    while attempt < 5:
        query_str = resource_handler.endpoint + '/instances/' + instanceid + '.xml'
        r = requests.get(query_str, auth=get_auth(resource_handler.auth_data))
        if (r.status_code != 200):
            log.debug('[%s] CloudBroker API call failed! query: %s, status code %d, response: %s',
                      resource_handler.name, query_str, r.status_code, r.text)
        else:
            DOMTree = xml.dom.minidom.parseString(r.text)
            instance = DOMTree.documentElement
            if 0 != instance.getElementsByTagName('id').length:
                return instance
            else:
                log.debug('[%s] CloudBroker API returned incorrect answer! No instance id is found.',
                          resource_handler.name, query_str, r.status_code, r.text)
        sleep(stime)
        stime = stime * 2
        attempt += 1
        log.debug('[%s] Retry calling the CloudBroker API...',
                  resource_handler.name)
    errormsg = 'Error in querying instance \'{0}\' {1} times through CloudBroker API at \'{2}\'.'.format(
               str(instanceid), str(attempt), resource_handler.endpoint)
    log.debug(errormsg)
    raise Exception(errormsg)

def getTagText(nodelist):
    rc = []
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc.append(node.data)
    return ''.join(rc)

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition
        self.input_type_id = None

    @wet_method(1)
    def _start_instance(self, resource_handler):
        """
        Start a CloudBroker instance.
        """
        log.debug("[%s] Creating CloudBroker instance...", resource_handler.name)
        descr = self.resolved_node_definition['resource']['description']
        descr.setdefault('disable_autostop', 'true')
        descr.setdefault('isolated', 'true')
        context = self.resolved_node_definition.get('context', None)
        if context is not None:
            descr['cloud-init'] = base64.b64encode(context.encode('utf-8')).decode('utf-8')
            descr['cloud-init-b64'] = 'true'
        start_in_vpc = self.resolved_node_definition.get('start_in_vpc', None)
        if start_in_vpc is not None:
            descr['start-in-vpc'] = start_in_vpc
        log.debug("[%s] XML to pass to CloudBroker: %s",
                  resource_handler.name, dicttoxml(descr, custom_root='instance', attr_type=False))
        r = requests.post(resource_handler.endpoint + '/instances.xml',
                          dicttoxml(descr, custom_root='instance', attr_type=False),
                          auth=get_auth(resource_handler.auth_data),
                          headers={'Content-Type': 'application/xml'})
        log.debug('[%s] CloudBroker instance create response status code %d, response: %s',
                  resource_handler.name, r.status_code, r.text)
        if (r.status_code == 201):
            DOMTree = xml.dom.minidom.parseString(r.text)
            instance = DOMTree.documentElement
            instanceID = instance.getElementsByTagName('id')[0].childNodes[0].data
            log.debug("[%s] CloudBroker instance started, internal id: %s", resource_handler.name, instanceID)
            return instanceID
        else:
            errormsg = '[{0}] Failed to create CloudBroker instance, request status code {1}, response: {2}'.format(
                       resource_handler.name, r.status_code, r.text)
            log.debug(errormsg)
            raise NodeCreationError(None, errormsg)

    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
                resource_handler.name, self.resolved_node_definition['name'])
        resource = self.resolved_node_definition['resource']
        instanceID = self._start_instance(resource_handler)
        log.debug("[%s] Done; instanceID = %r", resource_handler.name, instanceID)
        return instanceID

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method()
    def _delete_vms(self, resource_handler, *instance_ids):
        """
        Terminate CloudBroker instances.

        :param instance_ids: The list of CloudBroker instance identifiers.
        :type instance_ids: str

        :Remark: This is a "wet method", termination will not be attempted
            if the instance is in debug mode (``dry_run``).
        """
        for instance_id in instance_ids:
            r = requests.put(resource_handler.endpoint + '/instances/' + instance_id + '/stop',
                auth=get_auth(resource_handler.auth_data))

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

        self._delete_vms(resource_handler, instance_id)

        log.debug("[%s] Done", resource_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method(status.READY)
    def perform(self, resource_handler):
        instance = get_instance(resource_handler, self.instance_data['instance_id'])
        stat = getTagText(instance.getElementsByTagName('status').item(0).childNodes)
        statusMap = {
            'starting': status.PENDING,
            'initializing': status.PENDING,
            'preparing': status.PENDING,
            'running': status.READY,
            'stopping': status.SHUTDOWN,
            'halted': status.SHUTDOWN,
        }
        retval = statusMap.get(stat)
        if not retval:
            raise NotImplementedError()
        return retval

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    def perform(self, resource_handler):
        instance = get_instance(resource_handler, self.instance_data['instance_id'])
        int_ip = getTagText(instance.getElementsByTagName('internal-ip-address').item(0).childNodes)
        ext_ip = getTagText(instance.getElementsByTagName('external-ip-address').item(0).childNodes)
        log.debug("[%s] Internal IP is: %s, External IP is: %s", resource_handler.name,
                int_ip, ext_ip)
        return int_ip

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    def perform(self, resource_handler):
        instance = get_instance(resource_handler, self.instance_data['instance_id'])
        int_dns = getTagText(instance.getElementsByTagName('internal-hostname').item(0).childNodes)
        ext_dns = getTagText(instance.getElementsByTagName('external-hostname').item(0).childNodes)
        int_ip = getTagText(instance.getElementsByTagName('internal-ip-address').item(0).childNodes)
        ext_ip = getTagText(instance.getElementsByTagName('external-ip-address').item(0).childNodes)
        log.debug("[%s] Internal IP is: %s, External IP is: %s, Internal hostname is: %s, External hostname is: %s",
                resource_handler.name, int_ip, ext_ip, int_dns, ext_dns)
        addresses = list()
        addresses = addresses[:]+[ext_dns] if ext_dns  else addresses
        addresses = addresses[:]+[ext_ip] if ext_ip else addresses
        addresses = addresses[:]+[int_dns] if int_dns else addresses
        addresses = addresses[:]+[int_ip] if int_ip else addresses
        addresses = [''] if addresses == [] else addresses
        retaddr = list(OrderedDict.fromkeys(addresses))
        return retaddr

@factory.register(ResourceHandler, PROTOCOL_ID)
class CloudBrokerResourceHandler(ResourceHandler):
    """ Implementation of the
    :class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class utilizing the
    CloudBroker_ RESTful_ interface.

    :param str endpoint: Definition of the CloudBroker service URL.
    :param dict auth_data: Authentication infomration for the connection.

        * ``email``: The e-mail address used to log in.
        * ``password``: The password belonging to the e-mail address.

    :param str name: The name of this ``ResourceHandler`` instance. If unset,
        ``endpoint`` is used.
    :param bool dry_run: Skip actual resource aquisition, polling, etc.

    .. _CloudBroker: http://cloudbroker.com/
    .. _RESTful: https://en.wikipedia.org/wiki/Representational_state_transfer
    """
    def __init__(self, endpoint, auth_data,
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else endpoint
        if (not auth_data) or (not "email" in auth_data) or (not "password" in auth_data):
           errormsg = "Cannot find credentials for \""+endpoint+"\". Please, specify!"
           log.debug(errormsg)
           raise NodeCreationError(None, errormsg)
        self.endpoint = endpoint if not dry_run else None
        self.auth_data = auth_data if not dry_run else None

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
class CloudbrokerSchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "description"]
        self.req_desc_keys = ["deployment_id", "instance_type_id"]
        self.opt_keys = ["name", "start_in_vpc"]
    def perform_check(self, data):
        missing_keys = RHSchemaChecker.get_missing_keys(self, data, self.req_keys)
        if missing_keys:
            msg = "Missing key(s): " + ', '.join(str(key) for key in missing_keys)
            raise SchemaError(msg)
        missing_keys = RHSchemaChecker.get_missing_keys(self, data['description'], self.req_desc_keys)
        if missing_keys:
            msg = "Missing key(s) in description: " + ', '.join(str(key) for key in missing_keys)
            raise SchemaError(msg)
        valid_keys = self.req_keys + self.opt_keys
        invalid_keys = RHSchemaChecker.get_invalid_keys(self, data, valid_keys)
        if invalid_keys:
            msg = "Unknown key(s): " + ', '.join(str(key) for key in invalid_keys)
            raise SchemaError(msg)
        return True
