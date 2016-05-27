### Copyright 2016, MTA SZTAKI, www.sztaki.hu
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

""" CloudSigma implementation of the
:class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class.

.. moduleauthor:: Zoltan Farkas <zoltan.farkas@sztaki.mta.hu>
"""

from __future__ import absolute_import
import urlparse
import occo.util.factory as factory
from occo.util import wet_method, coalesce
from occo.resourcehandler import ResourceHandler, Command, RHSchemaChecker
import itertools as it
import logging
import occo.constants.status as status
import requests, json, uuid, time, base64
from occo.exceptions import SchemaError

__all__ = ['CloudSigmaResourceHandler']

PROTOCOL_ID='cloudsigma'
STATE_MAPPING = {
    'stopping'      : status.SHUTDOWN,
    'stopped'       : status.SHUTDOWN,
    'running'       : status.READY,
    'paused'        : status.PENDING,
    'starting'      : status.PENDING,
    'unavailable'   : status.FAIL,
}
log = logging.getLogger('occo.resourcehandler.cloudsigma')

def get_auth(auth_data):
    return (auth_data['email'], auth_data['password'])

def get_server_json(resource_handler, srv_id):
    r = requests.get(resource_handler.endpoint + '/servers/' + srv_id + '/',
        auth=get_auth(resource_handler.auth_data))
    if r.status_code != 200:
        log.error('[%s] Failed to get server\'s info, response code: %d', resource_handler.name, r.status_code)
        log.error('[%s] Response text: %s', resource_handler.name, r.text)
        return None
    return r.json()

class CreateNode(Command):
    def __init__(self, resolved_node_definition):
        Command.__init__(self)
        self.resolved_node_definition = resolved_node_definition

    @wet_method(1)
    def _clone_drive(self, resource_handler, libdrive_id):
        r = requests.post(resource_handler.endpoint + '/libdrives/' + libdrive_id + '/action/',
            auth=get_auth(resource_handler.auth_data), params={'do': 'clone'})
        if r.status_code != 202:
            log.error('[%s] Cloning library drive %s failed with status code %d!', resource_handler.name, libdrive_id, r.status_code)
            log.error('[%s] Response text: %s', resource_handler.name, r.text)
            return None
        json_data = json.loads(r.text)
        uuid = json_data['objects'][0]['uuid']
        if uuid == None:
            log.error('[%s] Cloning library drive %s failed: did not receive UUID!', resource_handler.name, libdrive_id)
        return uuid

    def _delete_drive(self, resource_handler, drv_id):
        r = requests.delete(resource_handler.endpoint + '/drives/' + drv_id + '/',
            auth=get_auth(resource_handler.auth_data))
        if r.status_code != 204:
            log.error('[%s] Deleting cloned drive %s failed with status code %d!', resource_handler.name, drv_id, r.status_code)
            log.error('[%s] Response text: %s', resource_handler.name, r.text)
       

    @wet_method('unmounted')
    def _get_drive_status(self, resource_handler, drv_id):
        r = requests.get(resource_handler.endpoint + '/drives/' + drv_id + '/',
            auth=get_auth(resource_handler.auth_data))
        if r.status_code != 200:
            log.error('[%s] Failed to query drive status, response code: %d', resource_handler.name, r.status_code)
            log.error('[%s] Response text: %s', resource_handler.name, r.text)
            return 'unknown'
        st = r.json()['status']
        log.debug('[%s] Status of drive %s is: %s', resource_handler.name, drv_id, st)
        return st

    @wet_method(1)
    def _create_server(self, resource_handler, drv_id):
        """
        Start the VM instance.

        :Remark: This is a "wet method", the VM will not be started
            if the instance is in debug mode (``dry_run``).
        """
        descr = self.resolved_node_definition['resource']['description']
        context = self.resolved_node_definition.get('context', None)
        if context is not None:
            descr['meta'] = {
                'base64_fields': 'cloudinit-user-data',
                'cloudinit-user-data': base64.b64encode(context)
            }
        if 'vnc_password' not in descr:
            descr['vnc_password'] = str(uuid.uuid4())
        if 'name' not in descr:
            descr['name'] = str(uuid.uuid4())
        if 'drivers' not in descr:
            descr['drives'] = []
        nd = {
            "boot_order": 1,
            "dev_channel": "0:0",
            "device": "virtio",
            "drive": drv_id
        }
        descr['drives'].append(nd)
        json_data = {}
        json_data['objects'] = [descr]
        r = requests.post(resource_handler.endpoint + '/servers/',
            auth=get_auth(resource_handler.auth_data), json=json_data)
        if r.status_code != 201:
            log.error('[%s] Failed to create server, response code: %d', resource_handler.name, r.status_code)
            log.error('[%s] Response text: %s', resource_handler.name, r.text)
            return None
        srv_uuid = r.json()['objects'][0]['uuid']
        log.debug('[%s] Created server\'s UUID is: %s', resource_handler.name, srv_uuid)
        return srv_uuid

    @wet_method(True)
    def _start_server(self, resource_handler, srv_id):
        r = requests.post(resource_handler.endpoint + '/servers/' + srv_id + '/action/',
            auth=get_auth(resource_handler.auth_data), params={'do': 'start'})
        if r.status_code != 202:
            log.error('[%s] Failed to start server, response code: %d', resource_handler.name, r.status_code)
            log.error('[%s] Response text: %s', resource_handler.name, r.text)
            return False
        return True

    def perform(self, resource_handler):
        log.debug("[%s] Creating node: %r",
                  resource_handler.name, self.resolved_node_definition['name'])

        drv_id = self._clone_drive(resource_handler, self.resolved_node_definition['resource']['libdrive_id'])
        drv_st = 'unknown'
        steps = 0
        sval = 1
        while drv_st != 'unmounted' and steps < 5:
            drv_st = self._get_drive_status(resource_handler, drv_id)
            time.sleep(sval)
            steps += 1
            sval *=  2
        if steps == 5 and drv_st != 'unmounted':
            log.error('[%s] Cloned drive failed to enter unmounted status, aborting', resource_handler.name)
            self._delete_drive(resource_handler, drv_id)
            return None

        srv_id = self._create_server(resource_handler, drv_id)
        while True != self._start_server(resource_handler, srv_id):
            time.sleep(5)

        return srv_id

class DropNode(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    def _stop_server(self, resource_handler, srv_id):
        r = requests.post(resource_handler.endpoint + '/servers/' + srv_id + '/action/',
            auth=get_auth(resource_handler.auth_data), params={'do': 'stop'})
        if r.status_code != 202:
            log.error('[%s] Failed to delete server, response code: %d', resource_handler.name, r.status_code)
            log.error('[%s] Response text: %s', resource_handler.name, r.text)

    def _delete_server(self, resource_handler, srv_id):
        r = requests.delete(resource_handler.endpoint + '/servers/' + srv_id + '/',
            auth=get_auth(resource_handler.auth_data), params={'recurse': 'all_drives'},
            headers={'Content-type': 'application/json'})
        if r.status_code != 204:
            log.error('[%s] Failed to delete server, response code: %d', resource_handler.name, r.status_code)
            log.error('[%s] Response text: %s', resource_handler.name, r.text)

    @wet_method()
    def perform(self, resource_handler):
        """
        Terminate a VM instance.

        :param instance_data: Information necessary to access the VM instance.
        :type instance_data: :ref:`Instance Data <instancedata>`
        """
        srv_id = self.instance_data['instance_id']
        log.debug("[%s] Deleting server %r", resource_handler.name,
                self.instance_data['node_id'])

        self._stop_server(resource_handler, srv_id)
        while 'stopped' != get_server_json(resource_handler, srv_id)['status']:
            time.sleep(5)
        self._delete_server(resource_handler, srv_id)

        log.debug("[%s] Done", resource_handler.name)

class GetState(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method(status.READY)
    def perform(self, resource_handler):
        srv_id = self.instance_data['instance_id']
        json_data = get_server_json(resource_handler, srv_id)
        if json_data == None:
            return status.TMP_FAIL
        srv_st = json_data['status']
        try:
            retval = STATE_MAPPING[srv_st]
        except KeyError:
            raise NotImplementedError('Unknown CloudSigma server state', srv_st)
        else:
            log.debug("[%s] Done; cloudsigma_state=%r; status=%r",
                      resource_handler.name, srv_st, retval)
            return retval

class GetIpAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    def perform(self, resource_handler):
        srv_id = self.instance_data['instance_id']
        rv = ''
        json_data = get_server_json(resource_handler, srv_id)
        if json_data == None:
            return rv
        if json_data['runtime'] == None:
            return rv
        if 'nics' not in json_data['runtime']:
            return rv
        for nic in json_data['runtime']['nics']:
            return nic['ip_v4']['uuid']

class GetAddress(Command):
    def __init__(self, instance_data):
        Command.__init__(self)
        self.instance_data = instance_data

    @wet_method('127.0.0.1')
    def perform(self, resource_handler):
        srv_id = self.instance_data['instance_id']
        rv = ''
        json_data = get_server_json(resource_handler, srv_id)
        if json_data == None:
            return rv
        if json_data['runtime'] == None:
            return rv
        if 'nics' not in json_data['runtime']:
            return None
        for nic in json_data['runtime']['nics']:
            return nic['ip_v4']['uuid']

@factory.register(ResourceHandler, PROTOCOL_ID)
class CloudSigmaResourceHandler(ResourceHandler):
    """ Implementation of the
    :class:`~occo.resourcehandler.resourcehandler.ResourceHandler` class utilizing the
    CloudSigma_ RESTful_ interface.

    :param str endpoint: Endpoint of the CloudSigma service URL.
    :param dict auth_data: Authentication infomration for the connection.

        * ``email``: The e-mail address used to log in.
        * ``password``: The password belonging to the e-mail address.

    :param str name: The name of this ``ResourceHandler`` instance. If unset,
        ``endpoint`` is used.
    :param bool dry_run: Skip actual resource aquisition, polling, etc.

    .. _CloudSigma: https://www.cloudsigma.com/
    .. _RESTful: https://en.wikipedia.org/wiki/Representational_state_transfer
    """
    def __init__(self, endpoint, auth_data,
                 name=None, dry_run=False,
                 **config):
        self.dry_run = dry_run
        self.name = name if name else endpoint
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
class CloudSigmaSchemaChecker(RHSchemaChecker):
    def __init__(self):
        self.req_keys = ["type", "endpoint", "libdrive_id", "description"]
        self.opt_keys = ["name"]
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

