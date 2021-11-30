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
#!/usr/bin/env python

import setuptools

setuptools.setup(
    name='OCCO-ResourceHandler',
    version='1.10',
    author='SZTAKI',
    author_email='occopus@lpds.sztaki.hu',
    namespace_packages=[
        'occo',
        'occo.plugins',
        'occo.plugins.resourcehandler',
    ],
    py_modules=[
        'occo.plugins.resourcehandler.ec2',
        'occo.plugins.resourcehandler.nova',
        'occo.plugins.resourcehandler.azure_vm',
        'occo.plugins.resourcehandler.azure_aci',
        'occo.plugins.resourcehandler.cloudbroker',
        'occo.plugins.resourcehandler.cloudsigma',
        'occo.plugins.resourcehandler.docker',
    ],
    packages=[
        'occo.resourcehandler',
    ],
    scripts=[],
    url='https://github.com/occopus',
    license='LICENSE.txt',
    description='Occopus Resource Handler',
    long_description=open('README.txt').read(),
    install_requires=[
        'openstacksdk',
        'azure-common',
        'azure-mgmt-compute',
        'azure-mgmt-network',
        'azure-mgmt-resource',
        'azure-mgmt-containerinstance',
        'argparse',
        'backports.ssl-match-hostname',
        'boto',
        'dicttoxml',
        'docker',
        'ndg-httpsclient',
        'python-dateutil',
        'PyYAML',
        'OCCO-Util',
        'OCCO-InfoBroker',
        'requests',
        'websocket-client',
        'python-novaclient==3.4.0',
        'ruamel.yaml',
        'voms-auth-system-openstack',
        'unicodecsv',
        'simplejson'
    ],
)
