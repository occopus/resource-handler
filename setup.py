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
from pip.req import parse_requirements

setuptools.setup(
    name='OCCO-CloudHandler',
    version='0.2.0',
    author='MTA SZTAKI',
    author_email='occopus@lpds.sztaki.hu',
    namespace_packages=[
        'occo',
        'occo.plugins',
        'occo.plugins.cloudhandler',
    ],
    py_modules=[
        'occo.plugins.cloudhandler.nova',
        'occo.plugins.cloudhandler.cloudbroker',
        'occo.plugins.cloudhandler.dummy',
        'occo.plugins.cloudhandler.boto'
    ],
    packages=[
        'occo.cloudhandler',
    ],
    scripts=[],
    url='https://github.com/occopus',
    license='LICENSE.txt',
    description='Occopus Cloud Handler',
    long_description=open('README.txt').read(),
    install_requires=[
        'argparse',
        'backports.ssl-match-hostname',
        'boto',
        'docker-py',
        'python-dateutil',
        'PyYAML',
        'OCCO-Util',
        'OCCO-InfoBroker',
        'requests',
        'websocket-client'
    ],
)
