#!/usr/bin/env python

import setuptools
from pip.req import parse_requirements

setuptools.setup(
    name='OCCO-CloudHandler',
    version='0.1.0',
    author='Adam Visegradi',
    author_email='adam.visegradi@sztaki.mta.hu',
    namespace_packages=[
        'occo',
        'occo.plugins',
        'occo.plugins.cloudhandler',
    ],
    py_modules=[
        'occo.plugins.cloudhandler.dummy',
        'occo.plugins.cloudhandler.boto'
    ],
    packages=[
        'occo.cloudhandler',
    ],
    scripts=[],
    url='http://www.lpds.sztaki.hu/',
    license='LICENSE.txt',
    description='OCCO Cloud Handler',
    long_description=open('README.txt').read(),
    install_requires=[
        'argparse',
        'boto',
        'drett-client',
        'python-dateutil',
        'PyYAML',
        'OCCO-Util',
        'OCCO-InfoBroker',
    ],
)
