#!/bin/bash

set -e

PDIR=env/packaging

if [ -d wheelhouse ]; then
    echo -n 'Delete old wheelhouse? [y/N]'
    read
    if [ ".$REPLY" == '.y' ]; then
        rm -rf wheelhouse
    fi
fi

virtualenv --no-site-packages $PDIR
source $PDIR/bin/activate
pip install --upgrade pip
pip install wheel
pip wheel --find-links http://pip.lpds.sztaki.hu/packages --trusted-host pip.lpds.sztaki.hu .
deactivate
rm -rf $PDIR
