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

rm -rf $PDIR
mkdir -p wheelhouse
virtualenv -p python3 $PDIR
source $PDIR/bin/activate
pip install --upgrade pip
pip install wheel
pip wheel --index-url https://pip3.lpds.sztaki.hu -w wheelhouse .
deactivate
rm -rf $PDIR
