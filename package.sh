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
pip install wheel
pip wheel --find-links http://c155-10.localcloud:8080/packages --no-index .
deactivate
rm -rf $PDIR
