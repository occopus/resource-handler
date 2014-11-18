#!/dev/null

import logging.config
import occo.util.config as config
import occo.infobroker.kvstore
import occo.cloudhandler.backends.dummy
import yaml

def setup():
    with open('occo_test/test.yaml') as f:
        cfg = config.DefaultYAMLConfig(f)
    logging.config.dictConfig(cfg.logging)

def test():
    pass
