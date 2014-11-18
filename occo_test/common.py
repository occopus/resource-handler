#!/dev/null

import logging.config
import occo.util.config as config
import occo.infobroker.kvstore
import occo.cloudhandler.backends.dummy
import yaml

def configure():
    global cfg
    with open('occo_test/test.yaml') as f:
        cfg = config.DefaultYAMLConfig(f)
    logging.config.dictConfig(cfg.logging)
