#!/dev/null

import logging.config
import occo.util as util
import occo.util.config as config
import occo.infobroker.kvstore
import occo.cloudhandler.backends.dummy
import yaml

cfg = object()

def configure():
    global cfg
    cfg = config.DefaultYAMLConfig('occo_test/test.yaml')
    logging.config.dictConfig(cfg.logging)
    return cfg
