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
    util.set_config_base_dir('etc/occo')
    with open('occo_test/test.yaml') as f:
        cfg = config.DefaultYAMLConfig(f)
    logging.config.dictConfig(cfg.logging)
    return cfg
