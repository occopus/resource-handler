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
#!/dev/null

import logging.config
import occo.util as util
import occo.util.config as config
import occo.infobroker.kvstore
import occo.plugins.cloudhandler.dummy
import yaml

cfg = object()

def configure():
    global cfg
    cfg = config.DefaultYAMLConfig('occo_test/test.yaml')
    logging.config.dictConfig(cfg.logging)
    return cfg
