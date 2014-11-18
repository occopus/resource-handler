#!/dev/null

from nose.tools import eq_, ok_
import common

def test():
    cfg = common.configure()
    ok_(hasattr(cfg, 'clouds'))
    ok_('dummy_cloud_instance0' in cfg.clouds)
