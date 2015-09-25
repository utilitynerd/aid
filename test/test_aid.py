from aid.iptables import  *
from aid.aid import *
import pytest
import requests
import collections


def test_no_duplicate_ips():
    c = collections.Counter(get_aidlist_ips())
    assert set(c.values()) == {1}

def test_AidEntry_captures_all_attributes():
    config = load_config()
    entry = call_sock_api(config, 'aggressive_ips')['aggressive_ips'][0]
    assert set(entry.keys()) == set(AIDEntry._fields)
