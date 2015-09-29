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
    # get a single entry as an example.  call_sock_api returns a list of dicts
    entry = call_sock_api(config, 'aggressive_ips')['aggressive_ips'][0]
    # compare the entries keys to the fields in AIDEntry
    assert set(entry.keys()) == set(AIDEntry._fields)
