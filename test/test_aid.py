from aid.aid import *
import collections


def test_no_duplicate_ips():
    c = collections.Counter(ips())
    assert set(c.values()) == {1}


def test_aidentry_captures_all_attributes():
    config = load_config()
    # get a single entry as an example.  call_sock_api returns a list of dicts
    entry = call_sock_api(config, 'aggressive_ips')['aggressive_ips'][0]
    # compare the entries keys to the fields in AIDEntry
    assert set(entry.keys()) == set(AIDEntry._fields)


def test_can_get_list_of_services():
    service_list = services()
    assert isinstance(service_list, list)
    assert len(service_list) != 0
    for service in ['ssh', 'vnc', 'web', 'rdp', 'mysql', 'postgresql', 'mongodb']:
        assert service in service_list

