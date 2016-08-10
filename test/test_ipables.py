import pytest
import os
from aid.iptables import *
import iptc

test_ips = [ipaddress.ip_address(ip) for ip in ['192.0.2.2', '198.51.100.50', '203.0.113.22']]
test_whitelist_nets = [ipaddress.ip_network(net) for net in ['192.0.2.2', '192.0.2.1', '203.0.113.0/24']]


def reset_iptables():
    table = iptc.Table(iptc.Table.FILTER)
    table.flush()


def list_rules_in_chain(chain_name):
    return [rule for rule in iptc.Chain(table, chain_name).rules]


@pytest.fixture(scope="function")
def setup_teardown(request):
    reset_iptables()
    request.addfinalizer(reset_iptables)


@pytest.fixture()
def create_whitelist(tmpdir):
    """
    Creates whitelist in tmp location and returns its file object
    """
    whitelist = os.path.join(str(tmpdir), 'whitelist')
    with open(whitelist, 'w') as f:
        f.writelines("\n".join(str(net) for net in test_whitelist_nets))
    return whitelist


def test_prepare_new_aid_chain(setup_teardown):
    assert table.is_chain('aid') is False
    prepare_aid_chain('aid')
    assert table.is_chain('aid')


def test_add_block_rules_to_chain(setup_teardown):
    chain = prepare_aid_chain('aid')
    assert len(chain.rules) == 0
    add_block_rules_to_chain(test_ips, 'aid')
    assert len(chain.rules) == 3
    assert [rule.src.split('/')[0] for rule in chain.rules] == [str(ip) for ip in test_ips]


def test_reset_existing_aid_chain(setup_teardown):
    assert not table.is_chain('aid')
    chain = prepare_aid_chain('aid')
    assert table.is_chain('aid')
    assert len(chain.rules) == 0
    add_block_rules_to_chain(test_ips)
    assert len(chain.rules) == 3
    chain = prepare_aid_chain('aid')
    assert len(chain.rules) == 0


def test_add_aid_chain_to_input(setup_teardown):
    chain_name = 'aid'
    prepare_aid_chain(chain_name)
    add_aid_chain_to_input(chain_name=chain_name, position=0)
    rules = list_rules_in_chain('INPUT')
    assert len(rules) == 1
    assert rules[0].target.name == 'aid'


def test_add_aid_chain_to_middle_of_input(setup_teardown):
    chain_name = 'aid'
    prepare_aid_chain(chain_name)
    add_block_rules_to_chain(test_ips, 'INPUT')
    assert len(list_rules_in_chain('INPUT')) == 3
    add_aid_chain_to_input(chain_name, 2)
    assert list_rules_in_chain('INPUT')[2].target.name == chain_name


def test_remove_aid_chain_from_input(setup_teardown):
    chain_name = 'aid'
    prepare_aid_chain(chain_name)
    add_block_rules_to_chain(test_ips, 'INPUT')
    add_aid_chain_to_input(chain_name=chain_name, position=1)
    assert list_rules_in_chain('INPUT')[1].target.name == chain_name
    remove_aid_chain_from_input(chain_name)
    assert len(list_rules_in_chain('INPUT')) == 3
    assert not any([rule.target.name == chain_name
                   for rule in list_rules_in_chain('INPUT')])


def test_load_whitelist(create_whitelist):
    whitelist = load_whitelist(create_whitelist)
    assert len(test_whitelist_nets) == len(whitelist)
    assert all([isinstance(ip, ipaddress.IPv4Network) for ip in whitelist])
    assert all([ip in test_whitelist_nets for ip in whitelist])


def test_fail_to_load_nonexistant_whitelist():
    with pytest.raises(SystemExit):
        load_whitelist('/fail')


def test_fail_when_whitelist_contains_invalid_entry(create_whitelist):
    with open(create_whitelist, 'a') as f:
            f.write('\n')
            f.write('a.b.c.d')
    with pytest.raises(SystemExit):
        load_whitelist(create_whitelist)


def test_remove_whitelisted_ips(create_whitelist):
    processed_list = remove_whitelisted_ips(test_ips, test_whitelist_nets)
    assert len(processed_list) == 1
    assert processed_list.pop() == ipaddress.ip_address('198.51.100.50',)

