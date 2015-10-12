import pytest
import os
from aid.iptables import *
import iptc

test_ips = [ipaddress.ip_address(ip) for ip in ['192.0.2.2', '198.51.100.50', '203.0.113.22']]
test_whitelist_nets = [ipaddress.ip_network(net) for net in ['192.0.2.2', '192.0.2.1', '203.0.113.0/24']]

def reset_iptables():
    table = iptc.Table(iptc.Table.FILTER)
    table.flush()


@pytest.fixture(scope="function")
def setup_teardown(request):
    reset_iptables()
    request.addfinalizer(reset_iptables)


@pytest.fixture()
def add_test_iptables_rules(setup_teardown):
    input_chain = iptc.Chain(table, 'INPUT')
    for ip in test_ips:
        rule = iptc.Rule()
        rule.src = str(ip)
        rule.target = iptc.Target(rule,'DROP')
        input_chain.append_rule(rule)


@pytest.fixture()
def create_whitelist(tmpdir):
    """
    Creates whitelist in tmp location and returns its file object
    """
    whitelist= os.path.join(str(tmpdir), 'whitelist')
    with open(whitelist, 'w') as f:
        f.writelines("\n".join(str(net) for net in test_whitelist_nets))
    return whitelist


def test_list_rules_in_chain(add_test_iptables_rules):
    rules = list_rules_in_chain('INPUT')
    assert len(test_ips) == len(rules)
    assert all([ipaddress.ip_address(rule.src.split('/')[0]) in test_ips for rule in rules])

@pytest.mark.parametrize("chain_name",[
    ("aid"),
    ("test")
])
def test_prepare_new_aid_chain(setup_teardown,  chain_name):
    assert table.is_chain(chain_name) is False
    if chain_name == 'aid':
        prepare_aid_chain()
    else:
        prepare_aid_chain(chain_name)
    assert table.is_chain(chain_name) == True


# def test_reset_existing_aid_chain(add_test_iptables_rules):
#     assert len(test_ips) == len(list_rules_in_chain('INPUT'))
#     reset_aid_chain('INPUT')
#     assert len(list_rules_in_chain('INPUT')) == 0


def test_load_whitelist(create_whitelist):
    whitelist = load_whitelist(create_whitelist)
    assert len(test_whitelist_nets) == len(whitelist)
    assert all(isinstance(ip, ipaddress.IPv4Network) for ip in whitelist)
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






# def test_add_aid_chain_to_input(setup_teardown):
#     table.create_chain
#     add_aid_chain_to_input()
#     rules = list_rules_in_chain('INPUT')
#     assert len(rules) == 1
#     assert rules[0].target.name == 'aid'
#     reset_iptables()
#     add_aid_chain_to_input('test')
#     assert rules[0].target.name == 'aid'

reset_iptables()