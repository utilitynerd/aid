import pytest
from aid.iptables import *
import iptc

test_ips = [ipaddress.ip_network(ip) for ip in ['192.0.2.2', '198.51.100.50', '203.0.113.0/24']]

def reset_iptables():
    iptc.Chain(table, 'INPUT').set_policy(iptc.Policy.ACCEPT)
    for chain in table.chains:
        chain.flush()

@pytest.fixture()
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


def test_list_rules_in_chain(add_test_iptables_rules):
    rules = list_rules_in_chain('INPUT')
    assert len(test_ips) == len(rules)
    assert all([ipaddress.ip_network(rule.src) in test_ips for rule in rules])


def test_reset_aid_chain(add_test_iptables_rules):
    assert len(test_ips) == len(list_rules_in_chain('INPUT'))
    reset_aid_chain('INPUT')
    assert len(list_rules_in_chain('INPUT')) == 0
