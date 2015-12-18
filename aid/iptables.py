import ipaddress
import sys

import aid

import requests

try:
    import iptc
    import click
except ImportError as e:
    sys.exit("{} requires the {} module.".format(__file__, e.name))

try:
    table = iptc.Table(iptc.Table.FILTER)
except iptc.ip4tc.IPTCError as e:
    sys.exit(e)


def prepare_aid_chain(chain_name='aid'):
    """
    Ensure an empty IPTables chain, named chain_name, exist

    :param chain_name: name of IPTables chain to create
    :return: prepared iptc.Chain object
    """
    if table.is_chain(chain_name):
        iptc.Chain(table, chain_name).flush()
    else:
        table.create_chain(chain_name)
    return iptc.Chain(table, chain_name)


def add_block_rules_to_chain(ips, chain_name='aid'):
    """
    Add a DROP  rule to chain_name for each ip in ips

    :param ips: iterable of ipaddress.IPV4Address objects
    :param chain_name: name of IPTables chain to add block rules to
    :return: None
    """
    chain = iptc.Chain(table, chain_name)
    for ip in ips:
        rule = iptc.Rule()
        rule.src = str(ip)
        rule.target = iptc.Target(rule, "DROP")
        chain.append_rule(rule)


def remove_aid_chain_from_input(chain_name='aid'):
    """
    remove any rules in the INPUT chain targeting chain_namej

    :param chain_name:  name of IPTables chain to remove rules that target it
    :return: None
    """
    for rule in iptc.Chain(table, "INPUT").rules:
        if rule.target.name == chain_name:
            iptc.Chain(table, 'INPUT').delete_rule(rule)


def add_aid_chain_to_input(chain_name='aid', position=0):
    """
    Adds a rule to the INPUT chain, at position, targeting chain_name

    :param chain_name: name of iptables chain that should be the target of the JUMP rule added to INPUT
    :param position: numberical position in the INPUT table where jump rule should be added, equivilant to iptables -I INPUT position
    :return: None
    """
    remove_aid_chain_from_input()
    jump_to_aid = iptc.Rule()
    jump_to_aid.create_target(chain_name)
    input_chain = iptc.Chain(table, 'INPUT')
    input_chain.insert_rule(jump_to_aid, position)


def load_whitelist(path):
    """
    parse a file containing one subnet per line into a list of ipaddress.IPv4Network objects

    :param path: path to whitelist file
    :return: list of ipaddress.IPv4Network objectsj
    """
    try:
        with open(path) as whitelist:
            try:
                whitelist = [ipaddress.ip_network(ip.strip()) for ip in whitelist]
            except ValueError as err:
                sys.exit("Error processing whitelist - {}".format(err))
    except FileNotFoundError:
        sys.exit('whitelist file: "{}"  was not found'.format(path))
    return whitelist


def remove_whitelisted_ips(ips, whitelisted_nets):
    """
    Filters out ips contained in whitelisted_nets

    :param ips: iterable of ipaddress.IP4Adress objects
    :param whitelist: iterable of ipaddress.IP4Network Objects
    :return: list only containing ips that are not in any subnets contained in whitelisted_nets
    """
    ips = list(ips)
    for idx, ip in enumerate(ips):
        if any([ip in whitelist_net for whitelist_net in whitelisted_nets]):
            del ips[idx]
    return ips


def fetch_aid_list(services=None, start_date='1 week', seen_count=10):
    """
    fetch the aid list

    :param services:  list of service names.  if not None, only aid entries matching one the service names are returned
    :param start_date: aid entries are only returned if they have been detected since start_date
    :param seen_count: minimum number of detections required for an ip to be returned
    :return: list of ipaddress.IPv4Address objects
    """
    try:
        bad_ips = aid.ips(services=services, start_date=start_date, seen_count=seen_count)
    except requests.HTTPError as e:
        sys.exit("HTTP ERROR: {}".format(e))
    except requests.exceptions.ConnectTimeout as e:
        sys.exit("HTTP Timeout: {}".format(e))
    return bad_ips


def generate_aid_list(services=None, start_date='1 week', seen_count=10, whitelist=None, chain_name='aid',
                      input_chain_position=0):
    # Try to fetch the aid list first, any error will stop the program leaving current
    # IPTables rules in place
    ips = fetch_aid_list(services=services, start_date=start_date, seen_count=seen_count)
    prepare_aid_chain(chain_name)
    if whitelist:
        whitelisted_nets = load_whitelist(whitelist)
        ips = remove_whitelisted_ips(ips, whitelisted_nets)
    add_block_rules_to_chain(ips, chain_name)
    add_aid_chain_to_input(chain_name, input_chain_position)
