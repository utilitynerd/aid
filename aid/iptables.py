import aid

import ipaddress
import sys
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


def list_rules_in_chain(chain):
    chain = iptc.Chain(table, chain)
    return [rule for rule in chain.rules]


def prepare_aid_chain(chain_name='aid'):
    """
    Creates / resets aid iptables chain

    :param chain_name: name for aid iptables chain
    :return : iptc.Chain object of prepared chain
    """
    if table.is_chain(chain_name):
        iptc.Chain(table, chain_name).flush()
    else:
        table.create_chain(chain_name)
    return iptc.Chain(table, chain_name)


def add_block_rules_to_chain(ips, chain_name='aid'):
    chain = iptc.Chain(table, chain_name)
    for ip in ips:
        rule = iptc.Rule()
        rule.src = str(ip)
        rule.target = iptc.Target(rule, "DROP")
        chain.append_rule(rule)

def build_aid_chain(chain_name='aid', services=None, start_date='1 week', whitelist=None, seen_count=10):
    # Try and fetch the aid list first.  This way if there is an error, the
    # current firewall rules remain in place
    try:
        bad_ips = aid.ips(services=services, start_date=start_date, seen_count=seen_count)
    except requests.HTTPError as e:
        sys.exit("HTTP ERROR: {}".format(e))
    except requests.exceptions.ConnectTimeout as e:
        sys.exit("HTTP Timeout: {}".format(e))

    prepare_aid_chain(chain_name)

    chain = iptc.Chain(table, chain_name)

    whitelisted_nets = load_whitelist(whitelist)
    bad_ips = remove_whitelisted_ips(bad_ips, whitelisted_nets)
    for ip in bad_ips:
        rule = iptc.Rule()
        rule.src = str(ip)
        rule.target = iptc.Target(rule, "DROP")
        chain.append_rule(rule)


def remove_aid_chain_from_input(chain_name='aid'):
    rules = list_rules_in_chain('INPUT')
    for rule in rules:
        if rule.target.name == chain_name:
            iptc.Chain(table, 'INPUT').delete_rule(rule)


def add_aid_chain_to_input(chain_name='aid', position=0):
    remove_aid_chain_from_input()
    jump_to_aid = iptc.Rule()
    jump_to_aid.create_target(chain_name)
    input_chain = iptc.Chain(table, 'INPUT')
    input_chain.insert_rule(jump_to_aid, position)


def load_whitelist(path):
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

@click.command()
@click.option('--start-date', '-d', default='1 week', help="Generate AID list with IPs detected since start-date")
@click.option('--service', '-s', 'services', multiple=True, help="Only include hits for the specified service")
@click.option('--whitelist', '-w', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True),
              help="Path to whitelist file containing one ip address or subnet per line")
@click.option('--seen-count', '-c', 'seen_count', default=10, type=click.INT,
              help="Minimum # of alerts an aid list IP has generated")
@click.option('--chain-name', '-n', 'chain_name', default='aid',
              help="The name of the iptables chain to use for the aid list")
@click.option('--input-chain-pos', '-i', 'input_chain_position', default=0, type=click.INT,
              help="Position in INPUT chain to add a jump to the aid chain")
def generate_aid_list(services=None, start_date='1 week', whitelist=None, chain_name='aid', input_chain_position=0, seen_count=10):
    build_aid_chain(chain_name=chain_name, services=services, start_date=start_date, whitelist=whitelist, seen_count=seen_count)
    add_aid_chain_to_input(chain_name, input_chain_position)


if __name__ == '__main__':
    generate_aid_list()


