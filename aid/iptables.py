import aid
import iptc
import ipaddress
import sys
import click

table = iptc.Table(iptc.Table.FILTER)


def list_rules_in_chain(chain):
    chain = iptc.Chain(table, chain)
    return [rule for rule in chain.rules]


def reset_aid_chain(chain_name='aid'):
    if table.is_chain(chain_name):
        iptc.Chain(table, chain_name).flush()
    else:
        table.create_chain(chain_name)


def build_aid_chain(chain_name='aid', services=None, start_date='1 week', whitelist=None, seen_count=10):
    if whitelist:
        whitelisted_nets = load_whitelist(whitelist)
    else:
        whitelisted_nets = []
    # Try and fetch the aid list first.  This way if there is an error, the
    # current firewall rules remain in place
    bad_ips = aid.get_aidlist_ips(services=services, start_date=start_date, seen_count=seen_count)
    reset_aid_chain(chain_name)

    chain = iptc.Chain(table, chain_name)
    for ip in bad_ips:
        if not any(((ip in whitelist_net) for whitelist_net in whitelisted_nets)):
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
                return [ipaddress.ip_network(ip.strip()) for ip in whitelist]
            except ValueError as err:
                sys.exit("Error processing whitelist - {}".format(err))
    except FileNotFoundError:
            sys.exit('whitelist file: "{}"  was not found'.format(path))


@click.command()
@click.option('--start-date', '-d', default='1 week', help="Generate AID list with IPs detected since start-date")
@click.option('--service', '-s', 'services', multiple=True, help="Only include hits for the specified service")
@click.option('--whitelist', '-w', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True),
              help="Path to whitelist file containing one ip address or subnet per line")
@click.option('--seencount', '-c', 'seen_count', default=10, type=click.INT,
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

