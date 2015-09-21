import aid
import iptc

table = iptc.Table(iptc.Table.FILTER)


def list_filter_chains():
    table = iptc.Table(iptc.Table.FILTER)
    return [chain.name for chain in table.chains]


def list_rules_in_chain(chain):
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, chain)
    return [rule for rule in chain.rules]


def reset_aid_chain(chain_name='aid'):
    if table.is_chain(chain_name):
        iptc.Chain(table, chain_name).flush()
    else:
        table.create_chain(chain_name)


def build_aid_chain(chain_name='aid'):
    reset_aid_chain()
    bad_ips = aid.get_aidlist_ips()[:20]
    chain = iptc.Chain(table, chain_name)
    for ip in bad_ips:
        rule = iptc.Rule()
        rule.src = str(ip)
        rule.target = iptc.Target(rule, "DROP")
        chain.append_rule(rule)





build_aid_chain()