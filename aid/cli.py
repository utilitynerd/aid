import click

try:
    from aid.aid import services, ips, entries
except ImportError:
    from aid import services, ips, entries

try:
    import iptc
except ImportError:
    pyiptables = False
else:
    pyiptables = True
    try:
        from aid.iptables import generate_aid_list
    except ImportError:
        from iptables import generate_aid_list

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


@cli.command(name="ips", context_settings=CONTEXT_SETTINGS,
             help="get list of IP Addresses from AID list")
@click.option('--start-date', default='1 week',
              help="default='1 week ago' - Generate AID list with IPs detected since start-date "
                   "(accepts most datetime formats)")
@click.option('--service', 'services', multiple=True,
              help="default='' filter results to only include specified service(s), ex: --service=ssh,rdp")
@click.option('--seen-count', 'seen_count', default=10, type=click.INT,
              help="default=10 - Minimum # of alerts an aid list IP has generated")
def ips_cli(**kwargs):
    click.echo("\n".join([str(ip) for ip in ips(**kwargs)]))


@cli.command(name="entries", context_settings=CONTEXT_SETTINGS,
             help="get list of entries from AID list")
@click.option('--start-date', default='1 week',
              help="default='1 week ago' - Generate AID list with IPs detected since start-date "
                   "(accepts most datetime formats)")
@click.option('--service', 'services', multiple=True,
              help="default='' filter results to only include specified service(s), ex: --service=ssh,rdp")
@click.option('--seen-count', 'seen_count', default=10, type=click.INT,
              help="default=10 - Minimum # of alerts an aid list IP has generated")
def entries_cli(**kwargs):
    click.echo("\n".join([str(entry) for entry in entries(**kwargs)]))


@cli.command(name='services', context_settings=CONTEXT_SETTINGS,
             help="List services monitored by AID list")
def services_cli():
    svcs = services()
    click.echo(', '.join(svcs))


@cli.command(context_settings=CONTEXT_SETTINGS,
             help="Create IPTables rules based on the AID list")
@click.option('--start-date', default='1 week',
              help="default='1 week ago' - Generate AID list with IPs detected since start-date "
                   "(accepts most datetime formats)")
@click.option('--service', 'services', multiple=True,
              help="default='' filter results to only include specified service(s), ex: --service=ssh,rdp")
@click.option('--whitelist',
              type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True),
              help="Path to whitelist file containing one ip address or subnet per line")
@click.option('--seen-count', 'seen_count', default=10, type=click.INT,
              help="default=10 - Minimum # of alerts an aid list IP has generated")
@click.option('--chain-name', 'chain_name', default='aid',
              help="default=aid - The name of the iptables chain to use for the aid list")
@click.option('--input-chain-pos', 'input_chain_position', default=1, type=click.INT,
              help="default=0 - Position in INPUT chain to add a jump to the aid chain")
def iptables(**kwargs):
    if pyiptables:
        generate_aid_list(**kwargs)
    else:
        click.echo("Using the iptables command require install python-iptables package.  "
                   "Please run: pip install -U aid[iptables]")
