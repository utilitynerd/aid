import click

try:
    # python 3
    from aid.aid import entries, ips, AIDEntry, services
except ImportError:
    # python 2
    from aid import entries, ips, AIDEntry, services
