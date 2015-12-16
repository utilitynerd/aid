try:
    # python 3
    from aid.aid import entries, ips, AIDEntry
except ImportError:
    # python 2
    from aid import entries, ips, AIDEntry
