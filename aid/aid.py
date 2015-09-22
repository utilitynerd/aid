import os.path
import sys
import json
import requests
import collections
import dateparser
import ipaddress

SockConfig = collections.namedtuple("SockConfig", ['host', 'timeout', 'token'])
AIDEntry = collections.namedtuple("AidEntry", ["ip", "tags", "dst_port", "last_seen_ts", "first_seen_ts", "service"])

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".sock.json")


def call_sock_api(config, endpoint, **params):
    params["token"] = config.token
    url = "{host}/api/{endpoint}".format(host=config.host, endpoint=endpoint)
    r = requests.get(url, params=params)
    return json.loads(r.text)


def load_config(path=CONFIG_PATH):
        with open(path) as fd:
            conf = json.load(fd)
            return SockConfig(host=conf['host'], timeout=conf['timeout'], token=conf['token'])


# setting services=[] in function definition can cause strange problems.
#  See: http://docs.python-guide.org/en/latest/writing/gotchas/
def get_aidlist(services=None, start_date="1 week ago", seen_count=10, config=None):
    if not services:
        services = []
    if not config:
        config = load_config()
    last_seen_ts = dateparser.parse(start_date)
    if not last_seen_ts:
        sys.exit("{} - invalid start date".format(start_date))

    aid_list = call_sock_api(config, 'aggressive_ips', service=",".join(services),
                             last_seen_ts=last_seen_ts.isoformat(), seen_count=seen_count)['aggressive_ips']
    return [AIDEntry(ip=ipaddress.ip_address(entry['ip']),
                     tags=entry['tags'],
                     dst_port=entry['dst_port'],
                     last_seen_ts=entry['last_seen_ts'],
                     first_seen_ts=entry['first_seen_ts'],
                     service=entry['service']) for entry in aid_list]


def get_aidlist_ips(services=None, start_date="1 week ago", seen_count=10, config=None):
    aid_list = get_aidlist(services, start_date, seen_count, config)
    return sorted([ipaddress.ip_address(entry.ip) for entry  in aid_list])

