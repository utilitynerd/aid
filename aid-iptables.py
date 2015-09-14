import os.path
import json
import requests
import collections

SockConfig = collections.namedtuple("SockConfig", ['host', 'timeout', 'token'])
AidEntry = collections.namedtuple("AidEntry", ["ip", "tags", "dst_port", "last_seen_ts", "first_seen_ts", "service"])

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".sock.json")


def call_sock_api(endpoint, **params):
    params["token"] = config.token
    url = "{host}/api/{endpoint}".format(host=config.host, endpoint=endpoint)
    r = requests.get(url, params=params)
    return json.loads(r.text)

def load_config(path=CONFIG_PATH):
        with open(path) as fd:
            conf = json.load(fd)
            return SockConfig(host=conf['host'], timeout=conf['timeout'], token=conf['token'])

def get_aidlist():
    aid_list = [AidEntry(**entry) for entry in call_sock_api('aggressive_ips')['aggressive_ips']]
    print(aid_list)


config = load_config()
get_aidlist()

