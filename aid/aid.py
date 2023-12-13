import collections
import json
import os.path
import sys
import time

import ipaddress
from datetime import date

from dateutil.parser import parse
import requests

SockConfig = collections.namedtuple("SockConfig", ['host', 'token'])
AIDEntry = collections.namedtuple("AidEntry", ["ip", "tags", "dst_port", "last_seen_ts",
                                               "first_seen_ts", "service", "seen_count"])

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".aid.json")


def call_sock_api(config, endpoint, **params):
    """
    Call sock api and return object created from returned json

    :param config: instance of SockConfig
    :param endpoint: api endpoint for request
    :param params: dict of additional parameters for api request
    :return: api response as python object
    """
    if not config:
        config = load_config()

    params["token"] = config.token
    url = "{host}/api/{endpoint}".format(host=config.host, endpoint=endpoint)
    attempts = 0
    while attempts < 6:
        r = requests.get(url, timeout=20, params=params)
        try:
            r.raise_for_status()
        except:
            time.sleep(10)
        finally:
            return json.loads(r.text)
    raise Exception(f"Reached {attempts} attempts on {url}.")


def load_config(path=CONFIG_PATH):
    """
    Instantiates a SockConfig object from config file located at path

    :param path: path to config file
    :return: SockConfig object
    """
    with open(path) as fd:
        conf = json.load(fd)
        return SockConfig(host=conf['server'], token=conf['api_key'])


def entries(services=None, start_date="1 week ago", seen_count=10, config=None):
    """
    Query aggressive ips api

    :param services: list of services to include in results. default is all services.
    :param start_date: return aggresive ip entries starting from this date
    :param seen_count: threshold for # of times an IP has triggered an alerts
    :param config: SockConfig object
    :return: list of AIDEntry objects
    """
    if services is not None:
        services = list(services)
    else:
        services = []

    last_seen_ts = parse(start_date, fuzzy_with_tokens=True)
    if not last_seen_ts:
        sys.exit("{} - invalid start date".format(start_date))

    aid_list = call_sock_api(config, 'aggressive_ips', service=",".join(services),
                             last_seen_ts=date.isoformat(last_seen_ts), seen_count=seen_count)['aggressive_ips']

    res = (AIDEntry(ip=ipaddress.ip_address(entry['ip']),
                     tags=entry['tags'],
                     dst_port=entry['dst_port'],
                     last_seen_ts=entry['last_seen_ts'],
                     first_seen_ts=entry['first_seen_ts'],
                     service=entry['service'],
                     seen_count=entry["seen_count"])
            for entry in aid_list )
    return [entry for entry in res if entry.ip.version == 4]


def ips(services=None, start_date="1 week ago", seen_count=10, config=None):
    """
    Query aggressive ips api, but only return a list of unique IPs

    :param services: list of services to include in results. default is all services.
    :param start_date: return aggresive ip entries starting from this date
    :param seen_count: threshold for # of times an IP has triggered an alerts
    :param config: SockConfig object
    :return: list of unique IPs
    """
    aid_list = entries(services, start_date, seen_count, config)
    return sorted({ipaddress.ip_address(entry.ip) for entry in aid_list})


def services(config=None):
    """
    returns the list of services currently monitored by aid

    :param config:
    :return:
    """
    service_list = call_sock_api(config, 'aggressive_ips/services')['services']
    service_list = [entry['name'] for entry in service_list]
    return service_list
