from aid.aid import *
import pytest
import requests

c = load_config()
bad_host_config = SockConfig('https://sock.security.berkeley.edu/fail', 10, 'xxx')
timeout_config = SockConfig('https://hudson.security.berkeley.edu', 0.0001, c.token)


def test_call_sock_bad_host():
    with pytest.raises(requests.HTTPError):
        call_sock_api(bad_host_config, 'api')


def test_get_aidlist_bad_host():
    with pytest.raises(SystemExit):
        get_aidlist_ips(config=bad_host_config)


def test_call_sock_timeout():
    with pytest.raises(requests.exceptions.ConnectTimeout):
        call_sock_api(timeout_config, 'aggressive_ips')


def test_get_aidlist_timeout():
    with pytest.raises(SystemExit):
        get_aidlist_ips(config=timeout_config)