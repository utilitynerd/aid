from aid.aid import *

import pytest

from requests.exceptions import HTTPError

def test_get_list_of_services():
    service_list = services()
    assert isinstance(service_list, list)
    assert len(service_list) > 0

def test_call_sock_http_error_results_in_HTTPError_exception():
    config = load_config()
    with pytest.raises(HTTPError) as e:
        call_sock_api(config, 'fail')
