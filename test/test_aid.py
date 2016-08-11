from aid.aid import *


def test_get_list_of_services():
    service_list = services()
    assert isinstance(service_list, list)
    assert len(service_list) > 0
