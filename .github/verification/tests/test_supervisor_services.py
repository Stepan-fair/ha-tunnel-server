from shared.supervisor_services import MqttService, parse_service
import pytest


def test_mqtt_service_credentials_are_redacted_and_validated():
    service=parse_service({'host':'broker','port':1883,'username':'test','password':'secret-value','ssl':False})
    assert isinstance(service,MqttService)
    assert 'secret-value' not in repr(service) and service.password=='secret-value'
    for data in ({}, {'host':'broker','port':True,'username':'test','password':'x'},
                 {'host':'http://broker/path','port':1883,'username':'test','password':'x'}):
        with pytest.raises(ValueError): parse_service(data)
