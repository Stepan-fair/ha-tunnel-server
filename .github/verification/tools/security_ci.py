"""Require Linux integrations and retain bounded acceptance evidence in CI logs."""
import json
import subprocess
import sys
import xml.etree.ElementTree as ET


def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('Duplicate evidence key')
        result[key]=value
    return result


def churn_evidence(report):
    """Never echo arbitrary JUnit properties, payloads or validation errors."""
    prefix='reservation_churn.'
    limits={prefix+'stabilized_control_socket_counts':256,prefix+'plugin_operations':1024}
    values={}
    try:
        for prop in report.findall('.//testsuite/properties/property'):
            name=prop.get('name')
            if name not in limits: continue
            raw=prop.get('value')
            if (name in values or set(prop.attrib)!={'name','value'} or len(prop) or
                    raw is None or len(raw)>limits[name]): raise ValueError('Invalid property')
            values[name]=json.loads(raw,object_pairs_hook=unique_object)
        if set(values)!=set(limits): raise ValueError('Missing evidence')
        samples=values[prefix+'stabilized_control_socket_counts']
        operations=values[prefix+'plugin_operations']
        allowed={'Login:accepted','Login:rejected','Ping:rejected','NewWorkConn:rejected',
                 'NewProxy:rejected','CloseProxy:accepted','CloseProxy:rejected'}
        if (type(samples) is not list or len(samples)!=8 or
                any(type(value) is not int or value!=1 for value in samples)):
            raise ValueError('Invalid samples')
        if (type(operations) is not dict or not set(operations)<=allowed or
                any(type(value) is not int or not 0<=value<=1000000 for value in operations.values()) or
                operations.get('Login:accepted',0)<8 or operations.get('Ping:rejected',0)!=0):
            raise ValueError('Invalid operations')
    except (ValueError,TypeError,RecursionError):
        raise SystemExit('Invalid reservation churn evidence') from None
    return {'stabilized_control_socket_counts':samples,'plugin_operations':operations}


result=subprocess.run([sys.executable,'-m','pytest','-q','--tb=short','-p','no:cacheprovider','--junitxml=/tmp/ha-tunnel-tests.xml'])
if result.returncode: raise SystemExit(result.returncode)
report=ET.parse('/tmp/ha-tunnel-tests.xml')
if report.findall('.//skipped'): raise SystemExit('Security gate requires all Linux integrations, no skips allowed')
if report.findall('.//failure') or report.findall('.//error'):
    raise SystemExit('Security gate requires a successful JUnit report')
# docker run --rm removes the report; stdout remains in the existing CI job log.
print('reservation_churn_evidence',json.dumps(churn_evidence(report),sort_keys=True,separators=(',',':')))
