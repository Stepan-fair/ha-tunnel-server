"""Exercise the release wrapper with real JUnit files, without nesting pytest."""
import json
from collections import Counter
from pathlib import Path
import runpy
import subprocess
import xml.etree.ElementTree as ET

import pytest


SCRIPT=Path(__file__).parents[1]/'tools'/'security_ci.py'
SAMPLES='reservation_churn.stabilized_control_socket_counts'
OPERATIONS='reservation_churn.plugin_operations'
VALID=[(SAMPLES,'[1,1,1,1,1,1,1,1]'),
       (OPERATIONS,'{"Login:accepted":8,"NewWorkConn:rejected":8,"Ping:rejected":0}')]


def run_gate(tmp_path,monkeypatch,properties,*,returncode=0,skip=False,failure=False):
    root=ET.Element('testsuites'); suite=ET.SubElement(root,'testsuite')
    props=ET.SubElement(suite,'properties')
    for name,value in properties: ET.SubElement(props,'property',name=name,value=value)
    case=ET.SubElement(suite,'testcase',name='reservation_churn')
    if skip: ET.SubElement(case,'skipped')
    if failure: ET.SubElement(case,'failure')
    path=tmp_path/'junit.xml'; ET.ElementTree(root).write(path)
    parse=ET.parse
    def read_report(report_path):
        assert report_path=='/tmp/ha-tunnel-tests.xml'
        return parse(path)
    def run(command):
        assert command[1:]==['-m','pytest','-q','--tb=short','-p','no:cacheprovider',
                             '--junitxml=/tmp/ha-tunnel-tests.xml']
        return subprocess.CompletedProcess(command,returncode)
    monkeypatch.setattr(ET,'parse',read_report)
    monkeypatch.setattr(subprocess,'run',run)
    runpy.run_path(str(SCRIPT),run_name='__main__')


def test_success_exports_only_validated_churn_evidence(tmp_path,monkeypatch,capsys):
    run_gate(tmp_path,monkeypatch,VALID+[
        ('private.debug','DO_NOT_EXPORT'),('reservation_churn.private_debug','DO_NOT_EXPORT')])
    output=capsys.readouterr().out
    prefix,payload=output.strip().split(' ',1)
    assert prefix=='reservation_churn_evidence'
    assert json.loads(payload)=={
        'stabilized_control_socket_counts':[1,1,1,1,1,1,1,1],
        'plugin_operations':{'Login:accepted':8,'NewWorkConn:rejected':8,'Ping:rejected':0}}
    assert 'DO_NOT_EXPORT' not in output
    assert len(output)<2048


def test_success_exports_counter_with_no_ping_events(tmp_path,monkeypatch,capsys):
    # Match the producer: reading an absent Counter key does not serialize it.
    operations=Counter({('Login','accepted'):8})
    assert operations[('Ping','rejected')]==0
    value=json.dumps({':'.join(key):count for key,count in sorted(operations.items())})
    run_gate(tmp_path,monkeypatch,[VALID[0],(OPERATIONS,value)])
    prefix,payload=capsys.readouterr().out.strip().split(' ',1)
    assert prefix=='reservation_churn_evidence'
    assert json.loads(payload)=={
        'stabilized_control_socket_counts':[1,1,1,1,1,1,1,1],
        'plugin_operations':{'Login:accepted':8}}


@pytest.mark.parametrize('properties',[
    [],VALID[:1],VALID+[VALID[0]],
    [(SAMPLES,'DO_NOT_EXPORT'),VALID[1]],
    [(SAMPLES,'[1,1,1,1,1,1,1,0]'),VALID[1]],
    [(SAMPLES,'[true,1,1,1,1,1,1,1]'),VALID[1]],
    [(SAMPLES,'[1,1,1,1,1,1,1]'),VALID[1]],
    [(SAMPLES,' '*4096),VALID[1]],
    [VALID[0],(OPERATIONS,'{"DO_NOT_EXPORT":8,"Login:accepted":8,"Ping:rejected":0}')],
    [VALID[0],(OPERATIONS,'{"Login:accepted":7,"Ping:rejected":0}')],
    [VALID[0],(OPERATIONS,'{"Login:accepted":8,"Ping:rejected":1}')],
    [VALID[0],(OPERATIONS,'{"Login:accepted":8,"Ping:rejected":false}')],
    [VALID[0],(OPERATIONS,'{"Login:accepted":1000001,"Ping:rejected":0}')],
    [VALID[0],(OPERATIONS,'{"Login:accepted":8,"Login:accepted":9,"Ping:rejected":0}')],
    [VALID[0],(OPERATIONS,' '*4096)],
],ids=['missing','incomplete','duplicate-property','malformed','zero-control','boolean-control',
       'short-samples','large-samples','unknown-operation','too-few-logins','rejected-ping',
       'boolean-count','large-count','duplicate-json-key','large-operations'])
def test_invalid_evidence_fails_closed_without_export(tmp_path,monkeypatch,capsys,properties):
    with pytest.raises(SystemExit) as error: run_gate(tmp_path,monkeypatch,properties)
    assert str(error.value)=='Invalid reservation churn evidence'
    assert capsys.readouterr().out==''


@pytest.mark.parametrize('code,skip,failure',[(3,False,False),(0,True,False),(0,False,True)])
def test_failed_or_skipped_suite_never_exports_success(tmp_path,monkeypatch,capsys,code,skip,failure):
    with pytest.raises(SystemExit) as error:
        run_gate(tmp_path,monkeypatch,VALID,returncode=code,skip=skip,failure=failure)
    if code: assert error.value.code==code
    assert capsys.readouterr().out==''
