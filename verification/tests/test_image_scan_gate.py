import pytest


def test_fixable_severe_image_advisory_blocks_release():
    from tools.check_image_scan import check
    with pytest.raises(ValueError,match='Fixable severe'):
        check({'matches':[{'vulnerability':{'id':'synthetic-CVE','severity':'High','fix':{'versions':['2.0']}}}]})


def test_unfixed_findings_remain_explicit_and_malformed_report_fails():
    from tools.check_image_scan import check
    assert check({'matches':[{'vulnerability':{'id':'synthetic-unfixed','severity':'Critical','fix':{'versions':[]}}}]})==['synthetic-unfixed']
    with pytest.raises(ValueError): check({})
