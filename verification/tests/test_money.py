import pytest
from server.app.subscription import parse_money


@pytest.mark.parametrize('text,amount',[('300',30000),('300.00',30000),('0',0),('0.01',1),('300,50',30050),('92233720368547758.07',2**63-1)])
def test_exact_kopecks(text,amount):
    assert parse_money(text)==amount


def test_negative_exact_balance_requires_explicit_permission():
    assert parse_money('-1.01',allow_negative=True)==-101
    with pytest.raises(ValueError): parse_money('-1.01')


@pytest.mark.parametrize('value',[True,300.0,'1e2','nan','inf','1.001','1_000','92233720368547758.08','-92233720368547758.09',None])
def test_invalid_money_never_rounded_or_coerced(value):
    with pytest.raises(ValueError): parse_money(value,allow_negative=True)
