import pytest

from anydns import RecordType
from anydns.base import AbstractDNSResolver

pytestmark = pytest.mark.anyio


@pytest.fixture(
    params=(pytest.param("A", id="str"), 
        pytest.param(RecordType.A, id="enum"),
        pytest.param(1, id="int")
    )
)
def query_a(request: pytest.FixtureRequest) -> RecordType | int | str:
    return request.param 


async def test_nameservers(resolver: AbstractDNSResolver) -> None:
    resolver.nameservers = ["8.8.8.8"]
    assert resolver.nameservers == ["8.8.8.8:53"]

# Dns Resolving for llparse.org should return somehting like the following.
# DNSResult(answer=[
# DNSRecord(name='llparse.org', record_type=<RecordType.A: 1>, 
# record_class=<RecordClass.IN: 1>, ttl=3600, 
# data=ARecordData(addr='185.199.110.153')), 
# DNSRecord(name='llparse.org', record_type=<RecordType.A: 1>, 
# record_class=<RecordClass.IN: 1>, ttl=3600, 
# data=ARecordData(addr='185.199.109.153')), 
# DNSRecord(name='llparse.org', record_type=<RecordType.A: 1>, 
# record_class=<RecordClass.IN: 1>, ttl=3600, data=ARecordData(
# addr='185.199.111.153')), DNSRecord(name='llparse.org', 
# record_type=<RecordType.A: 1>, record_class=<RecordClass.IN: 1>,
#  ttl=3600, data=ARecordData(addr='185.199.108.153'))], 
# authority=[], additional=[DNSRecord(name='', 
# record_type=<RecordType.OPT: 41>, 
# record_class=<RecordClass.IN: 1>, ttl=0, 
# data=OPTRecordData(udp_size=512, version=0, flags=0, options=[]))])


async def test_query(resolver: AbstractDNSResolver, query_a: RecordType | int | str):
    result = await resolver.query("llparse.org", query_a)
    # useful to know but you can filter the types if needed.
    addresses = {a.data.addr for a in result.answer if a.record_type == RecordType.A}
    # llparse's domain could change, but as long 
    # as we have something it's better than nothing.
    assert addresses

async def test_getnameinfo(resolver: AbstractDNSResolver):
    ni = await resolver.getnameinfo(("50.87.249.219", 80))
    assert ni.node == "box2079.bluehost.com"


# bfdi.tv has only a single IP address (it's actually a redirect but it's 
# still a host) so we should always be successful here. 
# If this IP changes throw an issue.

async def test_getaddrinfo(resolver: AbstractDNSResolver):
    ni = await resolver.getaddrinfo("bfdi.tv")
    items = {n.addr[0] for n in ni.nodes}
    assert "50.87.249.219" in items


async def test_gethostbyaddr(resolver: AbstractDNSResolver):
    host = await resolver.gethostbyaddr("8.8.8.8")
    assert host.name == "dns.google"
    assert 'dns.google' in host.aliases
    assert '8.8.8.8' in host.addresses




