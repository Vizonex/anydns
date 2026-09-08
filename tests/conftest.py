import sys
from collections.abc import Callable
from functools import partial
from importlib.util import find_spec
from typing import Any

import pytest

from anydns.base import AbstractDNSResolver


def has_module(library: str):
    """Finds out if library exists without executing any code for the
    library."""
    return find_spec(library) is not None


PARAMS = [pytest.param(("asyncio", {"use_uvloop": False}), id="asyncio")]

# NOTE: Extensions are optional now...
if has_module("winloop" if sys.platform == "win32" else "uvloop"):
    PARAMS.append(
        pytest.param(("asyncio", {"use_uvloop": True}), id="asyncio+uvloop")
    )

if has_module("trio"):
    PARAMS.append(
        pytest.param(
            ("trio", {"restrict_keyboard_interrupt_to_checkpoints": True}),
            id="trio",
        )
    )

SERVERS = [
    # cloudflare has a more respecful server than google does
    # so will let it go first in the resolution order with google
    # as a backup.
    "1.1.1.1", 
    "8.8.8.8",
    "8.8.4.4"
]

DNS_RESOLVERS: list[Callable[[], AbstractDNSResolver]] = []

def wrap_dns_func(dns_resolver_ty: type[AbstractDNSResolver], name: str):
    return pytest.param(partial(dns_resolver_ty, servers=SERVERS, tries=3, timeout=10), id=name)


if has_module("pycares"):
    from anydns.pycares import DNSResolver
    DNS_RESOLVERS.append(wrap_dns_func(DNSResolver, "pycares"))

if has_module("cyares"):
    from anydns.cyares import DNSResolver
    DNS_RESOLVERS.append(wrap_dns_func(DNSResolver, "cyares"))

@pytest.fixture(params=PARAMS)
def anyio_backend(request: pytest.FixtureRequest) -> Any:
    return request.param

@pytest.fixture(
    params=DNS_RESOLVERS,
    scope="function"
)
async def resolver(request: pytest.FixtureRequest):
    func: Callable[[], AbstractDNSResolver] = request.param
    async with func() as dns:
        yield dns


