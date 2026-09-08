import socket
from collections.abc import Callable, Iterable, Sequence
from contextlib import contextmanager
from weakref import ref

from anyio import Future
from typing_extensions import Self

from .converter import (
    AddrInfoResult,
    DNSResult,
    HostResult,
    NameInfoResult,
    RecordClass,
    RecordType,
)


class AbstractDNSResolver:
    """Abstraction layer for building DNS Resolver type classes."""
    def create_socket_state_callback(self) -> Callable[[int, bool, bool], None]:
        this_ref = ref(self)

        def socket_state_wrapper(fd: int, read: bool, write: bool) -> None:
            if t := this_ref():
                t.socket_state_callback(fd, read, write)

        return socket_state_wrapper

    @contextmanager
    def wrap_failure(self, fut: Future):
        try:
            yield
        except Exception as e:  # noqa: BLE001
            if fut.status == fut.Status.PENDING:
                fut.exception = e

    @property
    def nameservers(self) -> Sequence[str]:
        raise NotImplementedError

    @nameservers.setter
    def nameservers(self, value: Iterable[str | bytes]) -> None:
        raise NotImplementedError

    @property
    def running_queries(self) -> int:
        """tracks currently running dns queries. It will mainly be useful
        if you create multiple tasks from your :class:`AbstractDNSResolver`"""
        raise NotImplementedError

    async def query(
        self,
        host: str,
        rec_type: RecordType | int | str,
        rec_class: RecordClass | int | str | None = None,
    ) -> DNSResult:
        """Performs an asynchronous dns query for dns records

        :param host: target host to request information for
        :param rec_type: type of query to request.
        :param rec_class: type of class to request.
        """
        raise NotImplementedError

    async def getnameinfo(
        self,
        sockaddr: tuple[str, int] | tuple[str, int, int, int],
        flags: int = 0,
    ) -> NameInfoResult:
        raise NotImplementedError

    async def getaddrinfo(
        self,
        host: str,
        family: socket.AddressFamily = socket.AF_UNSPEC,
        port: int | None = None,
        proto: int = 0,
        type: int = 0,
        flags: int = 0,
    ) -> AddrInfoResult:
        raise NotImplementedError

    async def gethostbyaddr(self, name: str) -> HostResult:
        raise NotImplementedError

    @property
    def closed(self) -> bool:
        """determines if DNS resolver has been closed."""
        raise NotImplementedError

    async def close(self) -> None:
        """
        Cleanly close the DNS resolver.

        This should be called to ensure all resources are properly released.
        After calling close(), the resolver should not be used again.
        """
        raise NotImplementedError

    async def __aenter__(self) -> Self:
        raise NotImplementedError

    async def __aexit__(self, *args) -> Self:
        raise NotImplementedError
