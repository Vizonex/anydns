import socket
from collections.abc import Iterable, Sequence
from enum import IntEnum
from functools import partial
from typing import (
    Any,
    NoReturn,
    TypeVar,
)

import pycares
from anyio import (
    Future,
)
from pycares.errno import ARES_ECANCELLED, strerror
from typing_extensions import Self

from .base import AbstractDNSResolver
from .converter import (
    AddrInfoResult,
    DNSResult,
    HostResult,
    NameInfoResult,
    RecordClass,
    RecordType,
    convert_addrinfo_result,
    convert_dns_result,
    convert_host_result,
    convert_nameinfo_result,
)
from .error import DNSError, issue_deadlock_warning
from .utils import Selector

T = TypeVar("T")


def _convert_enum_type(rtype: int | str | IntEnum, renum: type[IntEnum]) -> int:
    if isinstance(rtype, str):
        return renum._member_map_[rtype.upper()].value
    elif isinstance(rtype, renum):
        return int(rtype)
    else:
        return rtype


class DNSResolver(AbstractDNSResolver):
    """pycares dns resolver. Backend uses `cffi` with `c-ares`
    under the hood.

    Advantages:
        - Backend has higher maturity than some other options
            and may be less prone to failure.

    Disadvantages:
        - pycares is most of the time using pure-python
            including with it's callbacks which means
            time can be a bit more costly.
    """

    __slots__ = (
        "_channel",
        "_closed",
        "_queries",
        "_selector",
        "_timeout",
    )

    def __init__(
        self,
        servers: Iterable[str | bytes] | None = None,
        *,
        flags: int | None = None,
        timeout: float | None = None,
        tries: int | None = None,
        ndots: int | None = None,
        tcp_port: int | None = None,
        udp_port: int | None = None,
        domains: Iterable[str | bytes] | None = None,
        lookups: str | bytes | None = None,
        socket_send_buffer_size: int | None = None,
        socket_receive_buffer_size: int | None = None,
        rotate: bool = False,
        local_ip: str | bytes | None = None,
        local_dev: str | None = None,
        resolvconf_path: str | bytes | None = None,
    ) -> None:
        super().__init__()
        # track if we need an exception raised for incomplete queries.
        # This is an anti-deadlock mechanism if things go wrong
        self._queries = 0
        self._channel = pycares.Channel(
            flags=flags,
            timeout=None,
            tries=tries,
            ndots=ndots,
            tcp_port=tcp_port,
            udp_port=udp_port,
            servers=servers,
            domains=domains,
            lookups=lookups,
            socket_send_buffer_size=socket_send_buffer_size,
            socket_receive_buffer_size=socket_receive_buffer_size,
            rotate=rotate,
            local_ip=local_ip,
            local_dev=local_dev,
            resolvconf_path=resolvconf_path,
            sock_state_cb=self.create_socket_state_callback(),
        )
        self._timeout = timeout
        self._selector = Selector(
            timeout, self.__on_timeout, self.__on_read, self.__on_write
        )
        self._closed = False

    async def __aenter__(self) -> Self:
        await self._selector.open()
        return self

    async def __aexit__(self, *args):
        await self.close()

    @property
    def nameservers(self) -> Sequence[str]:
        return self._channel.servers

    @nameservers.setter
    def nameservers(self, value: Iterable[str | bytes]) -> None:
        self._channel.servers = value

    @property
    def running_queries(self):
        """tracks currently running dns queries. It will mainly be useful
        if you create multiple tasks from your :class:`DNSResolver`"""
        return self._queries

    @running_queries.setter
    def running_queries(self, value: int) -> NoReturn:
        """running_queries is meant to be immutable do not use this."""
        raise AttributeError("running_queries is immutable")

    def __on_read(self, fd: int) -> None:
        self._channel.process_read_fd(fd)

    def __on_write(self, fd: int):
        self._channel.process_write_fd(fd)

    def __on_timeout(self) -> None:
        # TODO: pycares could benefit from a process_no_fds option.
        # Anybody brave enough should be able to request this without issue.
        self._channel.process_fd(pycares.ARES_SOCKET_BAD, pycares.ARES_SOCKET_BAD)

    def __handle_errno(self, fut: Future[Any], errno: int | None) -> bool:
        """Returns True if errno was in fact set on the asynchronous callback."""
        if errno is None:
            return False
        elif errno == ARES_ECANCELLED:
            fut.cancel()
        elif fut.status is fut.Status.PENDING:
            fut.exception = DNSError(errno, strerror(errno))
        return True

    def socket_state_callback(self, fd: int, read: bool, write: bool) -> None:
        if read or write:
            if read:
                self._selector.add_reader(fd)
            elif write:
                self._selector.add_writer(fd)
        else:
            if fd in self._selector.writers:
                self._selector.remove_writer(fd)
            if fd in self._selector.readers:
                self._selector.remove_reader(fd)
            if not (self._selector.readers or self._selector.writers):
                if self._selector.timer is not None:
                    self._selector.timer.cancel()
                if self._queries > 0:
                    # NOTE: Queries are in starvation mode with no fds
                    # to process them. This is a possibly a deadlock when code
                    # for remaining callbacks are not configured to parse dns
                    # responses properly this warning is to be kept around
                    # as safety mechanism. Do not try and remove this!!!
                    issue_deadlock_warning("pycares")
                    self._channel.cancel()

    # NOTE: We don't ever use event_threads due to it's ability to deadlock
    # using the GIL, the problem is also noticable (and abusive) in cyares
    def _on_query(
        self, fut: Future[DNSResult], result: pycares.DNSResult | None, err: int | None
    ):
        self._queries -= 1
        if self.__handle_errno(fut, err):
            return
        elif fut.status is fut.Status.PENDING:
            with self.wrap_failure(fut):
                fut.return_value = convert_dns_result(result)

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
        try:
            rt = _convert_enum_type(rec_type, RecordType)
        except KeyError as e:
            raise ValueError(f"Invalid record type value: {rec_type}") from e

        if rec_class is not None:
            try:
                rc = _convert_enum_type(rec_class, RecordClass)
            except KeyError as e:
                raise ValueError(f"Invalid record class value: {rec_type}") from e
        else:
            rc = RecordClass.IN.value

        fut = Future()
        with self.wrap_failure(fut):
            self._channel.query(
                host, rt, query_class=rc, callback=partial(self._on_query, fut)
            )
            self._queries += 1
        return await fut

    def _on_nameinfo(
        self,
        fut: Future[NameInfoResult],
        result: pycares.NameInfoResult,
        err: int | None,
    ) -> None:
        self._queries -= 1
        if self.__handle_errno(fut, err):
            return
        elif fut.status is fut.Status.PENDING:
            with self.wrap_failure(fut):
                fut.return_value = convert_nameinfo_result(result)

    async def getnameinfo(
        self,
        sockaddr: tuple[str, int] | tuple[str, int, int, int],
        flags: int = 0,
    ) -> NameInfoResult:
        fut = Future()
        with self.wrap_failure(fut):
            self._channel.getnameinfo(
                sockaddr, flags, callback=partial(self._on_nameinfo, fut)
            )
            self._queries += 1
        return await fut

    def _on_addrinfo(
        self,
        fut: Future[NameInfoResult],
        result: pycares.NameInfoResult,
        err: int | None,
    ) -> None:
        self._queries -= 1
        if self.__handle_errno(fut, err):
            return
        if fut.status is fut.Status.PENDING:
            with self.wrap_failure(fut):
                fut.return_value = convert_addrinfo_result(result)

    async def getaddrinfo(
        self,
        host: str,
        family: socket.AddressFamily = socket.AF_UNSPEC,
        port: int | None = None,
        proto: int = 0,
        type: int = 0,
        flags: int = 0,
    ) -> AddrInfoResult:
        fut = Future()
        with self.wrap_failure(fut):
            self._channel.getaddrinfo(
                host,
                port,
                family=family,
                type=type,
                proto=proto,
                flags=flags,
                callback=partial(self._on_addrinfo, fut),
            )
            self._queries += 1
        return await fut

    def _on_host_by_addr(
        self, fut: Future[HostResult], result: pycares.HostResult, err: int | None
    ) -> None:
        self._queries -= 1
        if err is not None:
            fut.exception = DNSError(err, strerror(err))
        elif fut.status is fut.Status.PENDING:
            with self.wrap_failure(fut):
                fut.return_value = convert_host_result(result)

    async def gethostbyaddr(self, name: str) -> HostResult:
        fut = Future()
        with self.wrap_failure(fut):
            self._channel.gethostbyaddr(
                name, callback=partial(self._on_host_by_addr, fut)
            )
            self._queries += 1
        return await fut

    @property
    def closed(self) -> bool:
        """determines if DNS resolver has been closed."""
        return self._closed

    async def close(self) -> None:
        """
        Cleanly close the DNS resolver.

        This should be called to ensure all resources are properly released.
        After calling close(), the resolver should not be used again.
        """
        if self._closed:
            return
        self._channel.cancel()
        self._channel.close()
        await self._selector.close()
        self._closed = True
