import socket
from collections.abc import Callable, Iterable, Sequence
from enum import IntEnum
from functools import partial
from typing import (
    Any,
    TypeVar,
)

import cyares
from anyio import (
    Future,
)
from cyares.error import AresError
from cyares.handles import Future as CyFuture
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
        return renum.value
    else:
        return rtype


class DNSResolver(AbstractDNSResolver):
    """cyares dns resolver. Backend uses `cython` with `c-ares`
    under the hood.

    Advantages:
        - Backend has greater speed than pycares depending on it's
            use-case.

        - Currentry cyares provides more DNS Query options than
            pycares. For Example: `OPT`

        - Has a couple of extra saftey mechanisms thanks to it's
          handle usage.

    Disadvantages:
        - cyares is not as mature and could do some unknown
            things that may or may not be accounted for.
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
        self._channel = cyares.Channel(
            flags=flags,
            event_thread=False,
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
            timeout, self._channel.process_no_fds, self.__on_read, self.__on_write
        )
        self._closed = False

    def __on_read(self, fd: int) -> None:
        self._channel.process_read_fd(fd)

    def __on_write(self, fd: int):
        self._channel.process_write_fd(fd)

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
    def running_queries(self) -> int:
        """tracks currently running dns queries. It will mainly be useful
        if you create multiple tasks from your :class:`DNSResolver`"""
        return self._queries

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
                    # XXX: Queries migt be deadlocked, try and cancel it as cleanup...
                    issue_deadlock_warning("cyares")
                    self._channel.cancel()

    def __handle_exceptions(self, fut: CyFuture[Any], ret: Future[Any]):
        if fut.cancelled():
            ret.cancel()
        elif exc := fut.exception():
            if isinstance(exc, AresError):
                ret.exception = DNSError(
                    exc.status, exc.strerror.decode("utf-8", "surrogateescape")
                )
            else:
                ret.exception = exc
            return True
        return False

    def _on_callback(
        self, fut: CyFuture[Any], ret: Future[T], convert: Callable[[Any], T]
    ):
        self._queries -= 1

        if ret.status is not ret.Status.PENDING:
            # do nothing about it if nothing can be done.
            return
        elif self.__handle_exceptions(fut, ret):
            return
        else:
            with self.wrap_failure(ret):
                ret.return_value = convert(fut.result())

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
                host,
                rt,
                query_class=rc,
                callback=partial(
                    self._on_callback, convert=convert_dns_result, ret=fut
                ),
            )
            self._queries += 1
        return await fut

    async def getnameinfo(
        self,
        sockaddr: tuple[str, int] | tuple[str, int, int, int],
        flags: int = 0,
    ) -> NameInfoResult:
        fut = Future()
        with self.wrap_failure(fut):
            self._channel.getnameinfo(
                sockaddr,
                flags,
                callback=partial(
                    self._on_callback, convert=convert_nameinfo_result, ret=fut
                ),
            )
            self._queries += 1
        return await fut

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
                host=host,
                port=port,
                family=family,
                proto=proto,
                flags=flags,
                socktype=type,
                callback=partial(
                    self._on_callback, convert=convert_addrinfo_result, ret=fut
                ),
            )
            self._queries += 1
        return await fut

    async def gethostbyaddr(self, name: str) -> HostResult:
        fut = Future()
        with self.wrap_failure(fut):
            self._channel.gethostbyaddr(
                name,
                callback=partial(
                    self._on_callback, convert=convert_host_result, ret=fut
                ),
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
        await self._selector.close()
        self._closed = True
