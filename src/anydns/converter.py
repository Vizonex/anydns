"""
Converter
---------

Converts PyCares and Cyares Dataclasses into serlizable msgspec types
this makes it eaiser to detect types from both cyares and pycares
alike in a unified format but it also comes with the bonus of
serlizing dns results to json and other types, it's a rather
small performance trade for better features.
"""

from enum import IntEnum
from typing import TYPE_CHECKING

from msgspec import Struct


class RecordType(IntEnum):
    A = 1
    "Host address."
    NS = 2
    "Authoritative server."
    CNAME = 5
    "Canonical name."
    SOA = 6
    "Start of authority zone."
    PTR = 12
    "Domain name pointer."
    HINFO = 13
    "Host information."
    MX = 15
    "Mail routing information."
    TXT = 16
    "Text strings."
    SIG = 24
    "RFC 2535 / RFC 2931. SIG Record"
    AAAA = 28
    "RFC 3596. Ip6 Address."
    SRV = 33
    "RFC 2782. Server Selection."
    NAPTR = 35
    "RFC 3403. Naming Authority Pointer"
    OPT = 41
    "RFC 6891. EDNS0 option (meta-RR)"
    TLSA = 52
    """RFC 6698. DNS-Based Authentication of Named
    Entities (DANE) Transport Layer Security"
    (TLS) Protocol: TLSA
    """
    SVCB = 64
    "RFC 9460. General Purpose Service Binding"
    HTTPS = 65
    "RFC 9460. Service Binding type for use with"
    ANY = 255
    "Wildcard match."
    URI = 256
    "RFC 7553. Uniform Resource Identifier"
    CAA = 257
    "RFC 6844. Certification Authority"



class RecordClass(IntEnum):
    IN = 1
    CHAOS = 3
    HS = 4
    NONE = 254
    ANY = 255


if TYPE_CHECKING:
    import cyares
    import pycares

# Brought over from pycares & cyares alike to be unified.


class Base(Struct, tag="tag"):
    pass


class ARecordData(Base):
    """Data for A (IPv4 address) record"""

    addr: str


class AAAARecordData(Base):
    """Data for AAAA (IPv6 address) record"""

    addr: str


class MXRecordData(Base):
    """Data for MX (mail exchange) record"""

    priority: int
    exchange: str


class TXTRecordData(Base):
    """Data for TXT (text) record"""

    data: bytes


class CAARecordData(Base):
    """Data for CAA (certification authority authorization) record"""

    critical: int
    tag: str
    value: str


class CNAMERecordData(Base):
    """Data for CNAME (canonical name) record"""

    cname: str


class NAPTRRecordData(Base):
    """Data for NAPTR (naming authority pointer) record"""

    order: int
    preference: int
    flags: str
    service: str
    regexp: str
    replacement: str


class NSRecordData(Base):
    """Data for NS (name server) record"""

    nsdname: str


class PTRRecordData(Base):
    """Data for PTR (pointer) record"""

    dname: str


class SOARecordData(Base):
    """Data for SOA (start of authority) record"""

    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


class SRVRecordData(Base):
    """Data for SRV (service) record"""

    priority: int
    weight: int
    port: int
    target: str


class TLSARecordData(Base):
    """Data for TLSA (DANE TLS authentication) record - RFC 6698"""

    cert_usage: int
    selector: int
    matching_type: int
    cert_association_data: bytes


class OPTRecordData(Base):
    """Data for Opt Record - RFC 6891. EDNS0 option (meta-RR)"""

    udp_size: int
    version: int
    flags: int
    options: list[tuple[int, str]]


class SIGRecordData(Base):
    """Data for SIG Record - RFC 2535 / RFC 2931."""

    type_covered: int
    algorithm: int
    labels: int
    original_ttl: int
    expiration: int
    inception: int
    key_tag: int
    signers_name: bytes
    signature: str


class SVCBRecordData(Base):
    priority: int
    target: str
    options: list[tuple[int, str]]


class HTTPSRecordData(Base):
    """Data for HTTPS (service binding) record - RFC 9460"""

    priority: int
    target: str
    params: list[tuple[int, bytes]]


class URIRecordData(Base):
    """Data for URI (Uniform Resource Identifier) record - RFC 7553"""

    priority: int
    weight: int
    target: str


class HINFORecordData(Base):
    """Data for HINFO (Host information)"""

    cpu: str
    os: str


class DNSRecord(Base):
    """Represents a single DNS resource record"""

    name: str
    record_type: RecordType
    record_class: RecordClass
    ttl: int
    data: (
        ARecordData
        | AAAARecordData
        | MXRecordData
        | TXTRecordData
        | CAARecordData
        | CNAMERecordData
        | HTTPSRecordData
        | NAPTRRecordData
        | NSRecordData
        | PTRRecordData
        | SOARecordData
        | SRVRecordData
        | TLSARecordData
        | URIRecordData
        | OPTRecordData
        | SIGRecordData
        | HINFORecordData
        | None  # safety mechanism incase Unknown
    )


class DNSResult(Base):
    """Represents a complete DNS query result with all sections"""

    answer: list[DNSRecord]
    authority: list[DNSRecord]
    additional: list[DNSRecord]


# Host/AddrInfo result types


class HostResult(Base):
    """Result from gethostbyaddr() operation"""

    name: str
    aliases: list[str]
    addresses: list[str]


class NameInfoResult(Base):
    """Result from getnameinfo() operation"""

    node: str
    service: str | None


class AddrInfoNode(Base):
    """Single address node from getaddrinfo() result"""

    ttl: int
    flags: int
    family: int
    socktype: int
    protocol: int
    addr: tuple[str, int] | tuple[str, int, int, int]
    "(ip, port) or (ip, port, flowinfo, scope_id)"


class AddrInfoCname(Base):
    """CNAME information from getaddrinfo() result"""

    ttl: int
    alias: str
    name: str


class AddrInfoResult(Base):
    """Complete result from getaddrinfo() operation"""

    cnames: list[AddrInfoCname]
    nodes: list[AddrInfoNode]


def decode_if_bytes(i: bytes | str):
    if isinstance(i, bytes):
        return i.decode("utf-8", "surrogateescape")
    return i


def convert_dns_record(result: "cyares.DNSRecord | pycares.DNSRecord"):
    rd = result.data
    rt = RecordType(result.type)
    match rt:
        case RecordType.A:
            rec = ARecordData(rd.addr)
        case RecordType.AAAA:
            rec = AAAARecordData(rd.addr)
        case RecordType.MX:
            rec = MXRecordData(rd.priority, str(rd.exchange))
        case RecordType.TXT:
            rec = TXTRecordData(rd.data)
        case RecordType.CAA:
            rec = CAARecordData(rd.critical, rd.tag, rd.value)
        case RecordType.CNAME:
            rec = CNAMERecordData(rd.cname)
        case RecordType.NAPTR:
            rec = NAPTRRecordData(
                rd.order, rd.preference, rd.flags, rd.service, rd.regexp, rd.replacement
            )
        case RecordType.NS:
            rec = NSRecordData(rd.nsdname)
        case RecordType.PTR:
            rec = PTRRecordData(rd.dname)
        case RecordType.SOA:
            rec = SOARecordData(
                rd.mname,
                rd.rname,
                rd.serial,
                rd.refresh,
                rd.retry,
                rd.expire,
                rd.minimum,
            )
        case RecordType.SRV:
            rec = SRVRecordData(rd.priority, rd.weight, rd.port, rd.target)
        case RecordType.TLSA:
            rec = TLSARecordData(
                rd.cert_usage, rd.selector, rd.matching_type, rd.cert_association_data
            )
        case RecordType.OPT:
            rec = OPTRecordData(rd.udp_size, rd.version, rd.flags, rd.options)
        case RecordType.SIG:
            rec = SIGRecordData(
                rd.type_covered,
                rd.algorithm,
                rd.labels,
                rd.original_ttl,
                rd.expiration,
                rd.inception,
                rd.key_tag,
                rd.signers_name,
                rd.signature,
            )
        case RecordType.SVCB:
            rec = SVCBRecordData(rd.priority, rd.target, rd.options)
        case RecordType.HTTPS:
            rec = HTTPSRecordData(rd.priority, rd.target, rd.params)
        case RecordType.URI:
            rec = URIRecordData(rd.cpu, rd.os)
        case _:
            rec = None

    return DNSRecord(result.name, rt, RecordClass(result.record_class), result.ttl, rec)


# conversion support to bridge all the library types.


def convert_dns_records(result: "list[cyares.DNSResult | pycares.DNSResult]"):
    return [convert_dns_record(r) for r in result]


def convert_dns_result(result: "cyares.DNSResult | pycares.DNSResult"):
    return DNSResult(
        convert_dns_records(result.answer),
        convert_dns_records(result.authority),
        convert_dns_records(result.additional),
    )


def convert_host_result(result: "cyares.HostResult | pycares.HostResult"):
    return HostResult(result.name, result.aliases, result.addresses)


def convert_nameinfo_result(result: "cyares.NameInfoResult | pycares.NameInfoResult"):
    return NameInfoResult(result.node, result.service)


def convert_addrinfo_node(result: "cyares.AddrInfoNode | pycares.AddrInfoNode"):
    return AddrInfoNode(
        result.ttl,
        result.flags,
        result.family,
        result.socktype,
        result.protocol,
        (decode_if_bytes(result.addr[0]), *result.addr[1:]),
    )


def convert_addrinfo_cname(result: "cyares.AddrInfoCname | pycares.AddrInfoCname"):
    return AddrInfoCname(result.ttl, result.alias, result.name)


def convert_addrinfo_result(result: "cyares.AddrInfoResult | pycares.AddrInfoResult"):
    return AddrInfoResult(
        [convert_addrinfo_cname(r) for r in result.cnames],
        [convert_addrinfo_node(n) for n in result.nodes],
    )


__all__ = (
    "AAAARecordData",
    "ARecordData",
    "AddrInfoCname",
    "AddrInfoNode",
    "AddrInfoResult",
    "CAARecordData",
    "CNAMERecordData",
    "DNSRecord",
    "DNSResult",
    "HTTPSRecordData",
    "HostResult",
    "MXRecordData",
    "NAPTRRecordData",
    "NSRecordData",
    "NameInfoResult",
    "PTRRecordData",
    "SOARecordData",
    "SRVRecordData",
    "TLSARecordData",
    "TXTRecordData",
    "URIRecordData",
    "convert_addrinfo_result",
    "convert_dns_result",
    "convert_host_result",
    "convert_nameinfo_result",
)
