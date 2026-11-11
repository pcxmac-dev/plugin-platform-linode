"""A domain's records in Linode's DNS Manager, changed one record at a time (every other record kept: the reference's
create, update and delete each touch one record by its id):

- a set reads the domain's records fresh, then changes the host's record of its type (an A, AAAA or CNAME: there is at most
  one to change, else it is refused) or adds one beside the others (a TXT, MX, NS or CAA whose target differs; the same
  target there already: its TTL or priority changed, or nothing written);
- a remove names the record by its id and what it held: one that changed or went meanwhile is refused, nothing sent;
- after either, the records are read back and checked: the record as written (or gone), every other record kept.

The reference (post-domain-record, put-domain-record, delete-domain-record; read 2026-11-11): the types A, AAAA, NS, MX,
CNAME, TXT, SRV, PTR, CAA; a name of 1 to 100 characters ("" for the domain itself); a target of up to 65,535; ttl_sec one of
TTLS (another rounded to the nearest); priority 0 to 255 for MX and SRV; a CAA's tag issue, issuewild or iodef; an update
takes no type. DNS Manager takes no CNAME at the domain itself (no CNAME flattening), and serves a domain's records only
while the account has at least one active Linode (its guide)."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .refusal import Refusal

TTLS = (300, 3600, 7200, 14400, 28800, 57600, 86400, 172800, 345600, 604800, 1209600, 2419200)  # the reference's values
TTL_WORDS = {300: "5 minutes", 3600: "1 hour", 7200: "2 hours", 14400: "4 hours", 28800: "8 hours", 57600: "16 hours",
             86400: "1 day", 172800: "2 days", 345600: "4 days", 604800: "1 week", 1209600: "2 weeks", 2419200: "4 weeks"}
DDNS_TTL = 300  # a Dynamic DNS host's new A record: the least TTL, so a change is seen soon
SETTABLE = ("A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA")  # what a set here may be (SRV and PTR: removed, not set)
SINGLE = frozenset({"A", "AAAA", "CNAME"})  # a set changes the host's record of the type
NAMED = frozenset({"CNAME", "NS", "MX"})  # a target that is a host name
CAA_TAGS = ("issue", "issuewild", "iodef")
MAX_TARGET = 65535
MX_DEFAULT = 10
LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


@dataclass(frozen=True)
class Change:
    """A change planned: the request (`method`: POST, PUT, DELETE; the record's id for PUT and DELETE; the body), and what
    it does in words; `nothing`: what was asked is there already, nothing is sent."""

    method: str
    record_id: int | None
    body: dict | None
    words: str
    nothing: bool = False


def shown_name(name: str | None) -> str:
    """A record's name as the page shows it: @ for the domain itself."""
    return str(name or "").strip() or "@"


def host_name(name: str, domain: str) -> str:
    """A host as Linode names it in `domain`: "" for the domain itself (@, empty, or the domain's own name), else its labels
    below the domain (home, www, _dmarc, *, a.b; the domain's name given in full is taken off). ValueError when it is none."""
    n = str(name or "").strip().lower().rstrip(".")
    d = str(domain or "").strip().lower().rstrip(".")
    if n in ("", "@") or n == d:
        return ""
    if d and n.endswith("." + d):
        n = n[: -len(d) - 1]
    labels = n.split(".")
    if len(n) > 100 or not all(LABEL.match(x) or (i == 0 and x == "*") for i, x in enumerate(labels)):
        raise ValueError(f"{str(name).strip()!r} is not a host: @ (the domain itself), www, home, *, _dmarc")
    return n


def norm_target(rtype: str, target) -> str:
    """A target as compared: a name's without its trailing dot and in lowercase, an address's in its short form."""
    t = str(target or "").strip()
    if rtype in NAMED:
        return t.lower().rstrip(".")
    if rtype in ("A", "AAAA"):
        try:
            return str(ipaddress.ip_address(t))
        except ValueError:
            return t
    return t


def target_for(rtype: str, target) -> str:
    """The target of a record of `rtype` as written; ValueError when it is none."""
    t = str(target or "").strip()
    if not t:
        raise ValueError("no target given (an address, a host name or text, as its type says)")
    if rtype == "A":
        try:
            return str(ipaddress.IPv4Address(t))
        except ValueError:
            raise ValueError(f"{t!r} is not an IPv4 address (an A record's)") from None
    if rtype == "AAAA":
        try:
            return str(ipaddress.IPv6Address(t))
        except ValueError:
            raise ValueError(f"{t!r} is not an IPv6 address (an AAAA record's)") from None
    if rtype in NAMED:
        n = t.lower().rstrip(".")
        labels = n.split(".")
        if len(n) > 253 or len(labels) < 2 or not all(LABEL.match(x) for x in labels):
            raise ValueError(f"{t!r} is not a host name (a {rtype} record's)")
        return n
    if len(t) > MAX_TARGET or any(ord(c) < 32 or ord(c) == 127 for c in t):  # TXT, CAA
        raise ValueError(f"a {rtype} record's target is one line of at most {MAX_TARGET:,} characters")
    return t


def ttl_of(value) -> int | None:
    """A TTL asked (one of TTLS; None or empty: the record's own, else the domain's); ValueError otherwise."""
    if value in (None, ""):
        return None
    try:
        t = int(str(value).strip())
    except ValueError:
        raise ValueError(f"the TTL is a number of seconds: {', '.join(map(str, TTLS))}") from None
    if t not in TTLS:
        raise ValueError(f"the TTL is one of Linode's: {', '.join(f'{x} ({TTL_WORDS[x]})' for x in TTLS)}")
    return t


def priority_of(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        p = int(str(value).strip())
    except ValueError:
        raise ValueError("a priority is a number, 0 to 255") from None
    if not 0 <= p <= 255:
        raise ValueError("a priority is 0 to 255")
    return p


def said(r: Mapping, domain: str = "") -> str:
    """A record in words: its name, type and target (shortened), its priority or tag where it has one."""
    t = str(r.get("type") or "")
    target = str(r.get("target") or "")
    short = target if len(target) <= 60 else target[:59] + "…"
    extra = f" (priority {r.get('priority')})" if t in ("MX", "SRV") and r.get("priority") is not None else \
        f" ({r.get('tag')})" if t == "CAA" and r.get("tag") else ""
    return f"{shown_name(r.get('name'))} {t} {short}{extra}"


def key(r: Mapping) -> tuple:
    """What makes two records the same record: its name, its type, its target (and a CAA's tag)."""
    t = str(r.get("type") or "").upper()
    return (str(r.get("name") or "").strip().lower(), t, norm_target(t, r.get("target")),
            str(r.get("tag") or "") if t == "CAA" else "")


def _kept_ttl(r: Mapping) -> dict:
    """A record's own TTL to send back with an update (one of TTLS; 0 or another: left out, so it stays as it is)."""
    try:
        t = int(r.get("ttl_sec") or 0)
    except (TypeError, ValueError):
        return {}
    return {"ttl_sec": t} if t in TTLS else {}


# -- the changes -------------------------------------------------------------------------------------------------------------
def plan_set(domain: str, records: Sequence[Mapping], name, rtype, target, ttl=None, priority=None, tag=None) -> Change:
    """The request that sets a record in `domain` (whose records are `records`, read just now), and what it does."""
    t = str(rtype or "").strip().upper()
    if t not in SETTABLE:
        raise ValueError(f"{rtype!r} is not set here: {', '.join(SETTABLE)}")
    host = host_name(name, domain)
    value = target_for(t, target)
    when = ttl_of(ttl)
    prio = priority_of(priority)
    if prio is not None and t != "MX":
        raise ValueError("a priority is an MX record's alone here")
    caa = str(tag or "").strip().lower()
    if t == "CAA":
        if caa not in CAA_TAGS:
            raise ValueError(f"a CAA record's tag is one of {', '.join(CAA_TAGS)}")
    elif caa:
        raise ValueError("a tag is a CAA record's alone")
    fqdn = f"{host}.{domain}" if host else domain
    if t == "CNAME" and not host:
        raise Refusal(f"Linode's DNS Manager takes no CNAME at {domain} itself (no CNAME flattening): an A or AAAA record does")
    at_host = [r for r in records if str(r.get("name") or "").strip().lower() == host]
    types_there = sorted({str(r.get("type") or "").upper() for r in at_host})
    if t == "CNAME" and any(x != "CNAME" for x in types_there):
        raise Refusal(f"{fqdn} holds other records ({', '.join(types_there)}): a CNAME stands alone")
    if t != "CNAME" and "CNAME" in types_there:
        raise Refusal(f"{fqdn} is a CNAME: it holds no {t} record beside it")
    new = {"type": t, "name": host, "target": value}
    wanted = key({**new, "tag": caa})
    same_type = [r for r in at_host if str(r.get("type") or "").upper() == t]
    match = next((r for r in same_type if key(r) == wanted), None)
    if match is None and t in SINGLE and len(same_type) > 1:
        raise Refusal(f"{fqdn} holds {len(same_type)} {t} records ({', '.join(str(r.get('target')) for r in same_type)}): a "
                      "set changes one record; remove the ones not wanted first")
    base = match if match is not None else (same_type[0] if t in SINGLE and same_type else None)
    if base is None:  # a new record
        body = {**new, **({"ttl_sec": when} if when is not None else {})}
        if t == "MX":
            body["priority"] = MX_DEFAULT if prio is None else prio
        if t == "CAA":
            body["tag"] = caa
        return Change("POST", None, body, f"added {said(body)} to {domain}")
    rid = int(base["id"])
    ttl_now, prio_now = base.get("ttl_sec"), base.get("priority")
    ttl_changes = when is not None and when != ttl_now
    prio_changes = t == "MX" and prio is not None and prio != prio_now
    if match is not None and not ttl_changes and not prio_changes:
        return Change("PUT", rid, None, f"{said(base)} is there already in {domain}: nothing written", nothing=True)
    body = {"name": host, "target": value, **({"ttl_sec": when} if when is not None else _kept_ttl(base))}
    if t == "MX":
        body["priority"] = prio if prio is not None else prio_now if prio_now is not None else MX_DEFAULT
    if t == "CAA":
        body["tag"] = caa
    if match is not None:
        bits = ([f"TTL {when}"] if ttl_changes else []) + ([f"priority {prio}"] if prio_changes else [])
        return Change("PUT", rid, body, f"{said(base)} in {domain}: {', '.join(bits)}")
    return Change("PUT", rid, body, f"set {said({**new, **body})} in {domain} (it was {base.get('target')})")


def plan_remove(domain: str, records: Sequence[Mapping], record_id, name=None, rtype=None, target=None) -> Change:
    """The request that removes a record by its id, refused when it is not there or no longer holds what was shown
    (`name`, `rtype`, `target`: what the page or the command line showed of it)."""
    try:
        rid = int(str(record_id).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{record_id!r} is not a record's id") from None
    r = next((x for x in records if int(x.get("id") or 0) == rid), None)
    if r is None:
        raise Refusal(f"{domain} holds no record {rid} any more (removed meanwhile?): nothing removed")
    t = str(r.get("type") or "").upper()
    shown = (host_name(name, domain) if name not in (None, "") else None,
             str(rtype).strip().upper() if rtype not in (None, "") else None,
             norm_target(t, target) if target not in (None, "") else None)
    now = (str(r.get("name") or "").strip().lower(), t, norm_target(t, r.get("target")))
    if any(s is not None and s != n for s, n in zip(shown, now)):
        raise Refusal(f"record {rid} of {domain} holds {said(r)} now, not what was shown: it changed since it was read, "
                      "so nothing is removed (read it again)")
    return Change("DELETE", rid, None, f"removed {said(r)} from {domain}")


# -- the check after a write -------------------------------------------------------------------------------------------------
def verify(before: Sequence[Mapping], after: Sequence[Mapping], change: Change, written: Mapping | None) -> dict:
    """What the records read after a change hold against what was meant: the record as written (or gone), every other
    record there before kept as it was (`lost`, `changed`), nothing else made (`unexpected`)."""
    by_id = {int(r.get("id") or 0): r for r in after}
    rid = change.record_id if change.record_id is not None else int((written or {}).get("id") or 0)
    problems: list[str] = []
    if change.method == "DELETE":
        if rid in by_id:
            problems.append(f"still there: {said(by_id[rid])}")
    else:
        got = by_id.get(rid)
        want = {**({} if change.method == "POST" else next((dict(r) for r in before if int(r.get("id") or 0) == rid), {})),
                **(change.body or {})}
        if got is None:
            problems.append(f"not there after the write: {said(want)}")
        elif key(got)[:3] != key(want)[:3]:
            problems.append(f"read back as {said(got)}, not {said(want)}")
        elif "ttl_sec" in (change.body or {}) and got.get("ttl_sec") != change.body["ttl_sec"]:
            problems.append(f"TTL {change.body['ttl_sec']} written, {got.get('ttl_sec')} read")
    others = [r for r in before if int(r.get("id") or 0) != rid]
    lost = [said(r) for r in others if int(r.get("id") or 0) not in by_id]
    changed = [said(r) for r in others if int(r.get("id") or 0) in by_id and key(by_id[int(r.get("id") or 0)]) != key(r)]
    known = {int(r.get("id") or 0) for r in before} | {rid}
    unexpected = [said(r) for i, r in by_id.items() if i not in known]
    return {"ok": not problems and not lost and not changed, "problems": problems, "lost": lost, "changed": changed,
            "unexpected": unexpected, "kept": len(others) - len(lost), "records": len(after)}
