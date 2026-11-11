"""Dynamic DNS through Linode's DNS Manager (the user, 2026-11-11: the cloud plugins "set and remove DNS records (and keep a
record at this PC's public address: dynamic DNS)"): the library's Keeper (liminal_libs.machines.ddns) with Linode's API as
the provider's side. Each host set (LINODE_DDNS_HOSTS) is in a domain DNS Manager holds as its master; a pass asks this
network's public IPv4 address of DNS (OpenDNS's myip.opendns.com, else Google's o-o.myaddr.l.google.com, each asked of the
name server by its IPv4 address: PUBLIC_IPV4), reads the host's records from the domain's (one list read a domain a pass),
and sets what is the keeper's own to change (liminal-libs 1.49.2, after an audit: a host with no A record, one already
pointing at this network or at the address the keeper set last, and one the user took over on the page; a host holding
another address, or several, is left as it is and said so, with a Take over…).

A write sets the host's A record to exactly one address, this network's: its A record changed (its TTL kept), or one made
(TTL 300, the least Linode takes, so a change is seen soon); a host the user took over that held several A records keeps
one, changed, the others removed (the take-over's confirmation says what it held is dropped). A host that is a CNAME is
never given an A record beside it (DNS Manager's own set refuses that too): it is said, and left as it is. AAAA records
are not Dynamic DNS's: they are left as they are.

The reference offers a target of "[remote_addr]" (the address the request comes from) for an A record; the plugin sends
the address it found instead, so the record is this network's IPv4 address even when the request goes out over IPv6."""
from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path

from liminal_libs.machines.ddns import Host

from .records import DDNS_TTL, TTLS

# the name servers that tell an asker its own address, asked by their IPv4 addresses (as hw-stats names them)
PUBLIC_IPV4 = (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
               ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))
DIR_VAR = "LIMINAL_PLATFORM_DIR"  # the platform's own folder (its app's variable): the keeper's state under it


def state_path() -> Path:
    """Where the keeper keeps what is its own and what it was let take over (liminal-libs 1.49.2's `state`): the
    platform's folder's linode/ddns.json (LIMINAL_PLATFORM_DIR, else the data folder's platform/)."""
    named = (os.environ.get(DIR_VAR) or "").strip()
    if named:
        return Path(named).expanduser() / "linode" / "ddns.json"
    from liminal_libs import layout

    return layout.data_dir() / "platform" / "linode" / "ddns.json"


class LinodeDns:
    """The Keeper's provider side over Linode's API: `api()` the client, `domain_of(zone)` a master domain's id (None: not
    one of the account's). The records read in a pass are kept for its writes (`begin`: the Keeper's on_pass, a pass
    read afresh)."""

    def __init__(self, api: Callable[[], object], domain_of: Callable[[str], int | None]):
        self._api = api
        self._domain_of = domain_of
        self._lock = threading.Lock()
        self._read: dict[str, list[dict]] = {}

    def begin(self) -> None:
        with self._lock:
            self._read.clear()

    def _records(self, h: Host) -> tuple[int, list[dict]]:
        did = self._domain_of(h.zone)
        if did is None:
            raise ValueError(f"{h.zone} is not a master domain of Linode's DNS Manager in this account")
        with self._lock:
            kept = self._read.get(h.zone)
        if kept is None:
            kept = self._api().records(did)
            with self._lock:
                self._read[h.zone] = kept
        return did, kept

    @staticmethod
    def name_of(h: Host) -> str:
        return "" if h.name == "@" else h.name

    def at_host(self, h: Host, records: list[dict], rtype: str) -> list[dict]:
        name = self.name_of(h)
        return [r for r in records if str(r.get("type") or "").upper() == rtype
                and str(r.get("name") or "").strip().lower() == name]

    def read(self, h: Host) -> list[str]:
        """The addresses the host's A records hold ([] none); a host that is a CNAME is refused (never an A beside it)."""
        _, records = self._records(h)
        cname = self.at_host(h, records, "CNAME")
        if cname:
            raise ValueError(f"{h.fqdn} is a CNAME (to {cname[0].get('target')}): an A record takes no place beside it, so "
                             "it is left as it is (remove the CNAME to keep the host here)")
        return [str(r.get("target") or "").strip() for r in self.at_host(h, records, "A")]

    def write(self, h: Host, ip: str) -> str:
        """The host's A record set to exactly `ip` (the Keeper asks this only of what is its own to change): the one there
        changed (its TTL kept), others removed, or one made; words of what was done."""
        did, records = self._records(h)
        if self.at_host(h, records, "CNAME"):
            raise ValueError(f"{h.fqdn} is a CNAME: no A record is made beside it")
        mine = self.at_host(h, records, "A")
        api = self._api()
        if mine:
            first, rest = mine[0], mine[1:]
            body = {"name": self.name_of(h), "target": ip}
            try:
                if int(first.get("ttl_sec") or 0) in TTLS:
                    body["ttl_sec"] = int(first["ttl_sec"])
            except (TypeError, ValueError):
                pass
            api.update_record(did, int(first["id"]), body)
            for r in rest:  # a host taken over that held several: one address, this network's
                api.delete_record(did, int(r["id"]))
            done = "set" + (f", {len(rest)} other A record{'' if len(rest) == 1 else 's'} removed" if rest else "")
        else:
            api.create_record(did, {"type": "A", "name": self.name_of(h), "target": ip, "ttl_sec": DDNS_TTL})
            done = "made"
        with self._lock:
            self._read.pop(h.zone, None)  # read again by the next host of the zone
        return done
