"""Dynamic DNS through Linode's DNS Manager (the user, 2026-11-11: the cloud plugins "set and remove DNS records (and keep a
record at this PC's public address: dynamic DNS)"): the library's Keeper (liminal_libs.machines.ddns) with Linode's API as
the provider's side. Each host set (LINODE_DDNS_HOSTS) is in a domain DNS Manager holds as its master; a pass asks this
network's public IPv4 address of DNS (OpenDNS's myip.opendns.com, else Google's o-o.myaddr.l.google.com, each asked of the
name server by its IPv4 address: PUBLIC_IPV4), reads the host's A record from the domain's records (one list read a domain
a pass), and sets it where it differs: the one A record changed (its TTL kept), or one made (TTL 300, the least Linode
takes, so a change is seen soon). A host holding several A records is left as it is and said (a set changes one record).

The reference offers a target of "[remote_addr]" (the address the request comes from) for an A record; the plugin sends
the address it found instead, so the record is this network's IPv4 address even when the request goes out over IPv6."""
from __future__ import annotations

import threading
from collections.abc import Callable

from liminal_libs.machines.ddns import Host

from .records import DDNS_TTL, TTLS

# the name servers that tell an asker its own address, asked by their IPv4 addresses (as hw-stats names them)
PUBLIC_IPV4 = (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
               ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


class LinodeDns:
    """The Keeper's provider side over Linode's API: `api()` the client, `domain_of(zone)` a master domain's id (None: not
    one of the account's). The records read in a pass are kept for its writes (`begin` starts a pass afresh)."""

    def __init__(self, api: Callable[[], object], domain_of: Callable[[str], int | None]):
        self._api = api
        self._domain_of = domain_of
        self._lock = threading.Lock()
        self._read: dict[str, list[dict]] = {}

    def begin(self) -> None:
        with self._lock:
            self._read.clear()

    def _records(self, h: Host, fresh: bool = False) -> tuple[int, list[dict]]:
        did = self._domain_of(h.zone)
        if did is None:
            raise ValueError(f"{h.zone} is not a master domain of Linode's DNS Manager in this account")
        with self._lock:
            kept = self._read.get(h.zone)
        if kept is None or fresh:
            kept = self._api().records(did)
            with self._lock:
                self._read[h.zone] = kept
        return did, kept

    @staticmethod
    def name_of(h: Host) -> str:
        return "" if h.name == "@" else h.name

    def a_records(self, h: Host, records: list[dict]) -> list[dict]:
        name = self.name_of(h)
        return [r for r in records if str(r.get("type") or "").upper() == "A"
                and str(r.get("name") or "").strip().lower() == name]

    def read(self, h: Host) -> list[str]:
        """The addresses the host's A record holds ([] none)."""
        _, records = self._records(h)
        return [str(r.get("target") or "").strip() for r in self.a_records(h, records)]

    def write(self, h: Host, ip: str) -> str:
        """The host's A record set to `ip`: the one there changed, else one made; words of what was done."""
        did, records = self._records(h)
        mine = self.a_records(h, records)
        api = self._api()
        if len(mine) > 1:
            raise ValueError(f"{h.fqdn} holds {len(mine)} A records ({', '.join(str(r.get('target')) for r in mine)}): "
                             "Dynamic DNS keeps one; remove the others")
        if mine:
            r = mine[0]
            body = {"name": self.name_of(h), "target": ip}
            try:
                if int(r.get("ttl_sec") or 0) in TTLS:
                    body["ttl_sec"] = int(r["ttl_sec"])
            except (TypeError, ValueError):
                pass
            api.update_record(did, int(r["id"]), body)
            done = "set"
        else:
            api.create_record(did, {"type": "A", "name": self.name_of(h), "target": ip, "ttl_sec": DDNS_TTL})
            done = "made"
        with self._lock:
            self._read.pop(h.zone, None)  # read again by the next host of the zone
        return done
