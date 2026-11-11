"""Stand-ins for Linode and DNS: the tests never reach Linode, a name server or the network. `FakeLinode` is Linode's API v4
as a transport for the library's RestClient (an account in memory, its answers in the shapes the reference shows: a list
as {data, page, pages, results} with page and page_size checked, an error as {"errors": [{"reason", "field"}]}, a firewall's
rules with their fingerprint and version, the rate limit's headers); every request kept. `Pairs` is a Login holding pairs
by name."""
from __future__ import annotations

import base64
import copy
import json
import re
import zlib
from urllib.parse import parse_qs, urlsplit

import pytest

import liminal_libs.dns as dns_mod
import liminal_libs.machines.rest as rest_mod
from liminal_libs.apps import Login, Unauthorized, pair_name
from plugin_platform_linode import LinodePlugin
from plugin_platform_linode.settings import NAMES

TOKEN = "0123456789abcdef" * 4  # a stand-in token (no account's): 64 hex digits, as Linode's are
HOME = "93.184.216.34"  # this network's public address in the tests
BASE = "https://api.linode.com"


def pub(comment: str = "tester@laptop", kind: str = "ssh-ed25519", fill: int = 1) -> str:
    """A public key's line of `kind` (its data a stand-in: 32 bytes of `fill`)."""
    body = bytes([fill]) * 32
    blob = len(kind).to_bytes(4, "big") + kind.encode() + len(body).to_bytes(4, "big") + body
    return f"{kind} {base64.b64encode(blob).decode()} {comment}"


def fingerprint(rules: dict) -> str:
    """A rules' 32-bit hash as 8 hex digits (the reference's fingerprint; this one the stand-in's own)."""
    keep = {k: rules.get(k) for k in ("inbound", "outbound", "inbound_policy", "outbound_policy")}
    return "%08x" % zlib.crc32(json.dumps(keep, sort_keys=True).encode())


def rules_of(inbound, outbound=(), inbound_policy="DROP", outbound_policy="ACCEPT", version=1) -> dict:
    r = {"inbound": list(inbound), "outbound": list(outbound), "inbound_policy": inbound_policy,
         "outbound_policy": outbound_policy, "version": version}
    r["fingerprint"] = fingerprint(r)
    return r


SSH_ALL = {"action": "ACCEPT", "protocol": "TCP", "ports": "22", "addresses": {"ipv4": ["0.0.0.0/0"], "ipv6": ["::/0"]},
           "label": "ssh"}
WEB = {"action": "ACCEPT", "protocol": "TCP", "ports": "80, 443", "addresses": {"ipv4": ["0.0.0.0/0"], "ipv6": ["::/0"]},
       "label": "web"}
SSH_HOME = {"action": "ACCEPT", "protocol": "TCP", "ports": "22", "addresses": {"ipv4": ["203.0.113.7/32"]},
            "label": "ssh-home", "description": "from home only"}
RECORD_TYPES = {"A", "AAAA", "NS", "MX", "CNAME", "TXT", "SRV", "PTR", "CAA"}
RULE_FIELDS = {"action", "protocol", "ports", "addresses", "label", "description"}


class FakeLinode:
    """Linode's API v4 in memory; every request kept (`requests`: method, path, query, headers, body as JSON or None)."""

    def __init__(self, token: str = TOKEN):
        self.token = token
        self.requests: list[dict] = []
        self.errors: dict[tuple[str, str], tuple[int, str]] = {}  # (method, path) -> (status, reason) answered instead
        self.limits = {"X-RateLimit-Limit": "1600", "X-RateLimit-Remaining": "1599", "X-RateLimit-Reset": "1762862460"}
        self.meanwhile = None  # called before a rules PUT is taken: a change written elsewhere in between
        self.profile = {"username": "tester", "email": "tester@example.org", "uid": 1234, "restricted": False,
                        "two_factor_auth": True}
        self.account = {"balance": 0, "balance_uninvoiced": 12.34, "active_since": "2024-01-01T00:00:00",
                        "email": "tester@example.org", "first_name": "Test", "last_name": "Er", "country": "US",
                        "billing_source": "linode", "capabilities": ["Linodes", "Block Storage", "Cloud Firewall"],
                        "active_promotions": [{"credit_remaining": "50.00", "credit_monthly_cap": "10.00",
                                               "service_type": "all", "summary": "a stand-in credit"}]}
        self.transfer = {"used": 12, "quota": 5000, "billable": 0}
        self.linodes = [
            {"id": 11, "label": "web-1", "status": "running", "type": "g6-standard-2", "region": "us-east",
             "ipv4": ["203.0.113.10", "192.168.130.5"], "ipv6": "2600:3c03::f03c:91ff:fe24:3a2f/128",
             "specs": {"vcpus": 2, "memory": 4096, "disk": 81920, "transfer": 4000, "gpus": 0},
             "created": "2025-03-01T10:00:00", "updated": "2026-11-01T10:00:00", "tags": ["web"], "hypervisor": "kvm",
             "backups": {"enabled": True, "available": True}, "lke_cluster_id": None},
            {"id": 12, "label": "db-1", "status": "offline", "type": "g6-nanode-1", "region": "br-gru",
             "ipv4": ["198.51.100.12"], "ipv6": None, "specs": {"vcpus": 1, "memory": 1024, "disk": 25600, "transfer": 1000},
             "created": "2025-06-01T10:00:00", "tags": [], "hypervisor": "kvm", "backups": {"enabled": False}},
        ]
        self.types = [
            {"id": "g6-standard-2", "label": "Linode 4GB", "class": "standard", "price": {"hourly": 0.036, "monthly": 24},
             "region_prices": [{"id": "br-gru", "hourly": 0.05, "monthly": 33.6}], "memory": 4096, "vcpus": 2,
             "disk": 81920, "transfer": 4000,
             "addons": {"backups": {"price": {"hourly": 0.008, "monthly": 5}, "region_prices": []}}},
            {"id": "g6-nanode-1", "label": "Nanode 1GB", "class": "nanode", "price": {"hourly": 0.0075, "monthly": 5},
             "region_prices": [{"id": "br-gru", "hourly": 0.0105, "monthly": 7}], "memory": 1024, "vcpus": 1,
             "disk": 25600, "transfer": 1000,
             "addons": {"backups": {"price": {"hourly": 0.003, "monthly": 2}, "region_prices": []}}},
        ]
        self.domains = [
            {"id": 1, "domain": "example.com", "type": "master", "status": "active", "soa_email": "admin@example.com",
             "ttl_sec": 0, "tags": [], "description": None},
            {"id": 2, "domain": "example.net", "type": "slave", "status": "active", "master_ips": ["198.51.100.53"],
             "ttl_sec": 0, "tags": []},
        ]
        self.records = {1: [
            {"id": 100, "type": "A", "name": "", "target": "203.0.113.10", "ttl_sec": 3600, "priority": 0},
            {"id": 101, "type": "MX", "name": "", "target": "mail.example.com", "ttl_sec": 0, "priority": 10},
            {"id": 102, "type": "TXT", "name": "", "target": "v=spf1 mx -all", "ttl_sec": 0, "priority": 0},
            {"id": 103, "type": "CNAME", "name": "www", "target": "example.com", "ttl_sec": 0, "priority": 0},
            {"id": 104, "type": "A", "name": "home", "target": "198.51.100.7", "ttl_sec": 300, "priority": 0},
        ]}
        self.next_id = 1000
        self.firewalls = [
            {"id": 9, "label": "web-fw", "status": "enabled", "rules": rules_of([SSH_ALL, WEB], version=3),
             "tags": [], "entities": [{"id": 11, "label": "web-1", "type": "linode", "url": "/v4/linode/instances/11"}]},
            {"id": 8, "label": "db-fw", "status": "enabled", "rules": rules_of([SSH_HOME], version=1), "tags": [],
             "entities": [{"id": 12, "label": "db-1", "type": "linode", "url": "/v4/linode/instances/12"}]},
        ]
        self.volumes = [{"id": 21, "label": "data", "status": "active", "size": 40, "region": "us-east", "linode_id": 11,
                         "linode_label": "web-1", "hardware_type": "nvme", "encryption": "enabled",
                         "filesystem_path": "/dev/disk/by-id/scsi-0Linode_Volume_data", "tags": []}]
        self.keys = [{"id": 5, "label": "laptop", "ssh_key": pub(), "created": "2025-01-02T03:04:05"}]
        self.reserved = [{"address": "198.51.100.20", "region": "us-east", "reserved": True, "public": True,
                          "rdns": "198-51-100-20.ip.linodeusercontent.com", "linode_id": 11,
                          "assigned_entity": {"id": 11, "label": "web-1", "type": "linode", "url": "/v4/linode/instances/11"}}]
        self.counted = {"/lke/clusters": 1, "/nodebalancers": 0, "/databases/instances": 2, "/object-storage/buckets": 3,
                        "/images": 4, "/vpcs": 0, "/placement/groups": 1}

    # -- what was asked ------------------------------------------------------------------------------------------------
    def writes(self) -> list[tuple]:
        return [(r["method"], r["path"], r["body"]) for r in self.requests if r["method"] != "GET"]

    def paths(self, method: str = "GET") -> list[str]:
        return [r["path"] for r in self.requests if r["method"] == method]

    # -- answering --------------------------------------------------------------------------------------------------------
    def answer(self, status: int, data=None, headers=None):
        return status, {"Content-Type": "application/json", **self.limits, **(headers or {})}, \
            json.dumps(data if data is not None else {}).encode()

    def error(self, status: int, reason: str, field: str | None = None):
        e = {"reason": reason, **({"field": field} if field else {})}
        return self.answer(status, {"errors": [e]})

    def page(self, items: list, query: dict):
        size = int(query.get("page_size", ["100"])[0])
        at = int(query.get("page", ["1"])[0])
        if not 25 <= size <= 500:
            return self.error(400, "Must be between 25 and 500", "page_size")
        pages = max(1, -(-len(items) // size))
        return self.answer(200, {"data": copy.deepcopy(items[(at - 1) * size: at * size]), "page": at, "pages": pages,
                                 "results": len(items)})

    def __call__(self, method, url, headers, body, timeout):
        parts = urlsplit(url)
        assert parts.scheme == "https" and parts.netloc == "api.linode.com", url
        query = parse_qs(parts.query)
        data = json.loads(body) if body else None
        self.requests.append({"method": method, "path": parts.path, "query": {k: v[0] for k, v in query.items()},
                              "headers": dict(headers), "body": data})
        if headers.get("Authorization") != f"Bearer {self.token}":
            return self.error(401, "Invalid Token")
        if (method, parts.path) in self.errors:
            return self.error(*self.errors[(method, parts.path)])
        path = parts.path
        assert path.startswith("/v4/"), path
        p = path[3:]
        if method == "GET":
            return self.get(p, query, headers)
        return self.write(method, p, data)

    def get(self, p: str, query: dict, headers: dict):
        simple = {"/profile": self.profile, "/account": self.account, "/account/transfer": self.transfer}
        if p in simple:
            return self.answer(200, simple[p])
        lists = {"/linode/instances": self.linodes, "/linode/types": self.types, "/domains": self.domains,
                 "/networking/firewalls": self.firewalls, "/volumes": self.volumes, "/profile/sshkeys": self.keys,
                 "/networking/reserved/ips": self.reserved}
        if p in lists:
            return self.page(lists[p], query)
        if p in self.counted:
            if p == "/images":
                assert json.loads(headers.get("X-Filter") or "{}") == {"is_public": False}, "the account's own images"
            return self.page([{"id": i} for i in range(self.counted[p])], query)
        m = re.fullmatch(r"/linode/instances/(\d+)", p)
        if m:
            x = next((x for x in self.linodes if x["id"] == int(m.group(1))), None)
            return self.answer(200, x) if x else self.error(404, "Not found")
        m = re.fullmatch(r"/domains/(\d+)/records", p)
        if m:
            if int(m.group(1)) not in self.records:
                return self.error(404, "Not found")
            return self.page(self.records[int(m.group(1))], query)
        m = re.fullmatch(r"/networking/firewalls/(\d+)/rules", p)
        if m:
            f = next((f for f in self.firewalls if f["id"] == int(m.group(1))), None)
            return self.answer(200, f["rules"]) if f else self.error(404, "Not found")
        return self.error(404, f"Not found: {p}")

    def write(self, method: str, p: str, data):
        m = re.fullmatch(r"/linode/instances/(\d+)/(boot|shutdown|reboot)", p)
        if m and method == "POST":
            assert data is None, "the power changes are sent with no body"
            x = next((x for x in self.linodes if x["id"] == int(m.group(1))), None)
            if x is None:
                return self.error(404, "Not found")
            x["status"] = {"boot": "booting", "shutdown": "shutting_down", "reboot": "rebooting"}[m.group(2)]
            return self.answer(200, {})
        m = re.fullmatch(r"/domains/(\d+)/records(?:/(\d+))?", p)
        if m:
            held = self.records.setdefault(int(m.group(1)), [])
            if method == "POST" and not m.group(2):
                if data.get("type") not in RECORD_TYPES:
                    return self.error(400, "type is required", "type")
                if set(data) - {"type", "name", "target", "ttl_sec", "priority", "weight", "port", "service", "protocol",
                                "tag"}:
                    return self.error(400, "Unknown field", "body")
                self.next_id += 1
                r = {"id": self.next_id, "name": "", "ttl_sec": 0, "priority": 0, **data}
                held.append(r)
                return self.answer(200, r)
            r = next((r for r in held if r["id"] == int(m.group(2) or 0)), None)
            if r is None:
                return self.error(404, "Not found")
            if method == "PUT":
                if "type" in data:
                    return self.error(400, "Unknown field", "type")
                r.update(data)
                return self.answer(200, r)
            if method == "DELETE":
                held.remove(r)
                return self.answer(200, {})
        m = re.fullmatch(r"/networking/firewalls/(\d+)/rules", p)
        if m and method == "PUT":
            f = next((f for f in self.firewalls if f["id"] == int(m.group(1))), None)
            if f is None:
                return self.error(404, "Not found")
            if set(data) != {"inbound", "outbound", "inbound_policy", "outbound_policy"}:
                return self.error(400, "Unknown or missing field", "body")
            for d in ("inbound", "outbound"):
                for r in data[d]:
                    if set(r) - RULE_FIELDS or not r.get("addresses") or any(not v for v in r["addresses"].values()):
                        return self.error(400, "a rule as the reference takes it", d)
            if len(data["inbound"]) + len(data["outbound"]) > 25:
                return self.error(400, "Too many rules", "inbound")
            if self.meanwhile:
                self.meanwhile(f)
            new = {**copy.deepcopy(data), "version": f["rules"]["version"] + 1}
            new["fingerprint"] = fingerprint(new)
            f["rules"] = new
            return self.answer(200, new)
        if p == "/profile/sshkeys" and method == "POST":
            assert set(data) == {"label", "ssh_key"}, data
            self.next_id += 1
            k = {"id": self.next_id, "created": "2026-11-11T12:00:00", **data}
            self.keys.append(k)
            return self.answer(200, k)
        m = re.fullmatch(r"/profile/sshkeys/(\d+)", p)
        if m and method == "DELETE":
            k = next((k for k in self.keys if k["id"] == int(m.group(1))), None)
            if k is None:
                return self.error(404, "Not found")
            self.keys.remove(k)
            return self.answer(200, {})
        return self.error(405, f"{method} {p} is not a stand-in's")


class Pairs(Login):
    """A login holding pairs by name (the login app's store, as the Login interface asks it)."""

    NAMESPACE = "test"

    def __init__(self, values: dict[str, str]):
        self.pairs = {pair_name(k): v for k, v in values.items()}
        self.asked: list[str] = []

    def user(self) -> dict:
        return {"name": "tester"}

    def vector(self, name: str) -> str:
        self.asked.append(name)
        if name not in self.pairs:
            raise Unauthorized(f"no {name}", 404)
        return self.pairs[name]

    def names(self) -> set[str]:
        return set(self.pairs)


def settings_of(token: bool = True, ddns: str | None = None, **more) -> dict[str, str]:
    out = {"LINODE_TOKEN": TOKEN} if token else {}
    if ddns:
        out["LINODE_DDNS_HOSTS"] = ddns
    out.update(more)
    return out


def page_args(form: dict, values: dict, accepted=()) -> list:
    """What the platform's page sends for a form (platform.js argsOf): the fields' values in order, a field whose `when` is
    unmet or left empty null (the hook's default), a number as a number, an accept field true only once accepted."""
    now = {**{x["name"]: x.get("value") for x in form["fields"]}, **values}
    out = []
    for x in form["fields"]:
        if x["type"] == "accept":
            out.append(x["name"] in accepted)
            continue
        shown = all(str(now.get(k) or "") in [str(v) for v in vs] for k, vs in (x.get("when") or {}).items())
        v = now.get(x["name"])
        out.append(None if not shown or v in (None, "") else int(v) if x["type"] == "number" else v)
    return out


def forms_of(status: dict) -> dict:
    return {f["id"]: f for f in status["forms"]}


def table(status: dict, title: str) -> dict:
    return next(t for t in status["tables"] if t["title"] == title)


@pytest.fixture(autouse=True)
def _no_linode_no_network(monkeypatch, tmp_path):
    """No test reaches Linode, a name server or this machine's settings: HTTPS and nslookup refused, every LINODE_ variable
    cleared, the platform's folder the test's own."""
    def refused(*a, **k):
        raise AssertionError("a test reached for the network")
    monkeypatch.setattr(rest_mod, "_requests_transport", refused)
    monkeypatch.setattr(dns_mod, "query", refused)
    for n in NAMES:
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", str(tmp_path / "platform"))


@pytest.fixture
def env(monkeypatch):
    """Sets the plugin's variables (the EnvironmentLogin's: what the platform reads today)."""
    def put(values: dict[str, str]):
        for k, v in values.items():
            monkeypatch.setenv(k, v)
    return put


@pytest.fixture
def made():
    """A plugin over the stand-ins: (plugin, fake Linode); this network's address HOME unless `public` says otherwise."""
    def make(fake: FakeLinode | None = None, public=(HOME, "OpenDNS")):
        fake = fake or FakeLinode()
        p = LinodePlugin(transport=fake, public=(lambda: public), sleep=lambda s: None)
        return p, fake
    return make
