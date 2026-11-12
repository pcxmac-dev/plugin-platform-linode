"""Linode for Liminal (the user, 2026-11-11: "ALSO i would like to add two new plugins, Digital Ocean and LINODE"; for the
cloud plugins, "Free changes only"): the account through Linode's API v4 (Akamai Cloud): its balance and this month's
charges so far, the Linodes with their plans and prices, DNS Manager's domains and records, the Cloud Firewalls with
their rules and what they guard, the volumes, the profile's SSH keys, the reserved IPs, and counts of the rest (Kubernetes
clusters, NodeBalancers, databases, buckets, images, VPCs, placement groups). It changes only what costs nothing, each
change confirmed first: a Linode booted, shut down or rebooted; a DNS record set or removed (every other record kept); a
Cloud Firewall rule added or removed (the whole set written back as read, refused when it changed meanwhile; a change
that opens every port, SSH or another port servers are broken into through to the whole internet, or that ends SSH to a
Linode the firewall guards, asked twice, whatever rule it adds or removes); an SSH key added to the profile or removed.
And Dynamic DNS keeping hosts of DNS Manager's domains at this network's public IPv4 address: only what is its own (a host
holding another address is left as it is until taken over on the page). Nothing that starts a charge: no Linode, volume,
snapshot, backup or reserved IP made, nothing resized or destroyed. A powered-off Linode still bills (Akamai's pricing
FAQ), and the page says so.

Its settings are pairs asked of the login of the app it is attached to (settings.py: LINODE_TOKEN, LINODE_DDNS_HOSTS,
LINODE_DDNS_MINUTES), never a file of its own. Attached to the platform app, once the token is set, it reads the account
every quarter of an hour and checks the Dynamic DNS hosts every few minutes in a thread of its own; attached by another
app, or detached, nothing of it runs, and once detached no setting is read. Its status is what was read last (no request
is made to answer it): the platform's page draws its tables, its actions (Refresh, Update DNS now) and its forms, and its
API card (card.py: plugin API 2.2).

0.1.1 and 0.1.2 (2026-11-11) are what an audit of the cloud plugins and its re-verification found before any key went
in: see CHANGELOG.md.

    python -m plugin_platform_linode status | servers | domains | records DOMAIN | ddns [--now] | firewalls | keys
        | power LINODE on|off|reboot | set DOMAIN HOST TYPE TARGET [--ttl N] [--priority N] [--tag T]
        | remove DOMAIN HOST TYPE [TARGET]
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from liminal_libs.machines.ddns import Keeper, hosts_of
from liminal_libs.machines.plugin import MachinePlugin
from liminal_libs.machines.rest import RestError

from . import firewall as fw
from . import records as rec
from . import settings as settings_mod
from .api import COUNTED, LinodeApi
from .card import APIS, LINODE_API
from .ddns import PUBLIC_IPV4, LinodeDns, state_path
from .refusal import Refusal
from .settings import ACCESS_SHORT, DDNS_HOSTS, KEYS, NAMES, SCOPE_WORDS, TOKEN, TOKEN_PAGE, Config

__version__ = "0.1.2"
REFRESH_S = 900.0  # the account read again at most this often while attached (or by Refresh)
CONFIG_S = 30.0  # the settings asked of the login again after this long
RETRY_S = 900.0  # a read that failed is taken as untried after this long while detached: attached again, it is tried again
TYPES_S = 86400.0  # the plans and their prices read again after a day
DOMAINS_MAX = 20  # the domains whose records a refresh reads (the rest: `records DOMAIN`)
NOT_SET = (f"not set up: {TOKEN}, a personal access token made in Cloud Manager (your username > API Tokens: {TOKEN_PAGE}) "
           f"with {SCOPE_WORDS}")
BILLS_OFF = ("A powered-off Linode still bills: Akamai keeps its disks and holds its resources for it while it is off "
             "(Akamai's pricing FAQ: a powered-off VM is still billed); only removing it ends the charge, which this plugin "
             "never does.")
RUNNING = "running"
OFF = frozenset({"offline", "stopped"})
POWER_WORDS = {  # action -> (its title, done in words, the confirmation's words, dangerous)
    "boot": ("Boot", "booting", "{linode} is booted (powered on) with its configuration (where it has several, the one it "
                                "last booted). Booting starts no new charge: a Linode bills the same by the hour whether it "
                                "runs or is off.", False),
    "shutdown": ("Shut down", "shutting down", "{linode} is shut down (powered off) until it is booted again: its services "
                                               "stop. Save unsaved work on it first: Linode's API does not say how long it "
                                               "waits for the system to stop. " + BILLS_OFF, True),
    "reboot": ("Reboot", "rebooting", "{linode} is rebooted into the configuration it last booted: its services stop until "
                                      "it is up again.", True),
}
ACTIONS_OF = {"boot": "boot", "on": "boot", "start": "boot", "power-on": "boot", "shutdown": "shutdown", "off": "shutdown",
              "stop": "shutdown", "shut-down": "shutdown", "power-off": "shutdown", "reboot": "reboot", "restart": "reboot"}
TYPE_NOTES = {  # the record types a set offers (records.SETTABLE), with what each holds and does
    "A": "an IPv4 address; changes the host's A record (or makes one)",
    "AAAA": "an IPv6 address; changes the host's AAAA record (or makes one)",
    "CNAME": "a host name the host stands for; it holds nothing else, and the domain itself takes none",
    "TXT": "text (SPF, DKIM, DMARC, a verification); added beside the host's others",
    "MX": "a mail server, with its priority; added beside the others",
    "NS": "a subdomain's name server; added beside the others",
    "CAA": "the certificate authorities that may issue for the domain (issue, issuewild, iodef); added beside the others",
}
CAA_NOTES = {"issue": "may issue certificates for the host", "issuewild": "may issue wildcard certificates",
             "iodef": "where reports of a refused request go (a mailto: or https: address)"}
SSH_KINDS = ("ssh-dss", "ssh-rsa", "ssh-ed25519")  # with ecdsa-sha2-nistp* and sk-ecdsa-sha2-nistp256 (the reference's)


def when(t: float | None) -> str:
    return "–" if not t else time.strftime("%b %d %H:%M", time.localtime(t))


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def cell(text, sub: str | None = None):
    return {"text": text, "sub": sub} if sub else text


def money(value, hourly: bool = False) -> str:
    """US dollars as Linode gives them: $24.00 a month, $0.036 an hour."""
    try:
        x = float(value)
    except (TypeError, ValueError):
        return "–"
    if hourly:
        text = f"{x:.4f}".rstrip("0")
        return "$" + (text + "0" * max(0, 2 - len(text.partition(".")[2])))
    return f"${x:,.2f}"


def day(stamp) -> str:
    return str(stamp or "")[:10] or "–"


def number(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# the private ranges (RFC 1918, shared address space, link-local, loopback): a Linode's private and VPC addresses are among
# them, never shown as its public address
LOCAL_V4 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                   "169.254.0.0/16", "127.0.0.0/8"))


def is_public_v4(address) -> bool:
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    return ip.version == 4 and not any(ip in n for n in LOCAL_V4)


def ssh_key_of(text) -> tuple[str, str, str]:
    """A public SSH key as typed: (its line, its kind, its SHA256 fingerprint as ssh-keygen -l prints it). ValueError for a
    private key or anything the reference's kinds are not (ssh-dss, ssh-rsa, ecdsa-sha2-nistp*, ssh-ed25519,
    sk-ecdsa-sha2-nistp256)."""
    line = " ".join(str(text or "").split())
    if "PRIVATE KEY" in line.upper():
        raise ValueError("that is a private key: never paste it anywhere. The public key is the .pub file's line "
                         "(ssh-ed25519 AAAA... you@host)")
    parts = line.split(" ")
    if len(parts) < 2:
        raise ValueError("a public key is one line: its kind, its key and a comment (ssh-ed25519 AAAA... you@host)")
    kind, blob = parts[0], parts[1]
    if not (kind in SSH_KINDS or kind.startswith("ecdsa-sha2-nistp") or kind.startswith("sk-ecdsa-sha2-nistp256")):
        raise ValueError(f"{kind!r} is not a key kind Linode takes: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256/384/521, "
                         "sk-ecdsa-sha2-nistp256, ssh-dss")
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("the key's second part is not base64: copy the .pub file's line whole") from None
    size = int.from_bytes(raw[:4], "big") if len(raw) >= 4 else -1
    if raw[4:4 + size] != kind.encode("ascii", "replace"):
        raise ValueError(f"the key's data is not a {kind} key: copy the .pub file's line whole")
    if len(line) > 16384:
        raise ValueError("that key is too long to be a public key's line")
    return line, kind, "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def fingerprint_of(text) -> str:
    try:
        return ssh_key_of(text)[2]
    except ValueError:
        return ""


def typed_host(text) -> str:
    """A Dynamic DNS host as typed, as the keeper names it: lowercase, without @. for the domain itself, nor a final dot."""
    name = str(text or "").strip().rstrip(".").lower()
    return name[2:] if name.startswith("@.") else name


class _Detached(Exception):
    """The plugin was detached during a read: it ends there."""


@dataclass(frozen=True)
class Trouble:
    """A part of the account that could not be read, in words; `denied`: the token's access does not cover it (403)."""

    words: str
    denied: bool = False
    area: str = ""

    def __str__(self) -> str:
        return self.words


class _Runtime:
    """What the plugin read and holds, shared by its copies (the registry's with_ makes them)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.config: tuple[float, Config] | None = None
        self.api: tuple[str, LinodeApi] | None = None
        self.read: dict | None = None  # the last refresh's parts (each its data or a Trouble)
        self.types: tuple[float, dict[str, dict]] | None = None  # the plans by id, when read
        self.refreshed_at: float | None = None
        self.api_ok: bool | None = None  # the last refresh's outcome (None: none yet)
        self.api_error = ""
        self.api_error_at: float | None = None
        self.api_print = ""  # the settings that outcome is of
        self.ddns_print = ""
        self.ddns_at: float | None = None
        self.keeper: Keeper | None = None
        self.dns: LinodeDns | None = None
        self.detached = threading.Event()  # set by a detach: a pass under way writes nothing more, no settings are read
        self.worker: threading.Thread | None = None
        self.stop: threading.Event | None = None
        self.wake = threading.Event()
        self.refreshing = threading.Lock()


class LinodePlugin(MachinePlugin):
    """Linode: the account through its API, the free changes each confirmed, and Dynamic DNS; reading in the background
    while attached."""

    name = "linode"
    title = "Linode"
    about = ("Your Linode (Akamai Cloud) account through its API: the Linodes with their prices, DNS Manager's domains, "
             "Cloud Firewalls, volumes and SSH keys; free changes only, each confirmed; Dynamic DNS")
    api = "2.2"
    version = __version__
    order = 761
    ICON = "linode"  # Linode's prism (liminal-libs 1.49.0's icons.js)
    HOOKS = (*MachinePlugin.HOOKS, "refresh", "linodes", "domains", "records", "firewalls", "ssh_keys", "power",
             "set_record", "remove_record", "add_rule", "remove_rule", "add_ssh_key", "remove_ssh_key", "ddns_update",
             "ddns_take_over")
    keys = KEYS
    signup = TOKEN_PAGE
    limits = ("Linode's API: 200 list requests a minute and 1,600 others; the plugin makes about 20 a quarter of an hour "
              "(one more for each domain's records) and a Dynamic DNS check one a zone")
    apis = APIS

    def __init__(self, transport=None, public: Callable[[], tuple[str | None, str]] | None = None, clock=None, sleep=None):
        self._transport = transport  # (method, url, headers, body, timeout) -> (status, headers, body): a test's; else HTTPS
        self._public = public  # () -> (this network's IPv4 address, whose): a test's; else asked of PUBLIC_IPV4's servers
        self._clock = clock or time.time
        self._sleep = sleep or time.sleep
        self._rt = _Runtime()

    # -- the settings, the API, the Dynamic DNS keeper --------------------------------------------------------------------
    def config(self, fresh: bool = False) -> Config:
        """The settings, asked of the login (the attached app's, else the environment's); kept CONFIG_S. Once detached,
        none until a login is lent again (an audit, 2026-11-11: a pass outliving its detach must read no settings from
        the process environment)."""
        now = time.monotonic()
        with self._rt.lock:
            kept = self._rt.config
        if self.login is None and self._rt.detached.is_set():
            return Config()
        if kept is not None and not fresh and now - kept[0] < CONFIG_S:
            return kept[1]
        cfg = settings_mod.read(self.login)
        with self._rt.lock:
            self._rt.config = (now, cfg)
        return cfg

    def settings_changed(self) -> None:
        """Its settings were just entered (liminal-platform 0.9.0: Settings… on its page, kept through the login): read
        anew at once, a failed read tried again at once (no wait for its retry); the background reading started if it
        is attached to the platform and the token is set now."""
        with self._rt.lock:
            self._rt.config = None
        if self._on_platform() and not self.working:
            self._start_if_set()

    def client(self) -> LinodeApi:
        """The API with the settings as they are (ValueError when the token is not set)."""
        cfg = self.config()
        if not cfg.ready:
            raise ValueError("the API is not set up: " + NOT_SET)
        with self._rt.lock:
            held = self._rt.api
        if held is not None and held[0] == cfg.api_print:
            return held[1]
        made = LinodeApi(cfg.token, transport=self._transport, clock=self._clock, sleep=self._sleep)
        with self._rt.lock:
            self._rt.api = (cfg.api_print, made)
        return made

    def keeper(self) -> Keeper:
        """The Dynamic DNS keeper (liminal-libs 1.49.2): what is its own and what it was let take over kept in the
        platform's folder (ddns.state_path), the records of a pass read afresh at its start."""
        with self._rt.lock:
            if self._rt.keeper is None:
                self._rt.dns = LinodeDns(self.client, self._domain_id)
                self._rt.keeper = Keeper(read=self._rt.dns.read, write=self._rt.dns.write, servers=PUBLIC_IPV4,
                                         public=self._public, clock=self._clock, on_pass=self._rt.dns.begin,
                                         state=state_path())
            return self._rt.keeper

    # -- what was read, kept ------------------------------------------------------------------------------------------------
    def _kept(self, part: str):
        with self._rt.lock:
            read = self._rt.read
            return None if read is None else read.get(part)

    def _keep(self, part: str, value) -> None:
        with self._rt.lock:
            if self._rt.read is None:
                self._rt.read = {"at": None}
            self._rt.read[part] = value

    def _keep_records(self, domain_id: int, records: list[dict]) -> None:
        with self._rt.lock:
            if self._rt.read is None:
                self._rt.read = {"at": None}
            self._rt.read.setdefault("records", {})[int(domain_id)] = records

    def _keep_rules(self, firewall_id: int, rules: Mapping) -> None:
        if not isinstance(rules, Mapping) or not any(k in rules for k in ("inbound", "outbound")):
            return
        with self._rt.lock:
            found = (self._rt.read or {}).get("firewalls")
            if isinstance(found, list):
                self._rt.read["firewalls"] = [{**f, "rules": dict(rules)} if int(f.get("id") or 0) == int(firewall_id)
                                              else f for f in found]

    def _keep_linode(self, linode: Mapping) -> None:
        with self._rt.lock:
            found = (self._rt.read or {}).get("linodes")
            if isinstance(found, list) and linode.get("id") is not None:
                self._rt.read["linodes"] = [dict(linode) if l.get("id") == linode.get("id") else l for l in found]

    def _list(self, part: str, read: Callable[[], list]) -> list[dict]:
        """A part as kept, else read now (and kept)."""
        kept = self._kept(part)
        if isinstance(kept, list):
            return kept
        found = read()
        self._keep(part, found)
        return found

    def _masters(self) -> list[dict] | None:
        """DNS Manager's master domains as last read (None: not read)."""
        found = self._kept("domains")
        return [d for d in found if str(d.get("type") or "master") == "master"] if isinstance(found, list) else None

    def _domain_id(self, zone: str) -> int | None:
        for d in self._masters() or []:
            if str(d.get("domain") or "").lower().rstrip(".") == zone.lower().rstrip("."):
                return int(d["id"])
        return None

    # -- the hooks: reads ----------------------------------------------------------------------------------------------------
    def present(self) -> bool:
        """Whether anything of it is set."""
        return bool(self.config().present)

    def refresh(self) -> dict:
        """The account read again now: what the status shows until the next."""
        cfg = self.config(fresh=True)
        if not cfg.ready:
            raise ValueError("the API is not set up: " + NOT_SET)
        if not self._rt.refreshing.acquire(timeout=120):
            raise RuntimeError("a refresh is under way")
        try:
            return self._refresh(cfg)
        finally:
            self._rt.refreshing.release()

    @staticmethod
    def _try(read: Callable, area: str = ""):
        try:
            return read()
        except RestError as e:
            return Trouble(str(e), e.status == 403, area)
        except ValueError as e:
            return Trouble(str(e), False, area)

    def _types(self, api: LinodeApi, now: float):
        """The plans by id: kept a day, read again after it (the kept ones still used when that fails)."""
        with self._rt.lock:
            kept = self._rt.types
        if kept is not None and now - kept[0] < TYPES_S:
            return kept[1]
        found = self._try(api.types, "Linode types")
        if isinstance(found, Trouble):
            return kept[1] if kept is not None else found
        by_id = {str(t.get("id")): t for t in found if t.get("id")}
        with self._rt.lock:
            self._rt.types = (now, by_id)
        return by_id

    def _refresh(self, cfg: Config, stop: threading.Event | None = None) -> dict:
        now = self._clock()
        if stop is not None and stop.is_set():
            return {"detached": True}
        try:
            api = self.client()
            profile = api.profile()  # first: a token refused stops the read here
        except (RestError, ValueError) as e:
            if stop is not None and stop.is_set():
                return {"detached": True}  # detached meanwhile (its settings gone with its login): nothing of it kept
            with self._rt.lock:
                self._rt.api_ok, self._rt.api_error, self._rt.api_error_at, self._rt.api_print = False, str(e), now, cfg.api_print
            raise

        def get(read_part, area: str):  # one part; none once detached (the read ends there, nothing of it kept)
            if stop is not None and stop.is_set():
                raise _Detached()
            return self._try(read_part, area)
        try:
            read: dict = {"at": now, "profile": profile}
            read["account"] = get(api.account, "the account")
            read["transfer"] = get(api.transfer, "the transfer pool")
            read["linodes"] = get(api.linodes, "Linodes")
            read["types"] = self._types(api, now)
            read["domains"] = get(api.domains, "Domains")
            records: dict[int, object] = {}
            if isinstance(read["domains"], list):
                masters = [d for d in read["domains"] if str(d.get("type") or "master") == "master" and d.get("id")]
                for d in masters[:DOMAINS_MAX]:
                    records[int(d["id"])] = get(lambda d=d: api.records(d["id"]), "Domains")
                for d in masters[DOMAINS_MAX:]:
                    records[int(d["id"])] = Trouble(f"not read with the rest (more than {DOMAINS_MAX} domains): "
                                                    f"python -m plugin_platform_linode records {d.get('domain')}")
            read["records"] = records
            read["firewalls"] = get(api.firewalls, "Firewalls")
            read["volumes"] = get(api.volumes, "Volumes")
            read["keys"] = get(api.ssh_keys, "SSH keys")
            read["reserved"] = get(api.reserved_ips, "IPs")
            read["counts"] = {k: get(lambda k=k: api.count(k), words) for k, words, *_ in COUNTED}
        except _Detached:
            return {"detached": True}
        with self._rt.lock:
            self._rt.read, self._rt.refreshed_at = read, now
            self._rt.api_ok, self._rt.api_error, self._rt.api_error_at, self._rt.api_print = True, "", None, cfg.api_print
        if isinstance(read["domains"], list) and not (stop is not None and stop.is_set()):
            self._settle(cfg)
        linodes = read["linodes"] if isinstance(read["linodes"], list) else []
        domains = read["domains"] if isinstance(read["domains"], list) else []
        return {"linodes": len(linodes), "domains": len(domains),
                "firewalls": len(read["firewalls"]) if isinstance(read["firewalls"], list) else 0,
                "refreshedAt": when(now), "notRead": [t.area or t.words for t in self._troubles(read)]}

    def linodes(self) -> list[dict]:
        """The account's Linodes, read now."""
        found = self.client().linodes()
        self._keep("linodes", found)
        return found

    def domains(self) -> list[dict]:
        """DNS Manager's domains, read now."""
        found = self.client().domains()
        self._keep("domains", found)
        return found

    def records(self, domain) -> list[dict]:
        """A domain's records (by its name or its id), read now."""
        d = self._domain(domain)
        found = self.client().records(d["id"])
        self._keep_records(int(d["id"]), found)
        return found

    def firewalls(self) -> list[dict]:
        """The Cloud Firewalls with their rules, read now."""
        found = self.client().firewalls()
        self._keep("firewalls", found)
        return found

    def ssh_keys(self) -> list[dict]:
        """The profile's SSH keys, read now."""
        found = self.client().ssh_keys()
        self._keep("keys", found)
        return found

    def _domain(self, domain, write: bool = False) -> dict:
        """A domain of DNS Manager by its name or its id (the kept list, else read now); a write's must be a master."""
        want = str(domain or "").strip().lower().rstrip(".")
        if not want:
            raise ValueError("name a domain")
        found = self._list("domains", self.client().domains)
        d = next((x for x in found if str(x.get("id")) == want or str(x.get("domain") or "").lower() == want), None)
        if d is None and self._kept("domains") is not None:
            found = self.domains()  # read again: one added since
            d = next((x for x in found if str(x.get("id")) == want or str(x.get("domain") or "").lower() == want), None)
        if d is None:
            raise ValueError(f"{domain} is not a domain of this account's DNS Manager")
        if write and str(d.get("type") or "master") != "master":
            raise Refusal(f"{d.get('domain')} is a slave domain: its records come from its master name servers "
                          f"({', '.join(d.get('master_ips') or []) or 'elsewhere'}), so nothing is written here")
        return d

    def _linode(self, linode) -> dict:
        want = str(linode or "").strip()
        if not want:
            raise ValueError("name a Linode (its label or its id)")
        found = self._list("linodes", self.client().linodes)
        match = [x for x in found if str(x.get("id")) == want or str(x.get("label") or "").lower() == want.lower()]
        if not match and self._kept("linodes") is not None:
            found = self.linodes()
            match = [x for x in found if str(x.get("id")) == want or str(x.get("label") or "").lower() == want.lower()]
        if not match:
            raise ValueError(f"{linode} is not a Linode of this account")
        return match[0]

    def _firewall(self, firewall) -> dict:
        want = str(firewall or "").strip()
        if not want:
            raise ValueError("name a Cloud Firewall (its label or its id)")
        found = self._list("firewalls", self.client().firewalls)
        match = [x for x in found if str(x.get("id")) == want or str(x.get("label") or "").lower() == want.lower()]
        if not match and self._kept("firewalls") is not None:
            found = self.firewalls()
            match = [x for x in found if str(x.get("id")) == want or str(x.get("label") or "").lower() == want.lower()]
        if not match:
            raise ValueError(f"{firewall} is not a Cloud Firewall of this account")
        return match[0]

    # -- the hooks: the free changes ------------------------------------------------------------------------------------------
    def power(self, linode, action) -> dict:
        """A Linode booted, shut down or rebooted (`action`: boot | shutdown | reboot; on | off too), its state read just
        before and after; refused, nothing sent, when it is so already or busy."""
        act = ACTIONS_OF.get(str(action or "").strip().lower().replace(" ", "-"))
        if act is None:
            raise ValueError(f"{action!r} is no power change: boot (on), shutdown (off) or reboot")
        api = self.client()
        lid = int(self._linode(linode)["id"])
        now = api.linode(lid)
        label, state = now.get("label") or str(lid), str(now.get("status") or "")
        if act == "boot" and state in (RUNNING, "booting", "rebooting"):
            raise Refusal(f"{label} is {state.replace('_', ' ')} already: nothing sent")
        if act == "shutdown" and state in (*OFF, "shutting_down"):
            raise Refusal(f"{label} is {state.replace('_', ' ')} already: nothing sent")
        if act == "reboot" and state != RUNNING:
            raise Refusal(f"{label} is {state.replace('_', ' ') or 'not running'}: a reboot is for a running Linode"
                          + (" (boot it instead)" if state in OFF else ""))
        if act != "reboot" and state not in (RUNNING, *OFF):
            raise Refusal(f"{label} is {state.replace('_', ' ') or 'in no state said'}: Linode takes no power change until "
                          "that is done")
        getattr(api, act)(lid)
        after = self._try(lambda: api.linode(lid))
        title, doing, _, _ = POWER_WORDS[act]
        lines = []
        if isinstance(after, Mapping):
            self._keep_linode(after)
            lines.append(f"Linode says it is {str(after.get('status') or '–').replace('_', ' ')} now")
        else:
            lines.append(f"its state could not be read after it: {after}")
        if act == "shutdown":
            lines.append(BILLS_OFF)
        return {"said": f"{title} asked of {label}: {doing}", "lines": lines, "ok": True, "changed": True,
                "linode": label, "status": after.get("status") if isinstance(after, Mapping) else None}

    def set_record(self, domain, name, rtype, target, ttl=None, priority=None, tag=None) -> dict:
        """A record set in `domain` (records.plan_set): the host's record of its type changed, or one made; every other
        record kept; checked after."""
        api = self.client()
        d = self._domain(domain, write=True)
        before = api.records(d["id"])
        change = rec.plan_set(d["domain"], before, name, rtype, target, ttl=ttl, priority=priority, tag=tag)
        if change.nothing:
            self._keep_records(int(d["id"]), before)
            return {"said": change.words, "lines": [], "ok": True, "changed": False, "domain": d["domain"]}
        if change.method == "POST":
            written = api.create_record(d["id"], change.body)
        else:
            written = api.update_record(d["id"], change.record_id, change.body)
        return self._checked(api, d, before, change, written)

    def remove_record(self, domain, record, name=None, rtype=None, target=None) -> dict:
        """A record removed by its id (records.plan_remove: refused when it is gone or holds what was not shown: its host,
        type and target as shown, each needed), the rest kept; checked after."""
        if name is None or rtype is None or target is None:
            raise ValueError("name the record as it was shown (its host, its type and its target), so a record that changed "
                             "is never removed unseen")
        api = self.client()
        d = self._domain(domain, write=True)
        before = api.records(d["id"])
        change = rec.plan_remove(d["domain"], before, record, name=name, rtype=rtype, target=target)
        api.delete_record(d["id"], change.record_id)
        return self._checked(api, d, before, change, None)

    def _checked(self, api: LinodeApi, d: Mapping, before: list[dict], change: rec.Change, written) -> dict:
        """A record's change read back and checked: its report (`said`, `lines`, `ok`)."""
        base = {"said": change.words, "changed": True, "domain": d["domain"],
                "record": written if isinstance(written, Mapping) and written else None}
        try:
            after = api.records(d["id"])
        except RestError as e:
            return {**base, "ok": False, "lines": [f"written, but the records could not be read back to check it: {e}"]}
        self._keep_records(int(d["id"]), after)
        rep = rec.verify(before, after, change, written if isinstance(written, Mapping) else None)
        lines = []
        if rep["ok"]:
            lines.append(f"read back: {'the record gone' if change.method == 'DELETE' else 'the record as written'}; "
                         f"the other {plural(rep['kept'], 'record')} of {d['domain']} kept")
        lines += rep["problems"]
        lines += [f"missing after the change: {x}" for x in rep["lost"]]
        lines += [f"changed since it was read: {x}" for x in rep["changed"]]
        lines += [f"made meanwhile (kept): {x}" for x in rep["unexpected"]]
        rid = change.record_id if change.record_id is not None else int((written or {}).get("id") or 0)
        touched = next((r for r in [*after, *before] if int(r.get("id") or 0) == rid), None)
        if touched is not None and str(touched.get("type") or "").upper() == "A":
            fqdn = (f"{touched.get('name')}.{d['domain']}" if touched.get("name") else str(d["domain"])).lower()
            if fqdn in self._ddns_hosts_of(d["domain"]):
                lines.append(f"{fqdn} is a Dynamic DNS host ({DDNS_HOSTS}): its next check keeps it at this network's "
                             "address")
        return {**base, "ok": rep["ok"], "lines": lines}

    def _ddns_hosts_of(self, domain: str) -> set[str]:
        cfg = self.config()
        if not cfg.ddns_ready:
            return set()
        hosts, _ = hosts_of(cfg.hosts, [domain])
        return {h.fqdn.lower() for h in hosts}

    def firewall_rules(self, firewall) -> dict:
        """A firewall's rules, read now (with their fingerprint and version): what the command line shows before a change."""
        f = self._firewall(firewall)
        rules = self.client().rules(f["id"])
        self._keep_rules(int(f["id"]), rules)
        return rules

    def add_rule(self, firewall, seen, direction, action, protocol, ports=None, addresses=None, label=None,
                 description=None, accept_risk=False) -> dict:
        """A rule added to a Cloud Firewall after its direction's others (firewall.plan_add), every other rule and the
        policies written back as read; `seen`: the rules' fingerprint as shown (a change made since: refused)."""
        rule = fw.rule_of(action, protocol, ports, addresses, label, description)
        return self._rules_change(firewall, seen, lambda rules, f, name: fw.plan_add(rules, direction, rule, f, name),
                                  accept_risk)

    def remove_rule(self, firewall, seen, direction, position, rule=None, accept_risk=False) -> dict:
        """A Cloud Firewall's rule removed by its place in its direction (`rule`: it in words, as shown, needed), the rest
        written back as read (firewall.plan_remove)."""
        if rule in (None, ""):
            raise ValueError(f"name the rule as it was shown ({direction} rule {position} in words), so a rule that moved is "
                             "not removed unseen")
        return self._rules_change(firewall, seen,
                                  lambda rules, f, name: fw.plan_remove(rules, direction, position, f, name, rule),
                                  accept_risk)

    def _rules_change(self, firewall, seen, plan, accept_risk) -> dict:
        if seen in (None, ""):
            raise ValueError("the rules' fingerprint as they were shown (seen) is needed, so a change made meanwhile is "
                             "never written over unseen: read them first")
        api = self.client()
        f = self._firewall(firewall)
        name = str(f.get("label") or f.get("id"))
        before = api.rules(f["id"])
        self._keep_rules(int(f["id"]), before)
        if str(seen) != str(before.get("fingerprint")):
            raise Refusal(f"the rules of {name} changed since they were read (they are version {before.get('version')} "
                          f"now, fingerprint {before.get('fingerprint')}): look at them again before changing them; "
                          "nothing was sent")
        new, said, risk = plan(before, f, name)
        if risk and accept_risk is not True:  # the page's second confirmation sends true; nothing else counts
            raise Refusal(f"{risk}. Nothing was sent: a change like this is made only once it is accepted as well "
                          f"({fw.ACCEPT_RISK}: the platform's page asks a second time)", accept=fw.ACCEPT_RISK)
        body = fw.body_of(new)
        answer = api.put_rules(f["id"], body)
        self._keep_rules(int(f["id"]), answer)
        v0, v1 = before.get("version"), answer.get("version") if isinstance(answer, Mapping) else None
        lines, ok = [], True
        if isinstance(answer, Mapping) and any(k in answer for k in ("inbound", "outbound")) and not fw.same(answer, body):
            ok = False
            lines.append("the rules Linode answered differ from what was written: look at them in Cloud Manager")
        if isinstance(v0, int) and isinstance(v1, int) and v1 > v0 + 1:
            ok = False
            lines.append(f"the rules went from version {v0} to {v1}: another change was written between this plugin's "
                         "read and its write, and may be lost. The rules as they were before this change:")
            lines += [f"  {d} {i}: {fw.words(r)}" for d in fw.DIRECTIONS for i, r in enumerate(before.get(d) or [], 1)]
        elif isinstance(v0, int) and isinstance(v1, int):
            lines.append(f"written: version {v0} to {v1} (fingerprint {answer.get('fingerprint')}); every other rule and "
                         "both policies as they were read")
        else:
            lines.append("written: every other rule and both policies as they were read")
        if risk:
            lines.append(f"accepted: {risk}")
        return {"said": said, "lines": lines, "ok": ok, "changed": True, "firewall": name,
                "version": v1, "fingerprint": answer.get("fingerprint") if isinstance(answer, Mapping) else None}

    def add_ssh_key(self, label, ssh_key) -> dict:
        """A public SSH key added to the profile (refused for a private key, one that is no key, or one there already)."""
        line, kind, print_ = ssh_key_of(ssh_key)
        name = " ".join(str(label or "").split())
        if len(name) > 64:
            raise ValueError("an SSH key's label is at most 64 characters")
        api = self.client()
        there = api.ssh_keys()
        same = next((k for k in there if fingerprint_of(k.get("ssh_key")) == print_), None)
        if same is not None:
            self._keep("keys", there)
            raise Refusal(f"this key ({print_}) is in your profile already, as {same.get('label') or 'a key without a label'}")
        made = api.add_ssh_key(name, line)
        self._keep("keys", [*there, made] if isinstance(made, Mapping) and made else there)
        return {"said": f"added the {kind} key {name or '(no label)'} ({print_}) to your profile",
                "lines": ["the profile's keys are for the Linodes you deploy (Linode's reference: a key lets you in as "
                          "their root user); no Linode running now is changed"], "ok": True, "changed": True, "key": made.get("id") if isinstance(made, Mapping) else None}

    def remove_ssh_key(self, key, label=None) -> dict:
        """An SSH key removed from the profile by its id (refused when it is gone or holds another label now than the one
        shown, which is needed: "" for a key without one)."""
        if label is None:
            raise ValueError("name the key as it was shown (its label; \"\" for a key without one), so another key is "
                             "never removed unseen")
        try:
            kid = int(str(key).strip())
        except (TypeError, ValueError):
            raise ValueError(f"{key!r} is not an SSH key's id") from None
        api = self.client()
        there = api.ssh_keys()
        k = next((x for x in there if int(x.get("id") or 0) == kid), None)
        if k is None:
            self._keep("keys", there)
            raise Refusal(f"your profile holds no SSH key {kid} any more: nothing removed")
        if " ".join(str(label).split()) != " ".join(str(k.get("label") or "").split()):
            raise Refusal(f"SSH key {kid} is labelled {k.get('label')!r} now, not {label!r}: nothing removed (read it again)")
        api.delete_ssh_key(kid)
        self._keep("keys", [x for x in there if int(x.get("id") or 0) != kid])
        return {"said": f"removed the SSH key {k.get('label') or kid} from your profile",
                "lines": ["Linodes made with it keep it in their authorized_keys: Linode removes only its place in your "
                          "profile (take it off them by hand)"], "ok": True, "changed": True}

    def ddns_update(self, force: bool = True) -> list[dict]:
        """A Dynamic DNS pass now (the page's Update DNS now, once confirmed: `force`, every host of the keeper's own set
        whether it differs or not; the command line's `ddns` without --now sets only those that differ). A host holding
        another address is left as it is either way (Take over… on the page)."""
        cfg = self.config(fresh=True)
        if not cfg.ddns_ready:
            raise ValueError(f"Dynamic DNS is not set up: {DDNS_HOSTS} and {TOKEN}")
        return self._ddns_pass(cfg, bool(force))

    def ddns_take_over(self, host, holds=None, accept_take_over=False) -> list[dict]:
        """A host of LINODE_DDNS_HOSTS that holds another address taken over (the page's Take over…, confirmed twice:
        liminal-libs 1.49.7's take_over, refused with TakeOverRefused unless `accept_take_over` is exactly true, which the
        page asks as its second confirmation), then a pass for that host, which points its A record at this network's
        address. `holds`: what the page showed it holding; holding something else now, it is refused and nothing is
        taken over."""
        cfg = self.config(fresh=True)
        if not cfg.ddns_ready:
            raise ValueError(f"Dynamic DNS is not set up: {DDNS_HOSTS} and {TOKEN}")
        if self._masters() is None:
            self.domains()
        hosts, _ = hosts_of(cfg.hosts, [d.get("domain") for d in self._masters() or []])
        want = typed_host(host)
        h = next((x for x in hosts if x.fqdn == want), None)
        if h is None:
            raise ValueError(f"{host} is not one of {DDNS_HOSTS} in a master domain of this account's DNS Manager")
        k = self.keeper()
        self._rt.dns.begin()
        now = self._rt.dns.read(h)  # what it holds, read afresh: said by the second confirmation's refusal
        if holds is not None:
            shown = [a.strip() for a in str(holds).split(",") if a.strip()]
            if sorted(now) != sorted(shown):
                raise Refusal(f"{h.fqdn} holds {', '.join(now) or 'no A record'} now, not {holds or 'nothing'}: look at it "
                              "again; nothing is taken over")
        k.take_over(h.fqdn, accept=accept_take_over, holds=", ".join(now))  # TakeOverRefused unless exactly true
        return self._ddns_pass(cfg, force=False, only={h.fqdn})

    def _ddns_pass(self, cfg: Config, force: bool, wait: float = 120.0, stop: threading.Event | None = None,
                   only: set[str] | None = None) -> list[dict]:
        """A pass of the keeper over the hosts set (`only`: these), ended before its next write once detached (`stop`,
        the worker's; else the plugin's own detach)."""
        stop = stop if stop is not None else self._rt.detached
        if stop.is_set():
            return []  # detached: nothing asked, nothing written
        if self._masters() is None:
            self.domains()  # the zones it may keep hosts in: read once
        hosts, _ = hosts_of(cfg.hosts, [d.get("domain") for d in self._masters() or []])
        k = self.keeper()
        self._settle(cfg)
        if only is not None:
            hosts = [h for h in hosts if h.fqdn in only]
        out = k.run_pass(hosts, force=force, wait=wait, stop=stop)
        with self._rt.lock:
            self._rt.ddns_print, self._rt.ddns_at = cfg.ddns_print, self._clock()
        return out

    def _settle(self, cfg: Config) -> None:
        """The keeper's hosts that are not in the whole Dynamic DNS setting let go (liminal-libs 1.49.7's settle), so one
        taken out of it, while the plugin ran or not, comes back as not its own: asked about again. Only once the
        account's domains are read (never on a list the unread zones would cut short), with the setting whole, even empty
        (every host taken out)."""
        if self._masters() is None:
            return
        self.keeper().settle([typed_host(x) for x in cfg.hosts.replace(";", ",").replace(" ", ",").split(",") if x.strip()])

    # -- attached: the reading in the background ----------------------------------------------------------------------------
    def attach(self, app, login=None) -> dict:
        """Attached: its settings asked of the app's login from now on. Attached by the platform, and once the token is
        set, the account read and the Dynamic DNS hosts checked in the background (an audit, 2026-11-11: the charts app run
        alone attaches every plugin it finds, which must not start this)."""
        interface = super().attach(app, login)
        with self._rt.lock:
            self._rt.config = None
            self._rt.detached.clear()
        if self._on_platform():
            self._start_if_set()
        return interface

    def detach(self) -> None:
        """Detached (the platform ending, the plugin disabled or not valid): the background reading ends, and a pass
        under way writes nothing more."""
        self._rt.detached.set()
        self._stop()
        super().detach()
        with self._rt.lock:
            self._rt.config = None

    def _on_platform(self) -> bool:
        return getattr(self.app, "NAME", "") == "platform" and not getattr(self.app, "once", False)  # never a one-shot command's

    def _start_if_set(self) -> None:
        if self.config().ready:
            self._start()

    @property
    def working(self) -> bool:
        with self._rt.lock:
            t = self._rt.worker
        return t is not None and t.is_alive()

    def _start(self) -> None:
        with self._rt.lock:
            if self._rt.worker is not None and self._rt.worker.is_alive():
                return
            stop = threading.Event()
            t = threading.Thread(target=self._work, args=(stop,), name="linode", daemon=True)
            self._rt.worker, self._rt.stop = t, stop
            self._rt.wake.clear()
        t.start()

    def _stop(self) -> None:
        with self._rt.lock:
            t, stop = self._rt.worker, self._rt.stop
            self._rt.worker = self._rt.stop = None
        if stop is not None:
            stop.set()
            self._rt.wake.set()
        if t is not None and t is not threading.current_thread():
            t.join(timeout=10)

    def _work(self, stop: threading.Event) -> None:
        """The background: the account read every REFRESH_S, the Dynamic DNS hosts checked every LINODE_DDNS_MINUTES;
        it ends when the token is no longer set (entering it starts it again: settings_changed) or once detached (`stop`:
        a pass under way writes nothing more)."""
        next_api = next_ddns = 0.0
        while not stop.is_set():
            now = time.monotonic()
            cfg = None
            try:
                cfg = self.config()
                if not cfg.ready or stop.is_set():
                    break
                if now >= next_api:
                    next_api = now + REFRESH_S
                    if self._rt.refreshing.acquire(blocking=False):  # Refresh asked meanwhile: that one is enough
                        try:
                            self._refresh(cfg, stop)
                        except Exception:  # noqa: BLE001 - kept as its outcome (api_error), shown by the status
                            pass
                        finally:
                            self._rt.refreshing.release()
                if cfg.ddns_ready and now >= next_ddns and not stop.is_set():
                    next_ddns = now + cfg.minutes * 60.0
                    try:
                        self._ddns_pass(cfg, force=False, wait=0.5, stop=stop)
                    except Exception:  # noqa: BLE001 - a pass under way (Update DNS now), or its trouble kept by the hosts
                        pass
            except Exception:  # noqa: BLE001 - the background never ends on a trouble; the status says it
                pass
            due = [t for t, on in ((next_api, cfg is not None and cfg.ready), (next_ddns, cfg is not None and cfg.ddns_ready))
                   if on]
            wait = min([60.0, *(t - time.monotonic() for t in due)])
            self._rt.wake.wait(max(1.0, wait))
            self._rt.wake.clear()

    # -- what it learned of its API ---------------------------------------------------------------------------------------------
    def api_facts(self) -> dict[str, dict[str, str]]:
        """What it learned of Linode's API while it ran, asking nothing: the requests made, the last answer, the rate
        limit's headers as last given, when the account and the plans were read, the areas the token may not read."""
        with self._rt.lock:
            held, at, types, read = self._rt.api, self._rt.refreshed_at, self._rt.types, self._rt.read
        facts = held[1].facts() if held is not None else {"Requests": "none yet"}
        facts["Account read"] = when(at) if at else "not yet"
        if types is not None:
            facts["Plans and prices read"] = when(types[0])
        denied = [t.area for t in self._troubles(read or {}) if t.denied]
        if denied:
            facts["Not allowed by the token"] = ", ".join(dict.fromkeys(denied))
        return {LINODE_API.name: facts}

    @staticmethod
    def _troubles(read: Mapping) -> list[Trouble]:
        out = [v for k, v in read.items() if isinstance(v, Trouble)]
        out += [v for v in (read.get("records") or {}).values() if isinstance(v, Trouble)]
        out += [v for v in (read.get("counts") or {}).values() if isinstance(v, Trouble)]
        return out

    # -- what the platform's page shows ------------------------------------------------------------------------------------------
    def status(self) -> dict:
        """What was read last, asking nothing of Linode: the settings set (by name), the summary, valid (the token set
        and the last read worked or is untried) and why not, the facts, the tables, the actions and the forms."""
        cfg = self.config()
        if not cfg.present:
            return {"present": False, "valid": False, "why": NOT_SET, "summary": "not set up",
                    "settingsNotSet": ", ".join(NAMES), "tables": [], "actions": [], "forms": []}
        set_names = ", ".join(n for n in NAMES if n in cfg.present)
        missing = ", ".join(n for n in NAMES if n not in cfg.present)
        if not cfg.ready:
            why = cfg.token_problem or f"{TOKEN} is not set: " + NOT_SET
            return {"present": True, "valid": False, "why": why, "summary": "no token usable" if cfg.token_problem else "no token set",
                    "settingsSet": set_names, "settingsNotSet": missing, "tables": [], "actions": [], "forms": []}
        rt, now, attached = self._rt, self._clock(), self.app is not None
        with rt.lock:
            read = dict(rt.read or {})
            refreshed_at, api_ok, api_error, api_error_at = rt.refreshed_at, rt.api_ok, rt.api_error, rt.api_error_at
            api_print, keeper = rt.api_print, rt.keeper
        works = api_ok if api_print == cfg.api_print else None
        if works is False and not attached and api_error_at is not None and now - api_error_at >= RETRY_S:
            works = None  # tried again once the platform attaches it
        masters = [d for d in read.get("domains") or [] if str(d.get("type") or "master") == "master"] \
            if isinstance(read.get("domains"), list) else None
        hosts, wrong = hosts_of(cfg.hosts, [d.get("domain") for d in masters]) if masters is not None else ([], [])
        states = {s.fqdn: s for s in (keeper.states() if keeper is not None else [])}
        notes = [*cfg.problems, *([w + f" ({DDNS_HOSTS})" for w in wrong] if cfg.ddns_ready else [])]
        if works is not False:
            notes += self._notes(read, hosts, states)
        out: dict = {"present": True, "valid": works is not False,
                     "summary": self._summary(cfg, works, api_error, read, hosts, states, attached)}
        if works is False:
            out["why"] = f"the API: {api_error}" + ("" if "API Tokens" in api_error else
                                                    f" (a token: Cloud Manager, your username > API Tokens; {SCOPE_WORDS})")
        elif notes:
            out["problem"] = "; ".join(notes)
        out.update(self._facts(read, refreshed_at))
        out["tokenNeeds"] = ACCESS_SHORT  # the access a token for this plugin needs (the README names the scopes)
        out["settingsSet"] = set_names
        if missing:
            out["settingsNotSet"] = missing
        if cfg.ddns_ready:
            out["ddnsEvery"] = f"every {cfg.minutes:g} min" + ("" if attached else ", once attached")
        out["tables"] = self._tables(cfg, read, masters, hosts, keeper, attached)
        out["forms"] = self._forms(read) if works is not False else []
        if cfg.ddns_ready and works is not False:  # Take over… and Update DNS now, each confirmed (liminal-libs 1.49.2)
            k = keeper if keeper is not None else self.keeper()
            out["forms"] += [k.take_form(), k.now_form()]
        out["actions"] = [{"hook": "refresh", "args": [], "title": "Refresh",
                           "note": "the account read again now (about 20 requests)"}] + \
                         ([{"form": "ddns-now", "title": "Update DNS now",
                            "note": "the Dynamic DNS hosts of its own set now to this network's address, once confirmed"}]
                          if cfg.ddns_ready else [])
        return out

    def _notes(self, read: Mapping, hosts, states) -> list[str]:
        notes = []
        denied = [t.area for t in self._troubles(read) if t.denied]
        if denied:
            notes.append(f"the token's access does not cover {', '.join(dict.fromkeys(denied))} (Read Only is enough to "
                         "show them)")
        other = [t for t in self._troubles(read) if not t.denied and "not read with the rest" not in t.words]
        notes += [f"{t.area or 'a part'}: {t.words}" for t in other[:3]]
        linodes = read.get("linodes")
        if isinstance(read.get("domains"), list) and read["domains"] and isinstance(linodes, list) and not any(
                str(x.get("status")) == RUNNING for x in linodes):
            notes.append("DNS Manager serves a domain's records only while the account has an active Linode (its guide): "
                         "none is running now")
        notes += [f"{s.fqdn}: {s.result}" for h in hosts for s in [states.get(h.fqdn)] if s is not None and s.ok is False]
        return notes

    def _summary(self, cfg, works, api_error, read, hosts, states, attached) -> str:
        bits = []
        if works is True and read:
            linodes = read.get("linodes")
            if isinstance(linodes, list):
                up = sum(1 for x in linodes if str(x.get("status")) == RUNNING)
                bits.append(plural(len(linodes), "Linode") + (f" ({up} running)" if linodes else ""))
                monthly = self._monthly(linodes, read.get("types"))
                if monthly:
                    bits.append(f"{money(monthly)} a month")
            if isinstance(read.get("domains"), list):
                bits.append(plural(len(read["domains"]), "domain"))
            account = read.get("account")
            if isinstance(account, Mapping) and account.get("balance") is not None:
                bits.append(f"balance {money(account.get('balance'))}")
        elif works is None:
            bits.append("reading the account…" if attached else "the account is read once attached")
        else:
            short = " ".join(str(api_error or "failed").split())
            bits.append(f"the API: {short if len(short) <= 100 else short[:99] + '…'}")
        if cfg.ddns_ready:
            mine = [states[h.fqdn] for h in hosts if h.fqdn in states]
            if len(hosts) == 1 and mine and mine[0].ok:
                bits.append(f"{mine[0].fqdn} at {mine[0].address}")
            elif any(s.ok is not None for s in mine):
                bits.append(f"Dynamic DNS: {sum(1 for s in mine if s.ok)} of {plural(len(hosts), 'host')} current")
            else:
                bits.append("Dynamic DNS: the first check is under way" if attached else "Dynamic DNS: checked once attached")
        return " · ".join(bits) or "set up"

    @staticmethod
    def _price(linode: Mapping, types) -> tuple[float | None, float | None, float]:
        """A Linode's price (a month, an hour; its region's where its plan has one) and its backups' a month (0: none)."""
        t = (types or {}).get(str(linode.get("type"))) if isinstance(types, Mapping) else None
        if not t:
            return None, None, 0.0
        region = str(linode.get("region") or "")
        p = next((x for x in t.get("region_prices") or [] if x.get("id") == region), None) or t.get("price") or {}
        backups = 0.0
        if (linode.get("backups") or {}).get("enabled"):
            b = ((t.get("addons") or {}).get("backups") or {})
            bp = next((x for x in b.get("region_prices") or [] if x.get("id") == region), None) or b.get("price") or {}
            try:
                backups = float(bp.get("monthly") or 0.0)
            except (TypeError, ValueError):
                backups = 0.0
        try:
            monthly = float(p["monthly"]) if p.get("monthly") is not None else None
        except (TypeError, ValueError):
            monthly = None
        try:
            hourly = float(p["hourly"]) if p.get("hourly") is not None else None
        except (TypeError, ValueError):
            hourly = None
        return monthly, hourly, backups

    def _monthly(self, linodes, types) -> float:
        total = 0.0
        for x in linodes or []:
            monthly, _, backups = self._price(x, types)
            total += (monthly or 0.0) + backups
        return total

    def _facts(self, read: Mapping, refreshed_at) -> dict:
        out: dict = {}
        profile = read.get("profile")
        if isinstance(profile, Mapping) and profile.get("username"):
            out["account"] = str(profile["username"]) + (" · restricted user" if profile.get("restricted") else "")
            if profile.get("two_factor_auth") is not None:
                out["twoFactor"] = "on" if profile.get("two_factor_auth") else "off"
        account = read.get("account")
        if isinstance(account, Mapping):
            if account.get("balance") is not None:
                out["balance"] = money(account.get("balance"))
            if account.get("balance_uninvoiced") is not None:
                out["thisMonth"] = f"{money(account.get('balance_uninvoiced'))} so far (not invoiced yet, transfer left out)"
            credit = 0.0
            for promo in account.get("active_promotions") or []:
                try:
                    credit += float(promo.get("credit_remaining") or 0)
                except (TypeError, ValueError):
                    continue
            if credit:
                out["credit"] = f"{money(credit)} of promotions left"
        transfer = read.get("transfer")
        if isinstance(transfer, Mapping) and number(transfer.get("quota")) is not None:
            used, billable = number(transfer.get("used")) or 0, number(transfer.get("billable")) or 0
            out["transfer"] = (f"{used:,g} of {number(transfer.get('quota')):,g} GB used this cycle"
                               + (f" · {billable:,g} GB billable" if billable else ""))
        linodes = read.get("linodes")
        if isinstance(linodes, list) and linodes:
            monthly = self._monthly(linodes, read.get("types"))
            if monthly:
                out["linodesMonthly"] = f"{money(monthly)} a month, powered-off Linodes too"
        if refreshed_at:
            out["readAt"] = when(refreshed_at)
        return out

    # -- the tables ----------------------------------------------------------------------------------------------------------
    def _tables(self, cfg, read, masters, hosts, keeper, attached) -> list[dict]:
        out = []
        if cfg.ddns_ready:
            if masters is None:
                out.append({"title": "Dynamic DNS", "note": "checked once the account's domains are read",
                            "columns": [{"title": "Host"}, {"title": "Result"}],
                            "rows": [[h.strip(), "not checked yet"] for h in cfg.hosts.replace(";", ",").replace(" ", ",").split(",") if h.strip()],
                            "empty": f"No host could be read in {DDNS_HOSTS}."})
            else:
                k = keeper if keeper is not None else self.keeper()
                table = k.table(hosts, cfg.minutes, attached, when=when, take=True,
                                empty=f"No host of {DDNS_HOSTS} is in a master domain of this account's DNS Manager.")
                table["note"] += (" · through Linode's DNS Manager (a new record: TTL 300; A records only, a host's AAAA "
                                  "records left as they are)")
                out.append(table)
        if not read:
            return out
        out.append(self._linodes_table(read))
        if isinstance(read.get("domains"), (list, Trouble)):
            out += self._domain_tables(read)
        out += self._firewall_tables(read)
        out.append(self._volumes_table(read))
        out.append(self._keys_table(read))
        out.append(self._reserved_table(read))
        out.append(self._counts_table(read))
        return out

    @staticmethod
    def _not_read(title: str, part, columns: list[dict]) -> dict:
        return {"title": title, "note": f"not read: {part}", "columns": columns, "rows": [], "empty": "Not read."}

    def _linodes_table(self, read) -> dict:
        columns = [{"title": "Linode"}, {"title": "State"}, {"title": "Region"}, {"title": "Plan"}, {"title": "IPv4"},
                   {"title": "IPv6"}, {"title": "A month", "num": True}, {"title": "An hour", "num": True},
                   {"title": "Created"}, {"title": ""}, {"title": ""}]
        linodes = read.get("linodes")
        if not isinstance(linodes, list):
            return self._not_read("Linodes", linodes, columns)
        types = read.get("types") if isinstance(read.get("types"), Mapping) else {}
        rows = []
        for x in sorted(linodes, key=lambda x: str(x.get("label") or "").lower()):
            lid, label, state = x.get("id"), str(x.get("label") or x.get("id")), str(x.get("status") or "")
            t = types.get(str(x.get("type"))) or {}
            specs = x.get("specs") or {}
            plan = cell(t.get("label") or str(x.get("type") or "–"),
                        " · ".join(b for b in (f"{specs.get('vcpus')} vCPU" if specs.get("vcpus") else "",
                                               f"{round(specs['memory'] / 1024, 1):g} GB" if specs.get("memory") else "",
                                               f"{round(specs['disk'] / 1024):g} GB disk" if specs.get("disk") else "") if b) or None)
            public = [str(a) for a in x.get("ipv4") or [] if is_public_v4(a)]
            ipv6 = str(x.get("ipv6") or "").split("/")[0] or "–"
            monthly, hourly, backups = self._price(x, types)
            month = cell(money(monthly) if monthly is not None else "–",
                         f"+ {money(backups)} backups" if backups else None)
            sub = " · ".join(b for b in (str(lid), "LKE node" if x.get("lke_cluster_id") else "",
                                         ", ".join(x.get("tags") or [])) if b)
            first, second = "", ""
            if state == RUNNING:
                first = self._power_button("shutdown", lid, label)
                second = self._power_button("reboot", lid, label)
            elif state in OFF:
                first = self._power_button("boot", lid, label)
            rows.append([cell(label, sub or None), cell(state.replace("_", " ") or "–", "still bills while off" if state in OFF else None),
                         str(x.get("region") or "–"), plan, ", ".join(public) or "–", ipv6, month,
                         money(hourly, hourly=True) if hourly is not None else "–", day(x.get("created")), first, second])
        return {"title": "Linodes", "note": ("prices per month and per hour as Linode's plans give them (the region's, "
                                             "backups added where on) · " + BILLS_OFF),
                "columns": columns, "rows": rows, "empty": "No Linode in this account."}

    @staticmethod
    def _power_button(action: str, lid, label: str) -> dict:
        title = POWER_WORDS[action][0]
        return {"form": f"power:{action}", "title": f"{title}…", "label": f"{title} {label}", "values": {"linode": lid}}

    def _domain_tables(self, read) -> list[dict]:
        columns = [{"title": "Domain"}, {"title": "Type"}, {"title": "Status"}, {"title": "Records", "num": True},
                   {"title": "TTL"}]
        domains = read.get("domains")
        if not isinstance(domains, list):
            return [self._not_read("Domains", domains, columns)]
        records = read.get("records") or {}
        rows = []
        for d in sorted(domains, key=lambda d: str(d.get("domain") or "")):
            held = records.get(int(d.get("id") or 0))
            kind = str(d.get("type") or "master")
            rows.append([cell(str(d.get("domain")), str(d.get("description") or "") or None),
                         cell(kind, f"from {', '.join(d.get('master_ips') or [])}" if kind == "slave" else None),
                         str(d.get("status") or "–"), str(len(held)) if isinstance(held, list) else "–",
                         rec.TTL_WORDS.get(int(d.get("ttl_sec") or 0), "default")])
        out = [{"title": "Domains", "note": "Linode's DNS Manager (free); records of master domains are set and removed "
                                            "here, a slave's come from its master",
                "columns": columns, "rows": rows, "empty": "No domain in DNS Manager."}]
        for d in sorted(domains, key=lambda d: str(d.get("domain") or "")):
            if str(d.get("type") or "master") != "master" or int(d.get("id") or 0) not in records:
                continue
            out.append(self._records_table(d, records[int(d["id"])]))
        return out

    def _records_table(self, d: Mapping, held) -> dict:
        name, did = str(d.get("domain")), int(d["id"])
        columns = [{"title": "Host"}, {"title": "Type"}, {"title": "Target"}, {"title": "TTL"},
                   {"title": "Priority", "num": True}]
        if not isinstance(held, list):
            return {"title": f"{name} records", "note": f"not read: {held}", "columns": columns, "rows": [], "empty": "Not read."}
        columns.append({"title": ""})
        rows = []
        for r in sorted(held, key=lambda r: (bool(r.get("name")), str(r.get("name") or "").lower(), str(r.get("type") or ""))):
            target = str(r.get("target") or "")
            short = target if len(target) <= 64 else target[:63] + "…"
            t = str(r.get("type") or "")
            ttl = int(r.get("ttl_sec") or 0)
            rows.append([rec.shown_name(r.get("name")), cell(t, str(r.get("tag")) if t == "CAA" and r.get("tag") else None),
                         short, rec.TTL_WORDS.get(ttl, f"{ttl} s" if ttl else "default"),
                         str(r.get("priority")) if t in ("MX", "SRV") and r.get("priority") is not None else "",
                         {"form": f"record-remove:{did}", "title": "Remove", "label": f"Remove {rec.shown_name(r.get('name'))} {t} {short}",
                          "values": {"record": r.get("id"), "name": rec.shown_name(r.get("name")), "rtype": t, "target": target}}])
        return {"title": f"{name} records",
                "note": ("set and removed here or from the command line (python -m plugin_platform_linode set | remove): one "
                         "record at a time, every other record kept, read back after each change"),
                "columns": columns, "rows": rows, "empty": "No records.",
                "actions": [{"form": f"record-set:{did}", "title": "Set a record…"}]}

    def _firewall_tables(self, read) -> list[dict]:
        columns = [{"title": "Firewall"}, {"title": "Status"}, {"title": "Rules"}, {"title": "Policies"},
                   {"title": "Version"}, {"title": "Attached to"}]
        found = read.get("firewalls")
        if not isinstance(found, list):
            return [self._not_read("Cloud Firewalls", found, columns)]
        rows, out = [], []
        for f in sorted(found, key=lambda f: str(f.get("label") or "").lower()):
            rules = f.get("rules") or {}
            attached = [f"{e.get('label') or e.get('id')} ({str(e.get('type') or '').replace('_', ' ')})"
                        for e in f.get("entities") or [] if isinstance(e, Mapping)]
            rows.append([cell(str(f.get("label") or f.get("id")), str(f.get("id"))), str(f.get("status") or "–"),
                         f"{len(rules.get('inbound') or [])} in · {len(rules.get('outbound') or [])} out",
                         f"in {rules.get('inbound_policy') or '–'} · out {rules.get('outbound_policy') or '–'}",
                         cell(f"version {rules.get('version')}" if rules.get("version") is not None else "–",
                              str(rules.get("fingerprint") or "") or None),
                         ", ".join(attached) or "nothing"])
        out.append({"title": "Cloud Firewalls", "note": "free; each rule set written back whole by a change, read fresh "
                                                        "first; a firewall guards the Linodes and NodeBalancers attached",
                    "columns": columns, "rows": rows, "empty": "No Cloud Firewall in this account."})
        for f in sorted(found, key=lambda f: str(f.get("label") or "").lower()):
            out.append(self._rules_table(f))
        return out

    def _rules_table(self, f: Mapping) -> dict:
        fid, label = int(f["id"]), str(f.get("label") or f.get("id"))
        rules = f.get("rules") or {}
        why = self._unwritable(f)
        columns = [{"title": "#", "num": True}, {"title": "Direction"}, {"title": "Action"}, {"title": "Protocol"},
                   {"title": "Ports"}, {"title": "Addresses"}, {"title": "Label"}, *([] if why else [{"title": ""}])]
        rows = []
        for d in fw.DIRECTIONS:
            for i, r in enumerate(rules.get(d) or [], 1):
                if not isinstance(r, Mapping):
                    continue
                nets = [*((r.get("addresses") or {}).get("ipv4") or []), *((r.get("addresses") or {}).get("ipv6") or [])]
                shown = ", ".join(nets[:4]) + (f" +{len(nets) - 4}" if len(nets) > 4 else "")
                row = [str(i), d, str(r.get("action") or ""), str(r.get("protocol") or ""),
                       str(r.get("ports") or ("every port" if str(r.get("protocol")) in fw.PORTED else "–")),
                       cell(shown or "–", "every address" if any(n in ("0.0.0.0/0", "::/0") for n in nets) else None),
                       cell(str(r.get("label") or ""), str(r.get("description") or "") or None)]
                if not why:
                    row.append({"form": f"rule-remove:{fid}", "title": "Remove", "label": f"Remove {d} rule {i} of {label}",
                                "values": {"direction": d, "position": i, "rule": fw.words(r)}})
                rows.append(row)
        attached = fw.attached_linodes(f)
        note = (f"version {rules.get('version', '–')} · fingerprint {rules.get('fingerprint') or '–'} · inbound "
                f"{rules.get('inbound_policy') or '–'} and outbound {rules.get('outbound_policy') or '–'} unless a rule "
                "decides (the first that matches) · " + (f"guards {', '.join(attached)}" if attached else "guards no Linode")
                + (f" · not changed here: {why}" if why else ""))
        table = {"title": f"{label} rules", "note": note, "columns": columns, "rows": rows,
                 "empty": f"No rules: the policies decide (inbound {rules.get('inbound_policy') or '–'}, outbound "
                          f"{rules.get('outbound_policy') or '–'})."}
        if not why:
            table["actions"] = [{"form": f"rule-add:{fid}", "title": "Add a rule…"}]
        return table

    @staticmethod
    def _unwritable(f: Mapping) -> str | None:
        rules = f.get("rules")
        if not isinstance(rules, Mapping):
            return "its rules were not read"
        if str(f.get("status") or "") == "deleted":
            return "it is deleted"
        try:
            fw.check_writable(rules, str(f.get("label") or f.get("id")))
        except Refusal as e:
            return str(e)
        return None

    def _volumes_table(self, read) -> dict:
        columns = [{"title": "Volume"}, {"title": "Status"}, {"title": "Size", "num": True}, {"title": "Region"},
                   {"title": "Attached to"}, {"title": "Kind"}]
        found = read.get("volumes")
        if not isinstance(found, list):
            return self._not_read("Volumes", found, columns)
        rows = [[cell(str(v.get("label") or v.get("id")), str(v.get("id"))), str(v.get("status") or "–"),
                 f"{v.get('size')} GB" if v.get("size") is not None else "–", str(v.get("region") or "–"),
                 str(v.get("linode_label") or "") or ("–" if not v.get("linode_id") else str(v.get("linode_id"))),
                 " · ".join(b for b in (str(v.get("hardware_type") or ""),
                                        "encrypted" if v.get("encryption") == "enabled" else "") if b) or "–"]
                for v in sorted(found, key=lambda v: str(v.get("label") or "").lower())]
        return {"title": "Volumes", "note": "Block Storage bills per GB whether attached or not; none is made, resized or "
                                            "deleted here", "columns": columns, "rows": rows, "empty": "No volume."}

    def _keys_table(self, read) -> dict:
        columns = [{"title": "Label"}, {"title": "Key"}, {"title": "Added"}]
        found = read.get("keys")
        if not isinstance(found, list):
            return self._not_read("SSH keys", found, columns)
        columns.append({"title": ""})
        rows = []
        for k in sorted(found, key=lambda k: str(k.get("label") or "").lower()):
            text = str(k.get("ssh_key") or "")
            parts = text.split()
            print_ = fingerprint_of(text)
            rows.append([str(k.get("label") or "–"), cell(parts[0] if parts else "–", print_ or None), day(k.get("created")),
                         {"form": "sshkey-remove", "title": "Remove", "label": f"Remove the SSH key {k.get('label') or k.get('id')}",
                          "values": {"key": k.get("id"), "label": str(k.get("label") or "")}}])
        return {"title": "SSH keys", "note": ("your profile's public keys, for the Linodes you deploy (a key lets you in "
                                              "as their root user); added and removed here"),
                "columns": columns, "rows": rows, "empty": "No SSH key in your profile.",
                "actions": [{"form": "sshkey-add", "title": "Add an SSH key…"}]}

    def _reserved_table(self, read) -> dict:
        columns = [{"title": "Address"}, {"title": "Region"}, {"title": "Assigned to"}, {"title": "Reverse DNS"}]
        found = read.get("reserved")
        if not isinstance(found, list):
            return self._not_read("Reserved IPs", found, columns)
        rows = []
        for ip in found:
            to = ip.get("assigned_entity") or {}
            rows.append([str(ip.get("address") or "–"), str(ip.get("region") or "–"),
                         f"{to.get('label') or to.get('id')} ({to.get('type')})" if to else "nothing", str(ip.get("rdns") or "–")])
        return {"title": "Reserved IPs", "note": "a reserved IPv4 address bills monthly, assigned or not; none is reserved "
                                                 "here", "columns": columns, "rows": rows, "empty": "No reserved IP."}

    def _counts_table(self, read) -> dict:
        counts = read.get("counts") or {}
        rows = []
        for k, words, *_ in COUNTED:
            got = counts.get(k)
            rows.append([words, str(got) if isinstance(got, int) else "–",
                         ("not allowed by the token" if got.denied else str(got)[:120]) if isinstance(got, Trouble) else ""])
        return {"title": "The rest of the account", "note": "counted: one small read each, nothing changed here",
                "columns": [{"title": "Kind"}, {"title": "Count", "num": True}, {"title": ""}], "rows": rows,
                "empty": "Not counted."}

    # -- the forms -------------------------------------------------------------------------------------------------------
    def _forms(self, read: Mapping) -> list[dict]:
        """The forms the platform's page draws (liminal-platform 0.6.0, status.forms); the fields are the hooks' arguments
        in order. Each change is asked once the user has confirmed it; a risky rule change once the user has accepted that
        too (accept_risk, asked by the page when the change is refused for it: a second, explicit confirmation)."""
        out: list[dict] = []
        linodes = read.get("linodes")
        if isinstance(linodes, list) and linodes:
            out += self._power_forms(linodes)
        domains, records = read.get("domains"), read.get("records") or {}
        if isinstance(domains, list):
            for d in sorted(domains, key=lambda d: str(d.get("domain") or "")):
                if str(d.get("type") or "master") == "master" and isinstance(records.get(int(d.get("id") or 0)), list):
                    out += self._record_forms(d)
        firewalls = read.get("firewalls")
        if isinstance(firewalls, list):
            for f in sorted(firewalls, key=lambda f: str(f.get("label") or "").lower()):
                if self._unwritable(f) is None:
                    out += self._rule_forms(f)
        if isinstance(read.get("keys"), list):
            out += self._key_forms()
        return out

    @staticmethod
    def _power_forms(linodes: list[dict]) -> list[dict]:
        which = {"name": "linode", "label": "Linode", "type": "fixed",
                 "choices": [{"value": x.get("id"), "title": str(x.get("label") or x.get("id"))} for x in linodes]}
        out = []
        for action, (title, _, words, danger) in POWER_WORDS.items():
            out.append({"id": f"power:{action}", "hook": "power", "title": f"{title} a Linode",
                        "fields": [which, {"name": "action", "label": "Change", "type": "fixed", "value": action,
                                           "choices": [{"value": action, "title": title}]}],
                        "confirm": {"title": f"{title} {{linode}}?", "words": words, "yes": title, "danger": danger}})
        return out

    @staticmethod
    def _record_forms(d: Mapping) -> list[dict]:
        did, name = int(d["id"]), str(d.get("domain"))
        domain = {"name": "domain", "label": "Domain", "type": "fixed", "value": did, "choices": [{"value": did, "title": name}]}
        kept = ("Every other record is kept: DNS Manager changes one record at a time, and the records are read back after "
                "the change to check it.")
        return [
            {"id": f"record-set:{did}", "hook": "set_record", "title": f"Set a record in {name}",
             "note": ("An A, AAAA or CNAME record changes the host's record of its type (or makes one); a TXT, MX, NS or CAA "
                      "record is added beside the others (the same target there already: its TTL or priority changed)."),
             "fields": [domain,
                        {"name": "name", "label": "Host", "type": "text", "required": True, "placeholder": "@, www, home",
                         "note": f"@ is {name} itself; home is home.{name}"},
                        {"name": "rtype", "label": "Type", "type": "choice", "value": "A",
                         "choices": [{"value": t, "title": t, "note": TYPE_NOTES[t]} for t in rec.SETTABLE]},
                        {"name": "target", "label": "Target", "type": "text", "required": True,
                         "placeholder": "an address, a host name or text, as its type says"},
                        {"name": "ttl", "label": "TTL", "type": "choice", "value": "",
                         "choices": [{"value": "", "title": "the record's own, else the domain's"},
                                     *({"value": str(t), "title": f"{rec.TTL_WORDS[t]} ({t} s)"} for t in rec.TTLS)]},
                        {"name": "priority", "label": "Priority", "type": "number", "min": 0, "max": 255,
                         "placeholder": str(rec.MX_DEFAULT), "when": {"rtype": ["MX"]},
                         "empty": f"the record's own, else {rec.MX_DEFAULT}"},
                        {"name": "tag", "label": "CAA tag", "type": "choice", "value": "issue", "when": {"rtype": ["CAA"]},
                         "choices": [{"value": t, "title": t, "note": CAA_NOTES[t]} for t in rec.CAA_TAGS]}],
             "submit": "Review the change",
             "confirm": {"title": f"Set this record in {name}?",
                         "words": ("{name} {rtype} {target} is set in {domain}. Where {name} holds a record of that type "
                                   "already (an A, AAAA or CNAME, as its table shows), that record is changed to this one "
                                   "and what it held is dropped; a TXT, MX, NS or CAA record is added beside the others. "
                                   + kept), "yes": "Set the record"}},
            {"id": f"record-remove:{did}", "hook": "remove_record", "title": f"Remove a record from {name}",
             "fields": [domain, {"name": "record", "label": "Record id", "type": "fixed"},
                        {"name": "name", "label": "Host", "type": "fixed"}, {"name": "rtype", "label": "Type", "type": "fixed"},
                        {"name": "target", "label": "Target", "type": "fixed"}],
             "confirm": {"title": f"Remove this record from {name}?",
                         "words": "{name} {rtype} {target} is removed from {domain}. " + kept,
                         "yes": "Remove the record", "danger": True}},
        ]

    @staticmethod
    def _rule_forms(f: Mapping) -> list[dict]:
        fid, label = int(f["id"]), str(f.get("label") or f.get("id"))
        rules = f.get("rules") or {}
        version, print_ = rules.get("version"), str(rules.get("fingerprint") or "")
        which = {"name": "firewall", "label": "Cloud Firewall", "type": "fixed", "value": fid,
                 "choices": [{"value": fid, "title": label}]}
        seen = {"name": "seen", "label": "Rules as read", "type": "fixed", "value": print_,
                "choices": [{"value": print_, "title": f"version {version} (fingerprint {print_})"}]}
        accept = {"name": fw.ACCEPT_RISK, "type": "accept", "title": "Change the firewall anyway?", "yes": "Change it anyway",
                  "words": ("Changing it anyway writes exactly that to {firewall}: what the refusal names is opened to the "
                            "whole internet, or SSH from there ends. It can be changed back here or in Cloud Manager.")}
        attached = fw.attached_linodes(f)
        kept = (f"Every other rule and both policies are written back as read (Linode replaces the whole set): the rules are "
                f"read again first, and nothing is written if they are not version {version} any more."
                + (f" {label} guards {', '.join(attached)}." if attached else ""))
        direction = {"name": "direction", "label": "Direction", "type": "choice", "value": "inbound",
                     "choices": [{"value": "inbound", "title": "inbound",
                                  "note": f"to what it guards (the policy: {rules.get('inbound_policy') or '–'})"},
                                 {"value": "outbound", "title": "outbound",
                                  "note": f"from what it guards (the policy: {rules.get('outbound_policy') or '–'})"}]}
        return [
            {"id": f"rule-add:{fid}", "hook": "add_rule", "title": f"Add a rule to {label}",
             "note": ("The rule goes after the direction's others: the first rule that matches decides, else the policy. "
                      "An inbound rule opening SSH or every port to the whole internet, or one ending SSH to a Linode it "
                      "guards, is asked twice."),
             "fields": [which, seen, direction,
                        {"name": "action", "label": "Action", "type": "choice", "value": "ACCEPT",
                         "choices": [{"value": "ACCEPT", "title": "ACCEPT", "note": "let it through"},
                                     {"value": "DROP", "title": "DROP", "note": "stop it"}]},
                        {"name": "protocol", "label": "Protocol", "type": "choice", "value": "TCP",
                         "choices": [{"value": p, "title": p} for p in fw.PROTOCOLS]},
                        {"name": "ports", "label": "Ports", "type": "text", "placeholder": "22, 80, 443 or 8000-8080",
                         "when": {"protocol": sorted(fw.PORTED)}, "empty": "every port",
                         "note": f"at most {fw.MAX_PIECES} (a range counting as two); empty: every port"},
                        {"name": "addresses", "label": "Addresses", "type": "text", "required": True,
                         "placeholder": "203.0.113.7, 198.51.100.0/24, 2001:db8::/32",
                         "note": "0.0.0.0/0 and ::/0 are every address"},
                        {"name": "label", "label": "Label", "type": "text", "placeholder": "ssh-home",
                         "note": "3 to 32 characters"},
                        {"name": "description", "label": "Description", "type": "text", "note": "up to 100 characters"},
                        accept],
             "submit": "Review the change",
             "confirm": {"title": f"Add this rule to {label}?",
                         "words": "The {direction} rule {action} {protocol} from {addresses} is added to {firewall}. " + kept,
                         "yes": "Add the rule"}},
            {"id": f"rule-remove:{fid}", "hook": "remove_rule", "title": f"Remove a rule from {label}",
             "fields": [which, seen, {"name": "direction", "label": "Direction", "type": "fixed"},
                        {"name": "position", "label": "Rule", "type": "fixed"}, {"name": "rule", "label": "It", "type": "fixed"},
                        accept],
             "confirm": {"title": f"Remove this rule from {label}?",
                         "words": "The {direction} rule {position} ({rule}) is removed from {firewall}. " + kept,
                         "yes": "Remove the rule", "danger": True}},
        ]

    @staticmethod
    def _key_forms() -> list[dict]:
        return [
            {"id": "sshkey-add", "hook": "add_ssh_key", "title": "Add an SSH key to your profile",
             "note": ("The public key (the .pub file's line), never the private one. The profile's keys are for the "
                      "Linodes you deploy (a key lets you in as their root user); no Linode running now is changed."),
             "fields": [{"name": "label", "label": "Label", "type": "text", "placeholder": "laptop",
                         "note": "up to 64 characters"},
                        {"name": "ssh_key", "label": "Public key", "type": "text", "required": True,
                         "placeholder": "ssh-ed25519 AAAA... you@host"}],
             "submit": "Review the change",
             "confirm": {"title": "Add this SSH key to your profile?",
                         "words": "The public key {label} is added to your Linode profile.", "yes": "Add the key"}},
            {"id": "sshkey-remove", "hook": "remove_ssh_key", "title": "Remove an SSH key from your profile",
             "fields": [{"name": "key", "label": "Key id", "type": "fixed"}, {"name": "label", "label": "Label", "type": "fixed"}],
             "confirm": {"title": "Remove this SSH key from your profile?",
                         "words": ("{label} is removed from your Linode profile. Linodes made with it keep it in their "
                                   "authorized_keys: Linode removes only its place in your profile."),
                         "yes": "Remove the key", "danger": True}},
        ]


MACHINE = LinodePlugin()
