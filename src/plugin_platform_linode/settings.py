"""The plugin's settings, read through the library's Login interface and nothing else (the user, 2026-11-08: "again, all
the settings are stored on a login-app db"; "but we are not integrating login-app right now"). Each setting is a pair named
by its variable (LINODE_TOKEN is the pair `linode-token`: apps.authorization.pair_name), asked of the login of the app the
plugin is attached to: the platform's EnvironmentLogin today, the login app's pairs once the platform binds it. Not
attached (the command line), an EnvironmentLogin of its own. The plugin keeps no settings file: a value is never written
anywhere, never shown, and only the names of the settings set are said.

The token is a personal access token made in Cloud Manager (your username > API Tokens > Create a Personal Access Token),
with an access level for each area: the plugin reads every area it shows and changes only Linodes (power), Domains and
Firewalls, so the token it needs is Read Only everywhere but those (SCOPES); the profile's SSH keys are changed here only
with Account Read/Write, which the plugin asks for nowhere (an audit, 2026-11-11: that scope also reaches the account's
billing and users). A token holding a space or a line break inside is refused, never sent nor shown."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from liminal_libs.apps import EnvironmentLogin, Login
from liminal_libs.machines.ddns import MINUTES, minutes_of
from liminal_libs.sources.keys import KeyVar

TOKEN = "LINODE_TOKEN"
DDNS_HOSTS = "LINODE_DDNS_HOSTS"
DDNS_MINUTES = "LINODE_DDNS_MINUTES"
TOKEN_PAGE = "https://cloud.linode.com/profile/tokens"  # Cloud Manager: your username > API Tokens

# the token's access, area by area, as Linode's docs name the scopes (techdocs.akamai.com/linode-api/reference/get-started;
# each operation's page names the one it needs): read/write where the plugin changes something, read-only where it reads
WRITE_SCOPES = (
    ("linodes:read_write", "Linodes", "boot, shut down and reboot (and the Linodes, their plans and placement groups read)"),
    ("domains:read_write", "Domains", "records set and removed, Dynamic DNS"),
    ("firewall:read_write", "Firewalls", "Cloud Firewall rules added and removed"),
)
# the profile's SSH keys: Linode names no scope of the profile's own for adding and removing them, and the one it names
# (account:read_write) also lets a token make payments, add users or cancel the account (an audit, 2026-11-11): so
# Account is Read Only unless you want the keys added and removed here too
ACCOUNT_WRITE = "account:read_write"
READ_SCOPES = (
    ("account:read_only", "Account"),
    ("volumes:read_only", "Volumes"),
    ("ips:read_only", "IPs"),
    ("images:read_only", "Images"),
    ("lke:read_only", "Kubernetes"),
    ("nodebalancers:read_only", "NodeBalancers"),
    ("databases:read_only", "Databases"),
    ("object_storage:read_only", "Object Storage"),
    ("vpc:read_only", "VPCs"),
)
NO_ACCESS = ("events", "longview", "stackscripts")  # areas the plugin never asks: No Access is enough
SCOPES = tuple(s for s, *_ in WRITE_SCOPES) + tuple(s for s, *_ in READ_SCOPES)
SCOPE_WORDS = ("Read/Write for " + ", ".join(a for _, a, _ in WRITE_SCOPES) + " ("
               + " ".join(s for s, *_ in WRITE_SCOPES) + "); Read Only for "
               + ", ".join(a for _, a in READ_SCOPES) + " (" + " ".join(s for s, _ in READ_SCOPES)
               + "); No Access for the rest. Only to add and remove the profile's SSH keys here: Account Read/Write ("
               + ACCOUNT_WRITE + ", which also lets the token change the account's billing and users)")
ACCESS_SHORT = ("Read/Write: " + ", ".join(a for _, a, _ in WRITE_SCOPES)
                + "; Read Only: the rest it shows (Account too, unless SSH keys are changed here)")

# what the login app's "Pairs your plugins ask for" lists, once it lists the platform's plugins
KEYS = (
    KeyVar(TOKEN, label="Personal access token",
           hint=("Cloud Manager: your username > API Tokens > Create a Personal Access Token (" + TOKEN_PAGE + "); "
                 + SCOPE_WORDS)),
    KeyVar(DDNS_HOSTS, label="Dynamic DNS hosts", secret=False,
           hint=("optional: the hosts kept at this network's address, comma separated: home.example.com, @.example.com "
                 "(the domain itself); in a domain of Linode's DNS Manager")),
    KeyVar(DDNS_MINUTES, label="Dynamic DNS minutes", secret=False,
           hint="optional: minutes between Dynamic DNS checks, 1 to 1440 (5 unless set)"),
)
NAMES = tuple(k.name for k in KEYS)
TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9._~+/=-]{20,200}$")  # a bearer token's characters (Linode's are 64 hex digits)
SPACED = f"{TOKEN} holds a space or a line break inside: it is not sent anywhere; enter it again, alone"


@dataclass(frozen=True)
class Config:
    """The settings as read (`present`: the names of those set; `problems`: what was set but could not be taken, in words
    that never hold a secret)."""

    token: str = field(default="", repr=False)
    token_problem: str = ""  # why a token set is not used (it holds a space or a line break): said instead of "not set"
    hosts: str = ""  # the hosts as typed (split against the account's domains once they are known: ddns.hosts_of)
    minutes: float = MINUTES[2]
    present: frozenset = frozenset()
    problems: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        """Whether the API can be asked (the token set)."""
        return bool(self.token)

    @property
    def ddns_ready(self) -> bool:
        """Whether Dynamic DNS is set up: hosts named, and the token it sets them with."""
        return bool(self.token and self.hosts.strip())

    @property
    def secrets(self) -> tuple[str, ...]:
        """The values scrubbed from every message the plugin gives."""
        return (self.token,) if self.token else ()

    def print_of(self, *names: str) -> str:
        """A fingerprint of these settings' values (kept in memory to notice a change; never shown nor written)."""
        values = {TOKEN: self.token, DDNS_HOSTS: self.hosts, DDNS_MINUTES: str(self.minutes)}
        return hashlib.sha256("\0".join(f"{n}={values[n]}" for n in names).encode("utf-8")).hexdigest()

    @property
    def api_print(self) -> str:
        return self.print_of(TOKEN)

    @property
    def ddns_print(self) -> str:
        return self.print_of(TOKEN, DDNS_HOSTS)


def parse(values: Mapping[str, str]) -> Config:
    """The settings from their values by variable (those not set left out or empty)."""
    v = {n: str(values.get(n) or "").strip() for n in NAMES}
    present = frozenset(n for n in NAMES if v[n])
    problems: list[str] = []
    token = v[TOKEN]
    if token.lower().startswith("bearer "):
        token = token[7:].strip()  # pasted with its header's word
    token_problem = ""
    if any(c.isspace() for c in token):  # a wrapped paste (setx, a registry edit): never sent, never shown
        token, token_problem = "", SPACED
        problems.append(SPACED)
    elif token and not TOKEN_SHAPE.match(token):
        problems.append(f"{TOKEN} does not look like a personal access token (Linode's are 64 letters and digits): "
                        "it is sent as it is")
    minutes = minutes_of(v[DDNS_MINUTES])
    if v[DDNS_MINUTES]:
        try:
            float(v[DDNS_MINUTES])
        except ValueError:
            problems.append(f"{DDNS_MINUTES} is not a number of minutes: {MINUTES[2]:g} is used")
    if v[DDNS_HOSTS] and not token and not token_problem:
        problems.append(f"{DDNS_HOSTS} is set but {TOKEN} is not: Dynamic DNS sets the hosts through Linode's API with it")
    return Config(token=token, token_problem=token_problem, hosts=v[DDNS_HOSTS], minutes=minutes, present=present,
                  problems=tuple(problems))


def read(login: Login | None = None) -> Config:
    """The settings as `login` furnishes them (the login of the app the plugin is attached to), else an EnvironmentLogin's:
    the variables set, by their pairs' names; a login that cannot be asked furnishes none, and says so."""
    asked = login if login is not None else EnvironmentLogin()
    try:
        values = asked.variables(NAMES)
    except Exception as e:  # noqa: BLE001 - a login that cannot be asked: nothing set, and why
        return Config(problems=(f"the settings could not be read from the login: {type(e).__name__}",))
    return parse(values)
