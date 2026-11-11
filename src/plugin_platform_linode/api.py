"""Linode's API v4 (Akamai Cloud), as its reference gives it (https://techdocs.akamai.com/linode-api/reference/api, read
2026-11-11): https://api.linode.com/v4, a personal access token borne as a bearer token, JSON answers; a list paginated
(page from 1, page_size 25 to 500, 100 unless asked; {data, page, pages, results}) and filtered by an X-Filter header of
JSON; an error answered as {"errors": [{"reason", "field"}]}, 401 for a token refused (wrong, revoked, expired) and 403 for
one without the access the call needs; 200 list requests a minute and 1,600 others (429 over them, with Retry-After).

Only what the plugin uses is here: its reads (READS) and, of the writes, the free ones alone (FREE_WRITES): a Linode
booted, shut down and rebooted, a domain record made, changed and deleted, a Cloud Firewall's rules written back, an SSH
key added to the profile and removed. No other request can be sent from this client, and nothing that creates, resizes,
restores or destroys a billable thing, nor enables backups: those calls are named on the plugin's API card (card.py), as
the rest of the API, and nowhere else."""
from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping

from liminal_libs.machines.rest import Answer, RestClient, RestError, bearer

BASE = "https://api.linode.com/v4"
VERSION = "v4"
PAGE_SIZE = 500  # the most a page holds (Linode's limit): one request for most lists
COUNT_PAGE = 25  # the least a page holds: a count asks one page and reads its `results`
MOST_PAGES = 20  # a list longer than this many pages is read this far

# every read the plugin makes, as the reference names its paths (under /v4)
READS = (
    "/account",                                 # the balance, this month's charges so far
    "/account/transfer",                        # the transfer pool: used, quota, billable
    "/profile",                                 # whom the token is of
    "/profile/sshkeys",                         # the profile's SSH keys
    "/linode/instances",                        # the Linodes
    "/linode/instances/{linodeId}",             # one Linode's state, before and after a power change
    "/linode/types",                            # the plans and their prices
    "/domains",                                 # DNS Manager's domains
    "/domains/{domainId}/records",              # a domain's records
    "/networking/firewalls",                    # the Cloud Firewalls, their rules and what they are attached to
    "/networking/firewalls/{firewallId}/rules", # a firewall's rules read fresh before a change
    "/networking/reserved/ips",                 # the reserved IPv4 addresses
    "/volumes",                                 # Block Storage volumes
    "/lke/clusters",                            # counted
    "/nodebalancers",                           # counted
    "/databases/instances",                     # counted
    "/object-storage/buckets",                  # counted
    "/images",                                  # counted: the account's own (X-Filter is_public false)
    "/vpcs",                                    # counted
    "/placement/groups",                        # counted
)
# the only writes the plugin makes, each free (power changes, DNS records, firewall rules, SSH keys); each confirmed by the
# user first, on the platform's page or the command line
FREE_WRITES = (
    ("POST", "/linode/instances/{linodeId}/boot"),
    ("POST", "/linode/instances/{linodeId}/shutdown"),
    ("POST", "/linode/instances/{linodeId}/reboot"),
    ("POST", "/domains/{domainId}/records"),
    ("PUT", "/domains/{domainId}/records/{recordId}"),
    ("DELETE", "/domains/{domainId}/records/{recordId}"),
    ("PUT", "/networking/firewalls/{firewallId}/rules"),
    ("POST", "/profile/sshkeys"),
    ("DELETE", "/profile/sshkeys/{sshKeyId}"),
)
# the kinds counted (one cheap list call each: a page of COUNT_PAGE, its `results`): (key, words, path, X-Filter)
COUNTED = (
    ("lke", "Kubernetes (LKE) clusters", "/lke/clusters", None),
    ("nodebalancers", "NodeBalancers", "/nodebalancers", None),
    ("databases", "Managed Databases", "/databases/instances", None),
    ("buckets", "Object Storage buckets", "/object-storage/buckets", None),
    ("images", "Images of your own", "/images", {"is_public": False}),
    ("vpcs", "VPCs", "/vpcs", None),
    ("placement", "Placement groups", "/placement/groups", None),
)
HINTS = {  # an error's status in words of what to do; Linode's own words follow them
    401: "LINODE_TOKEN is refused (wrong, revoked or expired): make a new one in Cloud Manager (your username > API Tokens)",
    403: "the token's access does not cover this (a new token with Read Only for this area to read it, Read/Write to change it)",
    429: "Linode's rate limit: tried again after the wait it asked, then left for later",
}
LIMIT_LABELS = {"x-ratelimit-limit": "Rate limit (this call's window)", "x-ratelimit-remaining": "Left of it",
                "x-ratelimit-reset": "Its window resets", "retry-after": "Asked to wait (s)"}
PLACE = re.compile(r"\{(\w+)\}")


def words_of(answer: Answer) -> tuple[str, str]:
    """Linode's error answer in words ({"errors": [{"reason", "field"}]}), with what to do for a refused token, a token
    without the access, a rate limit; (words, code)."""
    data = answer.data
    errors = data.get("errors") if isinstance(data, Mapping) else None
    said = []
    for e in errors[:4] if isinstance(errors, list) else ():
        if isinstance(e, Mapping):
            reason = " ".join(str(e.get("reason") or "").split())
            where = str(e.get("field") or "").strip()
            if reason:
                said.append(f"{where}: {reason}" if where else reason)
    words = "; ".join(said)
    hint = HINTS.get(answer.status, "")
    if hint:
        words = f"{hint} (Linode: {words})" if words else hint
    return words, str(answer.status) if said else ""


def path_of(template: str, ids: Mapping[str, object]) -> str:
    """A path of the reference's (`/domains/{domainId}/records`) with its ids put in, each a whole number above 0."""
    def one(m: re.Match) -> str:
        name = m.group(1)
        if name not in ids:
            raise ValueError(f"{template}: no {name} given")
        try:
            n = int(str(ids[name]).strip())
        except (TypeError, ValueError):
            raise ValueError(f"{name} {ids[name]!r} is not an id (a whole number)") from None
        if n <= 0:
            raise ValueError(f"{name} {n} is not an id (a whole number above 0)")
        return str(n)
    return PLACE.sub(one, template)


def template_of(method: str, path: str) -> str | None:
    """The template of READS or FREE_WRITES a request's path (under /v4, its query left out) is, or None."""
    bare = path.split("?", 1)[0]
    if bare.startswith("/" + VERSION + "/"):
        bare = bare[len(VERSION) + 1:]
    method = method.upper()
    pool = [t for t in READS] if method == "GET" else [t for m, t in FREE_WRITES if m == method]
    for t in pool:
        if re.fullmatch(PLACE.sub(r"[1-9][0-9]*", t), bare):
            return t
    return None


class LinodeApi:
    """The account's API through the library's REST client: the reads and the free writes, nothing else."""

    def __init__(self, token: str, transport=None, clock=time.time, sleep=time.sleep, secrets=()):
        if not token:
            raise ValueError("the API needs LINODE_TOKEN (a personal access token)")
        self.rest = RestClient(BASE, auth=bearer(token), secrets=(token, *secrets), error=words_of, transport=transport,
                               clock=clock, sleep=sleep)

    def __repr__(self) -> str:
        return f"<LinodeApi {BASE}>"

    # -- sending ---------------------------------------------------------------------------------------------------------
    def _get(self, template: str, params: Mapping | None = None, filter: Mapping | None = None, **ids):
        if template not in READS:
            raise ValueError(f"GET {template} is not one of this plugin's reads")
        headers = {"X-Filter": json.dumps(filter, separators=(",", ":"))} if filter else None
        return self.rest.request("GET", path_of(template, ids), params=params, headers=headers).data

    def _all(self, template: str, filter: Mapping | None = None, **ids) -> list[dict]:
        """Every item of a list, page after page (PAGE_SIZE a page, at most MOST_PAGES)."""
        out: list[dict] = []
        for page in range(1, MOST_PAGES + 1):
            data = self._get(template, {"page": page, "page_size": PAGE_SIZE}, filter, **ids)
            items = data.get("data") if isinstance(data, Mapping) else None
            if not isinstance(items, list):
                raise RestError(f"GET {template}: the answer holds no list (data)")
            out += [x for x in items if isinstance(x, Mapping)]
            try:
                pages = int(data.get("pages") or 1)
            except (TypeError, ValueError):
                pages = 1
            if page >= pages or not items:
                break
        return out

    def _write(self, method: str, template: str, body: Mapping | None = None, **ids):
        """One of FREE_WRITES, and no other request: a change the user confirmed."""
        if (method, template) not in FREE_WRITES:
            raise ValueError(f"{method} {template} is not a change this plugin makes")
        return self.rest.request(method, path_of(template, ids), json=body).data

    # -- reads -----------------------------------------------------------------------------------------------------------
    def account(self) -> dict:
        return self._get("/account") or {}

    def transfer(self) -> dict:
        return self._get("/account/transfer") or {}

    def profile(self) -> dict:
        return self._get("/profile") or {}

    def ssh_keys(self) -> list[dict]:
        return self._all("/profile/sshkeys")

    def linodes(self) -> list[dict]:
        return self._all("/linode/instances")

    def linode(self, linode_id) -> dict:
        return self._get("/linode/instances/{linodeId}", linodeId=linode_id) or {}

    def types(self) -> list[dict]:
        return self._all("/linode/types")

    def domains(self) -> list[dict]:
        return self._all("/domains")

    def records(self, domain_id) -> list[dict]:
        return self._all("/domains/{domainId}/records", domainId=domain_id)

    def firewalls(self) -> list[dict]:
        return self._all("/networking/firewalls")

    def rules(self, firewall_id) -> dict:
        return self._get("/networking/firewalls/{firewallId}/rules", firewallId=firewall_id) or {}

    def reserved_ips(self) -> list[dict]:
        return self._all("/networking/reserved/ips")

    def volumes(self) -> list[dict]:
        return self._all("/volumes")

    def count(self, kind: str) -> int:
        """How many of a kind (COUNTED) the account holds: one page of the least size, its `results`."""
        for key, _, template, filter in COUNTED:
            if key == kind:
                data = self._get(template, {"page_size": COUNT_PAGE}, filter)
                try:
                    return int((data or {}).get("results"))
                except (TypeError, ValueError):
                    raise RestError(f"GET {template}: the answer holds no count (results)") from None
        raise ValueError(f"{kind!r} is not counted here: {', '.join(k for k, *_ in COUNTED)}")

    # -- the free writes ---------------------------------------------------------------------------------------------------
    def boot(self, linode_id) -> dict:
        """The Linode booted (no body: without a config_id, the reference boots its only configuration, else the one it
        last booted)."""
        return self._write("POST", "/linode/instances/{linodeId}/boot", linodeId=linode_id) or {}

    def shutdown(self, linode_id) -> dict:
        return self._write("POST", "/linode/instances/{linodeId}/shutdown", linodeId=linode_id) or {}

    def reboot(self, linode_id) -> dict:
        """The Linode rebooted into the configuration it last booted (no body)."""
        return self._write("POST", "/linode/instances/{linodeId}/reboot", linodeId=linode_id) or {}

    def create_record(self, domain_id, body: Mapping) -> dict:
        return self._write("POST", "/domains/{domainId}/records", dict(body), domainId=domain_id) or {}

    def update_record(self, domain_id, record_id, body: Mapping) -> dict:
        if "type" in body:
            raise ValueError("a record's type is not changed (the reference's update takes none)")
        return self._write("PUT", "/domains/{domainId}/records/{recordId}", dict(body), domainId=domain_id,
                           recordId=record_id) or {}

    def delete_record(self, domain_id, record_id) -> dict:
        return self._write("DELETE", "/domains/{domainId}/records/{recordId}", domainId=domain_id, recordId=record_id) or {}

    def put_rules(self, firewall_id, rules: Mapping) -> dict:
        """The firewall's rules written whole (the reference: it "replaces all of a Firewall's inbound and outbound
        rulesets"): the caller gives every rule (firewall.write)."""
        return self._write("PUT", "/networking/firewalls/{firewallId}/rules", dict(rules), firewallId=firewall_id) or {}

    def add_ssh_key(self, label: str, ssh_key: str) -> dict:
        return self._write("POST", "/profile/sshkeys", {"label": label, "ssh_key": ssh_key}) or {}

    def delete_ssh_key(self, key_id) -> dict:
        return self._write("DELETE", "/profile/sshkeys/{sshKeyId}", sshKeyId=key_id) or {}

    # -- what it learned ---------------------------------------------------------------------------------------------------
    def facts(self) -> dict[str, str]:
        """What the answers said (the plugin's api_facts): the requests made, the last answer, the rate limit's headers as
        last given, the reset as a time."""
        out = self.rest.facts(LIMIT_LABELS)
        reset = out.get(LIMIT_LABELS["x-ratelimit-reset"])
        if reset:
            try:
                out[LIMIT_LABELS["x-ratelimit-reset"]] = time.strftime("%H:%M:%S", time.localtime(float(reset)))
            except (TypeError, ValueError, OverflowError, OSError):
                pass
        return out
