"""A Cloud Firewall's rules changed the only way Linode's API allows: the whole set written back at once (the reference's
put-firewall-rules "replaces all of a Firewall's inbound and outbound rulesets", read 2026-11-11). So a change is a fresh
read, one rule added or removed, and everything written back:

- the rules read fresh (with their fingerprint, a hash of them, and their version, counting each change); the page's form
  carries the fingerprint it showed, and a change is refused, nothing sent, when the rules are not that any more (a change
  made meanwhile in Cloud Manager or elsewhere is never written over unseen); the reference has no conditional write, so the
  version the write answers is checked too: one more than the one read, else another change landed between the read and
  the write, and the report says so with the rules as they were;
- refused, nothing sent, when what was read cannot be written back as it is (a field this plugin does not know, no
  policies), or the change breaks the reference's limits (25 rules in all, 255 addresses a rule, 15 ports a rule);
- a risky change is refused once and made only when accepted (ACCEPT_RISK, exactly true: the page's second
  confirmation), whatever rule it adds or removes: each change is weighed by the inbound policy and the rules left, before
  and after it (risk_of), all of IPv4 and all of IPv6 each judged on its own (0.1.2: 0.1.1 merged them). Risky: a
  change that lets either reach every TCP or UDP port, or SSH, RDP, Docker, a database's or another port servers are
  broken into through (SENSITIVE), where it did not before (an ACCEPT added, or a DROP removed); and one that ends SSH,
  from where the rules let it in, to a Linode the firewall guards (an ACCEPT removed, or a DROP added).

Rules are applied in order, the first that matches deciding, else the direction's policy (ACCEPT or DROP). A rule:
{action ACCEPT|DROP, protocol TCP|UDP|ICMP|IPENCAP|ALL, ports "22, 80, 443" or "1-65535" (TCP and UDP alone; none: every
port), addresses {ipv4: [...], ipv6: [...]} (0.0.0.0/0 and ::/0 every address), label (3 to 32 characters), description
(1 to 100)}."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence

from .refusal import Refusal

DIRECTIONS = ("inbound", "outbound")
ACTIONS = ("ACCEPT", "DROP")
PROTOCOLS = ("TCP", "UDP", "ICMP", "IPENCAP", "ALL")
PORTED = frozenset({"TCP", "UDP"})  # the protocols that take ports here (the reference also SCTP and IANA numbers)
RULE_FIELDS = frozenset({"action", "protocol", "ports", "addresses", "label", "description"})  # the reference's
MAX_RULES = 25  # inbound and outbound together
MAX_ADDRESSES = 255  # a rule's, IPv4 and IPv6 together
MAX_PIECES = 15  # a rule's ports, a range counting as two
SSH = 22
EVERYONE = (ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0"))
FAMILIES = ((EVERYONE[0], "IPv4"), (EVERYONE[1], "IPv6"))  # the whole internet, each family judged on its own
WHOLE = {"IPv4": "0.0.0.0/0", "IPv6": "::/0"}
ATTACHED_KINDS = frozenset({"linode", "linode_interface"})  # what SSH goes to (a NodeBalancer takes none)
ACCEPT_RISK = "accept_risk"  # the hooks' argument accepting a risky change (the page's second confirmation)
# the ports servers are broken into through when the whole internet reaches them (beside every port): a change newly
# letting the internet in to one is asked twice (an audit, 2026-11-11: RDP, Docker and the databases were asked once)
SENSITIVE = {22: "SSH", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 2375: "Docker", 2376: "Docker over TLS",
             3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "the Kubernetes API",
             9200: "Elasticsearch", 11211: "memcached", 27017: "MongoDB"}
LABEL = re.compile(r"^[^\x00-\x1f\x7f]{3,32}$")


# -- a rule, as typed ----------------------------------------------------------------------------------------------------
def direction_of(value) -> str:
    d = str(value or "").strip().lower()
    if d not in DIRECTIONS:
        raise ValueError(f"{value!r} is no direction: inbound or outbound")
    return d


def ports_of(value, protocol: str) -> str | None:
    """A rule's ports as written ("22", "80, 443", "8000-8080"); None: every port (none given). ValueError otherwise."""
    text = str(value or "").strip()
    if protocol not in PORTED:
        if text:
            raise ValueError(f"a {protocol} rule takes no ports (TCP and UDP rules do)")
        return None
    if not text:
        return None
    pieces, out = 0, []
    for part in [p.strip() for p in text.split(",")]:
        m = re.fullmatch(r"([1-9][0-9]{0,4})(?:\s*-\s*([1-9][0-9]{0,4}))?", part)
        if not m:
            raise ValueError(f"{part!r} is not a port nor a range (22, 80, 443, 8000-8080: 1 to 65535, no leading zeros)")
        a, b = int(m.group(1)), int(m.group(2)) if m.group(2) else None
        if a > 65535 or (b is not None and (b > 65535 or b <= a)):
            raise ValueError(f"{part!r}: ports are 1 to 65535, a range's first below its last")
        pieces += 1 if b is None else 2
        out.append(str(a) if b is None else f"{a}-{b}")
    if pieces > MAX_PIECES:
        raise ValueError(f"a rule holds at most {MAX_PIECES} ports (a range counting as two)")
    return ", ".join(out)


def addresses_of(value) -> dict[str, list[str]]:
    """A rule's addresses as written ({ipv4: [...], ipv6: [...]}, in IP/mask form: 203.0.113.7 is 203.0.113.7/32).
    ValueError when one is none or none is given."""
    parts = [p for p in re.split(r"[,\s]+", str(value or "").strip()) if p]
    if not parts:
        raise ValueError("no address given: 0.0.0.0/0 and ::/0 for every address, 203.0.113.7 for one")
    out: dict[str, list[str]] = {"ipv4": [], "ipv6": []}
    for p in parts:
        try:
            net = ipaddress.ip_network(p, strict=True)
        except ValueError:
            try:
                loose = ipaddress.ip_network(p, strict=False)
            except ValueError:
                raise ValueError(f"{p!r} is not an address nor a network (203.0.113.7, 203.0.113.0/24, 2001:db8::/32)") from None
            raise ValueError(f"{p!r} has bits set below its mask: {loose} is that network") from None
        family = "ipv4" if net.version == 4 else "ipv6"
        if str(net) not in out[family]:
            out[family].append(str(net))
    if len(out["ipv4"]) + len(out["ipv6"]) > MAX_ADDRESSES:
        raise ValueError(f"a rule holds at most {MAX_ADDRESSES} addresses")
    return {k: v for k, v in out.items() if v}


def rule_of(action, protocol, ports=None, addresses=None, label=None, description=None) -> dict:
    """A rule from what was typed, as the reference takes it; ValueError for what it would refuse."""
    a = str(action or "").strip().upper()
    if a not in ACTIONS:
        raise ValueError(f"{action!r} is no action: ACCEPT or DROP")
    p = str(protocol or "").strip().upper()
    if p not in PROTOCOLS:
        raise ValueError(f"{protocol!r} is no protocol here: {', '.join(PROTOCOLS)}")
    rule: dict = {"action": a, "protocol": p}
    port_text = ports_of(ports, p)
    if port_text:
        rule["ports"] = port_text
    rule["addresses"] = addresses_of(addresses)
    name = str(label or "").strip()
    if name:
        if not LABEL.match(name):
            raise ValueError("a rule's label is 3 to 32 characters on one line")
        rule["label"] = name
    words = str(description or "").strip()
    if words:
        if len(words) > 100 or any(ord(c) < 32 or ord(c) == 127 for c in words):
            raise ValueError("a rule's description is 1 to 100 characters on one line")
        rule["description"] = words
    return rule


# -- a rule, as read -----------------------------------------------------------------------------------------------------
def clean(rule: Mapping) -> dict:
    """A rule as read, as it is written back: its fields with a value (an empty ports, label or address list left out)."""
    out: dict = {}
    for k in ("action", "protocol", "ports", "addresses", "label", "description"):
        v = rule.get(k)
        if k == "addresses" and isinstance(v, Mapping):
            v = {f: list(v[f]) for f in ("ipv4", "ipv6") if isinstance(v.get(f), list) and v.get(f)}
        if v not in (None, "", {}, []):
            out[k] = v
    return out


def unknown(rules: Mapping) -> list[str]:
    """The fields of the rules as read that this plugin does not know (a write back could lose them)."""
    odd: set[str] = set()
    for d in DIRECTIONS:
        for r in rules.get(d) or []:
            if isinstance(r, Mapping):
                odd |= set(r) - RULE_FIELDS
                a = r.get("addresses")
                if isinstance(a, Mapping):
                    odd |= {f"addresses.{k}" for k in a if k not in ("ipv4", "ipv6")}
            else:
                odd.add("(a rule that is not an object)")
    return sorted(odd)


def body_of(rules: Mapping) -> dict:
    """What put-firewall-rules is sent: every rule of both directions, cleaned, and both policies."""
    return {"inbound": [clean(r) for r in rules.get("inbound") or []],
            "outbound": [clean(r) for r in rules.get("outbound") or []],
            "inbound_policy": rules.get("inbound_policy"), "outbound_policy": rules.get("outbound_policy")}


def same(a: Mapping, b: Mapping) -> bool:
    """Whether two rule sets are the same rules and policies (as written back)."""
    x, y = body_of(a), body_of(b)
    return x == y


def nets_of(rule: Mapping) -> list:
    out = []
    a = rule.get("addresses") if isinstance(rule.get("addresses"), Mapping) else {}
    for f in ("ipv4", "ipv6"):
        for text in a.get(f) or []:
            try:
                out.append(ipaddress.ip_network(str(text), strict=False))
            except ValueError:
                continue
    return out


def covers(rule: Mapping, protocol: str = "TCP", port: int = SSH) -> bool:
    """Whether a rule applies to `protocol` traffic to `port` (ALL: every protocol; no ports: every port)."""
    p = str(rule.get("protocol") or "").upper()
    if p == "ALL":
        return True
    if p != protocol:
        return False
    text = str(rule.get("ports") or "").strip()
    if not text:
        return True
    for part in text.split(","):
        a, _, b = part.strip().partition("-")
        try:
            lo, hi = int(a), int(b or a)
        except ValueError:
            continue
        if lo <= port <= hi:
            return True
    return False


def every_port(rule: Mapping) -> bool:
    """Whether a rule applies to every TCP or UDP port (ALL, or TCP/UDP with no ports or 1-65535)."""
    p = str(rule.get("protocol") or "").upper()
    if p == "ALL":
        return True
    ports = str(rule.get("ports") or "").replace(" ", "")
    return p in PORTED and ports in ("", "1-65535")


def contains(rule: Mapping, probe) -> bool:
    return any(probe.version == n.version and probe.subnet_of(n) for n in nets_of(rule))


def verdict(rules: Sequence[Mapping], policy: str, probe, protocol: str = "TCP", port: int = SSH) -> str:
    """What the rules do to `protocol` traffic to `port` from the network `probe`: the first rule that covers it and holds
    it decides, else the policy."""
    for r in rules:
        if covers(r, protocol, port) and contains(r, probe):
            return str(r.get("action") or "").upper()
    return str(policy or "").upper()


def attached_linodes(firewall: Mapping) -> list[str]:
    """The Linodes (and Linode interfaces) a firewall is attached to, by their labels."""
    return [str(e.get("label") or e.get("id")) for e in firewall.get("entities") or []
            if isinstance(e, Mapping) and str(e.get("type") or "") in ATTACHED_KINDS]


def words(rule: Mapping) -> str:
    """A rule in words: ACCEPT TCP 22 from 0.0.0.0/0, ::/0 (ssh)."""
    p = str(rule.get("protocol") or "")
    ports = str(rule.get("ports") or "").strip()
    nets = [*((rule.get("addresses") or {}).get("ipv4") or []), *((rule.get("addresses") or {}).get("ipv6") or [])]
    shown = ", ".join(nets[:4]) + (f" and {len(nets) - 4} more" if len(nets) > 4 else "")
    where = f" {ports}" if ports else (" every port" if p in PORTED else "")
    name = f" ({rule.get('label')})" if rule.get("label") else ""
    return f"{rule.get('action')} {p}{where} from {shown or 'no address'}{name}"


# -- the risks -------------------------------------------------------------------------------------------------------------
def explicit_ports(rules: Sequence[Mapping], protocol: str) -> list[tuple[int, int]]:
    """The port ranges the rules of `protocol` name (a rule with no ports names none: it covers every port)."""
    out = []
    for r in rules:
        if str(r.get("protocol") or "").upper() != protocol:
            continue
        for part in str(r.get("ports") or "").split(","):
            a, _, b = part.strip().partition("-")
            try:
                out.append((int(a), int(b or a)))
            except ValueError:
                continue
    return out


def stretches(rules: Sequence[Mapping], protocol: str) -> list[int]:
    """A port from each stretch of ports that the rules of `protocol` treat alike (cut where a named range starts or
    ends): what the rules do to that port, they do to its whole stretch."""
    cuts = {1, 65536}
    for lo, hi in explicit_ports(rules, protocol):
        cuts |= {min(max(lo, 1), 65536), min(max(hi + 1, 1), 65536)}
    edges = sorted(cuts)
    return [a for a, b in zip(edges, edges[1:]) if a < b]


def exposed(rules: Mapping) -> list[tuple[str, str]]:
    """What the whole internet reaches through the inbound rules and policy, each family on its own (all of IPv4,
    0.0.0.0/0; all of IPv6, ::/0): (what, family) for every TCP port, every UDP port (each stretch of ports let in), and
    each of the ports servers are broken into through (SENSITIVE)."""
    inbound, policy = list(rules.get("inbound") or []), rules.get("inbound_policy")
    out: list[tuple[str, str]] = []
    for probe, family in FAMILIES:
        for proto in ("TCP", "UDP"):
            if all(verdict(inbound, policy, probe, proto, port) == "ACCEPT" for port in stretches(inbound, proto)):
                out.append((f"every {proto} port", family))
        for port, name in SENSITIVE.items():
            if verdict(inbound, policy, probe, "TCP", port) == "ACCEPT":
                out.append((f"{name} ({port})", family))
    return out


def opened(before: Mapping, after: Mapping) -> list[tuple[str, str]]:
    """What a change opens to the whole internet, family by family: what it reaches after and did not before (all of
    IPv4 opened where all of IPv6 was open already is opened all the same)."""
    was = set(exposed(before))
    return [x for x in exposed(after) if x not in was]


def _listed(whats: Sequence[str]) -> str:
    """Some ports in words: every TCP port standing for the TCP ports it holds (SSH named among them)."""
    if "every TCP port" in whats:
        parts = ["every TCP port" + (" (SSH among them)" if "SSH (22)" in whats else "")]
        parts += [x for x in whats if x == "every UDP port"]
    else:
        parts = list(whats)
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def opened_words(opens: Sequence[tuple[str, str]]) -> str:
    """What a change opens, in words, said by whom it opens it to: the whole internet (both families), all of IPv4
    (0.0.0.0/0) or all of IPv6 (::/0)."""
    families: dict[str, set[str]] = {}
    for what, family in opens:
        families.setdefault(what, set()).add(family)
    groups: dict[frozenset, list[str]] = {}
    for what, fams in families.items():
        groups.setdefault(frozenset(fams), []).append(what)
    parts = []
    for fams in sorted(groups, key=lambda f: (-len(f), sorted(f))):  # the whole internet first, then IPv4, then IPv6
        where = "the whole internet" if len(fams) == len(FAMILIES) else \
            " and ".join(f"all of {f} ({WHOLE[f]})" for f in sorted(fams))
        parts.append(f"{_listed(groups[fams])} to {where}")
    return "; ".join(parts)


def ssh_lost(before: Sequence[Mapping], after: Sequence[Mapping], policy: str, probes: Iterable) -> list[str]:
    """The networks among `probes` that SSH reached through the inbound rules `before` and does not `after`."""
    return [str(n) for n in dict.fromkeys(probes)
            if verdict(before, policy, n) == "ACCEPT" and verdict(after, policy, n) == "DROP"]


def ssh_probes(*rule_lists: Sequence[Mapping]) -> list:
    """The networks SSH is judged from: the whole internet's and every network an inbound rule names, before or after."""
    out = list(EVERYONE)
    for rules in rule_lists:
        for r in rules:
            out += [n for n in nets_of(r) if n not in out]
    return out


def risk_of(before: Mapping, after: Mapping, firewall: Mapping, label: str) -> str | None:
    """A change's risk in words (None: none), whatever rule it adds or removes: weighed by the inbound policy and the
    rules left, before and after it. What it opens to all of IPv4 or all of IPv6, each family on its own (every TCP or
    UDP port, SSH, RDP, a database's or Docker's port: `exposed`), and the SSH it ends, from where the rules let it in,
    to a Linode the firewall guards (you may lock yourself out)."""
    bits = []
    guards = attached_linodes(firewall)
    opens = opened(before, after)
    if opens:
        bits.append(f"the change opens {opened_words(opens)} on {label}" + (f" (it guards {', '.join(guards)})" if guards else ""))
    if guards:
        b, a = list(before.get("inbound") or []), list(after.get("inbound") or [])
        lost = ssh_lost(b, a, before.get("inbound_policy"), ssh_probes(b, a))
        if lost:
            bits.append(f"the change ends SSH (22) from {', '.join(lost)} to {', '.join(guards)}, which {label} let in: "
                        "you may lock yourself out of them")
    if not bits:
        return None
    off = "" if str(firewall.get("status") or "enabled") == "enabled" else \
        f" ({label} is {firewall.get('status')} now: so once it is enabled)"
    return "; ".join(bits) + off


# -- the changes -----------------------------------------------------------------------------------------------------------
def check_writable(rules: Mapping, label: str) -> None:
    """Refusal when what was read cannot be written back as it is."""
    odd = unknown(rules)
    if odd:
        raise Refusal(f"the rules of {label} hold what this plugin does not know ({', '.join(odd)}): writing them back "
                      "could lose it, so nothing is written (change them in Cloud Manager)")
    for p in ("inbound_policy", "outbound_policy"):
        if str(rules.get(p) or "").upper() not in ACTIONS:
            raise Refusal(f"the rules of {label} were read without their {p.replace('_', ' ')}: nothing is written")


def plan_add(rules: Mapping, direction: str, rule: Mapping, firewall: Mapping, label: str) -> tuple[dict, str, str | None]:
    """The rules with `rule` added after the direction's others, what that does in words, and its risk in words (None)."""
    d = direction_of(direction)
    check_writable(rules, label)
    total = len(rules.get("inbound") or []) + len(rules.get("outbound") or [])
    if total >= MAX_RULES:
        raise Refusal(f"{label} holds {total} rules: a firewall holds at most {MAX_RULES}, inbound and outbound together")
    if any(clean(r) == clean(rule) for r in rules.get(d) or []):
        raise Refusal(f"{label} has this {d} rule already: {words(rule)}")
    new = {**rules, d: [*(rules.get(d) or []), dict(rule)]}
    said = f"added the {d} rule {words(rule)} to {label} (after its other {d} rules)"
    return new, said, risk_of(rules, new, firewall, label)


def plan_remove(rules: Mapping, direction: str, position, firewall: Mapping, label: str,
                shown: str | None = None) -> tuple[dict, str, str | None]:
    """The rules without the direction's rule at `position` (1, 2 ...; `shown`: that rule in words, as it was shown, so a
    rule that moved or changed is not removed unseen), what that does in words, and its risk in words (None)."""
    d = direction_of(direction)
    check_writable(rules, label)
    try:
        at = int(str(position).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{position!r} is not a rule's place (1, 2 ...)") from None
    current = list(rules.get(d) or [])
    if not 1 <= at <= len(current):
        raise Refusal(f"{label} has no {d} rule {at} (it has {len(current)}): nothing removed")
    gone = current[at - 1]
    if shown in (None, ""):
        raise ValueError(f"name the rule as it was shown ({d} rule {at} in words), so a rule that moved is not removed unseen")
    if " ".join(str(shown).split()) != " ".join(words(gone).split()):
        raise Refusal(f"{d} rule {at} of {label} is {words(gone)} now, not {shown}: the rules changed since they were "
                      "read, so nothing is removed (read them again)")
    rest = current[: at - 1] + current[at:]
    new = {**rules, d: rest}
    said = f"removed the {d} rule {at} of {label}: {words(gone)}"
    return new, said, risk_of(rules, new, firewall, label)
