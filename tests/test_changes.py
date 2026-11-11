"""The changes planned, before anything is sent: a record's host, target and TTL as Linode takes them; a set changing one
record or adding one; a firewall rule as typed; the rules applied in order (the first that matches decides, else the
policy) to say what a change opens to the whole internet or which SSH it ends. No stand-in needed: nothing is sent."""
from __future__ import annotations

import ipaddress

import pytest

from conftest import SSH_ALL, SSH_HOME, WEB, rules_of
from plugin_platform_linode import firewall as fw
from plugin_platform_linode import records as rec
from plugin_platform_linode.refusal import Refusal

ZONE = [{"id": 1, "type": "A", "name": "", "target": "203.0.113.10", "ttl_sec": 3600},
        {"id": 2, "type": "TXT", "name": "", "target": "v=spf1 -all", "ttl_sec": 0},
        {"id": 3, "type": "MX", "name": "", "target": "mail.example.com", "ttl_sec": 0, "priority": 10}]


def test_a_host_and_a_target_as_linode_takes_them():
    assert [rec.host_name(n, "example.com") for n in ("@", "", "example.com.", "Home", "home.example.com", "*.lab", "_dmarc")] \
        == ["", "", "", "home", "home", "*.lab", "_dmarc"]
    for bad in ("two words", "a..b", "-x", "x" * 101):
        with pytest.raises(ValueError):
            rec.host_name(bad, "example.com")
    assert rec.target_for("A", " 203.0.113.7 ") == "203.0.113.7" and rec.target_for("AAAA", "2001:DB8::1") == "2001:db8::1"
    assert rec.target_for("CNAME", "Other.Example.org.") == "other.example.org"
    with pytest.raises(ValueError, match="not an IPv4 address"):
        rec.target_for("A", "2001:db8::1")
    with pytest.raises(ValueError, match="not a host name"):
        rec.target_for("MX", "localhost")
    with pytest.raises(ValueError, match="one line"):
        rec.target_for("TXT", "a\nb")
    assert rec.ttl_of("") is None and rec.ttl_of("86400") == 86400
    with pytest.raises(ValueError, match="one of Linode's"):
        rec.ttl_of(60)


def test_a_set_changes_one_record_or_adds_one():
    c = rec.plan_set("example.com", ZONE, "@", "A", "203.0.113.11")
    assert (c.method, c.record_id, c.body) == ("PUT", 1, {"name": "", "target": "203.0.113.11", "ttl_sec": 3600})
    assert c.words == "set @ A 203.0.113.11 in example.com (it was 203.0.113.10)"
    c = rec.plan_set("example.com", ZONE, "@", "TXT", "google-site-verification=abc", ttl=300)
    assert (c.method, c.body) == ("POST", {"type": "TXT", "name": "", "target": "google-site-verification=abc", "ttl_sec": 300})
    c = rec.plan_set("example.com", ZONE, "@", "MX", "mail.example.com", priority=20)
    assert (c.method, c.record_id, c.body) == ("PUT", 3, {"name": "", "target": "mail.example.com", "priority": 20})
    assert c.words == "@ MX mail.example.com (priority 10) in example.com: priority 20"  # its TTL left as it is (default)
    c = rec.plan_set("example.com", ZONE, "@", "TXT", "v=spf1 -all")
    assert c.nothing and c.words == "@ TXT v=spf1 -all is there already in example.com: nothing written"
    with pytest.raises(ValueError, match="a priority is an MX record's alone"):
        rec.plan_set("example.com", ZONE, "@", "A", "203.0.113.11", priority=5)
    with pytest.raises(ValueError, match="tag is one of issue, issuewild, iodef"):
        rec.plan_set("example.com", ZONE, "@", "CAA", "letsencrypt.org")
    with pytest.raises(ValueError, match="is not set here"):
        rec.plan_set("example.com", ZONE, "@", "SRV", "x")


def test_the_check_after_a_change_names_what_went_missing():
    change = rec.plan_set("example.com", ZONE, "@", "A", "203.0.113.11")
    after = [{**ZONE[0], "target": "203.0.113.11"}, ZONE[2]]
    rep = rec.verify(ZONE, after, change, None)
    assert rep["ok"] is False and rep["lost"] == ["@ TXT v=spf1 -all"] and rep["problems"] == []
    rep = rec.verify(ZONE, [*after, ZONE[1], {"id": 9, "type": "A", "name": "x", "target": "203.0.113.1"}], change, None)
    assert rep["ok"] is True and rep["unexpected"] == ["x A 203.0.113.1"] and rep["kept"] == 2


def test_a_rule_as_typed():
    assert fw.rule_of("accept", "tcp", "22, 80-81", "203.0.113.7 2001:db8::/32", "ssh-web", "both") == {
        "action": "ACCEPT", "protocol": "TCP", "ports": "22, 80-81",
        "addresses": {"ipv4": ["203.0.113.7/32"], "ipv6": ["2001:db8::/32"]}, "label": "ssh-web", "description": "both"}
    assert fw.rule_of("DROP", "ALL", "", "0.0.0.0/0") == {"action": "DROP", "protocol": "ALL",
                                                          "addresses": {"ipv4": ["0.0.0.0/0"]}}
    for bad in (("ACCEPT", "TCP", "022", "0.0.0.0/0"), ("ACCEPT", "TCP", "70000", "0.0.0.0/0"),
                ("ACCEPT", "TCP", "90-80", "0.0.0.0/0"), ("ACCEPT", "ICMP", "22", "0.0.0.0/0"),
                ("ACCEPT", "TCP", "22", ""), ("ALLOW", "TCP", "22", "0.0.0.0/0"), ("ACCEPT", "SCTP", "", "0.0.0.0/0")):
        with pytest.raises(ValueError):
            fw.rule_of(*bad)
    with pytest.raises(ValueError, match="3 to 32 characters"):
        fw.rule_of("ACCEPT", "TCP", "22", "0.0.0.0/0", "ab")


def test_the_rules_apply_in_order_and_the_policy_decides_the_rest():
    every4 = ipaddress.ip_network("0.0.0.0/0")
    home = ipaddress.ip_network("203.0.113.7/32")
    drop_all = {"action": "DROP", "protocol": "TCP", "addresses": {"ipv4": ["0.0.0.0/0"]}}
    assert fw.verdict([SSH_HOME], "DROP", home) == "ACCEPT" and fw.verdict([SSH_HOME], "DROP", every4) == "DROP"
    assert fw.verdict([drop_all, SSH_HOME], "ACCEPT", home) == "DROP"  # the first that matches decides
    assert fw.verdict([WEB], "ACCEPT", home) == "ACCEPT" and fw.verdict([WEB], "DROP", home, port=443) == "ACCEPT"
    assert fw.covers({"protocol": "ALL"}) and not fw.covers({"protocol": "UDP", "ports": "22"})
    assert fw.every_port({"protocol": "TCP", "ports": "1-65535"}) and not fw.every_port(WEB)


def with_inbound(rules: dict, *inbound) -> dict:
    return {**rules, "inbound": list(inbound)}


def test_what_a_change_opens_to_the_whole_internet_is_weighed_before_and_after_it():
    home = rules_of([SSH_HOME])  # policy DROP: the internet reaches nothing
    assert fw.exposed(home) == []
    wide = fw.rule_of("ACCEPT", "TCP", "22", "0.0.0.0/0")
    assert fw.opened(home, with_inbound(home, SSH_HOME, wide)) == ["SSH (22)"]
    assert fw.opened(rules_of([SSH_ALL]), with_inbound(rules_of([SSH_ALL]), SSH_ALL, wide)) == []  # open already: nothing
    every = fw.opened(home, with_inbound(home, SSH_HOME, fw.rule_of("ACCEPT", "ALL", None, "::/0")))
    assert every[:3] == ["every TCP port", "every UDP port", "SSH (22)"] and "RDP (3389)" in every
    assert fw.opened_words(every) == "every TCP port (SSH among them) and every UDP port"
    assert fw.opened(home, with_inbound(home, SSH_HOME, fw.rule_of("ACCEPT", "TCP", "1-65535", "0.0.0.0/0")))[0] == \
        "every TCP port"  # every port named by a rule is every port too
    assert fw.opened(home, with_inbound(home, SSH_HOME, fw.rule_of("ACCEPT", "TCP", "22", "198.51.100.0/24"))) == []
    # the ports servers are broken into through: RDP, Docker, a database (the audit: asked once before); a web port is not
    for port, words in (("3389", "RDP (3389)"), ("2375", "Docker (2375)"), ("3306", "MySQL (3306)"), ("27017", "MongoDB (27017)")):
        assert fw.opened(home, with_inbound(home, SSH_HOME, fw.rule_of("ACCEPT", "TCP", port, "0.0.0.0/0"))) == [words]
    assert fw.opened(home, with_inbound(home, SSH_HOME, fw.rule_of("ACCEPT", "TCP", "80, 443", "0.0.0.0/0, ::/0"))) == []
    # removing a DROP opens what it kept closed (the audit's two cases), weighed by the policy and the rules left
    drop22 = fw.rule_of("DROP", "TCP", "22", "0.0.0.0/0, ::/0")
    allow_all = fw.rule_of("ACCEPT", "ALL", None, "0.0.0.0/0, ::/0")
    shut = rules_of([drop22], inbound_policy="ACCEPT")
    assert fw.opened(shut, with_inbound(shut)) == ["every TCP port", "SSH (22)"]
    shut = rules_of([drop22, allow_all])
    assert fw.opened(shut, with_inbound(shut, allow_all)) == ["every TCP port", "SSH (22)"]
    assert fw.opened(shut, with_inbound(shut, drop22, allow_all, wide)) == []  # the DROP still first: nothing more
    probes = fw.nets_of(SSH_HOME)
    assert fw.ssh_lost([SSH_HOME], [], "DROP", probes) == ["203.0.113.7/32"]
    assert fw.ssh_lost([SSH_HOME], [], "ACCEPT", probes) == []  # the policy lets it in still
    assert fw.ssh_lost([SSH_HOME, SSH_ALL], [SSH_ALL], "DROP", probes) == []  # another rule lets it in still


def test_a_removal_names_its_rule_and_refuses_one_that_moved():
    rules = rules_of([SSH_ALL, WEB])
    f = {"id": 9, "label": "web-fw", "status": "enabled", "entities": [{"id": 11, "label": "web-1", "type": "linode"}]}
    new, said, risk = fw.plan_remove(rules, "inbound", 2, f, "web-fw", "ACCEPT TCP 80, 443 from 0.0.0.0/0, ::/0 (web)")
    assert new["inbound"] == [SSH_ALL] and risk is None and said.startswith("removed the inbound rule 2 of web-fw")
    with pytest.raises(Refusal, match="the rules changed since they were read"):
        fw.plan_remove(rules, "inbound", 1, f, "web-fw", "ACCEPT TCP 80, 443 from 0.0.0.0/0, ::/0 (web)")
    with pytest.raises(Refusal, match="has no inbound rule 3"):
        fw.plan_remove(rules, "inbound", 3, f, "web-fw", "ACCEPT TCP 22 from 0.0.0.0/0, ::/0 (ssh)")
    with pytest.raises(ValueError, match="name the rule as it was shown"):
        fw.plan_remove(rules, "inbound", 1, f, "web-fw")  # what was shown is needed
    ssh = fw.words(SSH_ALL)
    new, _, risk = fw.plan_remove(rules, "inbound", 1, f, "web-fw", ssh)
    assert risk == ("the change ends SSH (22) from 0.0.0.0/0, ::/0 to web-1, which web-fw let in: you may lock yourself "
                    "out of them")
    new, _, risk = fw.plan_remove(rules, "inbound", 1, {**f, "entities": []}, "web-fw", ssh)
    assert risk is None  # it guards no Linode: no SSH to lose
    # a DROP removed: what it kept closed is opened, said whatever the rule
    shut = rules_of([fw.rule_of("DROP", "TCP", "22", "0.0.0.0/0, ::/0")], inbound_policy="ACCEPT")
    _, _, risk = fw.plan_remove(shut, "inbound", 1, f, "web-fw", "DROP TCP 22 from 0.0.0.0/0, ::/0")
    assert risk == "the change opens every TCP port (SSH among them) to the whole internet on web-fw (it guards web-1)"
    _, _, risk = fw.plan_remove(shut, "inbound", 1, {**f, "status": "disabled"}, "web-fw", "DROP TCP 22 from 0.0.0.0/0, ::/0")
    assert risk.endswith("(web-fw is disabled now: so once it is enabled)")
    full = rules_of([WEB] * 25)
    with pytest.raises(Refusal, match="at most 25"):
        fw.plan_add(full, "outbound", fw.rule_of("DROP", "TCP", "25", "0.0.0.0/0"), f, "web-fw")
    with pytest.raises(Refusal, match="has this inbound rule already"):
        fw.plan_add(rules, "inbound", dict(WEB), f, "web-fw")


def test_rules_are_written_back_as_read_with_their_empty_parts_left_out():
    read = {"action": "ACCEPT", "protocol": "ICMP", "ports": None, "addresses": {"ipv4": ["0.0.0.0/0"], "ipv6": []},
            "label": "", "description": None}
    assert fw.clean(read) == {"action": "ACCEPT", "protocol": "ICMP", "addresses": {"ipv4": ["0.0.0.0/0"]}}
    body = fw.body_of({**rules_of([read]), "fingerprint": "x", "version": 9})
    assert set(body) == {"inbound", "outbound", "inbound_policy", "outbound_policy"}  # fingerprint and version: read only
