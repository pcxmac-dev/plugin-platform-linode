"""The platform's page makes the free changes through the plugin's forms (liminal-platform 0.6.0 draws status.forms): the
fields the hooks' arguments in order, each change confirmed by the user with the exact change named, a risky firewall
change made only once the user has accepted that too (a second confirmation, offered when the change is refused for it).
Each hook sends exactly the request Linode's reference gives (method, path, body), and nothing else. Over the stand-ins."""
from __future__ import annotations

import inspect
import re

import pytest

from conftest import HOME, SSH_ALL, SSH_HOME, WEB, forms_of, page_args, pub, rules_of, settings_of, table
from plugin_platform_linode import BILLS_OFF
from plugin_platform_linode.firewall import ACCEPT_RISK
from plugin_platform_linode.refusal import Refusal

FIELD_TYPES = ("text", "number", "choice", "fixed", "accept")


@pytest.fixture
def ready(made, env):
    env(settings_of())
    p, fake = made()
    p.refresh()
    return p, fake


def test_the_forms_name_the_hooks_arguments_in_order_and_the_change_in_their_confirmation(ready):
    p, fake = ready
    forms = forms_of(p.status())
    assert list(forms) == ["power:boot", "power:shutdown", "power:reboot", "record-set:1", "record-remove:1",
                           "rule-add:8", "rule-remove:8", "rule-add:9", "rule-remove:9", "sshkey-add", "sshkey-remove"]
    hooks = p.interface()["hooks"]
    for f in forms.values():
        assert f["hook"] in hooks
        assert [x["name"] for x in f["fields"]] == list(inspect.signature(getattr(p, f["hook"])).parameters)  # in order
        assert all(x["type"] in FIELD_TYPES for x in f["fields"]) and f["confirm"]["title"] and f["confirm"]["yes"]
    assert "{linode}" in forms["power:shutdown"]["confirm"]["words"] and BILLS_OFF in forms["power:shutdown"]["confirm"]["words"]
    assert forms["power:shutdown"]["confirm"]["danger"] is True and forms["power:boot"]["confirm"]["danger"] is False
    assert "Booting starts no new charge: a Linode bills the same" in forms["power:boot"]["confirm"]["words"]
    assert "that record is changed to this one and what it held is dropped" in forms["record-set:1"]["confirm"]["words"]
    assert "{name} {rtype} {target}" in forms["record-set:1"]["confirm"]["words"]
    assert "Every other record is kept" in forms["record-remove:1"]["confirm"]["words"]
    for fid in ("rule-add:9", "rule-remove:9"):
        f = forms[fid]
        assert "nothing is written if they are not version 3 any more" in f["confirm"]["words"]
        (accept,) = [x for x in f["fields"] if x["type"] == "accept"]
        assert accept["name"] == ACCEPT_RISK and accept["yes"] == "Change it anyway" and "{firewall}" in accept["words"]
        seen = next(x for x in f["fields"] if x["name"] == "seen")
        assert seen["type"] == "fixed" and seen["value"] == fake.firewalls[0]["rules"]["fingerprint"]
    assert next(x for x in forms["rule-add:9"]["fields"] if x["name"] == "ports")["when"] == {"protocol": ["TCP", "UDP"]}
    assert fake.writes() == []  # drawn: nothing written


def test_power_boot_shutdown_and_reboot_send_exactly_the_references_requests(ready):
    p, fake = ready
    forms = forms_of(p.status())
    web = table(p.status(), "Linodes")["rows"][1]
    shutdown = forms[web[9]["form"]]
    rep = p.ask(shutdown["hook"], *page_args(shutdown, web[9]["values"]))
    assert fake.writes() == [("POST", "/v4/linode/instances/11/shutdown", None)]  # no body: the reference documents none
    assert fake.paths()[-2:] == ["/v4/linode/instances/11", "/v4/linode/instances/11"]  # its state before and after
    assert rep["said"] == "Shut down asked of web-1: shutting down" and rep["lines"] == [
        "Linode says it is shutting down now", BILLS_OFF]
    assert table(p.status(), "Linodes")["rows"][1][1] == "shutting down"  # kept as read after it
    db = table(p.status(), "Linodes")["rows"][0]
    boot = forms[db[9]["form"]]
    assert page_args(boot, db[9]["values"]) == [12, "boot"]
    p.ask(boot["hook"], *page_args(boot, db[9]["values"]))
    assert fake.writes()[-1] == ("POST", "/v4/linode/instances/12/boot", None)
    fake.linodes[1]["status"] = "running"
    p.power("db-1", "reboot")
    assert fake.writes()[-1] == ("POST", "/v4/linode/instances/12/reboot", None)
    # refused, nothing sent: so already, or busy
    calls = len(fake.writes())
    with pytest.raises(Refusal, match="rebooting already"):
        p.power(12, "boot")
    with pytest.raises(Refusal, match="a reboot is for a running Linode"):
        p.power(11, "reboot")
    with pytest.raises(ValueError, match="no power change"):
        p.power(11, "destroy")
    assert len(fake.writes()) == calls


def test_a_record_set_makes_or_changes_one_record_and_keeps_every_other(ready):
    p, fake = ready
    form = forms_of(p.status())["record-set:1"]
    others = [dict(r) for r in fake.records[1]]
    args = page_args(form, {"name": "blog", "rtype": "A", "target": "203.0.113.7"})
    assert args == [1, "blog", "A", "203.0.113.7", None, None, None]  # TTL left to Linode, no priority or tag for an A
    rep = p.ask(form["hook"], *args)
    assert fake.writes() == [("POST", "/v4/domains/1/records", {"type": "A", "name": "blog", "target": "203.0.113.7"})]
    assert rep["ok"] and rep["said"] == "added blog A 203.0.113.7 to example.com"
    assert rep["lines"] == ["read back: the record as written; the other 5 records of example.com kept"]
    assert fake.records[1][:5] == others  # every other record as it was
    # the host's A record there: changed in place, its TTL kept
    p.ask(form["hook"], *page_args(form, {"name": "home", "rtype": "A", "target": "203.0.113.8"}))
    assert fake.writes()[-1] == ("PUT", "/v4/domains/1/records/104", {"name": "home", "target": "203.0.113.8", "ttl_sec": 300})
    p.ask(form["hook"], *page_args(form, {"name": "home.example.com", "rtype": "A", "target": "203.0.113.8", "ttl": "3600"}))
    assert fake.writes()[-1] == ("PUT", "/v4/domains/1/records/104", {"name": "home", "target": "203.0.113.8", "ttl_sec": 3600})
    # added beside the others: an MX with its priority (10 unless given), a TXT, a CAA with its tag
    p.ask(form["hook"], *page_args(form, {"name": "@", "rtype": "MX", "target": "mail2.example.com.", "priority": ""}))
    assert fake.writes()[-1] == ("POST", "/v4/domains/1/records",
                                 {"type": "MX", "name": "", "target": "mail2.example.com", "priority": 10})
    p.ask(form["hook"], *page_args(form, {"name": "_dmarc", "rtype": "TXT", "target": "v=DMARC1; p=none"}))
    assert fake.writes()[-1] == ("POST", "/v4/domains/1/records", {"type": "TXT", "name": "_dmarc", "target": "v=DMARC1; p=none"})
    p.ask(form["hook"], *page_args(form, {"name": "@", "rtype": "CAA", "target": "letsencrypt.org", "tag": "issue"}))
    assert fake.writes()[-1] == ("POST", "/v4/domains/1/records",
                                 {"type": "CAA", "name": "", "target": "letsencrypt.org", "tag": "issue"})
    # there already: nothing written; refused before anything is sent
    calls = len(fake.writes())
    rep = p.ask(form["hook"], *page_args(form, {"name": "@", "rtype": "TXT", "target": "v=spf1 mx -all"}))
    assert rep["changed"] is False and "is there already" in rep["said"] and rep["lines"] == []
    with pytest.raises(Refusal, match="no CNAME at example.com itself"):
        p.ask(form["hook"], *page_args(form, {"name": "@", "rtype": "CNAME", "target": "other.example.org"}))
    with pytest.raises(Refusal, match="www.example.com is a CNAME"):
        p.ask(form["hook"], *page_args(form, {"name": "www", "rtype": "A", "target": HOME}))
    with pytest.raises(ValueError, match="not an IPv4 address"):
        p.ask(form["hook"], *page_args(form, {"name": "home", "rtype": "A", "target": "not-an-address"}))
    with pytest.raises(ValueError, match="the TTL is one of Linode's"):
        p.set_record("example.com", "home", "A", HOME, ttl=600)
    with pytest.raises(Refusal, match="is a slave domain"):
        p.set_record("example.net", "home", "A", HOME)
    assert len(fake.writes()) == calls


def test_a_set_over_a_host_with_several_a_records_is_refused(ready):
    p, fake = ready
    fake.records[1].append({"id": 105, "type": "A", "name": "home", "target": "198.51.100.8", "ttl_sec": 300})
    with pytest.raises(Refusal, match="holds 2 A records"):
        p.set_record("example.com", "home", "A", HOME)
    assert fake.writes() == []


def test_a_records_remove_deletes_that_record_alone_and_refuses_one_changed_meanwhile(ready):
    p, fake = ready
    st = p.status()
    form = forms_of(st)["record-remove:1"]
    row = next(r for r in table(st, "example.com records")["rows"] if r[1] == "TXT")
    assert row[-1]["values"] == {"record": 102, "name": "@", "rtype": "TXT", "target": "v=spf1 mx -all"}
    assert page_args(form, row[-1]["values"]) == [1, 102, "@", "TXT", "v=spf1 mx -all"]
    rep = p.ask(form["hook"], *page_args(form, row[-1]["values"]))
    assert fake.writes() == [("DELETE", "/v4/domains/1/records/102", None)]
    assert rep["ok"] and rep["lines"] == ["read back: the record gone; the other 4 records of example.com kept"]
    assert [r["id"] for r in fake.records[1]] == [100, 101, 103, 104]
    home = next(r for r in table(p.status(), "example.com records")["rows"] if r[0] == "home")
    fake.records[1][-1]["target"] = "198.51.100.99"  # changed in Cloud Manager since the page read it
    with pytest.raises(Refusal, match="changed since it was read"):
        p.ask(form["hook"], *page_args(form, home[-1]["values"]))
    with pytest.raises(Refusal, match="no record 102 any more"):
        p.remove_record("example.com", 102, "@", "TXT", "v=spf1 mx -all")
    with pytest.raises(ValueError, match="name the record as it was shown"):
        p.remove_record("example.com", 104)  # its host, type and target as shown are needed: never removed unseen
    assert len(fake.writes()) == 1


def test_a_rule_added_writes_back_every_other_rule_and_the_policies_as_read(ready):
    p, fake = ready
    form = forms_of(p.status())["rule-add:9"]
    args = page_args(form, {"direction": "inbound", "action": "ACCEPT", "protocol": "TCP", "ports": "8080, 8443",
                            "addresses": "203.0.113.0/24, 2001:db8::/32", "label": "admin", "description": ""})
    fp = fake.firewalls[0]["rules"]["fingerprint"]
    assert args == [9, fp, "inbound", "ACCEPT", "TCP", "8080, 8443", "203.0.113.0/24, 2001:db8::/32", "admin", None, False]
    rep = p.ask(form["hook"], *args)
    new = {"action": "ACCEPT", "protocol": "TCP", "ports": "8080, 8443",
           "addresses": {"ipv4": ["203.0.113.0/24"], "ipv6": ["2001:db8::/32"]}, "label": "admin"}
    assert fake.writes() == [("PUT", "/v4/networking/firewalls/9/rules",
                              {"inbound": [SSH_ALL, WEB, new], "outbound": [], "inbound_policy": "DROP",
                               "outbound_policy": "ACCEPT"})]
    assert fake.paths()[-1] == "/v4/networking/firewalls/9/rules"  # read fresh just before
    assert rep["ok"] and rep["said"] == ("added the inbound rule ACCEPT TCP 8080, 8443 from 203.0.113.0/24, 2001:db8::/32 "
                                         "(admin) to web-fw (after its other inbound rules)")
    assert rep["lines"][0].startswith("written: version 3 to 4 (fingerprint ") and rep["version"] == 4
    rules = table(p.status(), "web-fw rules")
    assert len(rules["rows"]) == 3 and "version 4" in rules["note"]  # the page draws the rules as written
    # an ICMP rule takes no ports (the form hides the field: sent as null), and an outbound one goes after the outbound rules
    form = forms_of(p.status())["rule-add:9"]
    p.ask(form["hook"], *page_args(form, {"direction": "outbound", "action": "DROP", "protocol": "ICMP", "ports": "22",
                                          "addresses": "0.0.0.0/0", "label": "", "description": "no pings out"}))
    assert fake.writes()[-1][2]["outbound"] == [{"action": "DROP", "protocol": "ICMP", "addresses": {"ipv4": ["0.0.0.0/0"]},
                                                 "description": "no pings out"}]
    seen = fake.firewalls[0]["rules"]["fingerprint"]
    with pytest.raises(ValueError, match="has bits set below its mask"):
        p.add_rule(9, seen, "inbound", "ACCEPT", "TCP", "22", "203.0.113.7/24")
    with pytest.raises(ValueError, match="at most 15 ports"):
        p.add_rule(9, seen, "inbound", "ACCEPT", "TCP", ",".join(str(1000 + i) for i in range(16)), "203.0.113.7")
    calls = len(fake.requests)
    with pytest.raises(ValueError, match=r"the rules' fingerprint as they were shown \(seen\) is needed"):
        p.add_rule(9, None, "inbound", "ACCEPT", "TCP", "8080", "203.0.113.9")
    with pytest.raises(ValueError, match="name the rule as it was shown"):
        p.remove_rule(9, seen, "inbound", 1)
    assert len(fake.requests) == calls  # refused before anything is asked


def test_a_rule_opening_ssh_or_every_port_to_the_internet_is_refused_until_accepted(ready):
    p, fake = ready
    form = forms_of(p.status())["rule-add:8"]  # db-fw lets SSH in from one address, its policy DROP
    values = {"direction": "inbound", "action": "ACCEPT", "protocol": "TCP", "ports": "22", "addresses": "0.0.0.0/0, ::/0"}
    with pytest.raises(Refusal, match=r"opens SSH \(22\) to the whole internet on db-fw \(it guards db-1\)") as refused:
        p.ask(form["hook"], *page_args(form, values))
    assert refused.value.accept == ACCEPT_RISK and fake.writes() == []  # the argument the page's second confirmation sets
    with pytest.raises(Refusal, match=r"opens every TCP port \(SSH among them\) and every UDP port"):
        p.ask(form["hook"], *page_args(form, {**values, "protocol": "ALL", "ports": ""}))
    with pytest.raises(Refusal, match="opens every UDP port to the whole internet"):
        p.ask(form["hook"], *page_args(form, {**values, "protocol": "UDP", "ports": ""}))
    for port, words in (("3389", "RDP (3389)"), ("2375", "Docker (2375)"), ("3306", "MySQL (3306)")):  # asked twice now
        with pytest.raises(Refusal, match=f"opens {re.escape(words)} to the whole internet"):
            p.ask(form["hook"], *page_args(form, {**values, "ports": port}))
    assert fake.writes() == []
    rep = p.ask(form["hook"], *page_args(form, values, accepted={ACCEPT_RISK}))  # accepted: written
    assert fake.writes()[-1][0:2] == ("PUT", "/v4/networking/firewalls/8/rules") and rep["ok"]
    assert rep["lines"][-1] == "accepted: the change opens SSH (22) to the whole internet on db-fw (it guards db-1)"
    form = forms_of(p.status())["rule-add:8"]  # a web port opened to everyone: asked once
    p.ask(form["hook"], *page_args(form, {**values, "ports": "443"}))
    assert fake.writes()[-1][2]["inbound"][-1]["ports"] == "443"
    # where SSH is open to everyone already (web-fw), another such rule opens nothing more: asked once
    form = forms_of(p.status())["rule-add:9"]
    p.ask(form["hook"], *page_args(form, {**values, "ports": "22, 2222"}))
    assert fake.writes()[-1][1] == "/v4/networking/firewalls/9/rules"


def test_removing_the_rule_letting_ssh_in_to_an_attached_linode_is_refused_until_accepted(ready):
    p, fake = ready
    st = p.status()
    form = forms_of(st)["rule-remove:8"]
    row = table(st, "db-fw rules")["rows"][0]
    assert row[-1]["values"] == {"direction": "inbound", "position": 1,
                                 "rule": "ACCEPT TCP 22 from 203.0.113.7/32 (ssh-home)"}
    args = page_args(form, row[-1]["values"])
    with pytest.raises(Refusal, match=r"ends SSH \(22\) from 203.0.113.7/32 to db-1, which db-fw let in") as refused:
        p.ask(form["hook"], *args)
    assert refused.value.accept == ACCEPT_RISK and fake.writes() == []
    rep = p.ask(form["hook"], *page_args(form, row[-1]["values"], accepted={ACCEPT_RISK}))
    assert fake.writes() == [("PUT", "/v4/networking/firewalls/8/rules",
                              {"inbound": [], "outbound": [], "inbound_policy": "DROP", "outbound_policy": "ACCEPT"})]
    assert rep["ok"] and rep["said"] == "removed the inbound rule 1 of db-fw: ACCEPT TCP 22 from 203.0.113.7/32 (ssh-home)"
    # web-fw's web rule lets no SSH in: removed with one confirmation
    st = p.status()
    form = forms_of(st)["rule-remove:9"]
    web = table(st, "web-fw rules")["rows"][1]
    p.ask(form["hook"], *page_args(form, web[-1]["values"]))
    assert fake.writes()[-1][2]["inbound"] == [SSH_ALL]


def test_a_dropping_rule_ending_ssh_to_an_attached_linode_is_asked_twice(ready):
    p, fake = ready
    fake.firewalls[1]["rules"] = rules_of([SSH_HOME], inbound_policy="ACCEPT", version=2)
    p.refresh()
    seen = fake.firewalls[1]["rules"]["fingerprint"]
    with pytest.raises(Refusal, match=r"ends SSH \(22\) from 0.0.0.0/0 to db-1") as refused:
        p.add_rule("db-fw", seen, "inbound", "DROP", "TCP", "22", "0.0.0.0/0")
    assert refused.value.accept == ACCEPT_RISK and fake.writes() == []


def test_removing_a_drop_rule_that_kept_ssh_shut_is_asked_twice(ready):
    """The audit's case (firewall.py:318 in 0.1.0): a DROP rule removed opened SSH to the whole internet on one
    confirmation. Every change is weighed now by the policy and the rules left, before and after it."""
    p, fake = ready
    drop22 = {"action": "DROP", "protocol": "TCP", "ports": "22", "addresses": {"ipv4": ["0.0.0.0/0"], "ipv6": ["::/0"]}}
    allow_all = {"action": "ACCEPT", "protocol": "ALL", "addresses": {"ipv4": ["0.0.0.0/0"], "ipv6": ["::/0"]}}
    for inbound, policy in (([drop22], "ACCEPT"), ([drop22, allow_all], "DROP")):
        fake.firewalls[0]["rules"] = rules_of(inbound, inbound_policy=policy, version=7)
        p.refresh()
        st = p.status()
        form = forms_of(st)["rule-remove:9"]
        row = table(st, "web-fw rules")["rows"][0]
        assert row[-1]["values"]["rule"] == "DROP TCP 22 from 0.0.0.0/0, ::/0"
        with pytest.raises(Refusal, match=r"the change opens every TCP port \(SSH among them\) to the whole internet on "
                                          r"web-fw \(it guards web-1\)") as refused:
            p.ask(form["hook"], *page_args(form, row[-1]["values"]))
        assert refused.value.accept == ACCEPT_RISK and fake.writes() == []
    rep = p.ask(form["hook"], *page_args(form, row[-1]["values"], accepted={ACCEPT_RISK}))
    assert rep["ok"] and fake.writes()[-1][2]["inbound"] == [allow_all]


@pytest.mark.parametrize("open_already, opened, family, whole", [
    ("::/0", "0.0.0.0/0", "IPv4", "0.0.0.0/0"),  # all of IPv4 opened, IPv6 open already
    ("0.0.0.0/0", "::/0", "IPv6", "::/0"),  # all of IPv6 opened, IPv4 open already
    ("203.0.113.7/32", "0.0.0.0/0", "IPv4", "0.0.0.0/0"),  # all of IPv4 alone opened on a shut firewall
    ("203.0.113.7/32", "::/0", "IPv6", "::/0"),  # all of IPv6 alone opened on a shut firewall
])
def test_opening_ssh_or_every_port_to_one_family_alone_is_asked_twice(ready, open_already, opened, family, whole):
    """The re-verification: 0.1.1 merged IPv4 and IPv6, so opening one family where the other was open already went on
    one confirmation. Each family is judged on its own now, through the page's own form."""
    p, fake = ready
    fake.firewalls[1]["rules"] = rules_of([{"action": "ACCEPT", "protocol": "ALL",
                                            "addresses": {"ipv4" if "." in open_already else "ipv6": [open_already]}}],
                                          version=5)
    p.refresh()
    form = forms_of(p.status())["rule-add:8"]
    for protocol, ports, words in (("TCP", "22", "SSH (22)"), ("ALL", "", "every TCP port (SSH among them) and every UDP port")):
        values = {"direction": "inbound", "action": "ACCEPT", "protocol": protocol, "ports": ports, "addresses": opened}
        with pytest.raises(Refusal) as refused:
            p.ask(form["hook"], *page_args(form, values))
        assert refused.value.accept == ACCEPT_RISK and fake.writes() == []
        assert str(refused.value).startswith(f"the change opens {words} to all of {family} ({whole}) on db-fw (it guards db-1)")
    rep = p.ask(form["hook"], *page_args(form, values, accepted={ACCEPT_RISK}))  # the second yes: written
    assert rep["ok"] and fake.writes()[-1][1] == "/v4/networking/firewalls/8/rules"


def test_the_second_confirmation_counts_only_when_exactly_true(ready):
    """accept_risk is honoured only when it is True (the page sends JSON true): a string, a 1 or anything else from a
    local program is refused like no accept at all."""
    p, fake = ready
    seen = fake.firewalls[1]["rules"]["fingerprint"]
    for almost in ("true", "yes", "false", 1, "1", [True], {"yes": True}):
        with pytest.raises(Refusal, match="opens SSH") as refused:
            p.add_rule("db-fw", seen, "inbound", "ACCEPT", "TCP", "22", "0.0.0.0/0", accept_risk=almost)
        assert refused.value.accept == ACCEPT_RISK
    assert fake.writes() == []
    rep = p.add_rule("db-fw", seen, "inbound", "ACCEPT", "TCP", "22", "0.0.0.0/0", accept_risk=True)
    assert rep["ok"] and fake.writes()[-1][1] == "/v4/networking/firewalls/8/rules"


def test_rules_changed_since_the_page_read_them_are_never_written_over(ready):
    p, fake = ready
    form = forms_of(p.status())["rule-add:9"]
    values = {"direction": "inbound", "action": "ACCEPT", "protocol": "TCP", "ports": "8080", "addresses": "203.0.113.9"}
    fake.firewalls[0]["rules"] = rules_of([SSH_ALL], version=4)  # changed in Cloud Manager meanwhile: web removed there
    with pytest.raises(Refusal, match="the rules of web-fw changed since they were read") as refused:
        p.ask(form["hook"], *page_args(form, values))
    assert refused.value.accept is None and fake.writes() == []  # nothing the user could accept: read them again
    assert len(table(p.status(), "web-fw rules")["rows"]) == 1  # the page shows them as they are now
    rep = p.ask(form["hook"], *page_args(forms_of(p.status())["rule-add:9"], values))
    assert rep["ok"] and fake.writes()[-1][2]["inbound"][0] == SSH_ALL and len(fake.writes()[-1][2]["inbound"]) == 2


def test_a_change_landing_between_the_read_and_the_write_is_said_with_the_rules_as_they_were(ready):
    p, fake = ready

    def elsewhere(f):  # another client's write, taken between this plugin's read and its write
        f["rules"] = {**f["rules"], "version": f["rules"]["version"] + 1}
    fake.meanwhile = elsewhere
    rep = p.add_rule(9, fake.firewalls[0]["rules"]["fingerprint"], "outbound", "DROP", "TCP", "25", "0.0.0.0/0")
    assert rep["ok"] is False and rep["lines"][0].startswith("the rules went from version 3 to 5: another change was written")
    assert "  inbound 1: ACCEPT TCP 22 from 0.0.0.0/0, ::/0 (ssh)" in rep["lines"]


def test_rules_holding_a_field_this_plugin_does_not_know_are_not_written(ready):
    p, fake = ready
    fake.firewalls[0]["rules"]["inbound"][0] = {**SSH_ALL, "priority": 5}
    p.refresh()
    st = p.status()
    assert "rule-add:9" not in forms_of(st) and "not changed here" in table(st, "web-fw rules")["note"]
    with pytest.raises(Refusal, match=r"hold what this plugin does not know \(priority\)"):
        p.add_rule(9, fake.firewalls[0]["rules"]["fingerprint"], "inbound", "ACCEPT", "TCP", "8080", "203.0.113.9")
    assert fake.writes() == []


def test_an_ssh_key_is_added_and_removed_through_the_profile(ready):
    p, fake = ready
    st = p.status()
    add = forms_of(st)["sshkey-add"]
    key = pub("tester@desk", fill=2)
    rep = p.ask(add["hook"], *page_args(add, {"label": "desk", "ssh_key": "  " + key + "\n"}))
    assert fake.writes() == [("POST", "/v4/profile/sshkeys", {"label": "desk", "ssh_key": key})]
    assert rep["ok"] and rep["said"].startswith("added the ssh-ed25519 key desk (SHA256:")
    calls = len(fake.writes())
    with pytest.raises(Refusal, match="is in your profile already, as desk"):
        p.add_ssh_key("again", key)
    with pytest.raises(ValueError, match="that is a private key"):
        p.add_ssh_key("oops", "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAA -----END OPENSSH PRIVATE KEY-----")
    with pytest.raises(ValueError, match="is not a key kind Linode takes"):
        p.add_ssh_key("odd", "ssh-unknown AAAA")
    with pytest.raises(ValueError, match="is not a ssh-rsa key"):
        p.add_ssh_key("lying", key.replace("ssh-ed25519", "ssh-rsa", 1))
    assert len(fake.writes()) == calls
    st = p.status()
    remove = forms_of(st)["sshkey-remove"]
    row = next(r for r in table(st, "SSH keys")["rows"] if r[0] == "laptop")
    assert row[-1]["values"] == {"key": 5, "label": "laptop"}
    rep = p.ask(remove["hook"], *page_args(remove, row[-1]["values"]))
    assert fake.writes()[-1] == ("DELETE", "/v4/profile/sshkeys/5", None)
    assert rep["ok"] and "keep it in their authorized_keys" in rep["lines"][0]
    assert [r[0] for r in table(p.status(), "SSH keys")["rows"]] == ["desk"]
    with pytest.raises(Refusal, match="no SSH key 5 any more"):
        p.remove_ssh_key(5, "laptop")
    with pytest.raises(ValueError, match="name the key as it was shown"):
        p.remove_ssh_key(6)


def test_errors_are_worded_with_the_token_taken_out(ready):
    p, fake = ready
    from conftest import TOKEN

    fake.errors[("POST", "/v4/domains/1/records")] = (400, f"target is invalid for token {TOKEN}")
    with pytest.raises(Exception) as failed:
        p.set_record("example.com", "blog", "A", HOME)
    words = str(failed.value)
    assert TOKEN not in words and words == "POST /v4/domains/1/records: HTTP 400: target is invalid for token •••"
    fake.errors[("PUT", "/v4/networking/firewalls/9/rules")] = (403, "You do not have permission")
    with pytest.raises(Exception, match=r"HTTP 403: the token's access does not cover this .*Linode: You do not have permission"):
        p.add_rule(9, fake.firewalls[0]["rules"]["fingerprint"], "inbound", "ACCEPT", "TCP", "8080", "203.0.113.9")
