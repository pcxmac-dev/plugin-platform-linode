"""Dynamic DNS through Linode's DNS Manager (the library's Keeper, Linode's records as the provider's side), over the
stand-ins: a host's A record set only where it differs from this network's address (every one with Update DNS now), one
made where the host has none, a host of no master domain said, nothing set without an address."""
from __future__ import annotations

import pytest

from conftest import HOME, FakeLinode, settings_of, table
from plugin_platform_linode.ddns import PUBLIC_IPV4


def test_a_pass_sets_only_the_hosts_that_differ_and_makes_a_missing_one(made, env):
    env(settings_of(ddns="home.example.com, lab.example.com, @.example.com, x.example.net, nowhere.example.org"))
    fake = FakeLinode()
    fake.records[1][0]["target"] = HOME  # the domain itself is here already
    p, fake = made(fake)
    states = {s["host"]: s for s in p.ddns_update(force=False)}
    assert fake.writes() == [
        ("PUT", "/v4/domains/1/records/104", {"name": "home", "target": HOME, "ttl_sec": 300}),  # its TTL kept
        ("POST", "/v4/domains/1/records", {"type": "A", "name": "lab", "target": HOME, "ttl_sec": 300}),  # made
    ]
    assert states["home.example.com"]["result"] == "set (was 198.51.100.7)" and states["home.example.com"]["ok"]
    assert states["lab.example.com"]["result"] == "made (was none)"
    assert states["example.com"]["result"] == "current" and set(states) == {"home.example.com", "lab.example.com", "example.com"}
    st = p.status()
    assert "x.example.net is in none of the account's domains (LINODE_DDNS_HOSTS)" in st["problem"]  # a slave: not kept
    assert "nowhere.example.org is in none of the account's domains" in st["problem"]
    rows = table(st, "Dynamic DNS")["rows"]
    assert [r[0] for r in rows] == ["home.example.com", "lab.example.com", "example.com"] and all(r[1] == HOME for r in rows)
    assert "through Linode's DNS Manager" in table(st, "Dynamic DNS")["note"]
    calls = len(fake.writes())
    states = {s["host"]: s["result"] for s in p.ddns_update(force=False)}
    assert len(fake.writes()) == calls and set(states.values()) == {"current"}  # all current: nothing set
    p.ddns_update(force=True)  # Update DNS now: every host's record set
    assert [w[0] for w in fake.writes()[calls:]] == ["PUT", "PUT", "PUT"]


def test_a_host_with_several_a_records_is_left_as_it_is_and_said(made, env):
    env(settings_of(ddns="home.example.com"))
    fake = FakeLinode()
    fake.records[1].append({"id": 105, "type": "A", "name": "home", "target": "198.51.100.8", "ttl_sec": 300})
    p, fake = made(fake)
    (state,) = p.ddns_update(force=False)
    assert state["ok"] is False and "holds 2 A records" in state["result"] and fake.writes() == []
    assert "home.example.com: not updated: home.example.com holds 2 A records" in p.status()["problem"]


def test_without_this_networks_address_nothing_is_set(made, env):
    env(settings_of(ddns="home.example.com"))
    p, fake = made(public=(None, "neither OpenDNS nor Google answered with a public IPv4 address"))
    (state,) = p.ddns_update(force=True)
    assert state["ok"] is False and state["result"].startswith("this network's address was not found: neither OpenDNS")
    assert fake.writes() == []


def test_the_public_address_is_asked_of_the_name_servers_the_plugin_names():
    assert PUBLIC_IPV4 == (("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),
                           ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"))


def test_a_record_change_at_a_dynamic_dns_host_says_the_next_check_keeps_it_here(made, env):
    env(settings_of(ddns="home.example.com"))
    p, fake = made()
    p.refresh()
    rep = p.set_record("example.com", "home", "A", "203.0.113.8")
    assert rep["lines"][-1] == ("home.example.com is a Dynamic DNS host (LINODE_DDNS_HOSTS): its next check keeps it at "
                                "this network's address")
    rep = p.set_record("example.com", "blog", "A", "203.0.113.8")
    assert not any("Dynamic DNS host" in line for line in rep["lines"])


def test_not_set_up_it_refuses(made, env):
    env(settings_of())
    p, _ = made()
    with pytest.raises(ValueError, match="Dynamic DNS is not set up"):
        p.ddns_update()
