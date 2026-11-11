"""Dynamic DNS through Linode's DNS Manager (the library's Keeper, liminal-libs 1.49.2; Linode's records the provider's
side), over the stand-ins. The keeper changes only what is its own (an audit, 2026-11-11: a host listed in the settings had
its live record pointed at home within a minute, unasked): a host with no A record is made, one already pointing here or at
the address it set last is kept current (after a restart too: its state file), and one holding another address, or
several, is left as it is with a Take over… on the page until the user takes it over; several addresses are never cut to
one unasked. Update DNS now is confirmed; a pass ends once the plugin is detached; a CNAME host gets no A beside it."""
from __future__ import annotations

import json
import threading

import pytest

from conftest import HOME, FakeLinode, forms_of, page_args, settings_of, table
from plugin_platform_linode.ddns import PUBLIC_IPV4, state_path
from plugin_platform_linode.refusal import Refusal

HOME2 = "93.184.216.35"  # this network's address after it changed


def a_records(fake, name: str) -> list[str]:
    return [r["target"] for r in fake.records[1] if r["type"] == "A" and r["name"] == name]


def test_a_host_holding_another_address_is_left_as_it_is_and_offers_take_over(made, env):
    env(settings_of(ddns="home.example.com, lab.example.com, @.example.com, x.example.net, nowhere.example.org"))
    fake = FakeLinode()
    fake.records[1][0]["target"] = HOME  # the domain itself points here already: its own from now on
    p, fake = made(fake)
    states = {s["host"]: s for s in p.ddns_update(force=False)}
    assert fake.writes() == [  # only the missing host made: the live record at home.example.com left as it is
        ("POST", "/v4/domains/1/records", {"type": "A", "name": "lab", "target": HOME, "ttl_sec": 300})]
    assert states["home.example.com"]["result"] == ("holds 198.51.100.7, not this network's address: left as it is "
                                                    "(Take over… to point it here)")
    assert states["home.example.com"]["foreign"] and states["home.example.com"]["ok"] is False
    assert states["lab.example.com"]["result"] == "made (was none)" and states["example.com"]["result"] == "current"
    st = p.status()
    assert "x.example.net is in none of the account's domains (LINODE_DDNS_HOSTS)" in st["problem"]  # a slave: not kept
    assert "home.example.com: holds 198.51.100.7, not this network's address" in st["problem"]
    rows = table(st, "Dynamic DNS")["rows"]
    assert [r[0] for r in rows] == ["home.example.com", "lab.example.com", "example.com"]
    assert rows[0][1] == "198.51.100.7" and rows[0][5] == {"form": "ddns-take", "title": "Take over…",
                                                          "label": "Take over home.example.com",
                                                          "values": {"host": "home.example.com", "holds": "198.51.100.7"}}
    assert rows[1][5] == "" and rows[2][5] == ""  # its own: nothing to take over
    forms = forms_of(st)
    assert forms["ddns-take"]["hook"] == "ddns_take_over" and forms["ddns-take"]["confirm"]["danger"] is True
    assert [x["name"] for x in forms["ddns-take"]["fields"]] == ["host", "holds"]
    assert forms["ddns-now"]["hook"] == "ddns_update" and forms["ddns-now"]["fields"] == []
    assert {"form": "ddns-now", "title": "Update DNS now",
            "note": "the Dynamic DNS hosts of its own set now to this network's address, once confirmed"} in st["actions"]
    assert not any(a.get("hook") == "ddns_update" for a in st["actions"])  # no write on one click any more
    calls = len(fake.writes())
    p.ddns_update(force=True)  # Update DNS now, confirmed: its own hosts set, the other still left as it is
    assert [w[0] for w in fake.writes()[calls:]] == ["PUT", "PUT"] and a_records(fake, "home") == ["198.51.100.7"]


def test_take_over_then_a_pass_sets_it_and_a_stale_take_over_is_refused(made, env):
    env(settings_of(ddns="home.example.com"))
    p, fake = made()
    p.ddns_update(force=False)
    st = p.status()
    take = forms_of(st)["ddns-take"]
    row = table(st, "Dynamic DNS")["rows"][0]
    fake.records[1][-1]["target"] = "198.51.100.8"  # changed elsewhere since the page read it
    with pytest.raises(Refusal, match="holds 198.51.100.8 now, not 198.51.100.7: look at it again; nothing is taken over"):
        p.ask(take["hook"], *page_args(take, row[5]["values"]))
    assert fake.writes() == [] and not p.keeper().taken("home.example.com")
    fake.records[1][-1]["target"] = "198.51.100.7"
    (state,) = p.ask(take["hook"], *page_args(take, row[5]["values"]))
    assert fake.writes() == [("PUT", "/v4/domains/1/records/104", {"name": "home", "target": HOME, "ttl_sec": 300})]
    assert state["result"] == "set (was 198.51.100.7)" and a_records(fake, "home") == [HOME]
    with pytest.raises(ValueError, match="is not one of LINODE_DDNS_HOSTS"):
        p.ddns_take_over("www.example.com")
    saved = json.loads(state_path().read_text(encoding="utf-8"))
    assert saved == {"own": {"home.example.com": HOME}, "taken": ["home.example.com"]}


def test_a_host_with_several_addresses_is_never_cut_to_one_unless_taken_over(made, env):
    env(settings_of(ddns="home.example.com"))
    fake = FakeLinode()
    fake.records[1].append({"id": 105, "type": "A", "name": "home", "target": "198.51.100.8", "ttl_sec": 300})
    p, fake = made(fake)
    (state,) = p.ddns_update(force=True)
    assert state["foreign"] and state["result"].startswith("holds 2 addresses (198.51.100.7, 198.51.100.8)")
    assert fake.writes() == [] and a_records(fake, "home") == ["198.51.100.7", "198.51.100.8"]
    (state,) = p.ddns_take_over("home.example.com", "198.51.100.7, 198.51.100.8")  # the page's Take over…, confirmed
    assert fake.writes() == [("PUT", "/v4/domains/1/records/104", {"name": "home", "target": HOME, "ttl_sec": 300}),
                             ("DELETE", "/v4/domains/1/records/105", None)]  # one address: this network's
    assert state["result"] == "set, 1 other A record removed (was 198.51.100.7, 198.51.100.8)"
    assert a_records(fake, "home") == [HOME]


def test_its_own_old_address_is_updated_after_the_networks_address_changed_after_a_restart_too(made, env):
    env(settings_of(ddns="lab.example.com"))
    p, fake = made()
    p.ddns_update(force=False)
    assert a_records(fake, "lab") == [HOME]  # made: its own
    p2, _ = made(fake, public=(HOME2, "OpenDNS"))  # the platform started again, the network's address moved
    (state,) = p2.ddns_update(force=False)
    assert fake.writes()[-1][0] == "PUT" and a_records(fake, "lab") == [HOME2]
    assert state["result"] == f"set (was {HOME})" and p2.keeper().own("lab.example.com") == HOME2


def test_a_host_taken_out_of_the_settings_is_let_go(made, env, monkeypatch):
    env(settings_of(ddns="home.example.com"))
    p, fake = made()
    p.ddns_update(force=False)
    p.ddns_take_over("home.example.com", "198.51.100.7")
    assert p.keeper().taken("home.example.com")
    monkeypatch.setenv("LINODE_DDNS_HOSTS", "lab.example.com")
    p.ddns_update(force=False)
    assert not p.keeper().taken("home.example.com") and p.keeper().own("home.example.com") is None
    # a fresh start lets go what its state file held of a host no longer set
    monkeypatch.setenv("LINODE_DDNS_HOSTS", "home.example.com")
    p.ddns_take_over("home.example.com", HOME)
    monkeypatch.setenv("LINODE_DDNS_HOSTS", "lab.example.com")
    again, _ = made(fake)
    assert again.keeper().taken("home.example.com")
    again.ddns_update(force=False)
    assert not again.keeper().taken("home.example.com")


def test_a_cname_host_gets_no_a_record_beside_it(made, env):
    env(settings_of(ddns="www.example.com"))
    p, fake = made()
    (state,) = p.ddns_update(force=True)
    assert state["ok"] is False and state["result"].startswith(
        "its record could not be read: www.example.com is a CNAME (to example.com)") and fake.writes() == []
    with pytest.raises(ValueError, match="is a CNAME"):
        p.ddns_take_over("www.example.com", "")


def test_a_pass_writes_nothing_once_the_plugin_is_detached(made, env):
    env(settings_of(ddns="lab.example.com"))
    p, fake = made()
    stop = threading.Event()
    stop.set()
    assert p._ddns_pass(p.config(fresh=True), force=False, stop=stop) == [] and fake.requests == []  # nothing asked


def test_without_this_networks_address_nothing_is_set(made, env):
    env(settings_of(ddns="lab.example.com"))
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
    with pytest.raises(ValueError, match="Dynamic DNS is not set up"):
        p.ddns_take_over("home.example.com")
