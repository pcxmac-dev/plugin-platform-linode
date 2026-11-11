"""The plugin conforms to the class contract (plugin API 2.2): liminal_libs.sources.conformance, read from the plugin alone
(nothing runs). Its API card names the calls its client really makes (each request the stand-in saw is one of the
client's reads or free writes, and those are exactly the card's calls in use), nothing billable is in the client's
source, and (LIMINAL_VENDOR_PAGES=1) every address on the card answers."""
from __future__ import annotations

import inspect
import os
import re

import pytest

import plugin_platform_linode as module
from conftest import HOME, forms_of, page_args, pub, settings_of, table
from liminal_libs.sources.apis import dead_links, problems
from liminal_libs.sources.conformance import assert_module_conforms
from plugin_platform_linode import api, card
from plugin_platform_linode.firewall import ACCEPT_RISK

V4 = "/" + api.VERSION


def test_every_plugin_here_conforms_to_the_class_contract():
    found = assert_module_conforms(module)
    assert [p.name for p in found] == ["linode"] and all(p.api == "2.2" and not p.is_record for p in found)
    assert {p.SYSTEM for p in found} == {"platform"} and {p.KIND for p in found} == {"machine"}
    (p,) = found
    assert (p.title, p.order, p.ICON, p.version, module.__version__) == ("Linode", 761, "linode", "0.1.0", "0.1.0")
    assert [a.name for a in p.apis] == ["Linode API v4"] and p.interface()["apis"] == ["Linode API v4"]


def test_its_settings_are_pairs_named_by_their_variables():
    p = module.MACHINE
    assert [k.pair for k in p.keys] == ["linode-token", "linode-ddns-hosts", "linode-ddns-minutes"]
    assert {k.name for k in p.keys if k.secret} == {"LINODE_TOKEN"}
    assert [k.hint.startswith("optional") for k in p.keys] == [False, True, True]
    token = p.keys[0].hint  # where it is made and the access it needs, in Linode's own scopes' areas
    assert "https://cloud.linode.com/profile/tokens" in token and "Read/Write for Linodes, Domains, Firewalls, Account" in token
    from plugin_platform_linode.settings import SCOPES
    assert SCOPES[:4] == ("linodes:read_write", "domains:read_write", "firewall:read_write", "account:read_write")
    assert all(s.endswith(":read_only") for s in SCOPES[4:]) and all(s in token for s in SCOPES)
    assert module.MACHINE.status()["why"].endswith("No Access for the rest")  # not set: the page names them too


def test_its_api_card_is_sound_and_covers_the_whole_reference():
    (a,) = card.APIS
    assert problems(card.APIS) == [] and a.verified == "2026-11-11" and a.kind == "rest" and a.base == api.BASE
    kinds = {x.kind for x in a.links}
    assert {"docs", "reference", "guide", "auth", "limits", "pricing", "status", "changelog", "spec", "console", "tool",
            "sdk"} <= kinds
    assert a.docs == "https://techdocs.akamai.com/linode-api/reference/api"
    assert a.link("status") == "https://status.linode.com" and a.link("console") == "https://cloud.linode.com/profile/tokens"
    assert [x.name for x in a.areas] == [  # every section of the reference's summary, in its order
        "Administration", "Beta programs", "Databases", "Domains", "Identity and access", "Images", "Linode instances",
        "Linode StackScripts", "Linode Kubernetes Engine (LKE)", "Longview", "Maintenance", "Managed", "Monitor",
        "Monitor metrics", "Network transfer prices", "Networking", "NodeBalancers", "Object Storage", "Placement groups",
        "Profile", "Regions", "Resource locking", "Support", "Tags", "Volumes", "VPCs"]
    assert all(x.docs.startswith(card.REF) for x in a.areas)
    areas = {x.name for x in a.areas}
    assert all(c.area in areas for c in a.calls) and all(c.docs.startswith(card.REF) for c in a.calls)
    assert {c.area for c in a.used} <= {x.name for x in a.covered}  # an area a call is made in says what it is for
    assert "powered off" in a.costs and "still billed" in a.costs


def client_calls() -> set[str]:
    return {f"GET {V4}{t}" for t in api.READS} | {f"{m} {V4}{t}" for m, t in api.FREE_WRITES}


def test_the_card_names_the_calls_the_client_makes_and_no_other():
    (a,) = card.APIS
    used = {c.name for c in a.used}
    assert used == client_calls()  # each read and free write named, with what it is made for
    for c in a.used:
        writes = c.name.split(" ")[0] != "GET"
        assert c.writes is writes and c.costs is False, c.name  # every change the plugin makes is free
    templates = set(api.READS) | {t for _, t in api.FREE_WRITES}
    assert {re.sub(r"\{\w+\}", "{}", t) for t in re.findall(r'"(/[a-z][^"\s]*)"', inspect.getsource(api))
            if not t.startswith("/v4")} <= {re.sub(r"\{\w+\}", "{}", t) for t in templates}  # no other path in the client


def test_every_request_a_full_run_makes_is_one_the_card_names(made, env):
    """A refresh, every form's change, a Dynamic DNS pass: each request the stand-in saw is a call the card names as used,
    and every call the card names as used was made."""
    env(settings_of(ddns="home.example.com, lab.example.com"))
    p, fake = made()
    p.refresh()
    p.ddns_update(force=False)
    st = p.status()
    forms = forms_of(st)
    web = table(st, "Linodes")["rows"][1]
    p.ask("power", *page_args(forms["power:shutdown"], web[9]["values"]))
    p.power("db-1", "boot")
    fake.linodes[1]["status"] = "running"
    p.power("db-1", "reboot")
    p.ask("set_record", *page_args(forms["record-set:1"], {"name": "blog", "rtype": "A", "target": "203.0.113.7"}))
    p.set_record("example.com", "home", "A", "203.0.113.8")
    rid = next(r["id"] for r in fake.records[1] if r["name"] == "blog")
    p.remove_record("example.com", rid)
    p.ask("add_rule", *page_args(forms["rule-add:9"], {"direction": "inbound", "action": "ACCEPT", "protocol": "TCP",
                                                       "ports": "8080", "addresses": "203.0.113.9"}))
    row = table(p.status(), "web-fw rules")["rows"][2]
    p.ask("remove_rule", *page_args(forms_of(p.status())["rule-remove:9"], row[-1]["values"]))
    p.add_ssh_key("desk", pub("tester@desk", fill=3))
    p.remove_ssh_key(5)
    seen = set()
    for r in fake.requests:
        t = api.template_of(r["method"], r["path"])
        assert t is not None, (r["method"], r["path"])
        seen.add(f"{r['method']} {V4}{t}")
    assert seen == {c.name for c in card.LINODE_API.used}
    assert HOME in {r["target"] for r in fake.records[1] if r["type"] == "A"}  # the Dynamic DNS pass wrote
    assert ACCEPT_RISK  # (the risky changes: test_forms)


def test_nothing_billable_is_in_the_clients_source():
    """No call that makes, resizes, restores or destroys a billable thing, nor turns on backups, can be sent: the client
    writes only FREE_WRITES (checked again before each write), and the paths of every other write the card names appear
    nowhere outside the card (card.py)."""
    assert set(api.FREE_WRITES) == {
        ("POST", "/linode/instances/{linodeId}/boot"), ("POST", "/linode/instances/{linodeId}/shutdown"),
        ("POST", "/linode/instances/{linodeId}/reboot"), ("POST", "/domains/{domainId}/records"),
        ("PUT", "/domains/{domainId}/records/{recordId}"), ("DELETE", "/domains/{domainId}/records/{recordId}"),
        ("PUT", "/networking/firewalls/{firewallId}/rules"), ("POST", "/profile/sshkeys"),
        ("DELETE", "/profile/sshkeys/{sshKeyId}")}
    with pytest.raises(ValueError, match="is not a change this plugin makes"):
        api.LinodeApi("x" * 64, transport=lambda *a: (200, {}, b"{}"))._write("POST", "/linode/instances")
    sources = {m.__name__: inspect.getsource(m) for m in
               (api, module, module.records, module.firewall, module.ddns, module.settings, module.refusal,
                __import__("plugin_platform_linode.__main__", fromlist=["main"]))}
    known = {f"{V4}{t}" for t in api.READS} | {f"{V4}{t}" for _, t in api.FREE_WRITES}
    billable = [c for c in card.LINODE_API.calls if not c.used and (c.writes or c.costs)]
    assert {c.name.split(" ", 1)[1] for c in billable if c.costs} >= {
        "/v4/linode/instances", "/v4/linode/instances/{linodeId}/resize", "/v4/linode/instances/{linodeId}/clone",
        "/v4/linode/instances/{linodeId}/backups/enable", "/v4/volumes", "/v4/networking/reserved/ips", "/v4/lke/clusters"}
    for c in billable:
        method, path = c.name.split(" ", 1)
        template = path[len(V4):]
        assert (method, template) not in api.FREE_WRITES, c.name
        concrete = re.sub(r"\{\w+\}", "1", path)
        assert api.template_of(method, concrete) is None, c.name  # the client has no such write
        if path in known:
            continue  # the path of a read or a free write (a list's POST makes one): the client sends it that way alone
        assert api.template_of("GET", concrete) is None, c.name
        for name, src in sources.items():
            assert f'"{template}"' not in src, (name, c.name)  # its path nowhere outside the card
    for name, src in sources.items():
        for word in ("/resize", "/clone", "/rebuild", "/backups", "/mutate", "/migrate", "/disks", "/password"):
            assert word not in src, (name, word)


def test_its_icon_is_its_makers_mark_drawn_by_the_library():
    from liminal_libs.ui import STATIC

    drawn = set(re.findall(r"^\s*([a-z]+):\s*'", (STATIC / "icons.js").read_text(encoding="utf-8"), re.M))
    assert {p.ICON for p in assert_module_conforms(module)} == {"linode"} and "linode" in drawn


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="asks Akamai's and GitHub's pages: LIMINAL_VENDOR_PAGES=1")
def test_every_address_on_its_card_answers():
    assert dead_links(card.APIS) == []
