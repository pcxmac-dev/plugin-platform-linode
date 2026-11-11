"""The plugin over the stand-ins: its settings read through the Login interface (an EnvironmentLogin not attached, the
app's login attached), its status from what was read (no request made to answer it; no value of a setting in it), valid
while the token works or is untried, the background reading only while attached, its hooks asked by name, the command
line."""
from __future__ import annotations

import json
import time

import pytest

import plugin_platform_linode.__main__ as cli
from conftest import HOME, TOKEN, FakeLinode, Pairs, settings_of, table
from plugin_platform_linode import BILLS_OFF, NOT_SET, RETRY_S
from plugin_platform_linode.api import PAGE_SIZE
from plugin_platform_linode.settings import SCOPES, read


def wait_until(test, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if test():
            return True
        time.sleep(0.02)
    return False


def test_nothing_set_is_not_valid_and_names_the_token_and_where_to_make_it(made):
    p, fake = made()
    st = p.status()
    assert st["present"] is False and st["valid"] is False and st["why"] == NOT_SET and fake.requests == []
    assert "LINODE_TOKEN" in st["why"] and "https://cloud.linode.com/profile/tokens" in st["why"]
    for words in ("Read/Write for Linodes, Domains, Firewalls (", "Read Only for Account, Volumes", *SCOPES):
        assert words in st["why"]  # the access it needs, in Linode's own scopes
    assert "Only to add and remove the profile's SSH keys here: Account Read/Write (account:read_write" in st["why"]
    assert st["tables"] == [] and st["actions"] == [] and st["forms"] == [] and not p.present()
    with pytest.raises(ValueError, match="the API is not set up"):
        p.refresh()
    with pytest.raises(ValueError, match="Dynamic DNS is not set up"):
        p.ddns_update()


def test_dynamic_dns_hosts_without_a_token_are_not_valid(made, env):
    env(settings_of(token=False, ddns="home.example.com"))
    p, fake = made()
    st = p.status()
    assert st["present"] is True and st["valid"] is False and st["why"].startswith("LINODE_TOKEN is not set")
    assert st["settingsSet"] == "LINODE_DDNS_HOSTS" and "LINODE_TOKEN" in st["settingsNotSet"] and fake.requests == []


def test_the_settings_are_read_through_the_login_by_their_pairs():
    login = Pairs(settings_of(ddns="home.example.com", LINODE_DDNS_MINUTES="15"))
    c = read(login)
    assert (c.token, c.hosts, c.minutes) == (TOKEN, "home.example.com", 15.0) and c.ready and c.ddns_ready
    assert "linode-token" in login.asked and "LINODE_TOKEN" not in login.asked  # asked by the pairs' names
    assert TOKEN not in repr(c)
    assert read(Pairs({"LINODE_TOKEN": "Bearer " + TOKEN})).token == TOKEN  # pasted with its header's word
    assert read(Pairs({"LINODE_TOKEN": TOKEN, "LINODE_DDNS_MINUTES": "soon"})).problems == (
        "LINODE_DDNS_MINUTES is not a number of minutes: 5 is used",)

    class Down(Pairs):
        def names(self):
            raise ConnectionError("the login app is not answering")
    assert read(Down({})).problems == ("the settings could not be read from the login: ConnectionError",)


def test_a_refresh_draws_the_account_in_tables_and_the_status_asks_nothing(made, env):
    env(settings_of())
    p, fake = made()
    st = p.status()
    assert st["valid"] is True and st["summary"] == "the account is read once attached" and fake.requests == []
    done = p.refresh()
    assert (done["linodes"], done["domains"], done["firewalls"], done["notRead"]) == (2, 2, 2, [])
    calls = len(fake.requests)
    assert calls <= 25 and all(r["method"] == "GET" for r in fake.requests)  # a quarter hour's few requests, all reads
    lists = [r for r in fake.requests if r["path"] in ("/v4/linode/instances", "/v4/domains", "/v4/volumes")]
    assert lists and all(r["query"] == {"page": "1", "page_size": str(PAGE_SIZE)} for r in lists)
    st = p.status()
    assert len(fake.requests) == calls  # the status asks nothing of Linode
    assert st["valid"] is True and "problem" not in st
    assert st["summary"] == "2 Linodes (1 running) · $36.00 a month · 2 domains · balance $0.00"
    assert (st["account"], st["twoFactor"], st["balance"]) == ("tester", "on", "$0.00")
    assert st["thisMonth"].startswith("$12.34 so far") and st["credit"] == "$50.00 of promotions left"
    assert st["transfer"] == "12 of 5,000 GB used this cycle" and st["linodesMonthly"].startswith("$36.00 a month")
    assert st["settingsSet"] == "LINODE_TOKEN" and st["readAt"] == done["refreshedAt"]
    assert st["tokenNeeds"] == ("Read/Write: Linodes, Domains, Firewalls; Read Only: the rest it shows (Account too, "
                                "unless SSH keys are changed here)")
    assert [t["title"] for t in st["tables"]] == [
        "Linodes", "Domains", "example.com records", "Cloud Firewalls", "db-fw rules", "web-fw rules", "Volumes",
        "SSH keys", "Reserved IPs", "The rest of the account"]
    linodes = table(st, "Linodes")
    assert BILLS_OFF in linodes["note"] and all(len(r) == len(linodes["columns"]) for r in linodes["rows"])
    db, web = linodes["rows"]  # by label
    assert db[0] == {"text": "db-1", "sub": "12"} and db[1] == {"text": "offline", "sub": "still bills while off"}
    assert db[6] == "$7.00" and db[7] == "$0.0105"  # br-gru's own price for the plan
    assert web[3] == {"text": "Linode 4GB", "sub": "2 vCPU · 4 GB · 80 GB disk"} and web[4] == "203.0.113.10"  # public only
    assert web[5] == "2600:3c03::f03c:91ff:fe24:3a2f" and web[6] == {"text": "$24.00", "sub": "+ $5.00 backups"}
    assert web[7] == "$0.036" and web[8] == "2025-03-01"
    assert [c["form"] for c in web[9:]] == ["power:shutdown", "power:reboot"] and web[9]["values"] == {"linode": 11}
    assert db[9]["form"] == "power:boot" and db[10] == ""
    domains = table(st, "Domains")
    assert domains["rows"][0][:4] == ["example.com", "master", "active", "5"]
    assert domains["rows"][1][1] == {"text": "slave", "sub": "from 198.51.100.53"} and domains["rows"][1][3] == "–"
    records = table(st, "example.com records")
    assert records["actions"] == [{"form": "record-set:1", "title": "Set a record…"}]
    assert [r[:3] for r in records["rows"]][:3] == [["@", "A", "203.0.113.10"], ["@", "MX", "mail.example.com"],
                                                     ["@", "TXT", "v=spf1 mx -all"]]
    assert records["rows"][0][3] == "1 hour" and records["rows"][1][3:5] == ["default", "10"]
    firewalls = table(st, "Cloud Firewalls")
    assert firewalls["rows"][1][:4] == [{"text": "web-fw", "sub": "9"}, "enabled", "2 in · 0 out", "in DROP · out ACCEPT"]
    assert firewalls["rows"][1][5] == "web-1 (linode)"
    rules = table(st, "web-fw rules")
    assert rules["rows"][0][:6] == ["1", "inbound", "ACCEPT", "TCP", "22", {"text": "0.0.0.0/0, ::/0", "sub": "every address"}]
    assert "version 3" in rules["note"] and "guards web-1" in rules["note"] and rules["actions"][0]["form"] == "rule-add:9"
    assert rules["rows"][0][-1]["values"] == {"direction": "inbound", "position": 1,
                                               "rule": "ACCEPT TCP 22 from 0.0.0.0/0, ::/0 (ssh)"}
    assert table(st, "Volumes")["rows"][0] == [{"text": "data", "sub": "21"}, "active", "40 GB", "us-east", "web-1",
                                               "nvme · encrypted"]
    keys = table(st, "SSH keys")
    assert keys["rows"][0][0] == "laptop" and keys["rows"][0][1]["text"] == "ssh-ed25519"
    assert keys["rows"][0][1]["sub"].startswith("SHA256:") and keys["actions"] == [{"form": "sshkey-add", "title": "Add an SSH key…"}]
    assert table(st, "Reserved IPs")["rows"][0][:3] == ["198.51.100.20", "us-east", "web-1 (linode)"]
    rest = {r[0]: r[1] for r in table(st, "The rest of the account")["rows"]}
    assert rest == {"Kubernetes (LKE) clusters": "1", "NodeBalancers": "0", "Managed Databases": "2",
                    "Object Storage buckets": "3", "Images of your own": "4", "VPCs": "0", "Placement groups": "1"}
    assert [a["hook"] for a in st["actions"]] == ["refresh"] and st["actions"][0]["args"] == []
    text = json.dumps(st)
    assert TOKEN not in text and "tester@example.org" not in text  # names of the settings, never a value; no email


def test_the_plans_are_read_once_a_day(made, env):
    env(settings_of())
    p, fake = made()
    p.refresh()
    p.refresh()
    assert fake.paths().count("/v4/linode/types") == 1
    p._clock = lambda: time.time() + 86400 + 1
    p.refresh()
    assert fake.paths().count("/v4/linode/types") == 2


def test_a_refused_token_is_not_valid_says_what_to_do_and_is_tried_again_later_when_detached(made, env):
    env(settings_of())
    t = [1_000_000.0]
    p, fake = made(FakeLinode(token="another-token-that-is-not-this-one-0000"))
    p._clock = lambda: t[0]
    with pytest.raises(Exception, match="LINODE_TOKEN is refused"):
        p.refresh()
    assert fake.paths() == ["/v4/profile"]  # the first read: nothing more asked with a refused token
    st = p.status()
    assert st["valid"] is False and st["why"].startswith("the API: GET /v4/profile: HTTP 401: LINODE_TOKEN is refused")
    assert "(Linode: Invalid Token)" in st["why"] and TOKEN not in json.dumps(st) and st["forms"] == []
    t[0] += RETRY_S
    st = p.status()
    assert st["valid"] is True and st["summary"] == "the account is read once attached"  # the platform attaches it: again


def test_an_area_the_token_may_not_read_is_said_beside_the_rest(made, env):
    env(settings_of())
    p, fake = made()
    fake.errors[("GET", "/v4/lke/clusters")] = (403, "You do not have permission to access this resource")
    fake.errors[("GET", "/v4/volumes")] = (403, "You do not have permission to access this resource")
    p.refresh()
    st = p.status()
    assert st["valid"] is True and "the token's access does not cover Volumes, Kubernetes (LKE) clusters" in st["problem"]
    assert table(st, "Volumes")["note"].startswith("not read: GET /v4/volumes: HTTP 403: the token's access does not cover")
    rest = {r[0]: r[1:] for r in table(st, "The rest of the account")["rows"]}
    assert rest["Kubernetes (LKE) clusters"] == ["–", "not allowed by the token"]
    assert p.api_facts()["Linode API v4"]["Not allowed by the token"] == "Volumes, Kubernetes (LKE) clusters"


def test_no_running_linode_means_dns_manager_serves_no_records_and_the_page_says_so(made, env):
    env(settings_of())
    fake = FakeLinode()
    for x in fake.linodes:
        x["status"] = "offline"
    p, _ = made(fake)
    p.refresh()
    assert "DNS Manager serves a domain's records only while the account has an active Linode" in p.status()["problem"]


def test_what_it_learned_of_the_api_comes_from_the_answers_alone(made, env):
    env(settings_of())
    p, fake = made()
    assert p.api_facts() == {"Linode API v4": {"Requests": "none yet", "Account read": "not yet"}}
    p.refresh()
    calls = len(fake.requests)
    facts = p.api_facts()["Linode API v4"]
    assert len(fake.requests) == calls  # asking nothing to answer it
    assert facts["Requests"] == f"{calls} made" and facts["Last answer"].startswith("HTTP 200")
    assert facts["Rate limit (this call's window)"] == "1600" and facts["Left of it"] == "1599"
    assert facts["Its window resets"] == time.strftime("%H:%M:%S", time.localtime(1762862460))
    assert facts["Account read"] != "not yet" and "Plans and prices read" in facts


class Platform:
    """A stand-in for the platform app (its NAME: the one app whose attach starts the background reading)."""

    NAME = "platform"


class Charts:
    """A stand-in for the charts app run alone, which attaches every plugin it finds."""

    NAME = "charts"


def test_attached_by_the_platform_it_reads_in_the_background_and_detached_nothing_runs(made, env):
    p, fake = made()
    login = Pairs(settings_of(ddns="lab.example.com"))
    p.attach(Platform(), login)
    try:
        assert wait_until(lambda: p.status()["summary"].endswith(f"lab.example.com at {HOME}"))
        assert p.working and "linode-token" in login.asked
        st = p.status()
        assert st["valid"] is True and table(st, "Dynamic DNS")["rows"][0][:2] == ["lab.example.com", HOME]
        assert [a.get("hook") or a.get("form") for a in st["actions"]] == ["refresh", "ddns-now"]
    finally:
        p.detach()
    assert not p.working
    calls = len(fake.requests)
    time.sleep(0.2)
    assert len(fake.requests) == calls  # detached: nothing of it runs
    env(settings_of(ddns="lab.example.com"))  # the process environment holds the token too
    assert p.config(fresh=True).ready is False  # detached, no login lent: no settings read from the environment
    p.login = login  # the platform lends its login again to ask a status
    assert p.config(fresh=True).ready is True


def test_the_charts_app_attaching_it_starts_nothing_nor_does_the_platform_with_nothing_set(made):
    p, fake = made()
    p.attach(Charts(), Pairs(settings_of(ddns="lab.example.com")))  # the charts app run alone attaches every plugin
    try:
        time.sleep(0.2)
        assert not p.working and fake.requests == []
    finally:
        p.detach()
    login = Pairs({})
    p.attach(Platform(), login)  # under the platform, nothing set: no thread at all
    try:
        assert not p.working and fake.requests == []
        login.pairs.update(Pairs(settings_of()).pairs)  # the token entered on the page
        p.settings_changed()
        assert p.working and wait_until(lambda: "/v4/profile" in fake.paths())
    finally:
        p.detach()
    assert not p.working


def test_a_refresh_once_detached_asks_nothing_and_keeps_nothing(made, env):
    env(settings_of())
    p, fake = made()
    cfg = p.config(fresh=True)
    p._rt.detached.set()  # what a detach sets first
    assert p._refresh(cfg, p._rt.detached) == {"detached": True} and fake.requests == []
    assert p._rt.api_ok is None and p._rt.read is None  # no outcome kept: the status is not made invalid by it


def test_a_token_with_a_line_break_inside_is_never_sent_nor_shown(made, env):
    env({"LINODE_TOKEN": TOKEN[:32] + "\n" + TOKEN[32:]})  # set outside the page: a wrapped paste
    p, fake = made()
    st = p.status()
    assert st["valid"] is False and st["why"].startswith("LINODE_TOKEN holds a space or a line break inside")
    with pytest.raises(ValueError, match="the API is not set up"):
        p.refresh()
    text = json.dumps([st, p.api_facts()])
    assert fake.requests == [] and TOKEN[:32] not in text and TOKEN[32:] not in text


def test_the_hooks_are_asked_by_name(made, env):
    env(settings_of())
    p, fake = made()
    hooks = p.interface()["hooks"]
    assert {"present", "status", "refresh", "linodes", "domains", "records", "firewalls", "ssh_keys", "power",
            "set_record", "remove_record", "add_rule", "remove_rule", "add_ssh_key", "remove_ssh_key",
            "ddns_update"} <= set(hooks)
    assert [r["id"] for r in p.ask("records", "example.com")] == [100, 101, 102, 103, 104]
    with pytest.raises(LookupError):
        p.ask("delete_linode", 11)
    with pytest.raises(ValueError, match="not a domain of this account"):
        p.records("example.org")


def test_the_command_line_reads_and_asks_yes_before_a_change(made, env):
    env(settings_of())
    p, fake = made()
    said, told = [], []
    assert cli.main(["servers"], plugin=p, out=said.append, err=told.append) == 0
    assert said[0].startswith("web-1") and "$24.00/mo + $5.00 backups" in said[0]  # the API's order
    assert said[1].startswith("db-1") and said[1].endswith("$7.00/mo") and said[-1] == BILLS_OFF
    said.clear()
    assert cli.main(["firewalls"], plugin=p, out=said.append) == 0
    assert "  inbound 1: ACCEPT TCP 22 from 0.0.0.0/0, ::/0 (ssh)" in said
    said.clear()
    assert cli.main(["records", "example.com"], plugin=p, out=said.append) == 0 and "(id 104)" in said[-1]
    writes = len(fake.writes())
    assert cli.main(["power", "web-1", "off"], plugin=p, out=said.append, err=told.append, ask=lambda q: "no") == 1
    assert told[-1] == "nothing done" and len(fake.writes()) == writes  # not yes: nothing sent
    said.clear()
    assert cli.main(["power", "web-1", "off"], plugin=p, out=said.append, ask=lambda q: "yes") == 0
    assert fake.writes()[-1] == ("POST", "/v4/linode/instances/11/shutdown", None)
    assert said[-3:] == ["Shut down asked of web-1: shutting down", "  Linode says it is shutting down now", f"  {BILLS_OFF}"]
    assert cli.main(["set", "example.com", "blog", "A", "203.0.113.7", "--yes"], plugin=p, out=said.append) == 0
    assert fake.writes()[-1] == ("POST", "/v4/domains/1/records", {"type": "A", "name": "blog", "target": "203.0.113.7"})
    assert cli.main(["remove", "example.com", "blog", "A", "--yes"], plugin=p, out=said.append) == 0
    assert fake.writes()[-1][0] == "DELETE" and fake.writes()[-1][1].startswith("/v4/domains/1/records/")
    assert cli.main(["remove", "example.com", "blog", "A", "--yes"], plugin=p, out=said.append, err=told.append) == 1
    assert told[-1] == "refused: example.com has no A record at blog"
    said.clear()
    assert cli.main(["--json", "status"], plugin=p, out=said.append) == 0 and json.loads(said[0])["valid"] is True
    env(settings_of(ddns="lab.example.com"))
    p.settings_changed()
    writes = len(fake.writes())
    assert cli.main(["ddns"], plugin=p, out=said.append, err=told.append, ask=lambda q: "no") == 1
    assert told[-1] == "nothing done" and len(fake.writes()) == writes  # a pass may write: asked first
    assert cli.main(["ddns", "--yes"], plugin=p, out=said.append) == 0 and fake.writes()[-1][0] == "POST"


def test_the_platforms_one_shot_command_starts_nothing(made):
    """The platform's status and machine commands attach it to answer and end (PlatformApp.once, liminal-platform
    0.20.1): nothing of it runs on its own then."""
    p, fake = made()
    p.attach(type("Once", (), {"NAME": "platform", "once": True})(), Pairs(settings_of(ddns="lab.example.com")))
    try:
        time.sleep(0.1)
        assert not p.working and fake.requests == []
    finally:
        p.detach()
