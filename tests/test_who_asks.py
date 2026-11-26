"""Who may ask the plugin's changes (0.1.5; the independent review's PLT-H1 and the sweep of the plugins after it,
2026-11-25). Its changes are asked only from its page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and
liminal-platform 0.34.0 read them): a Linode's power, a record set or removed, a Cloud Firewall's rule added or removed,
an SSH key added or removed, a Dynamic DNS pass and a host taken over. Another plugin's ask is refused, and so is an ask
that names no one; over HTTP the platform also asks its login whether you are at the page. Before, any program on this PC
asked them of the platform with a header anyone can send, and the token did the rest: the web Linode shut down, the
domain's address set to another, PostgreSQL opened to the whole internet and the rule letting SSH in removed (their
second confirmation being only an argument), an SSH key added to the profile. Its reads are asked by anyone, as before.
Asked through the library's own App (its ask names who asks as the platform's does), over the stand-in Linode: nothing
reaches Linode or the network."""
from __future__ import annotations

import pytest

pytest.importorskip("liminal_libs.apps.asking", reason="no hook is asked only from its page before liminal-libs 1.66.0")

from conftest import HOME, SSH_HOME, FakeLinode, pub, settings_of  # noqa: E402 - after the skip, as each of these
from liminal_libs import internal  # noqa: E402
from liminal_libs.apps import App, EnvironmentLogin, asking  # noqa: E402
from liminal_libs.machines.plugin import MachinePlugin  # noqa: E402
from plugin_platform_linode import MACHINE  # noqa: E402
from plugin_platform_linode import firewall as fw  # noqa: E402

CHANGES = ("power", "set_record", "remove_record", "add_rule", "remove_rule", "add_ssh_key", "remove_ssh_key",
           "ddns_update", "ddns_take_over")
READS = ("present", "status", "refresh", "linodes", "domains", "records", "firewalls", "ssh_keys")
HOSTS = "new.example.com,home.example.com"  # Dynamic DNS's: one with no record yet, one holding another address
WEB_SEEN, DB_SEEN = (f["rules"]["fingerprint"] for f in FakeLinode().firewalls)  # each firewall's rules as any read shows
ASKED = {  # each change as another program worded it: the hook's arguments, a second confirmation said where it has one
    "power": ("web-1", "shutdown"),  # the web Linode shut down
    "set_record": ("example.com", "", "A", "198.51.100.99"),  # the domain's own address, set to another
    "remove_record": ("example.com", 102, "", "TXT", "v=spf1 mx -all"),
    "add_rule": ("web-fw", WEB_SEEN, "inbound", "ACCEPT", "TCP", "5432", "0.0.0.0/0", "postgres", None, True),
    "remove_rule": ("db-fw", DB_SEEN, "inbound", 1, fw.words(SSH_HOME), True),  # the one rule letting SSH in to db-1
    "add_ssh_key": ("another", pub("someone@else", fill=2)),
    "remove_ssh_key": (5, "laptop"),
    "ddns_update": (),
    "ddns_take_over": ("home.example.com", None, True),  # a name holding another address pointed at this network
}
SENT = [  # what the same asks send from the page, in CHANGES' order
    ("POST", "/v4/linode/instances/11/shutdown"), ("PUT", "/v4/domains/1/records/100"),
    ("DELETE", "/v4/domains/1/records/102"), ("PUT", "/v4/networking/firewalls/9/rules"),
    ("PUT", "/v4/networking/firewalls/8/rules"), ("POST", "/v4/profile/sshkeys"), ("DELETE", "/v4/profile/sshkeys/5"),
    ("POST", "/v4/domains/1/records"),  # Update DNS now: new.example.com made, home.example.com left as it is
    ("PUT", "/v4/domains/1/records/104"),  # home.example.com taken over
]


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking Linode's through its app as any plugin may (a container plugin, or the MCP
    plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of Linode's asked through the app."""
        return self.app.ask("linode", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named. It holds the plugin as the platform's one-shot commands do (`once`): the plugin's
    background reads and Dynamic DNS passes are not started, so every request the stand-in sees is an ask's."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"
    once = True

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("linode", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("linode", hook, *args)


@pytest.fixture
def attached(made):
    """The plugin over the stand-in Linode, attached with another plugin to an app whose login holds its settings (the
    token and two Dynamic DNS hosts); let go after."""
    plugin, fake = made()
    neighbour = Neighbour()
    app = Platform(log=lambda m: None, login=EnvironmentLogin(env=settings_of(ddns=HOSTS)))
    app.attach(plugin)
    app.attach(neighbour)
    yield app, plugin, neighbour, fake
    app.detach(neighbour.name)
    app.detach(plugin.name)


def test_its_changes_are_said_to_be_asked_only_from_its_page_and_its_reads_by_anyone():
    assert set(internal.page_only(MACHINE)) == set(CHANGES)  # what the platform reads
    assert internal.plugin_only(MACHINE) == ()
    assert internal.problems(MACHINE) == []  # each a hook of its own, and someone may ask it
    assert set(CHANGES) | set(READS) == set(MACHINE.interface()["hooks"]) and set(ASKED) == set(CHANGES)
    for hook in CHANGES:
        assert asking.refusal(MACHINE, hook, asking.PAGE) == ""
        assert asking.refusal(MACHINE, hook, "neighbour") == (f"linode's {hook} is asked only from its page, "
                                                              "never by another plugin: neighbour asked it.")
        assert asking.refusal(MACHINE, hook, None).endswith("This ask names no asker: neither the page nor a plugin.")
    for hook in READS:
        assert {asking.refusal(MACHINE, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_change_sends_nothing_and_its_page_does(attached):
    app, plugin, neighbour, fake = attached
    for hook in CHANGES:
        for ask in (neighbour.wants, app.on_its_own):
            with pytest.raises(asking.AskRefused, match=f"linode's {hook} is asked only from its page"):
                ask(hook, *ASKED[hook])
    assert fake.requests == []  # nothing sent, nor read: not the read a change makes first
    assert neighbour.wants("present") is True and neighbour.wants("status")["valid"] is True  # its reads, as before
    assert [x["label"] for x in neighbour.wants("linodes")] == ["web-1", "db-1"]
    assert len(neighbour.wants("records", "example.com")) == 5 and app.on_its_own("refresh")["linodes"] == 2
    assert fake.writes() == []
    for hook in CHANGES:  # the same asks from its page: each one sent
        sent = len(fake.writes())
        assert app.from_page(hook, *ASKED[hook]) is not None
        assert len(fake.writes()) == sent + 1, hook
    assert [w[:2] for w in fake.writes()] == SENT
    assert fake.writes()[1][2]["target"] == "198.51.100.99" and fake.writes()[-1][2]["target"] == HOME


def test_its_own_code_asks_nothing_of_the_app_and_runs_as_before(attached):
    """The background's Dynamic DNS pass and the command line call the plugin's code themselves: not an ask, so no asker
    is named and none is needed."""
    app, plugin, neighbour, fake = attached
    assert asking.asker() is None
    new, home = plugin.ddns_update(force=False)
    assert new["result"] == "made (was none)" and home["foreign"] is True
    assert [w[:2] for w in fake.writes()] == [("POST", "/v4/domains/1/records")]
