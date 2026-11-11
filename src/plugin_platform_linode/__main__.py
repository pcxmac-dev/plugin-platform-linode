"""`python -m plugin_platform_linode ...`: the plugin from the command line, its settings read from the environment (an
EnvironmentLogin: the variables as this shell has them). The reads ask nothing of you; each change says what it does and
asks you to type yes first.

    status                                   the account read, then the plugin's status (JSON)
    servers                                  the Linodes, their state, plan, addresses and price
    domains                                  DNS Manager's domains
    records DOMAIN                           a domain's records
    firewalls                                the Cloud Firewalls and their rules
    keys                                     the profile's SSH keys
    ddns [--now]                             a Dynamic DNS pass: a host of its own set where it differs (--now: every
                                             one of its own), asks yes; a host holding another address left as it is
    power LINODE on|off|reboot               a Linode booted, shut down or rebooted (asks yes)
    set DOMAIN HOST TYPE TARGET [--ttl N] [--priority N] [--tag T]
                                             a record set, every other record kept (asks yes)
    remove DOMAIN HOST TYPE [TARGET]         a record removed, the rest kept (asks yes)

--json (before the command) prints the answer as JSON; a change's --yes answers yes for you."""
from __future__ import annotations

import argparse
import json
import sys

from liminal_libs.machines.rest import RestError

from . import ACTIONS_OF, BILLS_OFF, MACHINE, POWER_WORDS, Trouble, money, when
from . import firewall as fw
from . import records as rec
from .refusal import Refusal


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_linode",
                                description="Linode for Liminal: the account read, free changes only, Dynamic DNS")
    p.add_argument("--json", action="store_true", help="print the answer as JSON")
    sub = p.add_subparsers(dest="what")
    sub.add_parser("status", help="the account read, then the plugin's status")
    sub.add_parser("servers", help="the Linodes")
    sub.add_parser("domains", help="DNS Manager's domains")
    r = sub.add_parser("records", help="a domain's records")
    r.add_argument("domain")
    sub.add_parser("firewalls", help="the Cloud Firewalls and their rules")
    sub.add_parser("keys", help="the profile's SSH keys")
    d = sub.add_parser("ddns", help="a Dynamic DNS pass")
    d.add_argument("--now", action="store_true", help="every host of its own set, whether it differs or not")
    d.add_argument("--yes", action="store_true", help="answer yes to the question")
    w = sub.add_parser("power", help="a Linode booted, shut down or rebooted")
    w.add_argument("linode", help="its label or its id")
    w.add_argument("action", choices=sorted(ACTIONS_OF))
    w.add_argument("--yes", action="store_true", help="answer yes to the question")
    s = sub.add_parser("set", help="a record set, every other record kept")
    for a in ("domain", "host", "type", "target"):
        s.add_argument(a)
    s.add_argument("--ttl", type=int, help=f"one of {', '.join(map(str, rec.TTLS))}")
    s.add_argument("--priority", type=int, help="an MX record's priority (0 to 255)")
    s.add_argument("--tag", choices=rec.CAA_TAGS, help="a CAA record's tag")
    s.add_argument("--yes", action="store_true", help="answer yes to the question")
    m = sub.add_parser("remove", help="a record removed, the rest kept")
    for a in ("domain", "host", "type"):
        m.add_argument(a)
    m.add_argument("target", nargs="?", help="the record's target, when the host has several of the type")
    m.add_argument("--yes", action="store_true", help="answer yes to the question")
    return p


def report_lines(rep: dict) -> list[str]:
    """A change's report in words: its headline, then its words (as the platform's page shows them) indented."""
    return [str(rep.get("said") or "done"), *(f"  {line}" for line in rep.get("lines") or [])]


def main(argv: list[str] | None = None, plugin=None, out=None, err=None, ask=None) -> int:
    p = plugin if plugin is not None else MACHINE
    say = out or (lambda s: print(s))
    tell = err or (lambda s: print(s, file=sys.stderr))
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    question = ask or (lambda prompt: input(prompt))

    def confirmed(words: str) -> bool:
        say(words)
        if getattr(args, "yes", False):
            return True
        try:
            return question("Type yes to go on: ").strip().lower() == "yes"
        except EOFError:
            return False

    what = args.what or "status"
    try:
        if what == "status":
            if p.config().ready:
                try:
                    p.refresh()
                except (RestError, ValueError):
                    pass  # the status says it
            answer = p.status()
            say(json.dumps(answer, indent=1, default=str))
            return 0
        if what == "servers":
            answer = p.linodes()
            types = p._types(p.client(), p._clock())  # the plans and their prices (kept a day), else none
            lines = []
            for x in answer:
                monthly, hourly, backups = p._price(x, types)
                lines.append(f"{str(x.get('label')):<28} {str(x.get('status')):<14} {str(x.get('region')):<12} "
                             f"{str(x.get('type')):<18} {', '.join(x.get('ipv4') or []):<32} "
                             f"{money(monthly) if monthly is not None else '–'}/mo"
                             + (f" + {money(backups)} backups" if backups else ""))
            lines = lines or ["no Linode in this account"]
            if any(str(x.get("status")) in ("offline", "stopped") for x in answer):
                lines.append(BILLS_OFF)
        elif what == "domains":
            answer = p.domains()
            lines = [f"{str(d.get('domain')):<36} {str(d.get('type')):<7} {str(d.get('status')):<9} id {d.get('id')}"
                     for d in answer] or ["no domain in DNS Manager"]
        elif what == "records":
            answer = p.records(args.domain)
            lines = [f"  {rec.shown_name(r.get('name')):<28} {str(r.get('type')):<6} {str(r.get('target'))}  ttl "
                     f"{r.get('ttl_sec') or 'default'}" + (f"  priority {r.get('priority')}" if r.get("type") in ("MX", "SRV") else "")
                     + f"  (id {r.get('id')})" for r in answer] or ["  no records"]
        elif what == "firewalls":
            answer = p.firewalls()
            lines = []
            for f in answer:
                rules = f.get("rules") or {}
                lines.append(f"{f.get('label')} ({f.get('status')}): version {rules.get('version')}, inbound "
                             f"{rules.get('inbound_policy')}, outbound {rules.get('outbound_policy')}; guards "
                             f"{', '.join(fw.attached_linodes(f)) or 'no Linode'}")
                for d in fw.DIRECTIONS:
                    lines += [f"  {d} {i}: {fw.words(r)}" for i, r in enumerate(rules.get(d) or [], 1)]
            lines = lines or ["no Cloud Firewall in this account"]
        elif what == "keys":
            answer = p.ssh_keys()
            lines = [f"{str(k.get('label') or '–'):<24} {str(k.get('ssh_key') or '').split(' ')[0]:<20} added "
                     f"{str(k.get('created') or '')[:10]}  (id {k.get('id')})" for k in answer] or ["no SSH key in your profile"]
        elif what == "ddns":
            if not confirmed("A Dynamic DNS pass sets each host of its own to this network's address"
                             + (", even where it holds it already" if args.now else " where it differs")
                             + "; a host holding another address is left as it is (Take over… on the platform's page)."):
                tell("nothing done")
                return 1
            answer = p.ddns_update(force=args.now)
            lines = [f"{h['host']:<32} {h['address'] or '–':<16} {h['result']} (checked {when(h['checkedAt'])})"
                     for h in answer] or ["no host of LINODE_DDNS_HOSTS is in a master domain of DNS Manager"]
        elif what == "power":
            act = ACTIONS_OF[args.action]
            x = p._linode(args.linode)
            words = POWER_WORDS[act][2].replace("{linode}", str(x.get("label")))
            if not confirmed(f"{POWER_WORDS[act][0]} {x.get('label')} (it is {x.get('status')}): {words}"):
                tell("nothing done")
                return 1
            answer = p.power(x["id"], act)
            lines = report_lines(answer)
        elif what == "set":
            if not confirmed(f"{args.host} {args.type.upper()} {args.target} is set in {args.domain}: an A, AAAA or CNAME "
                             "record changes the host's record of its type, any other is added beside the others; every "
                             "other record is kept."):
                tell("nothing done")
                return 1
            answer = p.set_record(args.domain, args.host, args.type, args.target, ttl=args.ttl, priority=args.priority,
                                  tag=args.tag)
            lines = report_lines(answer)
        else:  # remove
            d = p._domain(args.domain, write=True)
            held = p.records(d["id"])
            host = rec.host_name(args.host, d["domain"])
            t = args.type.strip().upper()
            match = [r for r in held if str(r.get("name") or "").lower() == host and str(r.get("type") or "").upper() == t
                     and (args.target is None or rec.norm_target(t, r.get("target")) == rec.norm_target(t, args.target))]
            if not match:
                raise Refusal(f"{d['domain']} has no {t} record at {rec.shown_name(host)}"
                              + (f" holding {args.target}" if args.target else ""))
            if len(match) > 1:
                raise Refusal(f"{d['domain']} has {len(match)} {t} records at {rec.shown_name(host)}: name the one to "
                              "remove by its target")
            r = match[0]
            if not confirmed(f"{rec.said(r)} is removed from {d['domain']}; every other record is kept."):
                tell("nothing done")
                return 1
            answer = p.remove_record(d["id"], r["id"], rec.shown_name(r.get("name")), t, r.get("target"))
            lines = report_lines(answer)
    except RestError as e:
        tell(f"linode: {e}")
        return 1
    except (ValueError, RuntimeError) as e:  # a refusal, a setting not set, a pass under way
        tell(f"refused: {e}")
        return 1
    if args.json:
        say(json.dumps(answer, indent=1, default=lambda o: str(o) if isinstance(o, Trouble) else repr(o)))
    else:
        for line in lines:
            say(line)
    if isinstance(answer, dict) and answer.get("changed") and answer.get("ok") is False:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
