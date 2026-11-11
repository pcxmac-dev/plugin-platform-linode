# plugin-platform-linode

Linode (Akamai Cloud) for Liminal's platform: your account read through Linode's API v4, the changes that cost nothing
made from the platform's page (each confirmed first), and Dynamic DNS keeping hosts at this network's public address.

The user's words (2026-11-11): "ALSO i would like to add two new plugins, Digital Ocean and LINODE"; for the cloud
plugins, "Free changes only"; "each plugin should reflect the the API its attached to, and present links that provide
documentation".

## What it shows

A machine plugin of the platform (`liminal_libs.machines.MachinePlugin`, plugin API 2.2, its icon Linode's prism):

- **The account**: whom the token is of (and whether two-factor is on), the balance, this month's charges so far (the
  estimated invoice, transfer left out), promotion credit left, the transfer pool (used, quota, billable GB).
- **Linodes**: each one's state, region, plan (vCPUs, memory, disk), public IPv4 and IPv6, created, and its price a month
  and an hour as its plan gives it (the region's own price where the plan has one, the backups add-on added where on),
  with the account's total a month.
- **DNS Manager**: every domain (master or slave, its status, its records counted) and each master domain's records.
- **Cloud Firewalls**: each one's status, policies, rules (in order), version and fingerprint, and what it guards.
- **Volumes**, the profile's **SSH keys** (with their SHA256 fingerprints), the **reserved IPs**, and counts of the rest:
  Kubernetes clusters, NodeBalancers, Managed Databases, Object Storage buckets, your own images, VPCs, placement groups.
- **Its API** on its page: what Linode's API is, its pages, every section of its reference and the calls the plugin
  makes (below).

While it is attached to the platform app and its token is set, it reads the account every quarter of an hour (about 20
requests, one more for each domain's records; the plans and their prices once a day) and checks the Dynamic DNS hosts
every `LINODE_DDNS_MINUTES` (5), in a thread of its own. Attached by another app (the charts app run alone attaches every
plugin it finds), with no token set, or detached (the platform ending, the plugin disabled or not valid), nothing of it
runs; once detached, a pass under way writes nothing more and no setting is read. The page draws what it read last: no
request is made to answer it.

## What it changes: free changes only, each confirmed

| On the page | What is sent (Linode's reference) |
|---|---|
| **Boot…**, **Shut down…**, **Reboot…** on a Linode's row | `POST /v4/linode/instances/{linodeId}/boot`, `/shutdown`, `/reboot` (no body); its state read before and after |
| **Set a record…** under a domain's records | `POST /v4/domains/{domainId}/records` (a new one) or `PUT .../records/{recordId}` (the host's A, AAAA or CNAME, or the same target's TTL or priority) |
| **Remove** on a record | `DELETE /v4/domains/{domainId}/records/{recordId}` |
| **Add a rule…** under a firewall's rules, **Remove** on a rule | `PUT /v4/networking/firewalls/{firewallId}/rules`: the whole set, every other rule and both policies as read |
| **Add an SSH key…**, **Remove** on a key | `POST /v4/profile/sshkeys` ({label, ssh_key}), `DELETE /v4/profile/sshkeys/{sshKeyId}` |
| **Take over…** on a Dynamic DNS host holding another address | that host's A record set to this network's address, once confirmed (below) |
| **Refresh** | reads only |
| **Update DNS now** | the Dynamic DNS hosts of its own set now, once confirmed |

Nothing is sent until you confirm the change: the confirmation names it (the Linode, the record, the rule, the key) and
what is kept. The answer says what was done and what was read back after it.

- **A powered-off Linode still bills.** Akamai keeps its disks and holds its resources for it while it is off (its
  pricing FAQ: a powered-off VM is still billed); only removing a service ends its charge, which this plugin never does.
  The Linodes table and the Shut down confirmation say so. Linode's API does not say how long a shutdown waits for the
  system to stop: save unsaved work first.
- **A record** is one record of DNS Manager: an A, AAAA or CNAME set changes the host's record of its type (a host with
  several is refused: remove the ones not wanted first), a TXT, MX, NS or CAA record is added beside the others (the same
  target there already: its TTL or priority changed, or nothing written). Every other record is kept, and the records are
  read back after each change and checked. No CNAME at the domain itself (DNS Manager has no CNAME flattening); a slave
  domain's records come from its master and are not written. TTLs are Linode's own values (5 minutes to 4 weeks).
- **A firewall's rules** are written whole (the reference: the call "replaces all of a Firewall's inbound and outbound
  rulesets"), so each change reads the rules fresh, adds or removes one rule, and writes everything back as read. The
  page's form carries the fingerprint of the rules it showed: if they changed since (in Cloud Manager, say), nothing is
  written and the page shows them as they are now. The reference has no conditional write, so the version the write
  answers is checked too: one more than the one read, else another change landed in between, and the report says so
  with the rules as they were. Rules holding a field this plugin does not know are not written (their table says why).
  An added rule goes after its direction's others (the first rule that matches decides, else the policy).
- **Risky rule changes are asked twice**, whatever rule a change adds or removes: each is weighed by the inbound policy
  and the rules left, before and after it. Risky: a change that lets the whole internet (0.0.0.0/0, ::/0) reach every
  TCP or UDP port, or SSH, RDP, Telnet, SMB, VNC, Docker, the Kubernetes API or a database's port (MySQL, PostgreSQL,
  SQL Server, MongoDB, Redis, Elasticsearch, memcached), where it did not before: an ACCEPT added, or a DROP removed
  (removing a DROP that kept SSH shut was asked once in 0.1.0). And a change that ends SSH, from where the rules let it
  in, to a Linode the firewall guards: an ACCEPT removed, or a DROP added. The first confirmation is refused, naming the
  risk; the page then asks "Change the firewall anyway?" and writes only on that second yes (the hook's `accept_risk`,
  honoured only when it is exactly `true`). A web port opened to everyone (80, 443) is asked once.
- **An SSH key** is a public key (the .pub file's line, its kind one Linode takes: ssh-ed25519, ssh-rsa,
  ecdsa-sha2-nistp256/384/521, sk-ecdsa-sha2-nistp256, ssh-dss); a private key pasted by mistake is refused and never
  sent. The profile's keys are for the Linodes you deploy (Linode's reference: a key lets you in as their root user);
  removing one takes it off your profile, not off the Linodes deployed with it.

## What it never does

Nothing that starts or raises a charge: no Linode, volume, snapshot, backup, reserved or extra IP, Kubernetes cluster,
NodeBalancer, database or bucket is made, nothing is resized, cloned, rebuilt or deleted, and backups are never turned
on. The client (`api.py`) can send only its reads and the nine free writes above (`FREE_WRITES`, checked again before each
write); the paths of every other call appear only on its API card (`card.py`), and a test checks the client's source for
them. No firewall is made, deleted, disabled or attached here, and no domain is added or deleted.

## Setting it up

1. **Make a personal access token** in Cloud Manager: your username (top right) > **API Tokens** >
   **Create a Personal Access Token** (https://cloud.linode.com/profile/tokens). Give it a label, an expiry, and an
   access level for each area. What the plugin needs, in Linode's own scopes:

   | Area in Cloud Manager | Access | Scope | What for |
   |---|---|---|---|
   | Linodes | Read/Write | `linodes:read_write` | boot, shut down, reboot (and the Linodes and placement groups read) |
   | Domains | Read/Write | `domains:read_write` | records set and removed, Dynamic DNS |
   | Firewalls | Read/Write | `firewall:read_write` | rules added and removed |
   | Account | Read Only | `account:read_only` | the balance, the transfer pool and the profile's SSH keys shown |
   | Volumes, IPs, Images, Kubernetes, NodeBalancers, Databases, Object Storage, VPCs | Read Only | `volumes:read_only`, `ips:read_only`, `images:read_only`, `lke:read_only`, `nodebalancers:read_only`, `databases:read_only`, `object_storage:read_only`, `vpc:read_only` | shown and counted |
   | Events, Longview, StackScripts | No Access | | never asked |

   **Only if you want the profile's SSH keys added and removed here**: Account **Read/Write** (`account:read_write`).
   Linode names no scope of the profile's own for SSH keys, and the one its reference gives also lets a token make
   payments, add users and cancel the account, none of which the plugin ever asks; so Read Only is the default here.
   With it, the SSH keys are shown and their Add and Remove are refused by Linode (the page says so). An area left at
   No Access is shown as not allowed by the token, beside the rest. A token holding a space or a line break inside (a
   wrapped paste through setx or the registry) is refused: never sent, never shown.
2. **Dynamic DNS** (optional): add each host's domain to DNS Manager (Domains > Create Domain) and point the domain's
   name servers at Linode's. DNS Manager serves a domain's records only while the account has at least one active Linode
   (its guide); the plugin says so when none is running.
3. **Enter the settings**: on the platform's page, the plugin's **Settings…** asks for each one below, the token typed
   hidden; a field left empty keeps its value, and no value is ever shown back. They are pairs the plugin asks of the
   login of the app it is attached to, each named by its variable (LINODE_TOKEN is the pair `linode-token`): today the
   platform's login keeps them as your user environment variables, and the plugin reads them at once. Once the platform
   binds the login app, they are the signed-in user's pairs there instead. Setting the variables yourself works too.

| Variable | | |
|---|---|---|
| `LINODE_TOKEN` | the API (secret) | the personal access token of step 1 |
| `LINODE_DDNS_HOSTS` | optional | the hosts kept at this network's address, comma separated: `home.example.com`, `@.example.com` (the domain itself); each in a master domain of DNS Manager |
| `LINODE_DDNS_MINUTES` | optional | minutes between Dynamic DNS checks, 1 to 1440 (5 unless set) |

The plugin keeps no settings file and never shows a value: its status names the settings that are set.

## Dynamic DNS

This network's public IPv4 address is asked of DNS (`myip.opendns.com` of OpenDNS's resolver, else Google's
`o-o.myaddr.l.google.com`, each asked of the name server by its IPv4 address), then each host's records are read from
its domain's (one read a domain a pass). Dynamic DNS changes only what is its own (liminal-libs 1.49.2's keeper, after
an audit found 0.1.0 pointed a listed host's live record at home within a minute, unasked):

- a host with no A record: one is made, with a TTL of 300 seconds (the least Linode takes, so a change is seen soon);
- a host already pointing at this network, or at the address the keeper set there last: kept current, its A record
  changed when the network's address moves (its TTL kept), after a restart too (what is its own is kept in the
  platform's folder, `linode/ddns.json`);
- a host holding another address, or several: **left as it is**, its row saying what it holds, with a **Take over…**
  whose confirmation says what it holds and that it will point here instead. Once taken over, its A record is set to
  this network's address (several are never cut to one unasked; taken over, one is kept, the others removed);
- a host that is a CNAME gets no A record beside it (DNS Manager's own set refuses that): it is said and left as it is.
  A host's AAAA records are not Dynamic DNS's: they are left as they are.

Update DNS now (confirmed) sets each host of its own whether it differs or not. The address is asked again just before a
write: a stale one is never written back. A host taken out of `LINODE_DDNS_HOSTS` is let go, so one listed again later
is asked about again. The reference's `[remote_addr]` target is not used: the plugin sends the address it found, so the
record is this network's IPv4 address even when the request goes out over IPv6. A host in no master domain of the
account (a slave's, another provider's) is named as such.

## Valid, and the platform

The plugin is valid while its token is set and the last read worked or has not been tried yet; the platform disables a
plugin that is not valid. With nothing set, it is not valid and names the token, where to make it and the access it
needs. A token refused (401: wrong, revoked or expired) makes it not valid with Linode's words; an area the token may not
read (403) is said beside the rest. A failed read is taken as untried a quarter of an hour later (the platform attaches
it again and it is tried again), or at once when its settings change.

## Its API

It attaches to **Linode's API v4** (Akamai Cloud): `https://api.linode.com/v4`, a JSON REST API, a personal access token
as a bearer token. Its page draws the API card (`card.py`): what the API is, its address, its token, its limits and costs,
every section of the reference (26, from Administration to VPCs; the 13 the plugin uses say what for) and its calls (the
29 the plugin makes, each with what for, and 31 more worth knowing, the 10 that start a charge marked). The main pages:

- Reference: https://techdocs.akamai.com/linode-api/reference/api (every operation:
  https://techdocs.akamai.com/linode-api/reference/api-summary)
- Get started (tokens and scopes): https://techdocs.akamai.com/linode-api/reference/get-started
- Rate limits: https://techdocs.akamai.com/linode-api/reference/rate-limits (200 list requests a minute, 1,600 others)
- Pagination, filtering, errors: https://techdocs.akamai.com/linode-api/reference/pagination,
  https://techdocs.akamai.com/linode-api/reference/filtering-and-sorting, https://techdocs.akamai.com/linode-api/reference/errors
- Personal access tokens: https://techdocs.akamai.com/cloud-computing/docs/manage-personal-access-tokens
- Pricing: https://www.akamai.com/cloud/pricing; how billing works:
  https://techdocs.akamai.com/cloud-computing/docs/understanding-how-billing-works
- Status: https://status.linode.com; changelog: https://techdocs.akamai.com/linode-api/changelog
- OpenAPI description: https://github.com/linode/linode-api-openapi; the Linode CLI:
  https://techdocs.akamai.com/cloud-computing/docs/getting-started-with-the-linode-cli
- DNS Manager: https://techdocs.akamai.com/cloud-computing/docs/dns-manager; Cloud Firewall:
  https://techdocs.akamai.com/cloud-computing/docs/cloud-firewall

What it learned of the API while it ran (`api_facts`, asking nothing): the requests made, the last answer and when, the
rate limit's headers as last given (X-RateLimit-Limit, -Remaining, -Reset), when the account and the plans were read, and
the areas the token may not read.

## Its hooks

`present`, `status` (the summary, the facts, `tables`, `actions`, `forms`), `refresh()`, `linodes()`, `domains()`,
`records(domain)`, `firewalls()`, `ssh_keys()`, `power(linode, action)`,
`set_record(domain, name, rtype, target, ttl=None, priority=None, tag=None)`,
`remove_record(domain, record, name=None, rtype=None, target=None)`,
`add_rule(firewall, seen, direction, action, protocol, ports=None, addresses=None, label=None, description=None, accept_risk=False)`,
`remove_rule(firewall, seen, direction, position, rule=None, accept_risk=False)`, `add_ssh_key(label, ssh_key)`,
`remove_ssh_key(key, label=None)`, `ddns_update(force=True)`, `ddns_take_over(host, holds=None)`. A change's report:
`said`, `lines` (its words), `ok`, `changed`. What the page showed is needed, so nothing is changed unseen: a record's
host, type and target to remove it, the rules' fingerprint (`seen`) to change them and a rule's words to remove it, a
key's label (`""` for none) to remove it; `accept_risk` counts only when it is exactly `true`.

## From the command line

Its settings read from the environment (as this shell has them). The reads ask nothing; each change says what it does
and asks you to type yes (`--yes` answers for you):

```
python -m plugin_platform_linode status
python -m plugin_platform_linode servers
python -m plugin_platform_linode domains
python -m plugin_platform_linode records example.com
python -m plugin_platform_linode firewalls
python -m plugin_platform_linode keys
python -m plugin_platform_linode ddns [--now]          (asks yes: a pass may write)
python -m plugin_platform_linode power web-1 off
python -m plugin_platform_linode set example.com home A 203.0.113.7 --ttl 300
python -m plugin_platform_linode set example.com @ TXT "google-site-verification=..."
python -m plugin_platform_linode remove example.com @ TXT "google-site-verification=..."
```

`--json` before the command prints the answer as JSON. Firewall rules and SSH keys are changed from the platform's page.

## Install

```
pip install "plugin-platform-linode @ git+https://github.com/pcxmac-dev/plugin-platform-linode@main"
```

or, for the platform's preview, a checkout in the plugin directory (`LIMINAL_PLUGINS`). Its tests use a stand-in for
Linode's API alone (`python -m pytest`): none reaches Linode, a name server or the network. With
`LIMINAL_VENDOR_PAGES=1`, one more test asks every address on its API card.
