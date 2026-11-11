# Changelog

## 0.1.1 (2026-11-11)

What an audit of the cloud plugins found before any key went in (session 87405e6a: eight reviewers, a skeptic per
finding; the user's rule that a risky change is asked twice, and that nothing runs when the platform is not using it).
Needs liminal-libs>=1.49.2.

- **Every firewall change is weighed, whatever rule it adds or removes** (the audit: removing a DROP rule opened SSH to
  the whole internet on one confirmation, firewall.py:318; RDP, Docker and the databases' ports were asked once): the
  inbound policy and the rules left are compared before and after the change. One that lets the whole internet reach
  every TCP or UDP port, or SSH, RDP, Telnet, SMB, VNC, Docker, the Kubernetes API or a database's port where it did not
  before, or that ends SSH to a Linode the firewall guards, is refused once and asked again ("Change the firewall
  anyway?"). A web port opened to everyone is still asked once.
- **Dynamic DNS changes only what is its own** (the audit: a host listed in LINODE_DDNS_HOSTS had its live record
  pointed at home within a minute, unasked, ddns.py:81), through liminal-libs 1.49.2's keeper: a host with no A record
  made, one pointing here or at the address it set last kept current (its state in the platform's folder,
  linode/ddns.json, so a restart after the network's address moved still knows it), and one holding another address,
  or several, left as it is with a **Take over…** (its confirmation names what it holds) and the hook `ddns_take_over`
  (refused when the host holds something else than the page showed); several addresses never cut to one unasked;
  **Update DNS now** confirmed (a form, no longer one click); a host taken out of the settings let go; a CNAME host given
  no A record beside it; a write sets the host's A record to exactly one address.
- **The background reading runs only under the platform, and only once the token is set**: the charts app run alone,
  which attaches every plugin it finds, starts nothing; entering the token starts it (`settings_changed`). **A pass ends
  once detached**: it writes nothing more, and no setting is read from the process environment after a detach.
- **The second confirmation counts only when it is exactly true** (`accept_risk is True`: a "yes", "false" or a 1 from a
  local program is refused like none), and what the page showed is needed, never skipped when left out: the rules'
  fingerprint and a removed rule's words, a removed record's host, type and target, a removed key's label.
- **A token holding a space or a line break inside is refused**, never sent nor shown (the audit: requests' quoting of
  the header escaped it past the scrub; liminal-libs 1.49.2 scrubs it too).
- **Account Read Only by default**: Read/Write on Account only to add and remove the profile's SSH keys here (the audit:
  that scope also lets a token make payments, add users and cancel the account).
- The words: Boot's dialog says it starts no new charge (a Linode bills the same off); Set a record's says what a set
  over a host's record drops; the command line's `ddns` asks yes as its other changes do.
- Not this repo's: a private key pasted into Add an SSH key reached platform.log (the audit's blocker), which
  liminal-platform 0.20.1 fixed (75acf30: a change asked of a plugin is logged without its values); the account read
  every quarter of an hour while attached, and the ask route taking a change without the page, stay the user's and the
  platform's to decide.

The platform's one-shot commands (status, machine: `PlatformApp.once`, liminal-platform 0.20.1) start none of its background work.

## 0.1.0 (2026-11-11)

The first release (the user: "ALSO i would like to add two new plugins, Digital Ocean and LINODE"; for the cloud
plugins, "Free changes only"; "each plugin should reflect the the API its attached to, and present links that provide
documentation, the plugin interface should more or less contain what it already has, BUT, it should also expose more of
what the API is about"):

- the settings read through the library's Login interface alone, as pairs named by their variables (`linode-token` for
  LINODE_TOKEN, `linode-ddns-hosts`, `linode-ddns-minutes`): the platform's EnvironmentLogin today, the login app's pairs
  once the platform binds it; no settings file; the status names the settings set, never a value. The token's hint, the
  page's why and the README name where it is made (Cloud Manager: your username > API Tokens) and the access it needs in
  Linode's own scopes: Read/Write for Linodes, Domains, Firewalls and Account (the profile's SSH keys: Linode gives them
  no scope of their own), Read Only for the rest it shows;
- the account through Linode's API v4 (the library's RestClient, a bearer token): the balance and this month's charges
  so far, promotion credit, the transfer pool, the Linodes with their plans, addresses and prices a month and an hour
  (the region's own, backups added), DNS Manager's domains and records, the Cloud Firewalls with their rules and what
  they guard, the volumes, the profile's SSH keys, the reserved IPs, and counts of Kubernetes clusters, NodeBalancers,
  databases, buckets, the account's own images, VPCs and placement groups; about 20 requests a quarter of an hour while
  attached, the plans once a day; an area the token may not read said beside the rest;
- free changes only, each confirmed on the platform's page (its forms): a Linode booted, shut down or rebooted (its
  state read before and after; a powered-off Linode still bills, and the page says so); a DNS record set or removed, one
  record at a time, every other record kept and the records read back after; a Cloud Firewall rule added or removed, the
  whole set written back as read, refused when the rules changed since the page read them (their fingerprint) and the
  version answered checked against the one read; a rule opening SSH or every port to the whole internet, or a change
  ending SSH to a Linode the firewall guards, asked twice (accept_risk); an SSH key added to the profile or removed (a
  private key refused, never sent);
- nothing that starts a charge: the client sends its reads and nine free writes alone (`FREE_WRITES`, checked before each
  write), and the paths of every other call appear only on its API card, which a test checks;
- Dynamic DNS through DNS Manager with the library's Keeper: this network's IPv4 address asked of OpenDNS, else Google,
  each host's A record set where it differs (its TTL kept) or made (TTL 300), Update DNS now for every host;
- its API on its page (plugin API 2.2): Linode's API v4 with its pages (the reference, the summary, get started, rate
  limits, pagination, filtering, errors, tokens, pricing, billing, status, changelog, the OpenAPI description, the token
  page, the CLI, the Python SDK, DNS Manager, Cloud Firewall: every address read on 2026-11-11 and checked), the 26
  sections of its reference (13 used, each saying what for), 29 calls made and 31 more worth knowing (10 that start a
  charge marked); `api_facts` from the answers alone (requests, the last answer, the rate limit's headers, when read);
- `python -m plugin_platform_linode status | servers | domains | records | firewalls | keys | ddns | power | set | remove`
  (each change asks yes).
