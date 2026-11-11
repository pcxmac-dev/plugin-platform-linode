# Changelog

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
