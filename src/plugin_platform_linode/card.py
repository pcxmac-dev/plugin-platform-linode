"""What the plugin attaches to (plugin API 2.2: liminal_libs.sources.apis): Linode's API v4, as Akamai's pages give it (read
2026-11-11): what it is, its address, its token, its limits and costs, its pages, every part of its reference (the parts
the plugin uses said, the rest shown as such) and its calls: the ones the plugin makes, each with what for, and the rest
worth knowing, the ones that change something or start a charge marked. This module is the only place the billable calls'
paths are named: the client (api.py) holds none of them."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
REF = "https://techdocs.akamai.com/linode-api/reference/"
DOCS = "https://techdocs.akamai.com/cloud-computing/docs/"


def ref(page: str) -> str:
    return REF + page


LINKS = (
    Link("Linode API reference", ref("api"), "docs"),
    Link("API summary (every operation by section)", ref("api-summary"), "reference"),
    Link("Get started: tokens, scopes, the first request", ref("get-started"), "guide"),
    Link("Pagination", ref("pagination"), "guide"),
    Link("Filtering and sorting (X-Filter)", ref("filtering-and-sorting"), "guide"),
    Link("Errors", ref("errors"), "guide"),
    Link("DNS Manager", DOCS + "dns-manager", "guide"),
    Link("Cloud Firewall", DOCS + "cloud-firewall", "guide"),
    Link("Manage personal access tokens", DOCS + "manage-personal-access-tokens", "auth"),
    Link("Rate limits", ref("rate-limits"), "limits"),
    Link("Pricing", "https://www.akamai.com/cloud/pricing", "pricing"),
    Link("How billing works", DOCS + "understanding-how-billing-works", "pricing"),
    Link("Linode status", "https://status.linode.com", "status"),
    Link("Changelog (release notes)", "https://techdocs.akamai.com/linode-api/changelog", "changelog"),
    Link("OpenAPI description (linode-api-openapi)", "https://github.com/linode/linode-api-openapi", "spec"),
    Link("API Tokens in Cloud Manager", "https://cloud.linode.com/profile/tokens", "console"),
    Link("The Linode CLI (linode-cli)", DOCS + "getting-started-with-the-linode-cli", "tool"),
    Link("Python SDK (linode_api4)", "https://github.com/linode/linode_api4-python", "sdk"),
)

# every section of the reference's summary (api-summary), in its order, each with its first operation's page
AREAS = (
    Area("Administration", "The account: its balance and charges, invoices, payments, the transfer pool, users, events, "
         "settings, OAuth clients and service transfers", ref("get-account"),
         "the balance, this month's charges so far and the transfer pool"),
    Area("Beta programs", "The beta programs open to the account and those it joined", ref("get-beta-programs")),
    Area("Databases", "Managed Databases (MySQL, PostgreSQL, Valkey): instances, engines, types, credentials, backups",
         ref("get-databases-engines"), "the account's databases counted"),
    Area("Domains", "DNS Manager: domains, their records, zone files and imports", ref("get-domains"),
         "every domain and its records; records set and removed; Dynamic DNS"),
    Area("Identity and access", "Entities, delegation, identity providers and users' roles", ref("get-entities")),
    Area("Images", "Images made, uploaded and replicated; public distributions; share groups (beta)", ref("get-images"),
         "the account's own images counted"),
    Area("Linode instances", "The Linodes: their lifecycle, configurations, disks, interfaces, IPs, backups and stats, "
         "and the plans (types) with their prices", ref("get-linode-instances"),
         "every Linode with its plan, addresses and price; booted, shut down and rebooted"),
    Area("Linode StackScripts", "Scripts that set a Linode up as it is made", ref("get-stack-scripts")),
    Area("Linode Kubernetes Engine (LKE)", "Kubernetes clusters, node pools, kubeconfigs and versions",
         ref("get-lke-clusters"), "the clusters counted"),
    Area("Longview", "Longview's clients, plans, subscriptions and types", ref("get-longview-clients")),
    Area("Maintenance", "Maintenance policies", ref("get-maintenance-policies")),
    Area("Managed", "Linode Managed: contacts, credentials, issues, services, stats", ref("get-managed-contacts")),
    Area("Monitor", "Alert channels and definitions, dashboards, the services monitored", ref("get-notification-channels")),
    Area("Monitor metrics", "An entity's metrics", ref("post-read-metric")),
    Area("Network transfer prices", "What transfer beyond the pool costs", ref("get-network-transfer-prices")),
    Area("Networking", "Cloud Firewalls, IP addresses, NAT Gateways (beta), reserved IPs and VLANs", ref("get-firewalls"),
         "the Cloud Firewalls with their rules and attachments (rules added and removed); the reserved IPs"),
    Area("NodeBalancers", "Load balancers, their configs, nodes and VPC settings", ref("get-node-balancers"),
         "the NodeBalancers counted"),
    Area("Object Storage", "Buckets, access keys, quotas, endpoints", ref("get-object-storage-buckets"),
         "the buckets counted"),
    Area("Placement groups", "Groups placing Linodes apart (anti-affinity)", ref("get-placement-groups"),
         "the groups counted"),
    Area("Profile", "The token's user: apps, devices, logins, SSH keys, two-factor, tokens", ref("get-profile"),
         "whom the token is of; the SSH keys, added and removed"),
    Area("Regions", "The regions and what each offers", ref("get-regions")),
    Area("Resource locking", "Locks against deleting a resource (beta)", ref("get-resource-locks")),
    Area("Support", "Support tickets, their replies and attachments", ref("get-tickets")),
    Area("Tags", "Tags and what they are on", ref("get-tags")),
    Area("Volumes", "Block Storage volumes: made, attached, cloned, resized", ref("get-volumes"),
         "every volume with its size and where it is attached"),
    Area("VPCs", "VPCs, their subnets and addresses", ref("get-vpcs"), "the VPCs counted"),
)

V = "/v4"
CALLS = (
    # -- the calls the plugin makes (api.READS and api.FREE_WRITES) --
    Call(f"GET {V}/account", "The account: balance, the estimated invoice so far (balance_uninvoiced), promotions",
         "Administration", "the account's facts: balance and this month's charges so far", ref("get-account")),
    Call(f"GET {V}/account/transfer", "The transfer pool this billing cycle: used, quota, billable (GB)", "Administration",
         "the transfer pool's facts", ref("get-transfer")),
    Call(f"GET {V}/profile", "The token's user: username, two-factor, restricted", "Profile",
         "whom the token is of (the first read: a refused token stops the read there)", ref("get-profile")),
    Call(f"GET {V}/profile/sshkeys", "The SSH keys of the profile", "Profile", "the SSH keys table", ref("get-ssh-keys")),
    Call(f"POST {V}/profile/sshkeys", "An SSH key added to the profile ({label, ssh_key})", "Profile",
         "Add an SSH key…", ref("post-add-ssh-key"), writes=True),
    Call(f"DELETE {V}/profile/sshkeys/{{sshKeyId}}", "An SSH key removed from the profile (not from the Linodes made "
         "with it)", "Profile", "the SSH keys' Remove…", ref("delete-ssh-key"), writes=True),
    Call(f"GET {V}/linode/instances", "The Linodes", "Linode instances", "the Linodes table", ref("get-linode-instances")),
    Call(f"GET {V}/linode/instances/{{linodeId}}", "One Linode", "Linode instances",
         "a Linode's state before and after a power change", ref("get-linode-instance")),
    Call(f"GET {V}/linode/types", "The plans, each with its price per hour and per month, region prices and the "
         "backups add-on's", "Linode instances", "each Linode's price (read once a day)", ref("get-linode-types")),
    Call(f"POST {V}/linode/instances/{{linodeId}}/boot", "A Linode booted (no config_id: its only configuration, else "
         "the last one booted)",
         "Linode instances", "Boot…", ref("post-boot-linode-instance"), writes=True),
    Call(f"POST {V}/linode/instances/{{linodeId}}/shutdown", "A Linode shut down (it still bills while off)",
         "Linode instances", "Shut down…", ref("post-shutdown-linode-instance"), writes=True),
    Call(f"POST {V}/linode/instances/{{linodeId}}/reboot", "A Linode rebooted", "Linode instances", "Reboot…",
         ref("post-reboot-linode-instance"), writes=True),
    Call(f"GET {V}/domains", "DNS Manager's domains", "Domains", "the Domains table; the zones Dynamic DNS may keep",
         ref("get-domains")),
    Call(f"GET {V}/domains/{{domainId}}/records", "A domain's records", "Domains",
         "each domain's records; read fresh before each change and after it; Dynamic DNS's read", ref("get-domain-records")),
    Call(f"POST {V}/domains/{{domainId}}/records", "A record made", "Domains",
         "Set a record… (a new one); Dynamic DNS making a host's A record", ref("post-domain-record"), writes=True),
    Call(f"PUT {V}/domains/{{domainId}}/records/{{recordId}}", "A record changed (no type)", "Domains",
         "Set a record… (one there); Dynamic DNS setting a host's A record", ref("put-domain-record"), writes=True),
    Call(f"DELETE {V}/domains/{{domainId}}/records/{{recordId}}", "A record deleted", "Domains",
         "the records' Remove…; Dynamic DNS keeping one A record at a host you took over that held several",
         ref("delete-domain-record"), writes=True),
    Call(f"GET {V}/networking/firewalls", "The Cloud Firewalls, with their rules and what they are attached to",
         "Networking", "the Cloud Firewalls table and each one's rules", ref("get-firewalls")),
    Call(f"GET {V}/networking/firewalls/{{firewallId}}/rules", "A firewall's rules, their fingerprint and version",
         "Networking", "the rules read fresh before a change", ref("get-firewall-rules")),
    Call(f"PUT {V}/networking/firewalls/{{firewallId}}/rules", "A firewall's rules replaced, both directions whole",
         "Networking", "Add a rule… and the rules' Remove… (every other rule written back as read)",
         ref("put-firewall-rules"), writes=True),
    Call(f"GET {V}/networking/reserved/ips", "The reserved IPv4 addresses", "Networking", "the Reserved IPs table",
         ref("get-reserved-ips")),
    Call(f"GET {V}/volumes", "Block Storage volumes", "Volumes", "the Volumes table", ref("get-volumes")),
    Call(f"GET {V}/lke/clusters", "Kubernetes clusters", "Linode Kubernetes Engine (LKE)", "counted",
         ref("get-lke-clusters")),
    Call(f"GET {V}/nodebalancers", "NodeBalancers", "NodeBalancers", "counted", ref("get-node-balancers")),
    Call(f"GET {V}/databases/instances", "Managed Databases of every engine", "Databases", "counted",
         ref("get-databases-instances")),
    Call(f"GET {V}/object-storage/buckets", "Object Storage buckets", "Object Storage", "counted",
         ref("get-object-storage-buckets")),
    Call(f"GET {V}/images", "Images (filtered to the account's own: is_public false)", "Images", "counted",
         ref("get-images")),
    Call(f"GET {V}/vpcs", "VPCs", "VPCs", "counted", ref("get-vpcs")),
    Call(f"GET {V}/placement/groups", "Placement groups", "Placement groups", "counted", ref("get-placement-groups")),
    # -- the rest worth knowing: never made here (the ones that start a charge marked) --
    Call(f"POST {V}/linode/instances", "A Linode made", "Linode instances", "", ref("post-linode-instance"), writes=True,
         costs=True),
    Call(f"DELETE {V}/linode/instances/{{linodeId}}", "A Linode deleted (what ends its charge)", "Linode instances", "",
         ref("delete-linode-instance"), writes=True),
    Call(f"POST {V}/linode/instances/{{linodeId}}/resize", "A Linode moved to another plan", "Linode instances", "",
         ref("post-resize-linode-instance"), writes=True, costs=True),
    Call(f"POST {V}/linode/instances/{{linodeId}}/rebuild", "A Linode rebuilt from an image (its disks replaced)",
         "Linode instances", "", ref("post-rebuild-linode-instance"), writes=True),
    Call(f"POST {V}/linode/instances/{{linodeId}}/clone", "A Linode cloned", "Linode instances", "",
         ref("post-clone-linode-instance"), writes=True, costs=True),
    Call(f"POST {V}/linode/instances/{{linodeId}}/backups/enable", "The Backup service turned on for a Linode",
         "Linode instances", "", ref("post-enable-backups"), writes=True, costs=True),
    Call(f"POST {V}/linode/instances/{{linodeId}}/backups", "A manual snapshot of a Linode", "Linode instances", "",
         ref("post-snapshot"), writes=True),
    Call(f"POST {V}/volumes", "A volume made", "Volumes", "", ref("post-volume"), writes=True, costs=True),
    Call(f"POST {V}/volumes/{{volumeId}}/resize", "A volume made larger", "Volumes", "", ref("post-resize-volume"),
         writes=True, costs=True),
    Call(f"POST {V}/volumes/{{volumeId}}/clone", "A volume cloned", "Volumes", "", ref("post-clone-volume"), writes=True,
         costs=True),
    Call(f"DELETE {V}/volumes/{{volumeId}}", "A volume deleted", "Volumes", "", ref("delete-volume"), writes=True),
    Call(f"POST {V}/networking/reserved/ips", "A public IPv4 address reserved (billed monthly, assigned or not)",
         "Networking", "", ref("post-reserved-ip"), writes=True, costs=True),
    Call(f"DELETE {V}/networking/reserved/ips/{{address}}", "A reserved address given up", "Networking", "",
         ref("delete-reserved-ip"), writes=True),
    Call(f"POST {V}/networking/ips", "An IP address allocated to a Linode", "Networking", "", ref("post-allocate-ip"),
         writes=True, costs=True),
    Call(f"POST {V}/networking/firewalls", "A Cloud Firewall made", "Networking", "", ref("post-firewalls"), writes=True),
    Call(f"PUT {V}/networking/firewalls/{{firewallId}}", "A firewall's label, tags, or status (enabled, disabled)",
         "Networking", "", ref("put-firewall"), writes=True),
    Call(f"DELETE {V}/networking/firewalls/{{firewallId}}", "A Cloud Firewall deleted", "Networking", "",
         ref("delete-firewall"), writes=True),
    Call(f"POST {V}/networking/firewalls/{{firewallId}}/devices", "A firewall attached to a Linode or a NodeBalancer",
         "Networking", "", ref("post-firewall-device"), writes=True),
    Call(f"DELETE {V}/networking/firewalls/{{firewallId}}/devices/{{deviceId}}", "A firewall detached", "Networking", "",
         ref("delete-firewall-device"), writes=True),
    Call(f"GET {V}/networking/firewalls/{{firewallId}}/history", "Every version of a firewall's rules", "Networking", "",
         ref("get-firewall-rule-versions")),
    Call(f"POST {V}/domains", "A domain added to DNS Manager", "Domains", "", ref("post-domain"), writes=True),
    Call(f"DELETE {V}/domains/{{domainId}}", "A domain and its records deleted", "Domains", "", ref("delete-domain"),
         writes=True),
    Call(f"POST {V}/domains/import", "A domain imported from another name server (AXFR)", "Domains", "",
         ref("post-import-domain"), writes=True),
    Call(f"GET {V}/domains/{{domainId}}/zone-file", "A domain's zone file", "Domains", "", ref("get-domain-zone")),
    Call(f"PUT {V}/profile/sshkeys/{{sshKeyId}}", "An SSH key's label changed", "Profile", "", ref("put-ssh-key"),
         writes=True),
    Call(f"POST {V}/profile/tokens", "A personal access token made", "Profile", "", ref("post-personal-access-token"),
         writes=True),
    Call(f"GET {V}/account/invoices", "The invoices", "Administration", "", ref("get-invoices")),
    Call(f"GET {V}/account/events", "The account's events", "Administration", "", ref("get-events")),
    Call(f"POST {V}/lke/clusters", "A Kubernetes cluster made", "Linode Kubernetes Engine (LKE)", "",
         ref("post-lke-cluster"), writes=True, costs=True),
    Call(f"GET {V}/regions", "The regions", "Regions", "", ref("get-regions")),
    Call(f"GET {V}/network-transfer/prices", "Transfer prices beyond the pool", "Network transfer prices", "",
         ref("get-network-transfer-prices")),
)

LINODE_API = Api(
    name="Linode API v4",
    maker="Akamai (Linode)",
    about=("Akamai Cloud's API (Linode's), the one Cloud Manager and the Linode CLI use: a JSON REST API for everything an "
           "account holds, from its Linodes, volumes and Kubernetes clusters to DNS Manager's domains and the Cloud "
           "Firewalls. This plugin reads the account and makes only the changes that cost nothing: a Linode powered on, "
           "off or rebooted, DNS records, firewall rules and the profile's SSH keys."),
    kind="rest",
    base="https://api.linode.com/v4",
    version="v4 (v4beta for the operations in beta)",
    auth=("A personal access token as a bearer token (Authorization: Bearer ...), made in Cloud Manager (your username > "
          "API Tokens) with an expiry and an access level for each area: No Access, Read Only or Read/Write (the scopes "
          "linodes:read_write, domains:read_only ...); OAuth apps get the same scopes through login.linode.com"),
    limits=("Paginated GET lists: 200 requests a minute; other operations: 1,600 a minute; some their own (listing images "
            "20 a minute, making a Linode 20 every 15 seconds, a volume 100 a minute); over a limit HTTP 429 with "
            "Retry-After; the X-RateLimit-Limit, -Remaining and -Reset headers say where a call stands. This plugin makes "
            "about 20 requests a quarter of an hour (a domain's records one more each)"),
    costs=("Reading costs nothing, nor do DNS Manager and Cloud Firewalls (free in every region). Linodes bill by the hour "
           "up to a monthly cap whether running or powered off (Akamai's pricing FAQ: a powered-off VM is still billed; "
           "removing a service is what stops its charge); volumes per GB, backups per Linode, reserved IPs monthly, and "
           "NodeBalancers, Kubernetes, databases, Object Storage and transfer beyond the pool bill too"),
    links=LINKS,
    areas=AREAS,
    calls=CALLS,
    verified=VERIFIED,
)
APIS = (LINODE_API,)
