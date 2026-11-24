# Workload catalog and sizing suggestions

These editable values are small-lab/initial-pilot starting points, not production capacity or performance guarantees. Measure the actual workload, growth, redundancy, backup, licensing and stamp capacity before use. Values are per VM; explicit `count` multiplies them. All deployments request Arc guest management and AMA/DCR monitoring; monitoring follows successful guest acceptance.

| Profile | Suggested count in example | vCPU | RAM (MiB) | Suggested OS (GiB, advisory only) | Data disks (GiB) and role | What is configured |
| --- | --- | --- | --- | --- | --- | --- |
| `fileServer` | 1 | 2 | 4096 | 128 | 128 `data`: shares on `E:` | Standalone encrypted SMB share; client-scoped TCP 445 |
| `sqlServer` | 0 (enable 1 when licensing/source are ready) | 4 | 8192 | 128 | ISO: 128 `data`, SQL under `E:\Sql`; Marketplace: disk stays RAW, image database paths preserved | SQL 2022 ISO Developer/Evaluation or licensed Standard/Enterprise; alternatively verify preinstalled Enterprise without SQL/firewall changes |
| `webServer` | 0 (enable 1 for a pilot) | 2 | 2048 | 64 | None; demonstration content on OS disk | Ubuntu 24.04 (primary)/22.04 Nginx HTTP site with HTTP-layer client CIDR ACL |
| `iisServer` | 0 (enable 1 for a pilot) | 2 | 4096 | 128 | 64 `data`: site content at `E:\Iis` | Windows IIS static HTTP site; client-scoped TCP 80 |
| `windowsApp` | 0 (enable 1 for a pilot) | 2 | 4096 | 128 | 64 `appdata`, **unformatted** | Base Windows VM only; no application/runtime or service firewall rule |
| `linuxApp` | 0 (enable 1 for a pilot) | 2 | 2048 | 64 | 64 `appdata` + 32 `logs`, **unformatted** | Base Ubuntu VM only; no application/database or service firewall rule |

The [answer example](../answers/example.json) contains every profile with editable CPU, RAM, OS suggestion, disks and count. `fileServer`, `sqlServer` and `iisServer` require one `dataDiskSizeGB`. File/IIS and ISO SQL scripts identify exactly one expected-size non-OS disk and refuse existing unknown data. ISO SQL shares that disk between data/log/temp/backup; separate production SQL I/O and backup design is not implemented. Preinstalled SQL verification deliberately leaves that additional disk RAW and preserves the image's existing database locations. `webServer` has no data disk. Base profiles accept `dataDisks` with up to four unique, lowercase alphanumeric roles (1-12 characters), each with a `sizeGB`; role determines the stable resource-name suffix. The launcher sorts roles so answer-file order does not change attachment order or ownership hashes. Renaming a role or changing a disk size is an immutable configuration change, not a migration or resize operation.

Windows profiles use Windows Server 2022 by default; an already-imported Windows Server 2025 image is an explicit alternative (`source: "existing"`, `os: "WindowsServer2025"`). The Windows guest gate accepts server builds 20348 and 26100, not Windows client editions. The same disk/firewall/service safeguards apply to installations. ISO SQL Developer/Evaluation remain nonproduction-only; ISO Standard/Enterprise require explicit licensing/terms confirmation and a pinned Key Vault product-key reference, not a plaintext answer-file key. The separate preinstalled Marketplace mode allows only the exact SQL 2022 Enterprise/Windows Server 2022 tuple and no media/key; it verifies without modifying SQL, disks or firewall. See [SQL prerequisites](../README.md#sql-licensing-and-product-key-reference) and [Marketplace mode](../README.md#preinstalled-sql-marketplace-image). These compatibility options still require live acceptance.

## Count and addressing

An explicit `count: 2` with `name: "winapp"` deploys `winapp-01` and `winapp-02`, with NICs `winapp-01-nic`/`winapp-02-nic` and optional disks `winapp-01-appdata`/`winapp-02-appdata`. Explicit `count: 1` retains `-01`; increasing the count does not rename existing instances. `count: 0` creates nothing and does not resolve that entry's image or secrets. Omitted `count` preserves the old exact-name, single-VM behavior.

Each entry allows 0-20 instances; total active instances are capped at 100. Duplicate entry names, expanded names, data-disk roles and IP addresses fail validation. A counted base name can have at most 12 characters. Workload entries with count zero are still schema-checked but can retain example SSH/media/digest placeholders until enabled.

On Static logical networks, counted entries need `privateIpAddresses` containing exactly one explicit address per instance; legacy singles use `privateIpAddress`. You cannot mix the fields. Preflight checks each expanded IP against the network prefix, VM pool, gateway and referenced allocations. On DHCP omit both fields. No addresses are inferred, incremented or reserved offline.

## Applied versus advisory capacity

`processors` and `memoryMB` are applied to each VM. CPU allows 2-64; memory allows 2048-262144 MiB, in 1024-MiB increments. Windows file/IIS/base profiles require at least 4096 MiB; SQL requires at least 8192 MiB. Data disks are created/attached with the supplied 32-8192 GiB sizes.

**`suggestedOsDiskSizeGB` is planning-only.** The pinned `2024-01-01` VM API provides an OS-disk resource reference, not a size override on image-based creation. The actual OS disk inherits source image capacity. This launcher does not create a blank OS disk, resize an existing OS disk, shrink partitions or claim to apply the suggestion. Prepare an appropriately sized generalized image separately and verify actual guest free space. OS suggestions allow 32-2048 GiB and do not enter immutable configuration hashes.

Validate/Preflight/Deploy print aggregate active VM/vCPU/RAM/data-disk totals and separately labeled OS suggestions (with an unspecified count). For example, the unchanged sample selects one VM, 2 vCPU, 4096 MiB RAM, one 128-GiB data disk and a **128-GiB OS suggestion**. It does not assert 256 GiB of actual stamp consumption. Actual OS capacity, image downloads/cache, dynamic allocation, resiliency copies, free-space margins and monitoring ingestion are not included in applied data-disk totals.

## Prepared Linux sources

The Nginx example uses a prepared image already on the stamp's CSV; the base-Linux example demonstrates a page-blob source with a process-environment SAS reference. Both remain disabled until you prepare and verify an image, supply its real SHA256 and SSH key, and select the count. Alternatively use:

```json
"image": {
  "source": "existing",
  "os": "Ubuntu2204",
  "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-images/providers/Microsoft.AzureStackHCI/galleryImages/ubuntu-prepared",
  "preparedImageConfirmed": true
}
```

Use primary `Ubuntu2404` for a prepared 24.04 image; `Ubuntu2204` remains explicit. Both Linux profiles enforce the selected version at guest acceptance. Strict cloud-init validation is the default; the investigated provider-warning policy requires an explicit `linuxProvisioning.schemaPolicy: azureLocalKnownWarnings` selection and never changes the original seed. NIC DNS is copied from the selected logical network, not guessed or changed on shared infrastructure. Base Linux runs a validation-only extension, without installing an application or formatting its data disks. An unknown-provenance existing image is limited to the explicit one-per-profile pilot option documented in the deployment guide; it is not silently attested as prepared.

This is an Azure Local gallery resource ID, not a filename. See the [deployment guide's preparation and secret-handling requirements](../README.md#prepare-images). The importer trusts the operator-verified digest for provenance/reuse; it does not rehash bytes on the stamp. Never put a SAS, password, private key or customer-specific identifiers in a committed answer file.

## Deliberate exclusions

No AD controllers, domain joins, failover clusters, SQL HA, PostgreSQL service, application-specific runtime, certificate provisioning, public endpoint, backup or production capacity certification is implied by these profiles. In particular, base VMs are not ready-to-serve applications. Follow a separately reviewed installation and data-protection design for those workloads.
