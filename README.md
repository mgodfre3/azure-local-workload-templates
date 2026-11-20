# Azure Local workload templates

Bicep and PowerShell 7 tooling for deploying **Arc-enabled VMs on an existing Azure Local stamp**. These are `Microsoft.AzureStackHCI` resources scoped to `Microsoft.HybridCompute/machines`, not Azure IaaS VMs.

**Initial release: offline-verified reference implementation with partial pilot evidence, not full live acceptance or production certification.** Start in a disposable lab, review the generated deployment and guest scripts, and verify client connectivity, data protection, licensing, and monitoring before production use.

## Workloads

Select entries in a single answer file and set each `count` to the number of independent VMs to deploy (`0` disables an entry). The [workload catalog and starting sizes](docs/catalog.md) distinguish configured services from base VM-only profiles.

| Profile | Guest | Configuration |
| --- | --- | --- |
| `fileServer` | Windows Server 2022 | A dedicated data disk, encrypted SMB share, explicit administrator permissions and client-CIDR-scoped TCP 445 |
| `sqlServer` | Windows Server 2022 | ISO installation of SQL 2022 Developer/Evaluation or licensed Standard/Enterprise; alternatively verification-only of the exact preinstalled Enterprise Marketplace image |
| `webServer` | Prepared Ubuntu 22.04 or 24.04 LTS | Nginx, SSH key authentication and HTTP client-CIDR ACLs |
| `iisServer` | Windows Server 2022 | IIS static HTTP demonstration site on a dedicated data disk, client-CIDR-scoped TCP 80 |
| `windowsApp` | Windows Server 2022 | **Base VM only**: administrator login and optional unformatted data disks; no application or inbound firewall rules |
| `linuxApp` | Prepared Ubuntu 22.04 or 24.04 LTS | **Base VM only**: SSH key login and optional unformatted data disks; no application or inbound firewall rules |

Each deployment requests a system-assigned Arc identity, guest management, Azure Monitor Agent (AMA), an OS-specific data collection rule (DCR), and a DCR association targeting the supplied Log Analytics workspace. Configured service profiles also receive an Arc Custom Script extension; base Linux receives an image-acceptance-only extension, not an application script. AMA/DCR deployment waits for guest acceptance; VM provisioning alone is not service or monitoring success. Inherited policies can independently install agents/associations targeting other workspaces; this launcher does not remove them or guarantee a single destination. Collection is intentionally small: Windows System/Application warnings and errors, or selected Linux syslog warnings and errors, plus AMA heartbeat. This is **not** SQL-specific monitoring, VM Insights, auditing, or backup.

## Prerequisites

- An existing, healthy, supported **hyperconverged Azure Local 23H2-or-later** deployment with Arc VM management configured, a custom location, one logical network and one storage path (`Microsoft.AzureStackHCI/storageContainers`). Use generalized **English (en-us), generation-2** guest images, as required by Azure Local. These templates do not create or alter the stamp, logical network, routing, DNS, storage pool, or workspace.
- PowerShell **7.4+**, Azure CLI **2.61+**, Bicep **0.42.1+**, and a Git checkout. Install Bicep explicitly with `az bicep install`; the launcher never installs tools or changes Azure CLI's active subscription. Run `az login` to your own tenant beforehand. This release targets **Azure public cloud only** and one subscription. VM infrastructure is in the stamp region; the existing monitoring workspace may be in another region in that subscription.
- An existing target resource group and infrastructure resource groups in the **same region as the stamp**, following Azure Local requirements. The deployer needs read access to the supplied resources and subscription-wide image inventory; effective deployment permissions are checked at the target resource group. Typically use the documented Azure Local VM-management roles plus image-import permissions and Monitoring Contributor as appropriate, scoped by your administrator. The VM Contributor role alone cannot import images. Policy, deny assignments, cross-resource permissions and available capacity can still prevent deployment.
- Registered providers: `Microsoft.AzureStackHCI`, `Microsoft.HybridCompute`, `Microsoft.ExtendedLocation`, `Microsoft.Insights`, `Microsoft.OperationalInsights`, and `Microsoft.EdgeMarketplace`. For Marketplace import, assign the Azure Local resource provider app the documented **Azure Connected Machine Resource Manager** role. Provider registrations and role assignments are never changed by this project.
- Guest DNS and outbound HTTPS access for Arc onboarding/extensions and Azure Monitor. Linux additionally needs Ubuntu package repositories; SQL needs access to the supplied ISO; Windows needs `raw.githubusercontent.com` for the pinned guest script. Review the [Arc network requirements](https://learn.microsoft.com/azure/azure-arc/servers/network-requirements) and [AMA network configuration](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-network-configuration). Disconnected operation, proxies, Arc gateway customization, sovereign clouds, Private Link/AMPLS and DCE configuration are outside v1.
- Enough **operator-verified** CPU, memory, OS/data disk and image-download capacity. ARM metadata checks are not a host capacity reservation.

Authentication defaults to Azure CLI. Alternatively, with **Az.Accounts 5.0+ already installed and signed in**, use `-Authentication AzPowerShell`. This explicitly uses the already-selected Az context if it matches the answer's subscription; otherwise it requires a single matching account/tenant identity among existing contexts. ARM token refresh stays pinned to that profile and tenant. Neither mode changes global contexts, automatically signs in, disables token-cache encryption or silently falls back to another account. Azure CLI/Bicep is still required for local template compilation.

## Prepare images

**Windows:** the launcher searches the subscription's Azure Local image inventory for the exact publisher/offer/SKU/**pinned version** on the chosen custom location. It reuses a ready matching image even if its name differs. If missing, it imports the allowlisted Windows Server 2022 Datacenter Azure Edition image or the explicitly selected SQL Enterprise image described below into the chosen storage container and polls for readiness, with a timeout. It will not overwrite a conflicting name, update existing images, accept Marketplace terms, or purchase a plan. The operator must confirm licensing and any applicable terms beforehand.

The sample's Windows version is an **illustration from Microsoft's public Bicep documentation, not a current security baseline**. Replace it with a currently available, patched version approved for your stamp. Do not use `latest`; list compatible images in the stamp's **Add VM image > Azure Marketplace** portal experience. `source: "existing"` with an Azure Local gallery or Marketplace-gallery resource ID is also supported for Windows. All four Windows profiles additionally accept an already-imported Windows Server 2025 image with explicit `os: "WindowsServer2025"`. Marketplace imports remain restricted to Windows Server 2022; this existing-image compatibility option does not assert live or production certification.

**Ubuntu:** prepare a generalized Ubuntu image (including the **NoCloud** data source) before importing it as an Azure Local **custom gallery image**. This implementation accepts explicit `Ubuntu2204` and `Ubuntu2404` images; that compatibility boundary is not production certification. A generic Canonical Azure IaaS URN is not a safe direct-import substitute. Follow the [official Ubuntu preparation procedure](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-azure-marketplace-ubuntu) and verify current release-specific vendor support. Preparation/hosting can incur costs and is deliberately **not automated** here; the launcher never creates temporary Azure IaaS VMs, uploads files, publishes blobs, or generates SAS tokens. `preparedImageConfirmed: true` attests that the image is generalized, generation 2, NoCloud-enabled, ready for Arc onboarding, and free of machine-specific credentials. Both Linux profiles verify the requested Ubuntu release, clean cloud-init completion, NoCloud, the exact requested SSH key, locked administrator/root passwords, no inherited root/home SSH keys, password-disabled SSH and active SSH before configuring an application.

Choose exactly one Linux image source:

| `image.source` | Required source fields | Behavior |
| --- | --- | --- |
| `existing` | `os: "Ubuntu2204"` or `"Ubuntu2404"`, `resourceId`, `preparedImageConfirmed: true` | Reuse an existing **Azure Local** `Microsoft.AzureStackHCI/galleryImages` resource, not an Azure Compute Gallery ID or VHD URL. No import. |
| `local` | `os`, `name`, `path`, `sha256`, `preparedImageConfirmed: true`, `stampPathConfirmed: true` | Import a prepared `.vhdx` already on a cluster shared volume, for example `C:\ClusterStorage\Volume1\Images\ubuntu.vhdx`. The path is interpreted **on the stamp**, not on the launcher machine. |
| `blob` | `os`, `name`, `uri`, `sha256`, `preparedImageConfirmed: true`, `pageBlobConfirmed: true`, `sasTokenEnvironmentVariable` | Import a prepared VHD/VHDX hosted as an Azure Storage **page blob**. `uri` is an HTTPS `*.blob.core.windows.net` URL **without** a SAS/query. Inject an unexpired, blob-scoped, HTTPS-only read SAS in the named process environment variable. |

These modes use the supported [local-share/CSV import](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-image-local-share) and [Storage account import](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-image-storage-account) mechanisms (`galleryImages.properties.imagePath`). Local mode deliberately restricts inputs to absolute `drive:\ClusterStorage\volume\...\image.vhdx` paths accessible to every node; arbitrary UNC paths, client paths, relative paths and traversal are rejected. The launcher does **not** test local client filesystem existence as proof of stamp access. Verify stamp access yourself before setting `stampPathConfirmed`. Blob mode requires a page blob and stamp egress/access to the source; a block blob or an expired SAS is not sufficient. The SAS is read only when a missing image is actually imported, sent directly to ARM in memory, and never included in the answer, command line, deployment parameters, outputs, or image tags. Do not use shell history or transcripts to inject credentials; use your secret manager's environment injection and clear them afterwards.

For an **explicitly authorized disposable pilot only**, an existing Linux image with unknown preparation provenance can instead use `"pilotGuestValidation": true` **without** `preparedImageConfirmed`, plus `-AllowUnverifiedExistingLinuxImage` on the launcher. This permits at most one intended VM per Linux profile, never extra probe VMs or image imports. Only a public SSH key is supplied at VM creation; no password or secret custom data is delivered. The same guest checks run fail-closed before Nginx or managed monitoring, and do not repair an unsafe image. An explicitly non-NoCloud image still fails preflight. Null image metadata is unknown, not an attestation or proof of incompatibility. Even successful guest checks cannot establish trustworthy image provenance, absence of every inherited credential, or absence of malicious content: use only an operator-selected image in a trusted pilot network, verify unique machine/SSH host identities, and do not put production secrets or workloads on it. Reprepare the image for normal use.

`sha256` is the operator-verified digest of the final prepared file, not a download checksum enforced by the import API. Keep the source immutable through import and audit that the blob/CSV file matches this digest. Custom imports are tagged with this digest for future reuse: a ready NoCloud/Linux/V2 image with the same digest on the same custom location is reused even under another name. An occupied but incompatible/unverified target name fails rather than being overwritten; for a manually imported image lacking the tag, verify it and choose `existing` explicitly. The launcher does not attest or cryptographically verify remote image contents. Image names for custom imports cannot contain `Windows`. Imports poll with the existing bounded timeout, and verify returned OS/generation/NoCloud/digest metadata before any VM deployment. Missing prerequisites fail explicitly.

## Answer file

Copy [the nonsecret example](answers/example.json) to `answers/site.local.json` (ignored by Git). Replace **all** placeholders before validation. Remove unneeded workload entries. Keep local answer files private; network names and resource identifiers can disclose customer infrastructure even when they are not credentials.

```powershell
Copy-Item .\answers\example.json .\answers\site.local.json
# Edit answers\site.local.json; set counts and supply real keys/media/hashes for enabled profiles.
.\Deploy-Workloads.ps1 -AnswerFile .\answers\site.local.json -Mode Validate
```

The example enables one file server and sets the other five profiles to `count: 0`. Disabled entries still need schema-valid shapes, but their SSH/media/source prerequisites are not evaluated, imported or deployed. Before enabling SQL or Linux, replace the `ssh-rsa AAAA` placeholder, example SQL URL and all-zero hashes with actual independently verified values. Never fabricate values just to pass validation. The subscription IDs, stamp paths and Marketplace version are also illustrative: passing offline validation does **not** confirm them. For a Windows-only pilot, leave SQL/Linux counts at zero and edit the file-server settings.

The [JSON schema](answers/schema.json) rejects unknown properties and unsupported combinations. The launcher also checks typed resource IDs, same-subscription boundaries, reserved usernames, duplicate names/IPs, actual IPv4/CIDR values, RSA key encoding/size, and SQL URL/hash placeholders.

| Input | Meaning |
| --- | --- |
| `stamp.clusterResourceId` | Existing Azure Local cluster resource ID |
| `stamp.customLocationId` | Custom location for that cluster; **verify this mapping in the portal** before setting `mappingConfirmed: true` |
| `logicalNetworkId` | Existing Azure Local logical network (not an Azure VNet/subnet ID) |
| `storageContainerId` | Existing Azure Local storage path resource ID (not a filesystem/CSV path) |
| `adminUsername` | Local administrator on Windows; SSH user on Linux |
| `passwordSource` | Runtime secure prompt, process environment-variable name, or pinned Key Vault reference |
| `logAnalyticsWorkspaceId` | Existing same-subscription workspace with public ingestion enabled; DCRs use its region while AMA uses the VM region |
| `allowedCidrs` | Canonical IPv4 networks, `/8` through `/32`; no unrestricted or loopback/multicast networks |
| `privateIpAddress` | Legacy single-VM address on a Static logical network; counted entries use the list below; omit for DHCP |
| `count` | `0..20` per entry, maximum 100 active VMs in a deployment; omitted means legacy single VM with the exact `name` |
| `namingPrefix` | Optional fleet-wide, 1-8 alphanumeric characters starting with a letter; final VM/guest names including separators and count suffix must fit 15 characters |
| `tags` | Optional nonsecret metadata applied to taggable workload resources, alongside protected ownership tags; `Date Built` accepts only `"auto"` |
| `privateIpAddresses` | With explicit `count`, supply exactly that many static addresses in index order instead of `privateIpAddress`; omit on DHCP |
| `processors`, `memoryMB` | Applied per VM; 2-64 vCPU, 2048-262144 MiB in 1024-MiB steps, with higher per-profile minima |
| `suggestedOsDiskSizeGB` | **Planning only**, 32-2048 GiB; actual OS capacity is inherited from the source image, not resized by this launcher |
| `dataDiskSizeGB` | Applied single data disk, 32-8192 GiB, required by file/SQL/IIS profiles; roles described in the catalog |
| `dataDisks` | Base profiles only: zero to four `{ "role": "appdata", "sizeGB": 64 }` entries; disks are created and attached but never formatted |

Explicit counts always generate `name-01`, `name-02`, and so on, including `count: 1`. Use a base name of at most 12 characters so every Windows computer name remains at most 15 characters. Names, disk roles and static addresses must be unique; collisions after expansion fail offline. Disk names are `VMNAME-role`, NICs are `VMNAME-nic`. Counts can grow without renaming existing instances. **Do not add `count` to an existing legacy entry without reviewing the resulting names**: omit `count` to retain its exact existing VM name. Reducing a count, setting it to zero, or removing an entry does not delete anything. If every count is zero, all modes return without Azure authentication, passwords or writes.

With `"namingPrefix": "BOS"` and `"name": "SQL", "count": 1`, the VM/guest name is `BOS-SQL-01`. Increasing the count adds `BOS-SQL-02` without renumbering the first VM. The complete name must be **less than 16 characters**, including the prefix, both separators and numeric suffix; names are never silently truncated. Prefix casing is preserved and collisions are checked case-insensitively. Omit the prefix to retain legacy naming. Changing an existing fleet's prefix changes resource names: it is not an in-place rename and does not delete the old fleet. Azure-only NIC/disk names retain their separate provider limits.

For example, configure `"tags": { "Function": "WorkloadFleet", "Created By": "<operator>", "Date Built": "auto" }`. The launcher resolves `Date Built` to the creation date in UTC (`YYYY-MM-DD`), preserves an existing workload's original date on reruns/scale-out, and uses the existing machine's ARM creation timestamp when adding metadata to an older managed workload. Missing/unverifiable existing dates fail rather than being relabeled as newly built. NICs, managed data disks and the DCR receive the workload's metadata too; resources without tag support are not sent an unsupported field. Ownership tags `project`, `deploymentSet` and `configurationHash` are reserved. Metadata does not change the configuration hash. Tags are public metadata, never a secret store.

The same deployment invocation can be rerun after resolving a guest prerequisite. Windows configuration uses the extension's public timestamp setting to retrigger the unchanged protected bootstrap reliably. It still fails closed on a required reboot, unsafe inherited firewall rules or an incompatible/preinstalled SQL instance; this retry mechanism does not automatically grant SQL access, accept image preparation, reboot machines or weaken those checks. A successful ARM deployment is not proof of client access or workspace ingestion.

Every mode prints total VM count, vCPU, RAM and attached data-disk count/capacity, separately labeling advisory OS-disk capacity and entries without suggestions. CPU/RAM/data disk settings are deployment inputs; `suggestedOsDiskSizeGB` is intentionally **not** a fabricated VM API size override. The pinned stable VM API has no OS-disk size field for image-based creation. Prepare an appropriately sized image or follow a separately reviewed disk/guest-filesystem expansion procedure; this tool does neither. These are starting suggestions, not capacity guarantees or a host reservation; image caches, OS actual size, resiliency, free space and monitoring overhead are additional.

For two IIS VMs on a Static logical network, edit that catalog entry to include:

```json
"name": "iis",
"count": 2,
"privateIpAddresses": ["10.40.0.40", "10.40.0.41"]
```

On DHCP, omit both address fields. Address lists never auto-increment IPs or assume availability.

V1 supports a logical network with **one subnet**. Static addresses must be usable hosts within its prefix and VM IP pool; gateway conflicts and referenced NIC allocations are checked. IP availability can change after preflight: coordinate with IPAM/DHCP and other deployers. The launcher verifies logical network, storage and image custom-location alignment; the explicit cluster-to-custom-location mapping remains the operator's responsibility.

### Passwords and SSH

The default `{"type":"prompt"}` uses `Read-Host -AsSecureString` at deployment time. For automation, reference an already-injected process environment variable without putting its value in the answer file:

```json
"passwordSource": { "type": "environment", "name": "AZLOCAL_VM_ADMIN_PASSWORD" }
```

Or use an ARM-resolved, version-pinned Key Vault secret:

```json
"passwordSource": {
  "type": "keyVault",
  "vaultResourceId": "/subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.KeyVault/vaults/<vault>",
  "secretName": "vm-admin-password",
  "secretVersion": "<32-hex-character-version>"
}
```

Key Vault must have `enabledForTemplateDeployment: true`; the deployer needs `Microsoft.KeyVault/vaults/deploy/action` and the vault/network must support ARM template retrieval. The launcher does not fetch this secret. Ensure a referenced password meets Windows complexity requirements: this project's runtime password policy is 14-123 characters with upper/lowercase, digit and symbol, without the username or newlines.

Passwords are sent over HTTPS as ARM `secureString` parameters (including nested modules), not command-line arguments, parameter files, outputs, or logs. Prompt/environment values necessarily exist transiently in the PowerShell process and HTTPS request memory; this is not protection against a compromised deployment host, debugger or process dump. Use a trusted host, no transcripts/debug tracing, and clear injected environment variables after use.

Linux requires an actual `ssh-rsa` public key with a modulus of at least **2048 bits** (the pinned VM API's documented format). Password authentication is disabled; a Linux-only run does not read or send an administrator password. Generate and retain the private key yourself; never put it in this repository. SSH/RDP network access and firewall rules are not opened by these templates.

### SQL licensing and product-key reference

There are two mutually exclusive paths. Omit `installationMode` (or use `"iso"`) for the existing installer path. Use `"marketplace"` only to verify an already installed SQL image; it does not install SQL or accept a PID.

For **ISO installation**, Developer and Evaluation remain nonproduction-only and reject any product-key source. Standard and Enterprise require a matching legally licensed SQL Server 2022 PID, `productionLicenseConfirmed: true`, and explicit `acceptLicenseTerms: true`, as well as approved full ISO media and its independently verified SHA256. A product key is not license entitlement, media, or consent. Never paste the key into chat, an answer file, shell history, or source control. Replace the disabled example's `sqlServer` block with this **reference-only** shape when licensed installation is approved:

```json
"sqlServer": {
  "installerUrl": "https://downloads.example.org/sql-server-2022.iso",
  "installerSha256": "<verified 64-hex SHA256>",
  "edition": "Standard",
  "acceptLicenseTerms": true,
  "productionLicenseConfirmed": true,
  "productKeySource": {
    "type": "keyVault",
    "vaultResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/sql-license-vault",
    "secretName": "sql2022-standard-pid",
    "secretVersion": "<32-hex immutable secret version>"
  }
}
```

Use `Enterprise` only with its corresponding licensed media/key; no hardcoded paid-edition keys or key-to-edition guessing is implemented. Setup selects the edition from the PID/media and the guest verifies the actual SQL 2022 edition afterwards, rejecting mismatches instead of silently falling back to Evaluation/Developer. Free editions cannot be upgraded in place by this launcher.

Before enabling paid SQL, an administrator must place the key in an existing **same-subscription Azure public-cloud Key Vault** and grant the SQL guest's **system-assigned Arc identity** secret-get access to that secret (for RBAC, Key Vault Secrets User at the individual secret scope; not subscription/vault-wide Contributor). The guest needs HTTPS access to the vault and a working Arc identity endpoint. Pre-create the intended Arc identity through an independently reviewed bootstrap if access must be assigned before first deployment, or grant access to the retained partial pilot machine and rerun after the expected authorization failure. Do not adopt an unrelated machine. This project neither creates the secret nor grants access/changes vault networking. This is guest-side retrieval, not the administrator-password ARM Key Vault reference: `enabledForTemplateDeployment` is not required for the SQL key, and the launcher never fetches it.

The pinned nonsecret reference travels in existing protected extension settings. The guest retrieves the PID over HTTPS with its Arc identity, writes it to a new SYSTEM/Administrators-only temporary `setup.ini`, and invokes Setup with `/ConfigurationFile`, **not `/PID` or an encoded key in the process command**. Temporary config and captured stdout/stderr are removed in `finally` on success/failure; secret-bearing retrieval/setup exceptions are replaced with fixed messages. SQL Setup excludes the PID from its generated configuration file ([Microsoft reference](https://learn.microsoft.com/sql/database-engine/install-windows/view-and-read-sql-server-setup-log-files?view=sql-server-ver16#the-configurationfileini-file)). Do not publish native Setup logs without a secret review. Local administrators, malicious installers, host dumps and forced termination are outside this protection boundary; after an interrupted process, inspect the protected cache under `%ProgramData%\AzureLocalWorkload` and remove residual PID files before sharing diagnostics. No plaintext PID enters ARM parameters, deployment history, outputs or ownership tags.

### Preinstalled SQL Marketplace image

Microsoft's [Azure Local image catalog documentation](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-image-azure-marketplace) lists `microsoftsqlserver / sql2022-ws2022 / enterprise-gen2`. This is an Azure Local Marketplace image path, not an Azure IaaS URN. Select a concrete version available in **the target stamp's** catalog, never `latest`. Availability and catalog `legalTermsType: None` are **not** entitlement, license activation, or legal acceptance. The offer may be **Preview**; preflight surfaces that status and refuses a separate terms/purchase requirement it cannot safely handle.

After an operator independently confirms appropriate SQL Enterprise **and Windows Server** licensing and all applicable terms, replace the SQL entry's `image` and `sqlServer` objects with:

```json
"image": {
  "source": "marketplace",
  "os": "WindowsServer2022",
  "name": "sql2022-enterprise-pinned",
  "publisher": "microsoftsqlserver",
  "offer": "sql2022-ws2022",
  "sku": "enterprise-gen2",
  "version": "<approved concrete version from the stamp catalog>",
  "licenseAndMarketplaceTermsConfirmed": true
},
"sqlServer": {
  "installationMode": "marketplace",
  "edition": "Enterprise",
  "acceptLicenseTerms": true,
  "productionLicenseConfirmed": true
}
```

These are affirmative operator declarations, **not defaults to copy before approval**. An existing image may instead use `source: "existing"` with its exact `Microsoft.AzureStackHCI/marketplaceGalleryImages` resource ID and `os: "WindowsServer2022"`; the resolved image must carry the exact Enterprise tuple. Missing-image import reuses the bounded, create-only importer and verifies returned OS/V2/identifier/version metadata. SQL images cannot be adopted as base Windows or reinstalled through ISO mode.

This mode performs only local acceptance: the default SQL service must already be running, an integrated query must succeed, SQL must be major version 16 with **Enterprise Edition** (not Evaluation), Windows-only authentication must be configured, and databases must be ONLINE. It preserves preinstalled database locations and attached RAW data disks; it does not reinstall SQL, fetch/inject a key, relocate data, change the listener, open/narrow firewall rules, purchase/activate a plan or install the Azure IaaS SQL extension. Broad inherited inbound rules still fail the existing firewall safety check. Remote client/admin access, licensing activation workflow and production readiness require separately reviewed verification; a successful image download alone proves none of them.

## Preflight and deploy

```powershell
# Read-only Azure checks; does not compile, download images, read passwords, or deploy.
.\Deploy-Workloads.ps1 -AnswerFile .\answers\site.local.json -Mode Preflight

# Read-only preflight and a ShouldProcess preview, not ARM's full what-if analysis.
.\Deploy-Workloads.ps1 -AnswerFile .\answers\site.local.json -Mode Deploy -WhatIf

# MUTATING: imports missing supported images and deploys VMs/extensions/monitoring.
# Prompts before proceeding. Costs can include licensing, ingestion, storage and downloads.
.\Deploy-Workloads.ps1 -AnswerFile .\answers\site.local.json -Mode Deploy
```

Use `-Confirm:$false` only after external approval in unattended automation. Default mode is **Validate**, which is entirely offline. `Preflight` and `Deploy -WhatIf` authenticate and read Azure state but make no Azure writes.

The deployment uses ARM **Incremental** mode. Stable VM/NIC/data-disk/DCR names and ownership/configuration-hash tags permit repeat runs without replacing disks or adopting unrelated resources. Changing a VM's image, size, network, storage, username, SSH key, client allowlist, share name or SQL edition/media hash is rejected; use a new VM name or a separately reviewed migration. Removing an entry does **not** delete its resources. Guest configuration is rerun on each successful deployment attempt to verify service readiness. No destructive rollback or automatic cleanup is performed. Do not run concurrent deployments against the same names; preflight checks are not a distributed lock.

The launcher is the supported entry point. Direct deployment of the low-level Bicep modules bypasses answer validation, image resolution and collision checks.

Windows service-profile Custom Script uses `fileUris` pinned to the current **full Git commit SHA**, with SHA256 verification before execution. The guest file must be clean, committed, and pushed to the checkout's **public GitHub origin**; the launcher checks the hosted bytes before creating resources. A private fork, ZIP download or unpushed/modified Windows guest script is not supported for those profiles. Linux acceptance and Nginx scripts are embedded directly; base Linux runs acceptance only. This avoids Windows command-line size limits without dropping disk/firewall safety checks.

Timeouts are bounded per image/deployment (default three hours; `-TimeoutSeconds 60..21600`). Custom Script has its own **90-minute execution ceiling**, independent of the launcher timeout. Timeout is **not cancellation**: inspect Azure deployment and image state before retrying. Failed guests, networking or AMA leave partial resources and billable monitoring in place; the launcher exits with an error, never a success-shaped fallback. Inspect Azure deployment operations and Arc extension status on the failed VM. Provider errors are not echoed wholesale because they can reflect secure inputs.

## Workload behavior and limitations

- **File server:** standalone/workgroup SMB, not a domain-joined file-service design. One dedicated data disk is mounted as `E:`. Only a uniquely identified, expected-size RAW non-OS disk can be initialized. Existing partitions, label/drive collisions and ambiguity fail rather than risk data loss. Reruns only reuse the expected volume. Grant real user/group access through a separate reviewed domain/ACL design; the initial share is for the explicit local administrator. SMB encryption is required; stock broad TCP 445 allow rules are not silently enabled.
- **SQL:** Developer/Evaluation are nonproduction-only; licensed Standard/Enterprise additionally require the pinned Key Vault reference and confirmations above. Supply a full Microsoft-signed SQL Server **2022 x64 ISO** at a direct public HTTPS URL without redirects or URL credentials/SAS/query strings, and independently verify its SHA256. No bootstrapper, paid Marketplace SQL image, automatic purchase or SQL IaaS extension is used. Data/logs are placed on the dedicated `E:` disk; Windows authentication only, default instance, TCP 1433, no broad client access or SQL Browser exposure. This is not a production availability, TLS-certificate, backup, patching or capacity design.
- **Web:** private HTTP demonstration site, not a public/TLS production service. Nginx enforces client CIDRs at the HTTP layer (`403` for other clients); this is not a network firewall. No public IP, reverse proxy trust, TLS certificate or DNS record is created. Image must not contain unmanaged Nginx configuration. Existing service-start policy requires manual integration.
- **IIS:** standalone static HTTP demonstration site, not an ASP.NET/runtime, TLS, domain-authentication or production web-hosting design. Uses the same guarded single-disk initialization as file/SQL servers and stores a fixed test page in `E:\Iis`. IIS anonymous/worker identities receive read-only content access. Unexpected sites, bindings, content paths and existing page content fail rather than being overwritten. The role's two built-in HTTP/HTTPS firewall rules are disabled and replaced with client-CIDR-scoped TCP 80; pre-existing unrelated broad rules still require operator resolution.
- **Base application servers:** supported Windows Server or Ubuntu 22.04/24.04 with Arc/AMA, login configuration and optional disks; Linux also runs read-only image acceptance. No application, database, domain membership, service port, filesystem formatting or mount is configured. `allowedCidrs` is retained as a contract field for future service configuration, **not an enforced base-profile firewall**. Do not treat `linuxApp` as a configured PostgreSQL server. Those disks remain RAW for a separately reviewed application/storage configuration.
- Guest scripts verify local service readiness (SMB, an integrated SQL query, HTTP). They do not prove access from a customer client, TLS trust, name resolution, AD authentication, or data retention. Windows configuration is run as SYSTEM by the Arc extension; Linux runs as root. Workloads must be deployed to new, dedicated VMs, not adopted servers. Windows firewall profiles must be enabled with effective default inbound **Block**; conflicting broad allow rules (including program-scoped Any-port rules) and wider previous allowlists require operator resolution. Pending/required restarts fail deployment; restart manually and rerun rather than rebooting inside the extension.
- The Arc system identity is used by AMA; **no workspace keys or manually assigned workspace data-plane role** are required for normal AMA/DCR ingestion. A successful extension/DCR deployment does not prove that logs have arrived. Check workspace **Heartbeat**, **Event**, and **Syslog** after allowing for ingestion delay. Deliberately generate an OS warning in the lab and confirm its arrival. Existing Azure Policy can deploy other AMA extensions/DCRs; avoid duplicate collection and extra ingestion costs.
- No on-premises redundancy, domain join, production SQL licensing, SQL HA, backups, DR, storage QoS, host placement or application-level security hardening is configured. Windows licensing/activation, Ubuntu image preparation, capacity and stamp ownership are operator responsibilities.

## Development

```powershell
# On a trusted development host, install Pester 5.7.1+ if missing.
Install-PSResource Pester -Version 5.7.1 -Scope CurrentUser -TrustRepository
.\scripts\Test.ps1
```

[The optional GitHub Actions workflow](ci/validate.yml.example) runs the same offline tests and Bicep compilation on Windows and Linux, plus shell syntax checks on Linux. To activate it, copy it to `.github/workflows/validate.yml` and push with a credential authorized to write workflows. **Hosted CI has not run**; the workflow is provided as an opt-in example. Tests cover answer validation, image reuse/import decisions, collision protection, credential references, addressing, RBAC matching, bounded polling, guest disk-safety decisions and read-only modes. **No test creates Azure resources or asserts a successful live deployment.**

Read [the public API and support references](docs/support.md) before extending the support matrix. Contributions should include focused offline tests and identify any live testing separately. See [CONTRIBUTING](CONTRIBUTING.md) and [SECURITY](SECURITY.md).

## License

[MIT](LICENSE). Microsoft product names and documentation links do not imply endorsement or support.
