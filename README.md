# Azure Local workload templates

Bicep and PowerShell 7 tooling for deploying **Arc-enabled VMs on an existing Azure Local stamp**. These are `Microsoft.AzureStackHCI` resources scoped to `Microsoft.HybridCompute/machines`, not Azure IaaS VMs.

**Initial release: offline-verified reference implementation, not yet validated on a live stamp. Do not treat it as production-certified automation.** Start in a disposable lab, review the generated deployment and guest scripts, and verify client connectivity, data protection, licensing, and monitoring before production use.

## Workloads

Select one or more entries in a single answer file; each entry deploys an independent VM.

| Profile | Guest | Configuration |
| --- | --- | --- |
| `fileServer` | Windows Server 2022 | A dedicated data disk, encrypted SMB share, explicit administrator permissions and client-CIDR-scoped TCP 445 |
| `sqlServer` | Windows Server 2022 | SQL Server 2022 Developer or Evaluation, Windows authentication, dedicated data disk and client-CIDR-scoped TCP 1433 |
| `webServer` | Prepared Ubuntu 22.04 LTS | Nginx, SSH key authentication and HTTP client-CIDR ACLs |

Every VM receives a system-assigned Arc identity, guest management, a supported Arc Custom Script extension, Azure Monitor Agent (AMA), an OS-specific data collection rule (DCR), and a DCR association targeting the supplied Log Analytics workspace. Collection is intentionally small: Windows System/Application warnings and errors, or selected Linux syslog warnings and errors, plus AMA heartbeat. This is **not** SQL-specific monitoring, VM Insights, auditing, or backup.

## Prerequisites

- An existing, healthy, supported **hyperconverged Azure Local 23H2-or-later** deployment with Arc VM management configured, a custom location, one logical network and one storage path (`Microsoft.AzureStackHCI/storageContainers`). Use generalized **English (en-us), generation-2** guest images, as required by Azure Local. These templates do not create or alter the stamp, logical network, routing, DNS, storage pool, or workspace.
- PowerShell **7.4+**, Azure CLI **2.61+**, Bicep **0.42.1+**, and a Git checkout. Install Bicep explicitly with `az bicep install`; the launcher never installs tools or changes Azure CLI's active subscription. Run `az login` to your own tenant beforehand. This release targets **Azure public cloud only**, one subscription and one Azure region for all resources, including the workspace.
- An existing target resource group and infrastructure resource groups in the **same region as the stamp**, following Azure Local requirements. The deployer needs read access to the supplied resources and subscription-wide image inventory; effective deployment permissions are checked at the target resource group. Typically use the documented Azure Local VM-management roles plus image-import permissions and Monitoring Contributor as appropriate, scoped by your administrator. The VM Contributor role alone cannot import images. Policy, deny assignments, cross-resource permissions and available capacity can still prevent deployment.
- Registered providers: `Microsoft.AzureStackHCI`, `Microsoft.HybridCompute`, `Microsoft.ExtendedLocation`, `Microsoft.Insights`, `Microsoft.OperationalInsights`, and `Microsoft.EdgeMarketplace`. For Marketplace import, assign the Azure Local resource provider app the documented **Azure Connected Machine Resource Manager** role. Provider registrations and role assignments are never changed by this project.
- Guest DNS and outbound HTTPS access for Arc onboarding/extensions and Azure Monitor. Linux additionally needs Ubuntu package repositories; SQL needs access to the supplied ISO; Windows needs `raw.githubusercontent.com` for the pinned guest script. Review the [Arc network requirements](https://learn.microsoft.com/azure/azure-arc/servers/network-requirements) and [AMA network configuration](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-network-configuration). Disconnected operation, proxies, Arc gateway customization, sovereign clouds, Private Link/AMPLS and DCE configuration are outside v1.
- Enough **operator-verified** CPU, memory, OS/data disk and image-download capacity. ARM metadata checks are not a host capacity reservation.

## Prepare images

**Windows:** the launcher searches the subscription's Azure Local image inventory for the exact publisher/offer/SKU/**pinned version** on the chosen custom location. It reuses a ready matching image even if its name differs. If missing, it imports the allowlisted Windows Server 2022 Datacenter Azure Edition image into the chosen storage container and polls for readiness, with a timeout. It will not overwrite a conflicting name, update existing images, accept Marketplace terms, or purchase a plan. The operator must confirm licensing and any applicable terms beforehand.

The sample's Windows version is an **illustration from Microsoft's public Bicep documentation, not a current security baseline**. Replace it with a currently available, patched version approved for your stamp. Do not use `latest`; list compatible images in the stamp's **Add VM image > Azure Marketplace** portal experience. `source: "existing"` with an Azure Local gallery or Marketplace-gallery resource ID is also supported for Windows.

**Ubuntu:** current Microsoft guidance requires preparing a Marketplace-derived Ubuntu image (including the **NoCloud** data source) before importing it as an Azure Local **custom gallery image**. A generic Canonical Azure IaaS URN is not a safe direct-import substitute. Prepare/import this image separately using the [official Ubuntu procedure](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-azure-marketplace-ubuntu), and supply its `galleryImages` resource ID with `preparedImageConfirmed: true`. That preparation can incur Azure costs and is deliberately **not automated** here. V1 fails clearly if it is missing; it does not create temporary Azure IaaS VMs. The launcher checks Linux/V2 and rejects conflicting data-source metadata; missing data-source metadata relies on your explicit preparation confirmation, not an assumption that Azure images are compatible. The guest script independently verifies Ubuntu 22.04.

## Answer file

Copy [the nonsecret example](answers/example.json) to `answers/site.local.json` (ignored by Git). Replace **all** placeholders before validation. Remove unneeded workload entries. Keep local answer files private; network names and resource identifiers can disclose customer infrastructure even when they are not credentials.

```powershell
Copy-Item .\answers\example.json .\answers\site.local.json
# Edit answers\site.local.json, including the real SSH public key and SQL media/hash.
.\Deploy-Workloads.ps1 -AnswerFile .\answers\site.local.json -Mode Validate
```

The unedited example deliberately **fails** validation: it contains an SSH-key placeholder, example SQL URL and all-zero hash. Never replace those with fabricated values just to pass validation. For a Windows-only pilot, remove the SQL/web entries and edit the file-server settings.

The [JSON schema](answers/schema.json) rejects unknown properties and unsupported combinations. The launcher also checks typed resource IDs, same-subscription boundaries, reserved usernames, duplicate names/IPs, actual IPv4/CIDR values, RSA key encoding/size, and SQL URL/hash placeholders.

| Input | Meaning |
| --- | --- |
| `stamp.clusterResourceId` | Existing Azure Local cluster resource ID |
| `stamp.customLocationId` | Custom location for that cluster; **verify this mapping in the portal** before setting `mappingConfirmed: true` |
| `logicalNetworkId` | Existing Azure Local logical network (not an Azure VNet/subnet ID) |
| `storageContainerId` | Existing Azure Local storage path resource ID (not a filesystem/CSV path) |
| `adminUsername` | Local administrator on Windows; SSH user on Linux |
| `passwordSource` | Runtime secure prompt, process environment-variable name, or pinned Key Vault reference |
| `logAnalyticsWorkspaceId` | Existing workspace; public ingestion enabled and in the deployment region |
| `allowedCidrs` | Canonical IPv4 networks, `/8` through `/32`; no unrestricted or loopback/multicast networks |
| `privateIpAddress` | Required for every VM on a Static logical network; omit for DHCP |

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

Windows Custom Script uses `fileUris` pinned to the current **full Git commit SHA**, with SHA256 verification before execution. The guest file must be clean, committed, and pushed to the checkout's **public GitHub origin**; the launcher checks the hosted bytes before creating resources. A private fork, ZIP download or unpushed/modified Windows guest script is not supported. Linux's smaller script is embedded directly. This avoids Windows command-line size limits without dropping disk/firewall safety checks.

Timeouts are bounded per image/deployment (default three hours; `-TimeoutSeconds 60..21600`). Custom Script has its own **90-minute execution ceiling**, independent of the launcher timeout. Timeout is **not cancellation**: inspect Azure deployment and image state before retrying. Failed guests, networking or AMA leave partial resources and billable monitoring in place; the launcher exits with an error, never a success-shaped fallback. Inspect Azure deployment operations and Arc extension status on the failed VM. Provider errors are not echoed wholesale because they can reflect secure inputs.

## Workload behavior and limitations

- **File server:** standalone/workgroup SMB, not a domain-joined file-service design. One dedicated data disk is mounted as `E:`. Only a uniquely identified, expected-size RAW non-OS disk can be initialized. Existing partitions, label/drive collisions and ambiguity fail rather than risk data loss. Reruns only reuse the expected volume. Grant real user/group access through a separate reviewed domain/ACL design; the initial share is for the explicit local administrator. SMB encryption is required; stock broad TCP 445 allow rules are not silently enabled.
- **SQL:** v1 intentionally supports **nonproduction Developer/Evaluation only**. Developer is not licensed for production; Evaluation is time-limited. Supply your own licensed, full Microsoft-signed SQL Server **2022 x64 ISO**, reachable at a direct public HTTPS URL without redirects or URL credentials/SAS/query strings, and independently verify its SHA256. No bootstrapper, paid Marketplace SQL image, product key, paid-edition install, automatic purchase, or SQL IaaS extension is used. Even though some current Azure Local Marketplace catalogs list paid SQL images, they are not assumed or consumed here. Data/logs are placed on the dedicated `E:` disk; Windows authentication only, default instance, TCP 1433, no broad client access or SQL Browser exposure. This is not a production availability, TLS-certificate, backup, patching or capacity design.
- **Web:** private HTTP demonstration site, not a public/TLS production service. Nginx enforces client CIDRs at the HTTP layer (`403` for other clients); this is not a network firewall. No public IP, reverse proxy trust, TLS certificate or DNS record is created. Image must not contain unmanaged Nginx configuration. Existing service-start policy requires manual integration.
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
