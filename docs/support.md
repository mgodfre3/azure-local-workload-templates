# Support matrix and public implementation references

Documentation reviewed: 2026-11-17. Vendor support evolves; verify the current requirements for the actual stamp release before deploying. This project has not yet been live-deployment tested.

Windows Server 2025 is an explicit **existing-image** alternative for Windows profiles; Windows Server 2022 remains the default and the only automated Marketplace import. The guest guard accepts server builds 20348 and 26100 and rejects workstation editions. Microsoft lists Windows Server 2025 Datacenter: Azure Edition in the [SQL Server 2022 OS support matrix](https://learn.microsoft.com/sql/sql-server/install/hardware-and-software-requirements-for-installing-sql-server-2022#operating-system-support). This is an offline-tested compatibility boundary, not evidence that any particular image, SMB/IIS/SQL service or monitoring enrollment has passed live acceptance.

The existing Log Analytics workspace can be in another region in the same subscription. Each new DCR derives its location from that workspace, while AMA stays in the VM region; the existing destination and its resource group are not relocated. This follows the [Azure Monitor DCR region requirement](https://learn.microsoft.com/azure/azure-monitor/vm/data-collection#create-data-collection-rule-dcr). Private Link/AMPLS remains outside this implementation.

## Pinned resource APIs

| Resource | API | Purpose |
| --- | --- | --- |
| `Microsoft.HybridCompute/machines` and `/extensions` | `2024-07-10` | `kind: HCI`, system identity, Custom Script and AMA |
| `Microsoft.AzureStackHCI/virtualMachineInstances` | `2024-01-01` | `default` instance scoped to the Arc machine; VM/config agents enabled |
| `Microsoft.AzureStackHCI/networkInterfaces` | `2024-01-01` | Existing logical network; optional explicit static IP |
| `Microsoft.AzureStackHCI/virtualHardDisks` | `2024-01-01` | Dedicated data disk on the selected storage container |
| `Microsoft.AzureStackHCI/marketplaceGalleryImages` | `2024-01-01` | Exact Windows publisher/offer/SKU/version import |
| `Microsoft.AzureStackHCI/galleryImages` | `2024-01-01` | Prepared NoCloud Ubuntu image import from stamp CSV VHDX or Storage page blob |
| `Microsoft.Insights/dataCollectionRules` and `/dataCollectionRuleAssociations` | `2023-03-11` | OS logs to the existing workspace |
| `Microsoft.Resources/deployments` | `2022-09-01` | Incremental deployment with in-memory secure parameters |

Stable APIs are deliberately preferred over newly introduced preview features. The templates do not imply certification against every Azure Local release accepting these APIs.

## Official references

- [Create Azure Local Arc-enabled VMs, including Windows/Linux Bicep and guest management](https://learn.microsoft.com/azure/azure-local/manage/create-arc-virtual-machines)
- [VM instance schema, including `provisionVMConfigAgent`, SSH and storage path](https://learn.microsoft.com/azure/templates/microsoft.azurestackhci/2024-01-01/virtualmachineinstances)
- [Network interface schema](https://learn.microsoft.com/azure/templates/microsoft.azurestackhci/2024-01-01/networkinterfaces)
- [Logical network schema, IP allocation method and VM pools](https://learn.microsoft.com/azure/templates/microsoft.azurestackhci/2024-01-01/logicalnetworks)
- [Marketplace gallery image schema](https://learn.microsoft.com/azure/templates/microsoft.azurestackhci/2024-01-01/marketplacegalleryimages)
- [Custom gallery image schema: `imagePath` and `cloudInitDataSource`](https://learn.microsoft.com/azure/templates/microsoft.azurestackhci/2024-01-01/galleryimages)
- [Prepared image import from a local share/cluster shared volume](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-image-local-share)
- [Prepared image import from Azure Storage: page blobs and SAS URLs](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-image-storage-account)
- [Windows Marketplace image import, supported image catalog and provider prerequisites](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-image-azure-marketplace)
- [Ubuntu Marketplace image preparation: generalized image, NoCloud and custom import](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-azure-marketplace-ubuntu)
- [Azure Local VM extension support and guest-management prerequisite](https://learn.microsoft.com/azure/azure-local/manage/virtual-machine-manage-extension)
- [Arc extension matrix: Custom Script and AMA for both guest OS families](https://learn.microsoft.com/azure/azure-arc/servers/manage-vm-extensions)
- [Windows Custom Script behavior, SYSTEM context and 90-minute execution ceiling](https://learn.microsoft.com/azure/virtual-machines/extensions/custom-script-windows)
- [Linux Custom Script v2 inline script support and timeout](https://learn.microsoft.com/azure/virtual-machines/extensions/custom-script-linux)
- [AMA installation requires both agent and DCR association for collection](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-manage)
- [AMA identity and prerequisites](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-requirements)
- [Azure Local VM-management RBAC](https://learn.microsoft.com/azure/azure-local/manage/assign-vm-rbac-roles)
- [Key Vault secrets in ARM parameters](https://learn.microsoft.com/azure/azure-resource-manager/templates/key-vault-parameter)
- [SQL Server command-prompt installation, editions, service accounts and parameters](https://learn.microsoft.com/sql/database-engine/install-windows/install-sql-server-from-the-command-prompt)
- [SQL Server 2022 editions and supported features](https://learn.microsoft.com/sql/sql-server/editions-and-components-of-sql-server-2022)

## Required live acceptance before releasing production support

In an explicitly authorized disposable environment: run each of the six profiles separately, then together with counts greater than one; exercise DHCP and per-instance static IPs; prove Marketplace and digest-based custom image reuse plus missing Windows/CSV/blob image imports; verify expired/unreachable source failures and timeout behavior; confirm clean guest onboarding, safe disk identity, extension readiness and local/client service access; verify base-profile disks stay RAW and no application is claimed; rerun and increase/decrease counts without renaming or deleting existing resources; inject a guest failure and inspect partial state; verify AMA heartbeat and OS logs in the actual workspace. Test scoped IIS/firewall and Nginx HTTP denials from a second client. Confirm Windows and SQL licensing, actual OS-disk sizes and backup/restore separately. None of these live acceptance checks has been performed by the offline suite.

The stable VM schema has no image-based OS disk size override. `suggestedOsDiskSizeGB` is explicitly advisory; the launcher only applies CPU, RAM and data-disk sizes, and does not perform OS-disk resizing. CSV input is intentionally narrower than general share-path syntax: only stamp cluster shared volume VHDX paths are accepted. Blob import supports Azure public-cloud Storage page blobs using read-only SAS tokens supplied at runtime, not credentials in answer files. The digest tag records the operator's attestation, not a checksum independently verified by the provider.

Do not silently expand the image allowlist or use generic Azure IaaS URNs. If a desired guest image cannot use supported zero-touch Arc onboarding, stop and document the preparation gap rather than presenting an empty VM as a configured workload.
