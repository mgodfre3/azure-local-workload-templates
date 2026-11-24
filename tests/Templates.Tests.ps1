BeforeDiscovery {
    Import-Module (Join-Path $PSScriptRoot '..\scripts\WorkloadDeployment.psm1') -Force
}

Describe 'Compiled ARM deployment contract' {
    BeforeAll {
        $template = & (Get-Module WorkloadDeployment) { Get-CompiledTemplate }
        $workload = @($template.resources)[0].properties.template
        $monitoring = @($workload.resources | Where-Object type -EQ 'Microsoft.Resources/deployments')[0].properties.template
    }

    It 'uses Arc machines and Azure Local VM instances, never Azure IaaS VMs' {
        @($workload.resources | Where-Object type -EQ 'Microsoft.HybridCompute/machines').Count | Should -Be 1
        $vm = @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/virtualMachineInstances')[0]
        $vm.name | Should -Be default
        $vm.scope | Should -Match 'Microsoft.HybridCompute/machines'
        ($template | ConvertTo-Json -Depth 100) | Should -Not -Match '"Microsoft.Compute/virtualMachines'
    }

    It 'keeps passwords secure across both module boundaries and out of outputs' {
        $template.parameters.adminPassword.type | Should -Be securestring
        $workload.parameters.adminPassword.type | Should -Be securestring
        ($template.outputs | ConvertTo-Json -Depth 10) | Should -Not -Match 'Password|guestSettings'
    }

    It 'passes validated logical-network DNS explicitly to the workload NIC' {
        $nic = @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/networkInterfaces')[0]
        $nic.properties | Should -Match 'union\(if\(empty\(.*dnsServers'
        $nic.properties | Should -Match 'dnsSettings.*dnsServers.*workload.*dnsServers'
    }

    It 'enables guest management and a system-assigned Arc identity' {
        $machine = @($workload.resources | Where-Object type -EQ 'Microsoft.HybridCompute/machines')[0]
        $machine.kind | Should -Be HCI
        $machine.identity.type | Should -Be SystemAssigned
        $vm = @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/virtualMachineInstances')[0]
        $os = $vm.properties.osProfile | ConvertTo-Json -Depth 20
        $os | Should -Match 'provisionVMAgent'
        $os | Should -Match 'provisionVMConfigAgent'
        $os | Should -Match 'disablePasswordAuthentication'
        $os | Should -Not -Match 'customData|cloud-config|write_files'
    }

    It 'merges workload metadata into all existing ownership-tagged resources without tagging VM instances' {
        $workload.variables.ownership | Should -Match 'union\('
        $workload.variables.ownership | Should -Match '\.tags'
        foreach ($type in @('Microsoft.HybridCompute/machines', 'Microsoft.AzureStackHCI/networkInterfaces', 'Microsoft.AzureStackHCI/virtualHardDisks')) {
            @($workload.resources | Where-Object type -EQ $type)[0].tags | Should -Be "[variables('ownership')]"
        }
        @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/virtualMachineInstances')[0].ContainsKey('tags') | Should -BeFalse
    }

    It 'uses the supplied storage container for the data disk and VM configuration' {
        $disk = @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/virtualHardDisks')[0]
        $disk.properties.containerId | Should -Match "parameters\('storageContainerId'\)"
        $vm = @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/virtualMachineInstances')[0]
        $vm.properties.storageProfile.vmConfigStoragePathId | Should -Match "parameters\('storageContainerId'\)"
    }

    It 'creates role-named disks at the requested sizes for either OS and gates service configuration' {
        $disk = @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/virtualHardDisks')[0]
        $disk.copy.count | Should -Match 'dataDisks'
        $disk.name | Should -Match '\.role'
        $disk.properties.diskSizeGB | Should -Match '\.sizeGB'
        $vm = @($workload.resources | Where-Object type -EQ 'Microsoft.AzureStackHCI/virtualMachineInstances')[0]
        $vm.properties.storageProfile.copy[0].name | Should -Be dataDisks
        $vm.properties.storageProfile.copy[0].count | Should -Match 'dataDisks'
        $configure = @($workload.resources | Where-Object type -EQ 'Microsoft.HybridCompute/machines/extensions')[0]
        $configure.condition | Should -Match 'configureGuest'
        $workload.variables.isLinux | Should -Match '\.isLinux'
        ($vm.properties.storageProfile | ConvertTo-Json -Depth 20) | Should -Not -Match 'suggestedOsDiskSizeGB'
    }

    It 'waits for guest configuration before deploying real AMA, DCR and association resources' {
        $monitoringModule = @($workload.resources | Where-Object type -EQ 'Microsoft.Resources/deployments')[0]
        ($monitoringModule.dependsOn -join ' ') | Should -Match 'workload-configuration'
        $extension = @($monitoring.resources | Where-Object type -EQ 'Microsoft.HybridCompute/machines/extensions')[0]
        $extension.properties.publisher | Should -Be 'Microsoft.Azure.Monitor'
        @($monitoring.resources | Where-Object type -EQ 'Microsoft.Insights/dataCollectionRules').Count | Should -Be 1
        $association = @($monitoring.resources | Where-Object type -EQ 'Microsoft.Insights/dataCollectionRuleAssociations')[0]
        $association.scope | Should -Match 'Microsoft.HybridCompute/machines'
        $association.properties.dataCollectionRuleId | Should -Match 'dataCollectionRules'
        $rule = @($monitoring.resources | Where-Object type -EQ 'Microsoft.Insights/dataCollectionRules')[0]
        $rule.properties.destinations.logAnalytics[0].workspaceResourceId | Should -Match "parameters\('workspaceId'\)"
    }
    It 'keeps legacy phase defaults and gates both services and monitoring for VM-only convergence' {
        foreach($flag in @('configureServices','deployMonitoring')){
            $template.parameters[$flag].defaultValue | Should -BeTrue
            $workload.parameters[$flag].defaultValue | Should -BeTrue
            @($template.resources)[0].properties.parameters[$flag].value | Should -Be "[parameters('$flag')]"
        }
        @($workload.resources | Where-Object type -EQ 'Microsoft.HybridCompute/machines/extensions')[0].condition | Should -Match "parameters\('configureServices'\)"
        @($workload.resources | Where-Object type -EQ 'Microsoft.Resources/deployments')[0].condition | Should -Match "parameters\('deployMonitoring'\)"
    }

    It 'retriggers Windows configuration with a public timestamp while retaining a protected payload' {
        $configure = @($workload.resources | Where-Object type -EQ 'Microsoft.HybridCompute/machines/extensions')[0]
        ($configure.properties.settings | ConvertTo-Json -Depth 10) | Should -Match 'timestamp'
        ($configure.properties.settings | ConvertTo-Json -Depth 10) | Should -Match 'runId'
        ($configure.properties.settings | ConvertTo-Json -Depth 10) | Should -Not -Match 'guestSettings|password'
        $configure.properties.protectedSettings | Should -Match '\.guestSettings'
    }

    It 'places DCRs with the workspace while keeping AMA in the machine region' {
        $rule = @($monitoring.resources | Where-Object type -EQ 'Microsoft.Insights/dataCollectionRules')[0]
        $rule.location | Should -Be "[parameters('collectionLocation')]"
        $monitoringModule = @($workload.resources | Where-Object type -EQ 'Microsoft.Resources/deployments')[0]
        $region = $monitoringModule.properties.parameters.collectionLocation.value
        $region | Should -Match 'reference\('
        $region | Should -Match "parameters\('workspaceId'\)"
        $region | Should -Match '\.location\]'
        $extension = @($monitoring.resources | Where-Object type -EQ 'Microsoft.HybridCompute/machines/extensions')[0]
        $extension.location | Should -Be "[parameters('location')]"
    }

    It 'routes Windows warning/error collection to the standard Event table stream' {
        $rule = @($monitoring.resources | Where-Object type -EQ 'Microsoft.Insights/dataCollectionRules')[0]
        $sources = $rule.properties.dataSources | ConvertTo-Json -Depth 20
        $sources | Should -Match 'Microsoft-Event'
        $sources | Should -Not -Match 'Microsoft-WindowsEvent'
        $rule.properties.dataFlows[0].streams[0] | Should -Be "[if(parameters('isLinux'), 'Microsoft-Syslog', 'Microsoft-Event')]"
    }
}
