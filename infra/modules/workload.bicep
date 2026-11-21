param location string
param customLocationId string
param logicalNetworkId string
param storageContainerId string
param workspaceId string
param adminUsername string
@secure()
param adminPassword string
param workload object
param deploymentSet string
param runId string
param configureServices bool = true
param deployMonitoring bool = true

var isLinux = workload.isLinux
var ownership = union(workload.tags, {
  project: 'azure-local-workload-templates'
  deploymentSet: deploymentSet
  configurationHash: workload.configurationHash
})

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  scope: resourceGroup(split(workspaceId, '/')[2], split(workspaceId, '/')[4])
  name: last(split(workspaceId, '/'))
}

resource machine 'Microsoft.HybridCompute/machines@2024-07-10' = {
  name: workload.name
  location: location
  kind: 'HCI'
  identity: {
    type: 'SystemAssigned'
  }
  tags: ownership
}

resource nic 'Microsoft.AzureStackHCI/networkInterfaces@2024-01-01' = {
  name: '${workload.name}-nic'
  location: location
  tags: ownership
  extendedLocation: {
    type: 'CustomLocation'
    name: customLocationId
  }
  properties: {
    ipConfigurations: [
      {
        name: 'primary'
        properties: union({
          subnet: {
            id: logicalNetworkId
          }
        }, empty(workload.privateIpAddress) ? {} : {
          privateIPAddress: workload.privateIpAddress
        })
      }
    ]
  }
}

resource dataDisk 'Microsoft.AzureStackHCI/virtualHardDisks@2024-01-01' = [for disk in workload.dataDisks: {
  name: '${workload.name}-${disk.role}'
  location: location
  tags: ownership
  extendedLocation: {
    type: 'CustomLocation'
    name: customLocationId
  }
  properties: {
    containerId: storageContainerId
    diskSizeGB: disk.sizeGB
    dynamic: true
  }
}]

resource vm 'Microsoft.AzureStackHCI/virtualMachineInstances@2024-01-01' = {
  name: 'default'
  scope: machine
  extendedLocation: {
    type: 'CustomLocation'
    name: customLocationId
  }
  properties: {
    hardwareProfile: {
      vmSize: 'Custom'
      processors: workload.processors
      memoryMB: workload.memoryMB
    }
    osProfile: union({
      computerName: workload.name
      adminUsername: adminUsername
    }, isLinux ? {
      linuxConfiguration: {
        provisionVMAgent: true
        provisionVMConfigAgent: true
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              keyData: workload.sshPublicKey
              path: '/home/${adminUsername}/.ssh/authorized_keys'
            }
          ]
        }
      }
    } : {
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        provisionVMConfigAgent: true
        enableAutomaticUpdates: true
      }
    })
    storageProfile: {
      imageReference: {
        id: workload.imageId
      }
      vmConfigStoragePathId: storageContainerId
      dataDisks: [for (disk, i) in workload.dataDisks: {
        id: dataDisk[i].id
      }]
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

resource configure 'Microsoft.HybridCompute/machines/extensions@2024-07-10' = if (configureServices && workload.configureGuest) {
  parent: machine
  name: 'workload-configuration'
  location: location
  properties: {
    publisher: isLinux ? 'Microsoft.Azure.Extensions' : 'Microsoft.Compute'
    type: isLinux ? 'CustomScript' : 'CustomScriptExtension'
    typeHandlerVersion: isLinux ? '2.1' : '1.10'
    autoUpgradeMinorVersion: true
    forceUpdateTag: runId
    settings: isLinux ? {} : {
      timestamp: runId
    }
    protectedSettings: workload.guestSettings
  }
  dependsOn: [
    vm
  ]
}

module monitoring 'monitoring.bicep' = if (deployMonitoring) {
  name: '${workload.name}-monitoring'
  params: {
    location: location
    collectionLocation: workspace.location
    machineName: machine.name
    workspaceId: workspaceId
    isLinux: isLinux
    tags: ownership
  }
  dependsOn: [
    configure
    vm
  ]
}

output machineId string = machine.id
