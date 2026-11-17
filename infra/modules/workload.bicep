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

var isLinux = workload.profile == 'webServer'
var ownership = {
  project: 'azure-local-workload-templates'
  deploymentSet: deploymentSet
  configurationHash: workload.configurationHash
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

resource dataDisk 'Microsoft.AzureStackHCI/virtualHardDisks@2024-01-01' = if (!isLinux) {
  name: '${workload.name}-data'
  location: location
  tags: ownership
  extendedLocation: {
    type: 'CustomLocation'
    name: customLocationId
  }
  properties: {
    containerId: storageContainerId
    diskSizeGB: workload.dataDiskSizeGB
    dynamic: true
  }
}

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
      dataDisks: isLinux ? [] : [
        {
          id: dataDisk!.id
        }
      ]
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

resource configure 'Microsoft.HybridCompute/machines/extensions@2024-07-10' = {
  parent: machine
  name: 'workload-configuration'
  location: location
  properties: {
    publisher: isLinux ? 'Microsoft.Azure.Extensions' : 'Microsoft.Compute'
    type: isLinux ? 'CustomScript' : 'CustomScriptExtension'
    typeHandlerVersion: isLinux ? '2.1' : '1.10'
    autoUpgradeMinorVersion: true
    forceUpdateTag: runId
    protectedSettings: workload.guestSettings
  }
  dependsOn: [
    vm
  ]
}

module monitoring 'monitoring.bicep' = {
  name: '${workload.name}-monitoring'
  params: {
    location: location
    machineName: machine.name
    workspaceId: workspaceId
    isLinux: isLinux
    tags: ownership
  }
  dependsOn: [
    configure
  ]
}

output machineId string = machine.id
