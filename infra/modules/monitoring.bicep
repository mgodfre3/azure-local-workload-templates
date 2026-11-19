param location string
param collectionLocation string = location
param machineName string
param workspaceId string
param isLinux bool
param tags object

resource machine 'Microsoft.HybridCompute/machines@2024-07-10' existing = {
  name: machineName
}

resource agent 'Microsoft.HybridCompute/machines/extensions@2024-07-10' = {
  parent: machine
  name: isLinux ? 'AzureMonitorLinuxAgent' : 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: isLinux ? 'AzureMonitorLinuxAgent' : 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {}
  }
}

resource collection 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${machineName}-collection'
  location: collectionLocation
  kind: isLinux ? 'Linux' : 'Windows'
  tags: tags
  properties: {
    dataSources: isLinux ? {
      syslog: [
        {
          name: 'operatingSystem'
          streams: [
            'Microsoft-Syslog'
          ]
          facilityNames: [
            'auth'
            'authpriv'
            'daemon'
            'syslog'
            'user'
          ]
          logLevels: [
            'Warning'
            'Error'
            'Critical'
            'Alert'
            'Emergency'
          ]
        }
      ]
    } : {
      windowsEventLogs: [
        {
          name: 'operatingSystem'
          streams: [
            'Microsoft-Event'
          ]
          xPathQueries: [
            'System!*[System[(Level=1 or Level=2 or Level=3)]]'
            'Application!*[System[(Level=1 or Level=2 or Level=3)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'defaultWorkspace'
          workspaceResourceId: workspaceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          isLinux ? 'Microsoft-Syslog' : 'Microsoft-Event'
        ]
        destinations: [
          'defaultWorkspace'
        ]
      }
    ]
  }
}

resource association 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: 'workload-logs'
  scope: machine
  properties: {
    dataCollectionRuleId: collection.id
  }
  dependsOn: [
    agent
  ]
}
