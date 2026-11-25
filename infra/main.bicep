targetScope = 'resourceGroup'

param location string
param customLocationId string
param logicalNetworkId string
param storageContainerId string
param workspaceId string
param adminUsername string
@secure()
param adminPassword string
@description('Resolved by the launcher after answer-file and Azure preflight validation.')
param workloads array
param deploymentSet string
param runId string
param configureServices bool = true
param deployMonitoring bool = true

module workload 'modules/workload.bicep' = [for item in workloads: {
  name: '${deploymentSet}-${item.name}'
  params: {
    location: location
    customLocationId: customLocationId
    logicalNetworkId: logicalNetworkId
    storageContainerId: storageContainerId
    workspaceId: workspaceId
    adminUsername: adminUsername
    adminPassword: adminPassword
    workload: item
    deploymentSet: deploymentSet
    runId: runId
    configureServices: configureServices
    deployMonitoring: deployMonitoring
  }
}]

output machines array = [for (item, i) in workloads: {
  name: item.name
  resourceId: workload[i].outputs.machineId
}]
