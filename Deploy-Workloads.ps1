#requires -Version 7.4
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$AnswerFile,
    [ValidateSet('Validate', 'Preflight', 'Deploy')][string]$Mode = 'Validate',
    [ValidateRange(60, 21600)][int]$TimeoutSeconds = 10800,
    [switch]$AllowUnverifiedExistingLinuxImage
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'scripts\WorkloadDeployment.psm1') -Force
Start-WorkloadDeployment -AnswerFile $AnswerFile -Mode $Mode -TimeoutSeconds $TimeoutSeconds -AllowUnverifiedExistingLinuxImage:$AllowUnverifiedExistingLinuxImage -Confirm:($ConfirmPreference -ne 'None') -WhatIf:$WhatIfPreference
