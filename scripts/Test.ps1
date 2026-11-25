#requires -Version 7.4
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
& python (Join-Path $root 'tests\test_cloud_init.py')
if ($LASTEXITCODE -ne 0) { throw 'Python provisioning tests failed. Install tests/requirements.txt into your test environment if dependencies are missing.' }
Import-Module Pester -MinimumVersion 5.7.1
$files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' -and $_.FullName -notmatch '[\\/]\.tools[\\/]' }
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "PowerShell parse errors in $($file.Name): $($errors.Message -join '; ')" }
}
$result = Invoke-Pester -Path (Join-Path $root 'tests') -Output Detailed -PassThru
if ($result.Result -ne 'Passed') { throw 'Offline tests failed.' }
Import-Module (Join-Path $PSScriptRoot 'WorkloadDeployment.psm1') -Force
$null = & (Get-Module WorkloadDeployment) { Get-CompiledTemplate }
Write-Output 'Offline tests and Bicep build passed. No live Azure deployment was performed.'
