BeforeAll {
    $bash = if ($IsWindows) { Join-Path $env:ProgramFiles 'Git\bin\bash.exe' } else { (Get-Command bash -ErrorAction Stop).Source }
    if (!(Test-Path -LiteralPath $bash)) { throw 'Bash is required for Linux guest acceptance tests (Git for Windows supplies it).' }
    $validator = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\guest\validate-linux.sh') -Raw
    function Invoke-LinuxAcceptance {
        param(
            [string]$Version = '24.04', [string]$ExpectedVersion = '24.04',
            [int]$CloudExit = 0, [string]$CloudId = 'nocloud',
            [switch]$WrongKey, [switch]$InheritedKey, [switch]$PasswordEnabled
        )
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $etc = Join-Path $root 'etc'
        $adminSsh = Join-Path $root 'home' 'vmadmin' '.ssh'
        $rootSsh = Join-Path $root 'root' '.ssh'
        $null = New-Item -ItemType Directory -Path $etc, $adminSsh, $rootSsh
        $unixRoot = if ($IsWindows) { '/' + $root.Substring(0, 1).ToLowerInvariant() + $root.Substring(2).Replace('\', '/') } else { $root }
        [IO.File]::WriteAllText((Join-Path $etc 'os-release'), "ID=ubuntu`nVERSION_ID=$Version`n")
        [IO.File]::WriteAllText((Join-Path $etc 'machine-id'), 'fixture-identity')
        [IO.File]::WriteAllText((Join-Path $adminSsh 'authorized_keys'), $(if ($WrongKey) { "ssh-rsa unexpected`n" } else { "ssh-rsa public-fixture-key`n" }))
        if ($InheritedKey) { [IO.File]::WriteAllText((Join-Path $rootSsh 'authorized_keys'), "ssh-rsa inherited`n") }
        $mocks = @'
id() { echo 0; }
cloud-init() { return __CLOUD_EXIT__; }
cloud-id() { echo '__CLOUD_ID__'; }
timeout() { shift; "$@"; }
getent() { echo 'vmadmin:x:1000:1000::__ROOT__/home/vmadmin:/bin/bash'; }
passwd() { echo "$2 L"; }
sshd() { printf 'passwordauthentication __PASSWORD__\nkbdinteractiveauthentication no\n'; }
systemctl() { return 0; }
'@.Replace('__CLOUD_EXIT__', "$CloudExit").Replace('__CLOUD_ID__', $CloudId).
            Replace('__ROOT__', $unixRoot).Replace('__PASSWORD__', $(if ($PasswordEnabled) { 'yes' } else { 'no' }))
        $body = $validator.Replace('/etc/', "$unixRoot/etc/").Replace('/home/', "$unixRoot/home/").
            Replace('/root/', "$unixRoot/root/").Replace('/usr/sbin/sshd', 'sshd').
            Replace('__ADMIN_USERNAME__', 'vmadmin').Replace('__UBUNTU_VERSION__', $ExpectedVersion).
            Replace('__SSH_KEY_BASE64__', [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('ssh-rsa public-fixture-key')))
        [IO.File]::WriteAllText((Join-Path $root 'acceptance.sh'), (($mocks + "`n" + $body) -replace "`r`n", "`n"))
        $output = & $bash "$unixRoot/acceptance.sh" 2>&1
        @{ ExitCode = $LASTEXITCODE; Output = $output -join "`n" }
    }
}

Describe 'Linux guest acceptance (isolated Bash fixtures)' {
    It 'accepts exactly the selected Ubuntu 22.04 and 24.04 with the requested key and locked passwords' {
        foreach ($version in '22.04', '24.04') {
            $result = Invoke-LinuxAcceptance -Version $version -ExpectedVersion $version
            $result.ExitCode | Should -Be 0
            $result.Output | Should -Match 'provenance is not certified'
        }
    }
    It 'fails closed on degraded cloud-init and an unexpected release or datasource' {
        (Invoke-LinuxAcceptance -CloudExit 2).Output | Should -Match 'cloud-init did not finish cleanly'
        (Invoke-LinuxAcceptance -CloudExit 2).ExitCode | Should -Be 1
        (Invoke-LinuxAcceptance -Version '22.04').ExitCode | Should -Be 1
        (Invoke-LinuxAcceptance -CloudId 'azure').ExitCode | Should -Be 1
    }
    It 'rejects unexpected or inherited keys and password-enabled SSH' {
        (Invoke-LinuxAcceptance -WrongKey).Output | Should -Match 'SSH keys differ'
        (Invoke-LinuxAcceptance -InheritedKey).Output | Should -Match 'inherited SSH login keys'
        (Invoke-LinuxAcceptance -PasswordEnabled).Output | Should -Match 'password authentication is enabled'
    }
}
