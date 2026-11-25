BeforeAll {
    $bash = if ($IsWindows) { Join-Path $env:ProgramFiles 'Git\bin\bash.exe' } else { (Get-Command bash -ErrorAction Stop).Source }
    if (!(Test-Path -LiteralPath $bash)) { throw 'Bash is required for Linux guest acceptance tests (Git for Windows supplies it).' }
    $validator = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\guest\validate-linux.sh') -Raw
    function Invoke-LinuxAcceptance {
        param(
            [string]$Version = '24.04', [string]$ExpectedVersion = '24.04',
            [int]$CloudExit = 0, [int]$SchemaExit = 0, [string]$CloudId = 'nocloud',
            [switch]$WrongKey, [switch]$InheritedKey, [switch]$PasswordEnabled,
            [switch]$SocketOnly, [switch]$SshInactive, [switch]$StartFailure, [switch]$UnlockedPassword,
            [switch]$RootLogin, [switch]$DnsFailure
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
cloud-init() { if [ "$1" = schema ]; then return __SCHEMA_EXIT__; fi; return __CLOUD_EXIT__; }
cloud-id() { echo '__CLOUD_ID__'; }
timeout() { shift; "$@"; }
getent() { if [ "$1" = ahostsv4 ]; then return __DNS_EXIT__; fi; echo 'vmadmin:x:1000:1000::__ROOT__/home/vmadmin:/bin/bash'; }
passwd() { echo "$2 __ACCOUNT_LOCK__"; }
sshd() { printf 'passwordauthentication __PASSWORD__\nkbdinteractiveauthentication no\npermitrootlogin __ROOT_LOGIN__\n'; }
ssh_active=__SSH_ACTIVE__
systemctl() {
    case "$1:${3-}" in
        is-active:ssh) return "$ssh_active" ;;
        is-active:ssh.socket) return __SOCKET_EXIT__ ;;
        start:) printf 'ssh-start-attempted\n'; ssh_active=0; return __START_EXIT__ ;;
        *) return 1 ;;
    esac
}
'@.Replace('__CLOUD_EXIT__', "$CloudExit").Replace('__SCHEMA_EXIT__', "$SchemaExit").Replace('__CLOUD_ID__', $CloudId).
            Replace('__ROOT__', $unixRoot).Replace('__PASSWORD__', $(if ($PasswordEnabled) { 'yes' } else { 'no' })).
            Replace('__SSH_ACTIVE__', $(if ($SocketOnly -or $SshInactive) { '1' } else { '0' })).
            Replace('__SOCKET_EXIT__', $(if ($SshInactive) { '1' } else { '0' })).
            Replace('__START_EXIT__', $(if ($StartFailure) { '1' } else { '0' })).
            Replace('__ACCOUNT_LOCK__', $(if ($UnlockedPassword) { 'P' } else { 'L' })).
            Replace('__ROOT_LOGIN__', $(if ($RootLogin) { 'yes' } else { 'no' })).
            Replace('__DNS_EXIT__', $(if ($DnsFailure) { '1' } else { '0' }))
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
    It 'rejects malformed generated user data even when cloud-init reports clean completion, before SSH activation' {
        $result = Invoke-LinuxAcceptance -SchemaExit 1 -SocketOnly
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Match 'generated cloud-init user data schema is invalid'
        $result.Output | Should -Not -Match 'ssh-start-attempted'
    }
    It 'rejects unexpected or inherited keys and password-enabled SSH' {
        (Invoke-LinuxAcceptance -WrongKey).Output | Should -Match 'SSH keys differ'
        (Invoke-LinuxAcceptance -InheritedKey).Output | Should -Match 'inherited SSH login keys'
        (Invoke-LinuxAcceptance -PasswordEnabled).Output | Should -Match 'password authentication is enabled'
        (Invoke-LinuxAcceptance -RootLogin).Output | Should -Match 'root login is enabled'
        (Invoke-LinuxAcceptance -DnsFailure).Output | Should -Match 'DNS resolution failed'
    }
    It 'supports an already listening SSH socket without enabling a closed endpoint or ignoring startup failure' {
        $result = Invoke-LinuxAcceptance -SocketOnly
        $result.ExitCode | Should -Be 0
        $result.Output | Should -Match 'ssh-start-attempted'
        $result = Invoke-LinuxAcceptance -SshInactive
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Not -Match 'ssh-start-attempted'
        (Invoke-LinuxAcceptance -SocketOnly -StartFailure).Output | Should -Match 'could not start'
    }
    It 'never activates socket-backed SSH before clean cloud-init, key and password checks' {
        $result = Invoke-LinuxAcceptance -SocketOnly -CloudExit 2
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Not -Match 'ssh-start-attempted'
        $result = Invoke-LinuxAcceptance -SocketOnly -InheritedKey
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Not -Match 'ssh-start-attempted'
        $result = Invoke-LinuxAcceptance -SocketOnly -UnlockedPassword
        $result.ExitCode | Should -Be 1
        $result.Output | Should -Not -Match 'ssh-start-attempted'
        (Invoke-LinuxAcceptance -SocketOnly -PasswordEnabled).ExitCode | Should -Be 1
    }
}
