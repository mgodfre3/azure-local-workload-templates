#!/bin/sh
set -eu
fail() { echo "Linux image acceptance failed: $1" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "root execution required"
. /etc/os-release
[ "$ID" = ubuntu ] && [ "$VERSION_ID" = '__UBUNTU_VERSION__' ] || fail "unexpected Ubuntu release"
command -v cloud-init >/dev/null || fail "cloud-init is missing"
cloud_status=0
timeout 180 cloud-init status --wait >/dev/null 2>&1 || cloud_status=$?
[ "$(cloud-id)" = nocloud ] || fail "NoCloud onboarding was not observed"
case '__SCHEMA_POLICY__' in
    azureLocalKnownWarnings)
        [ "$cloud_status" = 0 ] || [ "$cloud_status" = 2 ] || fail "cloud-init did not finish"
        timeout 30 python3 -c "import base64; exec(compile(base64.b64decode('__CLOUD_INIT_VALIDATOR_BASE64__'), 'validate-cloud-init.py', 'exec'))" ||
            fail "original provisioning evidence does not match the explicit known-warning policy"
        ;;
    *)
        [ "$cloud_status" = 0 ] || fail "cloud-init did not finish cleanly"
        timeout 30 cloud-init schema --config-file /var/lib/cloud/instance/user-data.txt >/dev/null 2>&1 ||
            fail "generated cloud-init user data schema is invalid"
        ;;
esac
user='__ADMIN_USERNAME__'
home=$(getent passwd "$user" | cut -d: -f6)
[ "$home" = "/home/$user" ] || fail "unexpected administrator home"
[ -f "$home/.ssh/authorized_keys" ] && [ ! -L "$home/.ssh/authorized_keys" ] || fail "SSH key file is missing or a symlink"
actual=$(awk 'NF && $1 !~ /^#/ {print $1 " " $2}' "$home/.ssh/authorized_keys")
expected=$(printf '%s' '__SSH_KEY_BASE64__' | base64 -d)
[ "$actual" = "$expected" ] || fail "administrator SSH keys differ from the requested public key"
# Refuse inherited login keys, including root, rather than silently deleting them.
for keys in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ "$keys" = "$home/.ssh/authorized_keys" ] && continue
    if [ -f "$keys" ] && grep -q '^[[:space:]]*[^#[:space:]]' "$keys"; then
        fail "inherited SSH login keys require image preparation"
    fi
done
[ "$(passwd -S "$user" | awk '{print $2}')" = L ] || fail "administrator has an inherited password"
[ "$(passwd -S root | awk '{print $2}')" = L ] || fail "root has an inherited password"
if ! systemctl is-active --quiet ssh; then
    systemctl is-active --quiet ssh.socket || fail "SSH service and socket are not active"
    timeout 30 systemctl start ssh || fail "SSH socket-backed service could not start"
fi
sshd_config=$(/usr/sbin/sshd -T -C "user=$user,host=localhost,addr=127.0.0.1") || fail "effective SSH configuration could not be validated"
printf '%s\n' "$sshd_config" | grep -qx 'passwordauthentication no' || fail "SSH password authentication is enabled"
printf '%s\n' "$sshd_config" | grep -qx 'kbdinteractiveauthentication no' || fail "SSH interactive authentication is enabled"
printf '%s\n' "$sshd_config" | grep -qx 'permitrootlogin no' || fail "SSH root login is enabled"
[ -s /etc/machine-id ] || fail "machine identity is missing"
systemctl is-active --quiet ssh || fail "SSH is not active"
timeout 20 getent ahostsv4 aka.ms >/dev/null || fail "system DNS resolution failed"
echo "Linux guest acceptance passed: expected Ubuntu, NoCloud/cloud-init, requested SSH key and password-disabled login. Source preparation provenance is not certified."
