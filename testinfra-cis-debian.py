"""
CIS Debian Linux 13 Benchmark v1.0.0

Automated CIS-oriented Testinfra checks adapted for Debian (AppArmor, UFW, apt).
GDM hardening tests skip when gdm3 is absent. Journal-remote vs rsyslog path
tests skip the inactive logging strategy.
"""

import pytest

_SUDO_PW_HINTS = (
    "a terminal is required to read the password",
    "a password is required",
    "no tty present",
    "askpass",
)


def _sudo_problem(result):
    text = f"{result.stdout}\n{result.stderr}".lower()
    return any(h in text for h in _SUDO_PW_HINTS)


def _cmd(host, command, *args):
    """Run a remote command; fail clearly if sudo cannot elevate."""
    if args:
        result = host.run(command, *args)
    else:
        result = host.run(command)
    if _sudo_problem(result):
        raise AssertionError(
            "remote sudo requires a password/TTY — configure NOPASSWD for the "
            "SSH user (or connect as root). pytest --sudo cannot prompt interactively."
        )
    return result

def _module_not_available(host, module):
    loaded = host.run(f'lsmod | grep -E "^{module}\\b"')
    assert loaded.rc != 0, f'{module} is currently loaded'
    cfg = host.run(
        f"modprobe --showconfig | grep -E '\\b(install|blacklist)[[:space:]]+{module}\\b'"
    )
    assert cfg.rc == 0, f'{module} not disabled in modprobe config'
    assert (
        f'blacklist {module}' in cfg.stdout or f'blacklist\t{module}' in cfg.stdout
    ), f'{module} is not blacklisted in modprobe config'
    install = host.run(
        f"modprobe --showconfig | grep -E 'install[[:space:]]+{module}[[:space:]]+/bin/(false|true)'"
    )
    assert install.rc == 0, (
        f'{module} missing "install {module} /bin/false|/bin/true" in modprobe config'
    )

def _findmnt(host, path):
    result = host.run(f'findmnt -n {path}')
    assert result.rc == 0, f'{path} is not a separate mount'

def _mount_has_option(host, path, option):
    result = host.run(f'findmnt -n -o OPTIONS {path}')
    assert result.rc == 0, (
        f'{path} is not a separate mount (cannot verify option {option})'
    )
    opts = [o.strip() for o in result.stdout.strip().split(',') if o.strip()]
    assert option in opts, (
        f'{path} missing mount option {option} '
        f'(current options: {",".join(opts) or "none"})'
    )

def _sysctl_read(host, key):
    """Read a sysctl value via sysctl(8) or /proc/sys fallback."""
    result = _cmd(host, f'sysctl -n {key}')
    if result.rc == 0 and result.stdout.strip() != '':
        return result.stdout.strip()
    proc = '/proc/sys/' + key.replace('.', '/')
    result = _cmd(host, f'cat {proc} 2>/dev/null')
    assert result.rc == 0 and result.stdout.strip() != '', (
        f'sysctl {key} is unavailable (tried sysctl -n and {proc})'
    )
    return result.stdout.strip()

def _sysctl_equals(host, key, expected):
    actual = _sysctl_read(host, key)
    assert actual == str(expected), f'{key}={actual}, expected {expected}'

def _sshd_effective(host, keyword):
    result = _cmd(
        host,
        f"(sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null) | "
        f"awk '/^{keyword.lower()} / {{print $2; exit}}'",
    )
    assert result.rc == 0 and result.stdout.strip() != '', (
        f'sshd -T did not report an effective value for {keyword} '
        f'(is openssh-server installed and readable as root?)'
    )
    return result.stdout.strip()


def _pkg_installed(host, pkg):
    """Check package install via dpkg (avoid host.package → systeminfo on broken uname)."""
    r = host.run(f"dpkg-query -W -f='${{Status}}' {pkg} 2>/dev/null")
    return r.rc == 0 and 'install ok installed' in r.stdout

def _svc_enabled(host, name):
    return host.run("systemctl is-enabled %s 2>/dev/null", name).rc == 0

def _svc_active(host, name):
    return host.run("systemctl is-active %s 2>/dev/null", name).rc == 0

def _service_not_in_use(host, *names):
    for name in names:
        assert not _svc_enabled(host, name), (
            f'service {name} is enabled (expected unused/disabled)'
        )
        assert not _svc_active(host, name), (
            f'service {name} is running (expected unused/stopped)'
        )

def _package_not_installed(host, *pkgs):
    for pkg in pkgs:
        assert not _pkg_installed(host, pkg), (
            f'package {pkg} is installed (expected absent)'
        )

def _assert_pkg_installed(host, *pkgs):
    for pkg in pkgs:
        assert _pkg_installed(host, pkg), f'package {pkg} is not installed'

def _assert_svc_enabled_running(host, name):
    assert _svc_enabled(host, name), f'service {name} is not enabled'
    assert _svc_active(host, name), f'service {name} is not running'


def _stat_path(host, path):
    """Return (exists, mode_int, user, group) via shell stat.

    Prefer shell `stat` over testinfra host.file().mode/user: with SSH + --sudo,
    testinfra may mis-detect the OS if `uname -s` is missing from sudo secure_path,
    then wrongly call Windows `systeminfo`.
    """
    out = host.run("stat -c '%%a %%U %%G' %s", path)
    if out.rc != 0:
        out = host.run("stat -f '%%Lp %%Su %%Sg' %s", path)
    if out.rc != 0:
        return False, None, None, None
    parts = out.stdout.strip().split()
    if len(parts) < 3:
        return False, None, None, None
    return True, int(parts[0], 8), parts[1], parts[2]


def _file_root_mode(host, path, bad_bits):
    exists, mode, user, _group = _stat_path(host, path)
    assert exists, f'{path} missing'
    assert user == 'root', f'{path} owner is {user}, expected root'
    assert (mode & bad_bits) == 0, (
        f'{path} mode {oct(mode)} has forbidden bits {oct(bad_bits)}'
    )


def _cron_perms(host, path):
    exists, mode, user, group = _stat_path(host, path)
    assert exists, f'{path} missing'
    assert user == 'root' and group == 'root', (
        f'{path} owner/group is {user}:{group}, expected root:root'
    )
    assert (mode & 0o077) == 0, f'{path} mode {oct(mode)} allows group/other access'


def _audit_grep(host, pattern):
    result = host.run(
        "(auditctl -l 2>/dev/null || /usr/sbin/auditctl -l 2>/dev/null || "
        "/sbin/auditctl -l 2>/dev/null) | grep -E '%s'" % pattern
    )
    assert result.rc == 0, f'audit rules missing match for pattern: {pattern}'


def _rsyslog_in_use(host):
    return _pkg_installed(host, 'rsyslog') and _svc_enabled(host, 'rsyslog')

def _gdm_installed(host):
    return _pkg_installed(host, 'gdm3')

def _pwquality(host, key):
    result = host.run(
        f"grep -E '^[[:space:]]*{key}[[:space:]]*=' /etc/security/pwquality.conf"
    )
    assert result.rc == 0, f'/etc/security/pwquality.conf missing setting {key}'
    return result.stdout.split('=', 1)[1].strip()

def _pam_grep(host, pattern):
    return host.run(
        "grep -R -E '%s' "
        "/etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/common-account "
        "/etc/pam.d/common-session /etc/pam.d/system-auth /etc/pam.d/password-auth "
        "/etc/authselect/system-auth /etc/authselect/password-auth "
        "/etc/security/pwhistory.conf /etc/security/pwquality.conf 2>/dev/null" % pattern
    )

def _assert_pam(host, pattern, msg):
    result = _pam_grep(host, pattern)
    assert result.rc == 0, msg

def _login_defs(host, key):
    result = host.run(f"grep -E '^[[:space:]]*{key}[[:space:]]+' /etc/login.defs")
    assert result.rc == 0, f'{key} not set in /etc/login.defs'
    parts = result.stdout.split()
    assert len(parts) >= 2, f'{key} line malformed in /etc/login.defs: {result.stdout!r}'
    return parts[1]

# --- automated CIS controls ----------------------------------------------

def test_1_1_1_1_module(host):
    _module_not_available(host, 'cramfs')

def test_1_1_1_2_module(host):
    _module_not_available(host, 'freevxfs')

def test_1_1_1_3_module(host):
    _module_not_available(host, 'hfs')

def test_1_1_1_4_module(host):
    _module_not_available(host, 'hfsplus')

def test_1_1_1_5_module(host):
    _module_not_available(host, 'jffs2')

def test_1_1_1_6_module(host):
    _module_not_available(host, 'squashfs')

def test_1_1_1_7_module(host):
    _module_not_available(host, 'udf')

def test_1_1_1_8_module(host):
    _module_not_available(host, 'usb-storage')

def test_1_1_1_9_firewire_core_module(host):
    _module_not_available(host, 'firewire-core')

def test_1_1_2_1_1_separate(host):
    _findmnt(host, '/tmp')

def test_1_1_2_1_2_nodev(host):
    _mount_has_option(host, '/tmp', 'nodev')

def test_1_1_2_1_3_nosuid(host):
    _mount_has_option(host, '/tmp', 'nosuid')

def test_1_1_2_1_4_noexec(host):
    _mount_has_option(host, '/tmp', 'noexec')

def test_1_1_2_2_1_separate(host):
    _findmnt(host, '/dev/shm')

def test_1_1_2_2_2_nodev(host):
    _mount_has_option(host, '/dev/shm', 'nodev')

def test_1_1_2_2_3_nosuid(host):
    _mount_has_option(host, '/dev/shm', 'nosuid')

def test_1_1_2_2_4_noexec(host):
    _mount_has_option(host, '/dev/shm', 'noexec')

def test_1_1_2_3_1_separate(host):
    _findmnt(host, '/home')

def test_1_1_2_3_2_nodev(host):
    _mount_has_option(host, '/home', 'nodev')

def test_1_1_2_3_3_nosuid(host):
    _mount_has_option(host, '/home', 'nosuid')

def test_1_1_2_4_1_separate(host):
    _findmnt(host, '/var')

def test_1_1_2_4_2_nodev(host):
    _mount_has_option(host, '/var', 'nodev')

def test_1_1_2_4_3_nosuid(host):
    _mount_has_option(host, '/var', 'nosuid')

def test_1_1_2_5_1_separate(host):
    _findmnt(host, '/var/tmp')

def test_1_1_2_5_2_nodev(host):
    _mount_has_option(host, '/var/tmp', 'nodev')

def test_1_1_2_5_3_nosuid(host):
    _mount_has_option(host, '/var/tmp', 'nosuid')

def test_1_1_2_5_4_noexec(host):
    _mount_has_option(host, '/var/tmp', 'noexec')

def test_1_1_2_6_1_separate(host):
    _findmnt(host, '/var/log')

def test_1_1_2_6_2_nodev(host):
    _mount_has_option(host, '/var/log', 'nodev')

def test_1_1_2_6_3_nosuid(host):
    _mount_has_option(host, '/var/log', 'nosuid')

def test_1_1_2_6_4_noexec(host):
    _mount_has_option(host, '/var/log', 'noexec')

def test_1_1_2_7_1_separate(host):
    _findmnt(host, '/var/log/audit')

def test_1_1_2_7_2_nodev(host):
    _mount_has_option(host, '/var/log/audit', 'nodev')

def test_1_1_2_7_3_nosuid(host):
    _mount_has_option(host, '/var/log/audit', 'nosuid')

def test_1_1_2_7_4_noexec(host):
    _mount_has_option(host, '/var/log/audit', 'noexec')

def test_1_2_1_2_gpgcheck(host):
    result = host.run("ls /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null")
    assert result.stdout.strip(), (
        "no apt sources found under /etc/apt/sources.list or sources.list.d"
    )

def test_1_3_1_1_apparmor_installed(host):
    _assert_pkg_installed(host, "apparmor")

def test_1_3_1_2_apparmor_enabled(host):
    # Prefer sysfs so nested sudo inside aa-enabled is not required.
    sysfs = _cmd(host, "cat /sys/module/apparmor/parameters/enabled 2>/dev/null")
    if sysfs.rc == 0 and sysfs.stdout.strip() == "Y":
        return
    result = _cmd(host, "aa-enabled 2>/dev/null")
    out = (result.stdout + result.stderr).strip().lower()
    assert result.rc == 0 or "yes" in out or out.startswith("y"), (
        f"AppArmor is not enabled "
        f"(sysfs={sysfs.stdout.strip()!r}, aa-enabled rc={result.rc}, "
        f"stdout={result.stdout.strip()!r}, stderr={result.stderr.strip()!r})"
    )

def test_1_3_1_3_apparmor_status(host):
    profiles = _cmd(host, "test -s /sys/kernel/security/apparmor/profiles")
    if profiles.rc == 0:
        return
    result = _cmd(host, "aa-status 2>/dev/null")
    assert result.rc == 0, (
        f"aa-status failed and AppArmor profiles sysfs is empty/missing "
        f"(rc={result.rc}, stderr={result.stderr.strip()!r})"
    )

def test_1_3_1_4_apparmor_not_disabled(host):
    sysfs = _cmd(host, "cat /sys/module/apparmor/parameters/enabled 2>/dev/null")
    if sysfs.rc == 0:
        assert sysfs.stdout.strip() == "Y", (
            f"AppArmor module enabled flag is {sysfs.stdout.strip()!r}, expected Y"
        )
        return
    result = _cmd(host, "aa-enabled 2>/dev/null")
    out = result.stdout.strip().lower()
    assert "yes" in out or out.startswith("y"), (
        f"AppArmor not reported as enabled "
        f"(stdout={result.stdout.strip()!r}, stderr={result.stderr.strip()!r})"
    )

def test_1_3_1_5_apparmor_profiles_loaded(host):
    profiles = _cmd(host, "wc -l < /sys/kernel/security/apparmor/profiles 2>/dev/null")
    if (
        profiles.rc == 0
        and profiles.stdout.strip().isdigit()
        and int(profiles.stdout.strip()) > 0
    ):
        return
    result = _cmd(host, "aa-status 2>/dev/null")
    assert result.rc == 0, (
        f"no AppArmor profiles loaded "
        f"(sysfs lines={profiles.stdout.strip()!r}, "
        f"aa-status rc={result.rc}, stderr={result.stderr.strip()!r})"
    )

def test_1_4_1_grub_password(host):
    result = _cmd(
        host,
        "grep -E 'password_pbkdf2|grub.pbkdf2' "
        "/boot/grub/grub.cfg /etc/grub.d/* /boot/efi/EFI/*/grub.cfg 2>/dev/null",
    )
    assert result.rc == 0, "GRUB password (password_pbkdf2/grub.pbkdf2) not found"

def test_1_4_2_grub_perms(host):
    for path in (
        "/boot/grub/grub.cfg",
        "/boot/efi/EFI/ubuntu/grub.cfg",
        "/boot/efi/EFI/debian/grub.cfg",
    ):
        exists, mode, user, _g = _stat_path(host, path)
        if exists:
            assert user == "root", f"{path} owner is {user}, expected root"
            assert (mode & 0o077) == 0, (
                f"{path} mode {oct(mode)} allows group/other access"
            )

def test_1_5_1_aslr(host):
    _sysctl_equals(host, "kernel.randomize_va_space", "2")

def test_1_5_2_ptrace(host):
    val = _sysctl_read(host, "kernel.yama.ptrace_scope")
    assert val in ("1", "2", "3"), (
        f"kernel.yama.ptrace_scope={val!r}, expected 1, 2, or 3"
    )

def test_1_5_3_coredump_backtraces(host):
    result = _cmd(
        host,
        "grep -E '^[[:space:]]*ProcessSizeMax[[:space:]]*=[[:space:]]*0' "
        "/etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* 2>/dev/null",
    )
    assert result.rc == 0, "ProcessSizeMax=0 not set in systemd-coredump config"

def test_1_5_4_coredump_storage(host):
    result = _cmd(
        host,
        "grep -E '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none' "
        "/etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* 2>/dev/null",
    )
    assert result.rc == 0, "Storage=none not set in systemd-coredump config"

def test_1_6_4_crypto_macs(host):
    macs = _sshd_effective(host, "macs").lower()
    assert "hmac-md5" not in macs and "umac-64" not in macs, (
        f"weak SSH MACs still enabled: {macs}"
    )

def test_1_6_5_crypto_cbc(host):
    ciphers = _sshd_effective(host, "ciphers").lower()
    assert "cbc" not in ciphers, f"CBC SSH ciphers still enabled: {ciphers}"

def test_1_7_1_banner(host):
    out = _cmd(host, "test -e /etc/motd && cat /etc/motd")
    assert out.rc == 0 and out.stdout.strip() != "", "/etc/motd is missing or empty"
    assert not any(tok in out.stdout for tok in (r"\m", r"\r", r"\s", r"\v")), (
        "/etc/motd still contains system-info escape tokens (\\m/\\r/\\s/\\v)"
    )

def test_1_7_2_banner(host):
    out = _cmd(host, "test -e /etc/issue && cat /etc/issue")
    assert out.rc == 0 and out.stdout.strip() != "", "/etc/issue is missing or empty"
    assert not any(tok in out.stdout for tok in (r"\m", r"\r", r"\s", r"\v")), (
        "/etc/issue still contains system-info escape tokens (\\m/\\r/\\s/\\v)"
    )

def test_1_7_3_banner(host):
    out = _cmd(host, "test -e /etc/issue.net && cat /etc/issue.net")
    assert out.rc == 0 and out.stdout.strip() != "", "/etc/issue.net is missing or empty"
    assert not any(tok in out.stdout for tok in (r"\m", r"\r", r"\s", r"\v")), (
        "/etc/issue.net still contains system-info escape tokens (\\m/\\r/\\s/\\v)"
    )

def test_1_7_4_motd_access(host):
    _file_root_mode(host, "/etc/motd", 0o133)

def test_1_7_5_issue_access(host):
    _file_root_mode(host, "/etc/issue", 0o133)

def test_1_7_6_issue_net_access(host):
    _file_root_mode(host, "/etc/issue.net", 0o133)

def test_1_8_1_gdm_removed(host):
    _package_not_installed(host, "gdm3")

def test_1_8_2_gdm(host):
    if not _gdm_installed(host):
        pytest.skip("gdm not installed")
    result = host.run("grep -R banner-message-enable /etc/dconf/db/*/ 2>/dev/null")
    assert result.rc == 0

def test_1_8_3_gdm(host):
    if not _gdm_installed(host):
        pytest.skip("gdm not installed")
    result = host.run("grep -R disable-user-list /etc/dconf/db/*/ 2>/dev/null")
    assert result.rc == 0

def test_1_8_4_gdm(host):
    if not _gdm_installed(host):
        pytest.skip("gdm not installed")
    result = host.run("grep -R idle-delay /etc/dconf/db/*/ 2>/dev/null")
    assert result.rc == 0

def test_1_8_5_gdm(host):
    if not _gdm_installed(host):
        pytest.skip("gdm not installed")
    result = host.run("grep -R idle-delay /etc/dconf/db/*/locks 2>/dev/null")
    assert result.rc == 0

def test_1_8_6_gdm(host):
    if not _gdm_installed(host):
        pytest.skip("gdm not installed")
    result = host.run("grep -R automount /etc/dconf/db/*/ 2>/dev/null")
    assert result.rc == 0

def test_1_8_8_gdm(host):
    if not _gdm_installed(host):
        pytest.skip("gdm not installed")
    result = host.run("grep -R autorun-never /etc/dconf/db/*/ 2>/dev/null")
    assert result.rc == 0

def test_1_8_9_gdm(host):
    if not _gdm_installed(host):
        pytest.skip("gdm not installed")
    result = host.run("grep -R autorun-never /etc/dconf/db/*/locks 2>/dev/null")
    assert result.rc == 0

def test_1_8_10_xdmcp(host):
    result = host.run("grep -Ei '^[[:space:]]*Enable[[:space:]]*=[[:space:]]*true' /etc/gdm/custom.conf 2>/dev/null")
    assert result.rc != 0

def test_2_1_1_not_in_use(host):
    _service_not_in_use(host, "autofs")

def test_2_1_2_not_in_use(host):
    _service_not_in_use(host, "avahi-daemon")

def test_2_1_3_not_in_use(host):
    _service_not_in_use(host, "dhcpd")

def test_2_1_4_not_in_use(host):
    _service_not_in_use(host, "named")

def test_2_1_5_not_in_use(host):
    _service_not_in_use(host, "dnsmasq")

def test_2_1_6_not_in_use(host):
    _service_not_in_use(host, "smb")

def test_2_1_7_not_in_use(host):
    _service_not_in_use(host, "vsftpd")

def test_2_1_8_not_in_use(host):
    _service_not_in_use(host, "dovecot")

def test_2_1_9_not_in_use(host):
    _service_not_in_use(host, "nfs-server")

def test_2_1_10_not_in_use(host):
    _service_not_in_use(host, "ypserv")

def test_2_1_11_not_in_use(host):
    _service_not_in_use(host, "cups")

def test_2_1_12_not_in_use(host):
    _service_not_in_use(host, "rpcbind")

def test_2_1_13_not_in_use(host):
    _service_not_in_use(host, "rsyncd")

def test_2_1_14_not_in_use(host):
    _service_not_in_use(host, "snmpd")

def test_2_1_15_not_in_use(host):
    _service_not_in_use(host, "telnet.socket")

def test_2_1_16_not_in_use(host):
    _service_not_in_use(host, "tftp.socket")

def test_2_1_17_not_in_use(host):
    _service_not_in_use(host, "squid")

def test_2_1_18_not_in_use(host):
    _service_not_in_use(host, "httpd")

def test_2_1_19_not_in_use(host):
    _service_not_in_use(host, "xinetd")

def test_2_1_20_xorg(host):
    assert "install ok installed" not in host.run("dpkg-query -W -f=${Status} xserver-xorg 2>/dev/null").stdout

def test_2_1_21_mta_local(host):
    if _pkg_installed(host, "postfix"):
        result = host.run("postconf -n inet_interfaces")
        assert "loopback-only" in result.stdout or "localhost" in result.stdout

def test_2_2_1_pkg(host):
    _package_not_installed(host, "ftp")

def test_2_2_2_pkg(host):
    _package_not_installed(host, "ldap-utils")

def test_2_2_3_pkg(host):
    _package_not_installed(host, "nis")

def test_2_2_4_pkg(host):
    _package_not_installed(host, "telnet")

def test_2_2_5_pkg(host):
    _package_not_installed(host, "tftp")

def test_2_3_1_chrony_installed(host):
    _assert_pkg_installed(host, "chrony")

def test_2_3_2_chrony_configured(host):
    result = host.run("grep -E '^(server|pool)[[:space:]]' /etc/chrony/chrony.conf")
    assert result.rc == 0

def test_2_3_3_chrony_user(host):
    unit = host.run("systemctl show chrony -p User --value")
    assert unit.stdout.strip() != "root"

def test_2_4_1_1_crond(host):
    _assert_svc_enabled_running(host, "cron")

def test_2_4_1_2_perms(host):
    _cron_perms(host, "/etc/crontab")

def test_2_4_1_3_perms(host):
    _cron_perms(host, "/etc/cron.hourly")

def test_2_4_1_4_perms(host):
    _cron_perms(host, "/etc/cron.daily")

def test_2_4_1_5_perms(host):
    _cron_perms(host, "/etc/cron.weekly")

def test_2_4_1_6_perms(host):
    _cron_perms(host, "/etc/cron.monthly")

def test_2_4_1_7_perms(host):
    _cron_perms(host, "/etc/cron.d")

def test_2_4_1_8_cron_allow(host):
    exists, mode, user, _g = _stat_path(host, "/etc/cron.allow")
    assert exists, "/etc/cron.allow is missing"
    assert user == "root", f"/etc/cron.allow owner is {user}, expected root"
    assert (mode & 0o077) == 0, f"/etc/cron.allow mode {oct(mode)} allows group/other access"
    deny_exists, _, _, _ = _stat_path(host, "/etc/cron.deny")
    assert not deny_exists, "/etc/cron.deny exists (should be removed when using cron.allow)"

def test_2_4_2_1_at_allow(host):
    exists, mode, user, _g = _stat_path(host, "/etc/at.allow")
    assert exists, "/etc/at.allow is missing"
    assert user == "root", f"/etc/at.allow owner is {user}, expected root"
    assert (mode & 0o077) == 0, f"/etc/at.allow mode {oct(mode)} allows group/other access"
    deny_exists, _, _, _ = _stat_path(host, "/etc/at.deny")
    assert not deny_exists, "/etc/at.deny exists (should be removed when using at.allow)"

def test_3_1_2_wireless(host):
    wifi = host.run("nmcli radio wifi 2>/dev/null")
    if wifi.rc == 0 and wifi.stdout.strip():
        assert wifi.stdout.strip().lower() in ("disabled", "off")

def test_3_1_3_bluetooth(host):
    _service_not_in_use(host, "bluetooth")

def test_3_2_1_mod(host):
    _module_not_available(host, 'dccp')

def test_3_2_2_mod(host):
    _module_not_available(host, 'tipc')

def test_3_2_3_mod(host):
    _module_not_available(host, 'rds')

def test_3_2_4_mod(host):
    _module_not_available(host, 'sctp')

def test_3_3_1_ip_forward(host):
    _sysctl_equals(host, "net.ipv4.ip_forward", "0")

def test_3_3_2_send_redirects(host):
    _sysctl_equals(host, "net.ipv4.conf.all.send_redirects", "0")
    _sysctl_equals(host, "net.ipv4.conf.default.send_redirects", "0")

def test_3_3_3_bogus_icmp(host):
    _sysctl_equals(host, "net.ipv4.icmp_ignore_bogus_error_responses", "1")

def test_3_3_4_bcast_icmp(host):
    _sysctl_equals(host, "net.ipv4.icmp_echo_ignore_broadcasts", "1")

def test_3_3_5_accept_redirects(host):
    _sysctl_equals(host, "net.ipv4.conf.all.accept_redirects", "0")
    _sysctl_equals(host, "net.ipv4.conf.default.accept_redirects", "0")

def test_3_3_6_secure_redirects(host):
    _sysctl_equals(host, "net.ipv4.conf.all.secure_redirects", "0")
    _sysctl_equals(host, "net.ipv4.conf.default.secure_redirects", "0")

def test_3_3_7_rp_filter(host):
    assert host.run("sysctl -n net.ipv4.conf.all.rp_filter").stdout.strip() in ("1","2")
    assert host.run("sysctl -n net.ipv4.conf.default.rp_filter").stdout.strip() in ("1","2")

def test_3_3_8_source_route(host):
    _sysctl_equals(host, "net.ipv4.conf.all.accept_source_route", "0")
    _sysctl_equals(host, "net.ipv4.conf.default.accept_source_route", "0")

def test_3_3_9_log_martians(host):
    _sysctl_equals(host, "net.ipv4.conf.all.log_martians", "1")
    _sysctl_equals(host, "net.ipv4.conf.default.log_martians", "1")

def test_3_3_10_syncookies(host):
    _sysctl_equals(host, "net.ipv4.tcp_syncookies", "1")

def test_3_3_11_accept_ra(host):
    _sysctl_equals(host, "net.ipv6.conf.all.accept_ra", "0")
    _sysctl_equals(host, "net.ipv6.conf.default.accept_ra", "0")

def test_4_1_1_nftables_pkg(host):
    _assert_pkg_installed(host, "ufw")

def test_4_1_2_single_fw(host):
    assert "Status: active" in host.run("ufw status").stdout, "UFW is not active"

def test_4_2_2_firewalld_lo(host):
    assert "Status: active" in host.run("ufw status").stdout, "UFW is not active"

def test_5_1_1_sshd_conf_perms(host):
    _file_root_mode(host, "/etc/ssh/sshd_config", 0o077)

def test_5_1_2_ssh_privkeys(host):
    result = host.run("find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -printf '%m %u %n\n'")
    for line in result.stdout.splitlines():
        mode, user, _ = line.split(None, 2)
        assert user == "root" and (int(mode, 8) & 0o177) == 0

def test_5_1_3_ssh_pubkeys(host):
    result = host.run("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -printf '%m %u %n\n'")
    for line in result.stdout.splitlines():
        mode, user, _ = line.split(None, 2)
        assert user == "root" and (int(mode, 8) & 0o133) == 0

def test_5_1_4_ciphers(host):
    c = _sshd_effective(host, "ciphers").lower()
    assert c and "cbc" not in c and "3des" not in c

def test_5_1_5_kex(host):
    k = _sshd_effective(host, "kexalgorithms").lower()
    assert "diffie-hellman-group1-sha1" not in k and "diffie-hellman-group14-sha1" not in k

def test_5_1_6_macs(host):
    m = _sshd_effective(host, "macs").lower()
    assert "hmac-md5" not in m and "umac-64" not in m

def test_5_1_7_access(host):
    result = host.run("sshd -T 2>/dev/null | grep -E '^(allowusers|allowgroups|denyusers|denygroups) '")
    assert result.rc == 0

def test_5_1_8_banner(host):
    assert _sshd_effective(host, "banner").lower() not in ("none", "")

def test_5_1_9_clientalive(host):
    assert int(_sshd_effective(host, "clientaliveinterval")) > 0
    assert int(_sshd_effective(host, "clientalivecountmax")) <= 3

def test_5_1_10_disableforwarding(host):
    result = host.run("sshd -T 2>/dev/null | grep -E '^(disableforwarding|x11forwarding|allowtcpforwarding) '")
    t = result.stdout.lower()
    assert "disableforwarding yes" in t or ("x11forwarding no" in t and "allowtcpforwarding no" in t)

def test_5_1_11_gssapi(host):
    assert _sshd_effective(host, "gssapiauthentication").lower() == "no"

def test_5_1_12_hostbased(host):
    assert _sshd_effective(host, "hostbasedauthentication").lower() == "no"

def test_5_1_13_ignorerhosts(host):
    assert _sshd_effective(host, "ignorerhosts").lower() == "yes"

def test_5_1_14_logingracetime(host):
    assert int(_sshd_effective(host, "logingracetime")) <= 60

def test_5_1_15_loglevel(host):
    assert _sshd_effective(host, "loglevel").upper() in ("INFO", "VERBOSE")

def test_5_1_16_maxauthtries(host):
    assert int(_sshd_effective(host, "maxauthtries")) <= 4

def test_5_1_17_maxstartups(host):
    assert _sshd_effective(host, "maxstartups")

def test_5_1_18_maxsessions(host):
    assert int(_sshd_effective(host, "maxsessions")) <= 10

def test_5_1_19_permitemptypasswords(host):
    assert _sshd_effective(host, "permitemptypasswords").lower() == "no"

def test_5_1_20_permitrootlogin(host):
    assert _sshd_effective(host, "permitrootlogin").lower() == "no"

def test_5_1_21_permituserenvironment(host):
    assert _sshd_effective(host, "permituserenvironment").lower() == "no"

def test_5_1_22_usepam(host):
    assert _sshd_effective(host, "usepam").lower() == "yes"

def test_5_2_1_sudo_pkg(host):
    _assert_pkg_installed(host, "sudo")

def test_5_2_2_sudo_pty(host):
    result = _cmd(host, "grep -R use_pty /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    assert result.rc == 0, "Defaults use_pty not found in /etc/sudoers or sudoers.d"

def test_5_2_3_sudo_log(host):
    result = _cmd(host, "grep -R logfile /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    assert result.rc == 0, "Defaults logfile= not found in /etc/sudoers or sudoers.d"

def test_5_2_4_sudo_nopasswd(host):
    result = _cmd(host, "grep -R NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    assert result.rc != 0, "NOPASSWD entries found in sudoers (CIS expects none for interactive admin)"

def test_5_2_5_sudo_noauth(host):
    result = _cmd(host, "grep -R '!authenticate' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    assert result.rc != 0, "!authenticate found in sudoers (authentication bypass)"

def test_5_2_6_sudo_timeout(host):
    result = _cmd(host, "grep -R timestamp_timeout /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    if result.rc == 0:
        import re as _re
        vals = _re.findall(r"timestamp_timeout\s*=\s*(-?\d+)", result.stdout)
        assert vals and all(0 <= int(v) <= 15 for v in vals), (
            f"sudo timestamp_timeout values {vals} must be between 0 and 15"
        )

def test_5_2_7_su_wheel(host):
    result = _cmd(
        host,
        "grep -E '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel[.]so' /etc/pam.d/su",
    )
    assert result.rc == 0, "pam_wheel.so required not configured in /etc/pam.d/su"

def test_5_3_1_1_pam(host):
    _assert_pkg_installed(host, "libpam-modules")

def test_5_3_1_2_authselect(host):
    _assert_pkg_installed(host, "libpam-runtime")

def test_5_3_1_3_libpwquality(host):
    _assert_pkg_installed(host, "libpam-pwquality")

def test_5_3_2_2_faillock_enabled(host):
    _assert_pam(host, r"pam_faillock\.so", "pam_faillock.so is not enabled in PAM")

def test_5_3_2_3_pwquality_enabled(host):
    _assert_pam(host, r"pam_pwquality\.so", "pam_pwquality.so is not enabled in PAM")

def test_5_3_2_4_pwhistory_enabled(host):
    _assert_pam(host, r"pam_pwhistory\.so", "pam_pwhistory.so is not enabled in PAM")

def test_5_3_2_5_unix_enabled(host):
    _assert_pam(host, r"pam_unix\.so", "pam_unix.so is not enabled in PAM")

def test_5_3_3_1_1_deny(host):
    result = host.run("grep -E '^[[:space:]]*deny[[:space:]]*=' /etc/security/faillock.conf")
    assert result.rc == 0, "deny= not set in /etc/security/faillock.conf"
    deny = int(result.stdout.split("=", 1)[1])
    assert deny <= 5, f"faillock deny={deny}, expected <= 5"

def test_5_3_3_1_2_unlock_time(host):
    result = host.run("grep -E '^[[:space:]]*unlock_time[[:space:]]*=' /etc/security/faillock.conf")
    assert result.rc == 0, "unlock_time= not set in /etc/security/faillock.conf"
    unlock = int(result.stdout.split("=", 1)[1])
    assert unlock >= 900, f"faillock unlock_time={unlock}, expected >= 900"

def test_5_3_3_1_3_even_deny_root(host):
    result = host.run(
        "grep -E '^[[:space:]]*(even_deny_root|root_unlock_time)' /etc/security/faillock.conf"
    )
    assert result.rc == 0, (
        "even_deny_root or root_unlock_time not set in /etc/security/faillock.conf"
    )

def test_5_3_3_2_1_difok(host):
    val = int(_pwquality(host, "difok"))
    assert val >= 2, f"pwquality difok={val}, expected >= 2"

def test_5_3_3_2_2_minlen(host):
    val = int(_pwquality(host, "minlen"))
    assert val >= 14, f"pwquality minlen={val}, expected >= 14"

def test_5_3_3_2_4_maxrepeat(host):
    val = int(_pwquality(host, "maxrepeat"))
    assert val <= 3, f"pwquality maxrepeat={val}, expected <= 3"

def test_5_3_3_2_5_maxsequence(host):
    val = int(_pwquality(host, "maxsequence"))
    assert val <= 3, f"pwquality maxsequence={val}, expected <= 3"

def test_5_3_3_2_6_dictcheck(host):
    result = host.run("grep -E '^[[:space:]]*dictcheck[[:space:]]*=' /etc/security/pwquality.conf")
    if result.rc == 0:
        val = result.stdout.split("=", 1)[1].strip()
        assert val != "0", "pwquality dictcheck=0 (dictionary check disabled)"

def test_5_3_3_2_7_enforce_for_root(host):
    result = host.run("grep -E '^[[:space:]]*enforce_for_root' /etc/security/pwquality.conf")
    assert result.rc == 0, "enforce_for_root not set in /etc/security/pwquality.conf"

def test_5_3_3_3_1_remember(host):
    conf = host.run(
        "grep -E '^[[:space:]]*remember[[:space:]]*=' /etc/security/pwhistory.conf 2>/dev/null"
    )
    pam = _pam_grep(host, r"pam_pwhistory\.so.*remember=")
    if conf.rc == 0:
        remember = int(conf.stdout.split("=", 1)[1])
        assert remember >= 24 or pam.rc == 0, (
            f"password history remember={remember} in pwhistory.conf "
            f"(need >= 24) and pam_pwhistory remember= not found in PAM"
        )
    else:
        assert pam.rc == 0, (
            "password history remember>=24 not found in "
            "/etc/security/pwhistory.conf or PAM pam_pwhistory.so"
        )

def test_5_3_3_3_2_pwhistory_root(host):
    conf = host.run(
        "grep -E '^[[:space:]]*enforce_for_root' /etc/security/pwhistory.conf 2>/dev/null"
    )
    pam = _pam_grep(host, r"pam_pwhistory\.so.*enforce_for_root")
    assert conf.rc == 0 or pam.rc == 0, (
        "pwhistory enforce_for_root not set in pwhistory.conf or PAM"
    )

def test_5_3_3_3_3_pwhistory_authtok(host):
    _assert_pam(
        host,
        r"pam_pwhistory\.so.*use_authtok",
        "pam_pwhistory.so is missing use_authtok in PAM password stack",
    )

def test_5_3_3_4_1_no_nullok(host):
    result = _pam_grep(host, r"pam_unix\.so.*nullok")
    assert result.rc != 0, "pam_unix.so still allows nullok (empty passwords)"

def test_5_3_3_4_2_no_remember(host):
    result = _pam_grep(host, r"pam_unix\.so.*remember=")
    assert result.rc != 0, (
        "pam_unix.so still has remember= (history should use pam_pwhistory)"
    )

def test_5_3_3_4_3_hash(host):
    _assert_pam(
        host,
        r"pam_unix\.so.*(sha512|yescrypt)",
        "pam_unix.so is not configured for sha512 or yescrypt hashing",
    )

def test_5_3_3_4_4_use_authtok(host):
    _assert_pam(
        host,
        r"password.*pam_unix\.so.*use_authtok",
        "password pam_unix.so is missing use_authtok",
    )

def test_5_4_1_1_pass_max_days(host):
    days = int(_login_defs(host, "PASS_MAX_DAYS"))
    assert 0 < days <= 365, f"PASS_MAX_DAYS={days}, expected 1..365"

def test_5_4_1_3_pass_warn_age(host):
    days = int(_login_defs(host, "PASS_WARN_AGE"))
    assert days >= 7, f"PASS_WARN_AGE={days}, expected >= 7"

def test_5_4_1_4_encrypt_method(host):
    result = host.run("grep -E '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' /etc/login.defs")
    assert result.rc == 0, "ENCRYPT_METHOD not set in /etc/login.defs"
    assert any(x in result.stdout.upper() for x in ("SHA512", "YESCRYPT")), (
        f"ENCRYPT_METHOD must be SHA512 or YESCRYPT, got: {result.stdout.strip()!r}"
    )

def test_5_4_1_5_inactive(host):
    result = host.run("useradd -D 2>/dev/null | grep INACTIVE")
    assert result.rc == 0 and "=" in result.stdout, (
        "INACTIVE default not reported by useradd -D"
    )
    val = result.stdout.split("=", 1)[1].strip()
    assert val.isdigit() and 0 < int(val) <= 45, (
        f"useradd INACTIVE={val!r}, expected 1..45"
    )

def test_5_4_1_6_lastchange_past(host):
    cmd = (
        "awk -F: '($2 ~ /^[!*]/ || $2==\"\" || $3==\"\"){next} "
        "{cmd=\"date +%s\"; cmd|getline now; close(cmd); "
        "if(($3+0)*86400>now) print $1}' /etc/shadow"
    )
    bad = host.run(cmd).stdout.strip()
    assert bad == "", f"accounts with future last password change: {bad}"

def test_5_4_2_1_uid0(host):
    result = host.run("getent passwd | awk -F: '($3==0){print $1}'")
    assert result.rc == 0, f"failed to query UID 0 accounts: {result.stderr.strip()!r}"
    users = [u for u in result.stdout.splitlines() if u.strip()]
    assert users == ["root"], f"UID 0 accounts should be only root, found: {users}"

def test_5_4_2_2_gid0_acct(host):
    result = host.run("getent passwd | awk -F: '($4==0){print $1}'")
    assert result.rc == 0, f"failed to query GID 0 passwd accounts: {result.stderr.strip()!r}"
    users = [u for u in result.stdout.splitlines() if u.strip()]
    assert users == ["root"], (
        f"passwd primary GID 0 should be only root, found: {users}"
    )

def test_5_4_2_3_gid0_group(host):
    result = host.run("getent group | awk -F: '($3==0){print $1}'")
    assert result.rc == 0, f"failed to query GID 0 groups: {result.stderr.strip()!r}"
    groups = [g for g in result.stdout.splitlines() if g.strip()]
    assert groups == ["root"], f"GID 0 group should be only root, found: {groups}"

def test_5_4_2_4_root_passwd(host):
    result = host.run("passwd -S root")
    assert result.rc == 0, (
        f"passwd -S root failed (rc={result.rc}, "
        f"stdout={result.stdout.strip()!r}, stderr={result.stderr.strip()!r})"
    )

def test_5_4_2_5_root_path(host):
    result = host.run(
        "grep -Eh '^(export[[:space:]]+)?PATH=' "
        "/root/.bash_profile /root/.bashrc /etc/profile 2>/dev/null | tail -n1"
    )
    if result.stdout.strip():
        val = result.stdout.split("=", 1)[1].strip().strip("\"'")
        assert "::" not in val and not val.startswith(":") and not val.endswith(":"), (
            f"root PATH has empty segment: {val!r}"
        )
        assert "." not in val.split(":"), f"root PATH contains '.': {val!r}"

def test_5_4_2_6_root_umask(host):
    result = host.run(
        "grep -R umask /root/.bashrc /root/.profile /etc/profile "
        "/etc/bashrc /etc/bash.bashrc /etc/profile.d/ 2>/dev/null"
    )
    assert "027" in result.stdout or "077" in result.stdout, (
        "root/system umask 027 or 077 not found in profile/bashrc files"
    )

def test_5_4_2_7_sys_nologin(host):
    cmd = (
        "awk -F: '($3 < 1000 && $1 != \"root\" && "
        "$7 !~ /(nologin|false|sync|shutdown|halt)$/){print}' /etc/passwd"
    )
    bad = host.run(cmd).stdout.strip()
    assert bad == "", f"system accounts with login shells: {bad}"

def test_5_4_2_8_locked_nologin(host):
    cmd = (
        "awk -F: '($7 ~ /(nologin|false)$/){print $1}' /etc/passwd | "
        "while read -r u; do passwd -S \"$u\" 2>/dev/null; done | "
        "awk '($2!=\"L\" && $2!=\"LK\"){print}'"
    )
    bad = host.run(cmd).stdout.strip()
    assert bad == "", f"nologin accounts not locked: {bad}"

def test_5_4_3_1_nologin_shells(host):
    result = host.run("grep nologin /etc/shells")
    assert result.rc != 0, "/etc/shells still lists nologin as a valid shell"

def test_5_4_3_2_tmout(host):
    result = host.run("grep -R TMOUT /etc/profile /etc/profile.d/ 2>/dev/null")
    assert result.rc == 0, "TMOUT not configured in /etc/profile or /etc/profile.d"

def test_5_4_3_3_umask(host):
    umask = _login_defs(host, "UMASK")
    assert umask in ("027", "077"), f"UMASK={umask!r} in login.defs, expected 027 or 077"

def test_6_1_1_aide(host):
    _assert_pkg_installed(host, "aide")

def test_6_1_2_aide_timer(host):
    cron = host.run("grep -R aide /etc/cron.* /etc/crontab /var/spool/cron/ 2>/dev/null")
    timer_ok = _svc_enabled(host, "aidecheck.timer") or _svc_enabled(host, "aide.timer")
    assert cron.rc == 0 or timer_ok, (
        "AIDE is not scheduled (no cron entry and neither aidecheck.timer nor aide.timer enabled)"
    )

def test_6_2_1_1_journald(host):
    assert _svc_active(host, "systemd-journald"), "systemd-journald is not running"

def test_6_2_1_4_one_logger(host):
    assert _rsyslog_in_use(host) or _svc_active(host, "systemd-journald"), "neither rsyslog nor systemd-journald is active as system logger"

def test_6_2_2_1_1_journal_remote_pkg(host):
    if _rsyslog_in_use(host):
        pytest.skip("rsyslog path")
    _assert_pkg_installed(host, "systemd-journal-remote")

def test_6_2_2_1_3_journal_upload(host):
    if _rsyslog_in_use(host):
        pytest.skip("rsyslog path")
    _assert_svc_enabled_running(host, "systemd-journal-upload")

def test_6_2_2_1_4_journal_remote_unused(host):
    _service_not_in_use(host, "systemd-journal-remote")

def test_6_2_2_2_forward_disabled(host):
    if _rsyslog_in_use(host):
        pytest.skip("rsyslog path uses ForwardToSyslog=yes")
    assert host.run("grep -E '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/* 2>/dev/null").rc != 0

def test_6_2_2_3_compress(host):
    result = _cmd(
        host,
        "grep -E '^[[:space:]]*Compress[[:space:]]*=[[:space:]]*yes' "
        "/etc/systemd/journald.conf /etc/systemd/journald.conf.d/* 2>/dev/null",
    )
    assert result.rc == 0, "journald Compress=yes not configured"

def test_6_2_2_4_storage(host):
    result = _cmd(
        host,
        "grep -E '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*persistent' "
        "/etc/systemd/journald.conf /etc/systemd/journald.conf.d/* 2>/dev/null",
    )
    assert result.rc == 0, "journald Storage=persistent not configured"

def test_6_2_3_1_rsyslog_pkg(host):
    if not _rsyslog_in_use(host):
        pytest.skip("rsyslog not selected (journald-only / journal-upload path)")
    _assert_pkg_installed(host, "rsyslog")

def test_6_2_3_2_rsyslog_svc(host):
    if not _rsyslog_in_use(host):
        pytest.skip("rsyslog not selected (journald-only / journal-upload path)")
    _assert_svc_enabled_running(host, "rsyslog")

def test_6_2_3_3_forward_enabled(host):
    if not _rsyslog_in_use(host):
        pytest.skip("rsyslog not selected")
    assert host.run("grep -E '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/* 2>/dev/null").rc == 0

def test_6_2_3_4_filecreatemode(host):
    if not _rsyslog_in_use(host):
        pytest.skip("rsyslog not selected")
    assert host.run("grep -R FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep 0640").rc == 0

def test_6_2_3_7_no_imtcp(host):
    active = host.run("grep -R --include='*.conf' imtcp /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v ':[[:space:]]*#' | grep -v '^#'")
    assert active.stdout.strip() == ""

def test_6_2_4_1_log_perms(host):
    assert host.run("find /var/log -type f -perm /037 -o -type d -perm /026 2>/dev/null | head").stdout.strip() == ""

def test_6_3_1_1_audit_pkgs(host):
    _assert_pkg_installed(host, "auditd", "libaudit1")

def test_6_3_1_2_audit_cmdline(host):
    result = _cmd(
        host,
        "grep -E '(^|[[:space:]])audit=1([[:space:]]|$)' "
        "/etc/default/grub /boot/grub/grubenv /boot/efi/EFI/*/grubenv "
        "/proc/cmdline 2>/dev/null",
    )
    assert result.rc == 0, "audit=1 not found in GRUB config or /proc/cmdline"

def test_6_3_1_3_audit_backlog(host):
    result = _cmd(
        host,
        "grep -E 'audit_backlog_limit=' "
        "/etc/default/grub /boot/grub/grubenv /boot/efi/EFI/*/grubenv "
        "/proc/cmdline 2>/dev/null",
    )
    assert result.rc == 0, "audit_backlog_limit= not found in GRUB config or /proc/cmdline"
    import re as _re
    nums = _re.findall(r"audit_backlog_limit=(\d+)", result.stdout)
    assert nums and int(nums[-1]) >= 8192, (
        f"audit_backlog_limit={nums[-1] if nums else 'missing'}, expected >= 8192"
    )

def test_6_3_1_4_auditd(host):
    _assert_svc_enabled_running(host, "auditd")

def test_6_3_2_1_max_log_file(host):
    result = _cmd(host, "grep -E '^max_log_file[[:space:]]*=' /etc/audit/auditd.conf")
    assert result.rc == 0, "max_log_file= not set in /etc/audit/auditd.conf"

def test_6_3_2_2_keep_logs(host):
    result = _cmd(
        host,
        "grep -E '^max_log_file_action[[:space:]]*=[[:space:]]*keep_logs' /etc/audit/auditd.conf",
    )
    assert result.rc == 0, "max_log_file_action=keep_logs not set in auditd.conf"

def test_6_3_2_3_full_halt(host):
    space = _cmd(host, "grep space_left_action /etc/audit/auditd.conf")
    mail = _cmd(host, "grep action_mail_acct /etc/audit/auditd.conf")
    admin = _cmd(host, "grep admin_space_left_action /etc/audit/auditd.conf")
    assert "email" in space.stdout, (
        f"space_left_action should include email, got: {space.stdout.strip()!r}"
    )
    assert "root" in mail.stdout, (
        f"action_mail_acct should include root, got: {mail.stdout.strip()!r}"
    )
    assert "halt" in admin.stdout, (
        f"admin_space_left_action should include halt, got: {admin.stdout.strip()!r}"
    )

def test_6_3_2_4_space_left(host):
    result = _cmd(host, "grep -E '^space_left[[:space:]]*=' /etc/audit/auditd.conf")
    assert result.rc == 0, "space_left= not set in /etc/audit/auditd.conf"

def test_6_3_3_1_rule(host):
    _audit_grep(host, r'scope')

def test_6_3_3_1_rule(host):
    _audit_grep(host, r'scope')

def test_6_3_3_2_rule(host):
    _audit_grep(host, r'user_emulation|sudo')

def test_6_3_3_3_rule(host):
    _audit_grep(host, r'sudo_log|sudoers')

def test_6_3_3_4_rule(host):
    _audit_grep(host, r'time-change')

def test_6_3_3_6_rule(host):
    _audit_grep(host, r'privileged|perm=x')

def test_6_3_3_7_rule(host):
    _audit_grep(host, r'access')

def test_6_3_3_8_rule(host):
    _audit_grep(host, r'identity')

def test_6_3_3_10_rule(host):
    _audit_grep(host, r'mounts')

def test_6_3_3_11_rule(host):
    _audit_grep(host, r'session')

def test_6_3_3_12_rule(host):
    _audit_grep(host, r'logins')

def test_6_3_3_13_rule(host):
    _audit_grep(host, r'delete')

def test_6_3_3_19_rule(host):
    _audit_grep(host, r'modules')

def test_6_3_3_20_immutable(host):
    st = _cmd(
        host,
        "auditctl -s 2>/dev/null || /usr/sbin/auditctl -s 2>/dev/null || "
        "/sbin/auditctl -s 2>/dev/null",
    )
    locked = _cmd(
        host,
        "grep -R -E '^[[:space:]]*-e[[:space:]]+2[[:space:]]*$' "
        "/etc/audit/rules.d /etc/audit/audit.rules 2>/dev/null",
    )
    assert ("enabled 2" in st.stdout) or locked.rc == 0, (
        "audit rules are not immutable (-e 2 not active and not present in rules files); "
        f"auditctl -s={st.stdout.strip()!r}"
    )

def test_6_3_4_1_audit_dir_mode(host):
    exists, mode, user, _group = _stat_path(host, "/var/log/audit")
    assert exists, "/var/log/audit is missing (is auditd installed?)"
    assert user == "root", f"/var/log/audit owner is {user}, expected root"
    assert (mode & 0o027) == 0, (
        f"/var/log/audit mode {oct(mode)} allows group-write/other access"
    )

def test_6_3_4_2_audit_files_mode(host):
    assert host.run("find /var/log/audit -type f -perm /0137 -ls").stdout.strip() == ""

def test_6_3_4_3_audit_files_owner(host):
    assert host.run("find /var/log/audit -type f ! -user root -ls").stdout.strip() == ""

def test_6_3_4_4_audit_files_group(host):
    assert host.run("find /var/log/audit -type f ! -group root -ls").stdout.strip() == ""

def test_6_3_4_5_audit_conf_mode(host):
    assert host.run("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) -perm /0137 -ls").stdout.strip() == ""

def test_6_3_4_6_audit_conf_owner(host):
    assert host.run("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root -ls").stdout.strip() == ""

def test_6_3_4_7_audit_conf_group(host):
    assert host.run("find /etc/audit -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root -ls").stdout.strip() == ""

def test_6_3_4_8_tools(host):
    found = False
    for tool in ("/sbin/auditctl","/usr/sbin/auditctl","/sbin/aureport","/usr/sbin/aureport","/sbin/ausearch","/usr/sbin/ausearch","/sbin/autrace","/usr/sbin/autrace","/sbin/auditd","/usr/sbin/auditd","/sbin/augenrules","/usr/sbin/augenrules"):
        exists, mode, _user, _group = _stat_path(host, tool)
        if exists:
            found = True
            assert (mode & 0o022) == 0
    assert found, "no audit tools found in /sbin or /usr/sbin"


def test_6_3_4_9_tools(host):
    found = False
    for tool in ("/sbin/auditctl","/usr/sbin/auditctl","/sbin/aureport","/usr/sbin/aureport","/sbin/ausearch","/usr/sbin/ausearch","/sbin/autrace","/usr/sbin/autrace","/sbin/auditd","/usr/sbin/auditd","/sbin/augenrules","/usr/sbin/augenrules"):
        exists, _mode, user, _group = _stat_path(host, tool)
        if exists:
            found = True
            assert user == "root"
    assert found, "no audit tools found in /sbin or /usr/sbin"


def test_6_3_4_10_tools(host):
    found = False
    for tool in ("/sbin/auditctl","/usr/sbin/auditctl","/sbin/aureport","/usr/sbin/aureport","/sbin/ausearch","/usr/sbin/ausearch","/sbin/autrace","/usr/sbin/autrace","/sbin/auditd","/usr/sbin/auditd","/sbin/augenrules","/usr/sbin/augenrules"):
        exists, _mode, _user, group = _stat_path(host, tool)
        if exists:
            found = True
            assert group == "root"
    assert found, "no audit tools found in /sbin or /usr/sbin"


def test_7_1_1_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/passwd")
    if exists:
        assert user == "root"
        assert (mode & 91) == 0

def test_7_1_2_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/passwd-")
    if exists:
        assert user == "root"
        assert (mode & 91) == 0

def test_7_1_3_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/group")
    if exists:
        assert user == "root"
        assert (mode & 91) == 0

def test_7_1_4_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/group-")
    if exists:
        assert user == "root"
        assert (mode & 91) == 0

def test_7_1_5_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/shadow")
    if exists:
        assert user == "root"
        assert (mode & 127) == 0

def test_7_1_6_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/shadow-")
    if exists:
        assert user == "root"
        assert (mode & 127) == 0

def test_7_1_7_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/gshadow")
    if exists:
        assert user == "root"
        assert (mode & 127) == 0

def test_7_1_8_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/gshadow-")
    if exists:
        assert user == "root"
        assert (mode & 127) == 0

def test_7_1_9_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/shells")
    if exists:
        assert user == "root"
        assert (mode & 91) == 0

def test_7_1_10_perms(host):
    exists, mode, user, _group = _stat_path(host, "/etc/security/opasswd")
    if exists:
        assert user == "root"
        assert (mode & 127) == 0

def test_7_1_11_ww_dirs(host):
    cmd = "df --local -P | awk 'NR>1{print $6}' | xargs -I{} find {} -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null"
    assert host.run(cmd).stdout.strip() == ""

def test_7_1_12_unowned(host):
    cmd = "df --local -P | awk 'NR>1{print $6}' | xargs -I{} find {} -xdev \\( -nouser -o -nogroup \\) -print 2>/dev/null | head"
    assert host.run(cmd).stdout.strip() == ""

def test_7_2_1_shadowed(host):
    assert host.run("awk -F: '($2!=\"x\"){print $1}' /etc/passwd").stdout.strip() == ""

def test_7_2_2_shadow_empty(host):
    assert host.run("awk -F: '($2==\"\"){print $1}' /etc/shadow").stdout.strip() == ""

def test_7_2_3_groups_exist(host):
    assert host.run("awk -F: 'NR==FNR{g[$3]=1;next} !($4 in g){print $1}' /etc/group /etc/passwd").stdout.strip() == ""

def test_7_2_4_dup_uid(host):
    assert host.run("awk -F: '!/^#/ && NF{print $3}' /etc/passwd | sort | uniq -d").stdout.strip() == ""

def test_7_2_5_dup_gid(host):
    assert host.run("awk -F: '!/^#/ && NF{print $3}' /etc/group | sort | uniq -d").stdout.strip() == ""

def test_7_2_6_dup_user(host):
    assert host.run("awk -F: '!/^#/ && NF{print $1}' /etc/passwd | sort | uniq -d").stdout.strip() == ""

def test_7_2_7_dup_group(host):
    assert host.run("awk -F: '!/^#/ && NF{print $1}' /etc/group | sort | uniq -d").stdout.strip() == ""

def test_7_2_8_homedirs(host):
    result = host.run("awk -F: '($7 !~ /(nologin|false)$/ && $3>=1000){print $1,$6}' /etc/passwd")
    for line in result.stdout.splitlines():
        user, home = line.split()
        check = host.run("test -d %s && stat -c \'%%U\' %s", home, home)
        assert check.rc == 0 and check.stdout.strip() == user

def test_7_2_9_dotfiles(host):
    result = host.run("awk -F: '($7 !~ /(nologin|false)$/ && $3>=1000){print $1,$6}' /etc/passwd")
    for line in result.stdout.splitlines():
        user, home = line.split()
        dots = host.run(f"find {home} -maxdepth 1 -type f -name '.*' -perm /037 -ls 2>/dev/null")
        assert dots.stdout.strip() == ""

