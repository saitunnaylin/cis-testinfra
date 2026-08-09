# Testinfra CIS Benchmark Auditing

Testinfra/pytest suites for auditing Linux hosts against current CIS Benchmarks
for Enterprise Linux (RHEL/Alma/Rocky), Ubuntu, and Debian.

## Target CIS versions

| Suite | Target CIS Benchmark | Tests |
| --- | --- | --- |
| `testinfra-cis-el10.py` | CIS Red Hat Enterprise Linux 10 **v1.0.1** | 266 |
| `testinfra-cis-el9.py` | CIS Red Hat Enterprise Linux 9 **v2.0.0** | 265 |
| `testinfra-cis-el8.py` | CIS Red Hat Enterprise Linux 8 **v4.0.0** (legacy) | 265 |
| `testinfra-cis-ubuntu.py` | CIS Ubuntu Linux 24.04 LTS **v2.0.0** | 258 |
| `testinfra-cis-debian.py` | CIS Debian Linux 13 **v1.0.0** | 258 |

`testinfra-cis-el9.py` maps 1:1 to every **(Automated)** control in the CIS RHEL 9
v2.0.0 TOC. Other suites follow the same control set with distro adaptations
(AppArmor/UFW/apt on Debian & Ubuntu; `firewire-core` on EL10).

CIS **Manual** controls (site-policy / human review) are not asserted. Some tests
`pytest.skip` when an alternate CIS-allowed path is active (for example rsyslog
vs journal-upload, or GDM hardening when GDM is not installed).

## Requirements

- Python 3.8+
- Linux target host (local or SSH)
- Root/sudo on the target for many checks

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Local:

```bash
pytest -v --sudo testinfra-cis-el9.py
pytest -v --sudo testinfra-cis-ubuntu.py
```

Remote over SSH:

```bash
pytest -v --sudo --hosts=ssh://user@hostname --ssh-config=~/.ssh/config testinfra-cis-el9.py
```

Filter by section:

```bash
pytest -v --sudo -k '5_1_ or sshd' testinfra-cis-el9.py
pytest -v --sudo -k 'selinux or apparmor or ufw' testinfra-cis-ubuntu.py
```

## Coverage

1. Filesystems, package authenticity, MAC (SELinux/AppArmor), bootloader, hardening, banners  
2. Unused services/clients, chrony, cron/at  
3. Network sysctl and unused protocol modules  
4. Host firewall (firewalld/nftables or UFW)  
5. SSH, sudo, PAM/password policy, account defaults  
6. AIDE, journald/rsyslog, auditd  
7. Critical file permissions and local user/group consistency  

## Important

- These suites are for hardening verification and regression testing.
- They are **not** a drop-in replacement for CIS-CAT / OpenSCAP formal evidence.
  Always cross-check against the official CIS PDF for your OS minor release.
- Run against a Linux host that matches the suite (EL9 suite on EL9, etc.).
- Module checks expect both `blacklist <module>` and
  `install <module> /bin/false` (or `/bin/true`).
- File ownership/mode checks use shell `stat` (not `host.file().mode`) so SSH +
  `--sudo` does not trip testinfra’s Windows OS mis-detection when `uname` is
  outside sudo `secure_path`.
- SSH + `--sudo` needs **passwordless sudo** (NOPASSWD) or a root login; otherwise
  failures look like `remote sudo requires a password/TTY`.

## License

MIT — see [LICENSE](LICENSE).
