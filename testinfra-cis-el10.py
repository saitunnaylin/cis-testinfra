def test_cramfs_filesystems_is_disabled(host):
    cram1 = host.check_output('modprobe -n -v cramfs')
    cram2 = host.check_output('lsmod | grep cramfs')
    assert 'install /bin/true' in cram1
    assert cram2 == ''

def test_vfat_filesystems_is_limited(host):
    vfat2 = host.check_output('modprobe -n -v vfat')
    vfat3 = host.check_output('lsmod | grep vfat')
    assert 'install /bin/true' in vfat2
    assert vfat3 == ''

def test_squashfs_filesystems_is_disabled(host):
    squashfs1 = host.check_output('modprobe -n -v squashfs')
    squashfs2 = host.check_output('lsmod | grep squashfs')
    assert 'install /bin/true' in squashfs1
    assert squashfs2 == ''

def test_udf_filesystems_is_disabled(host):
    udf1 = host.check_output('modprobe -n -v udf')
    udf2 = host.check_output('lsmod | grep udf')
    assert 'install /bin/true' in udf1
    assert udf2 == ''

def test_tmp_partition_is_configured(host):
    tmp = host.check_output('mount | grep -E "[[:space:]]/tmp[[:space:]]"')
    assert '/tmp' in tmp

def test_nodev_option_set_on_tmp_partition(host):
    tmp = host.check_output('mount | grep -E "[[:space:]]/tmp[[:space:]]"')
    assert 'nodev' in tmp

def test_noexec_option_set_on_tmp_partition(host):
    tmp = host.check_output('mount | grep -E "[[:space:]]/tmp[[:space:]]"')
    assert 'noexec' in tmp

def test_separate_var_partition_is_configured(host):
    var = host.check_output('mount | grep -E "[[:space:]]/var[[:space:]]"')
    assert '/var' in var

def test_separate_vartmp_partition_is_configured(host):
    vartmp = host.check_output('mount | grep -E "[[:space:]]/var/tmp[[:space:]]"')
    assert '/var/tmp' in vartmp

def test_nodev_option_set_on_vartmp_partition(host):
    vartmp = host.check_output('mount | grep -E "[[:space:]]/var/tmp[[:space:]]"')
    assert 'nodev' in vartmp

def test_nosuid_option_set_on_vartmp_partition(host):
    vartmp = host.check_output('mount | grep -E "[[:space:]]/var/tmp[[:space:]]"')
    assert 'nosuid' in vartmp

def test_noexec_option_set_on_vartmp_partition(host):
    vartmp = host.check_output('mount | grep -E "[[:space:]]/var/tmp[[:space:]]"')
    assert 'noexec' in vartmp

def test_separate_varlog_partition_is_configured(host):
    varlog = host.check_output('mount | grep -E "[[:space:]]/var/log[[:space:]]"')
    assert '/var/log' in varlog

def test_separate_varlogaudit_partition_is_configured(host):
    varlogaudit = host.check_output('mount | grep -E "[[:space:]]/var/log/audit[[:space:]]"')
    assert '/var/log/audit' in varlogaudit

def test_separate_home_partition_is_configured(host):
    home = host.check_output('mount | grep -E "[[:space:]]/home[[:space:]]"')
    assert '/home' in home

def test_nodev_option_set_on_home_partition(host):
    home = host.check_output('mount | grep -E "[[:space:]]/home[[:space:]]"')
    assert 'nodev' in home

def test_nodev_option_set_on_devshm_partition(host):
    devshm = host.check_output('mount | grep -E "[[:space:]]/dev/shm[[:space:]]"')
    assert 'nodev' in devshm

def test_nosuid_option_set_on_devshm_partition(host):
    devshm = host.check_output('mount | grep -E "[[:space:]]/dev/shm[[:space:]]"')
    assert 'nosuid' in devshm

def test_noexec_option_set_on_devshm_partition(host):
    devshm = host.check_output('mount | grep -E "[[:space:]]/dev/shm[[:space:]]"')
    assert 'noexec' in devshm

def test_nodev_option_set_on_removable_media_partition(host):
    mounts = host.check_output('mount')
    assert 'cdrom' not in mounts
    assert 'usb' not in mounts
    assert 'floppy' not in mounts

def test_nosuid_option_set_on_removable_media_partition(host):
    mounts = host.check_output('mount')
    assert 'cdrom' not in mounts
    assert 'usb' not in mounts
    assert 'floppy' not in mounts

def test_noexec_option_set_on_removable_media_partition(host):
    mounts = host.check_output('mount')
    assert 'cdrom' not in mounts
    assert 'usb' not in mounts
    assert 'floppy' not in mounts

def test_ensure_sticky_bit_is_set_on_world_writable_directory(host):
    cmd = "df --local -P | awk 'NR>1 {print $6}' | xargs -I{} find {} -xdev -type d -perm -0002 ! -perm -1000 -print"
    output = host.check_output(cmd)
    assert output == ''

def test_disable_automounting(host):
    autofs = host.service('autofs')
    assert not autofs.is_enabled

def test_disable_usb_storage(host):
    usb1 = host.check_output('modprobe -n -v usb-storage')
    usb2 = host.check_output('lsmod | grep usb-storage')
    assert 'install /bin/true' in usb1
    assert usb2 == ''

def test_xinetd_is_not_installed(host):
    xinetd = host.package('xinetd')
    assert not xinetd.is_installed

def test_time_synchronization_in_use(host):
    chrony = host.package('chrony')
    assert chrony.is_installed

def test_chrony_is_configured(host):
    chrony_conf = host.check_output('grep -E "^(server|pool)" /etc/chrony.conf')
    assert chrony_conf != ''

def test_x_window_system_is_not_installed(host):
    xwindow = host.check_output('rpm -qa xorg-x11*')
    assert xwindow == ''

def test_rsync_is_not_enabled(host):
    rsyncd = host.service('rsyncd')
    assert not rsyncd.is_enabled

def test_avahi_is_not_enabled(host):
    avahi = host.service('avahi-daemon')
    assert not avahi.is_enabled

def test_snmp_server_is_not_enabled(host):
    snmpd = host.service('snmpd')
    assert not snmpd.is_enabled

def test_http_proxy_server_is_not_enabled(host):
    squid = host.service('squid')
    assert not squid.is_enabled

def test_samba_is_not_enabled(host):
    smb = host.service('smb')
    assert not smb.is_enabled

def test_imap_and_pop3_server_is_not_enabled(host):
    dovecot = host.service('dovecot')
    assert not dovecot.is_enabled

def test_http_server_is_not_enabled(host):
    httpd = host.service('httpd')
    assert not httpd.is_enabled

def test_ftp_server_is_not_enabled(host):
    vsftpd = host.service('vsftpd')
    assert not vsftpd.is_enabled

def test_dns_server_is_not_enabled(host):
    named = host.service('named')
    assert not named.is_enabled

def test_nfs_is_not_enabled(host):
    nfs = host.service('nfs-server')
    assert not nfs.is_enabled

def test_rpc_is_not_enabled(host):
    rpc = host.service('rpcbind')
    assert not rpc.is_enabled

def test_ldap_server_is_not_enabled(host):
    ldap = host.service('slapd')
    assert not ldap.is_enabled

def test_dhcp_server_is_not_enabled(host):
    dhcp = host.service('dhcpd')
    assert not dhcp.is_enabled

def test_cups_is_not_enabled(host):
    cups = host.service('cups')
    assert not cups.is_enabled

def test_nis_server_is_not_enabled(host):
    nis = host.service('ypserv')
    assert not nis.is_enabled

def test_nis_client_is_not_installed(host):
    nis = host.package('ypbind')
    assert not nis.is_installed

def test_telnet_client_is_not_installed(host):
    telnet = host.package('telnet')
    assert not telnet.is_installed

def test_ldap_client_is_not_installed(host):
    ldap = host.package('openldap-clients')
    assert not ldap.is_installed

def test_auditd_is_installed(host):
    auditd = host.package('auditd')
    auditdlibs = host.package('audit-libs')
    assert auditd.is_installed
    assert auditdlibs.is_installed

def test_auditd_is_enabled(host):
    auditd = host.service('auditd')
    assert auditd.is_enabled

def test_auditing_for_processes_prior_to_auditd_is_enabled(host):
    kaudit = host.check_output('grep -ow audit=1 /etc/default/grub /boot/grub2/grubenv /boot/efi/EFI/redhat/grubenv')
    assert 'audit=1' in kaudit

def test_audit_log_storage_size_is_configured(host):
    storage = host.check_output('grep -E "^max_log_file" /etc/audit/auditd.conf')
    assert storage != ''

def test_audit_are_not_automatically_deleted(host):
    delete = host.check_output('grep -E "^max_log_file_action" /etc/audit/auditd.conf')
    assert 'keep_logs' in delete

def test_audit_system_is_disabled_when_audit_logs_are_full(host):
    action = host.check_output('grep -E "^space_left_action" /etc/audit/auditd.conf')
    mail = host.check_output('grep -E "^action_mail_acct" /etc/audit/auditd.conf')
    admin = host.check_output('grep -E "^admin_space_left_action" /etc/audit/auditd.conf')
    assert 'email' in action
    assert 'root' in mail
    assert 'halt' in admin

def test_changes_to_system_administration_scope_is_collected(host):
    audit = host.check_output('auditctl -l | grep scope')
    assert audit != ''

def test_session_initiation_information_is_collected(host):
    audit = host.check_output('auditctl -l | grep -E "(session|logins)"')
    assert audit != ''

def test_events_that_modify_date_and_time_information_are_collected(host):
    audit = host.check_output('auditctl -l | grep time-change')
    assert audit != ''

def test_events_that_modify_mandatory_access_controls_are_collected(host):
    audit = host.check_output('auditctl -l | grep MAC-policy')
    assert audit != ''

def test_events_that_modify_system_network_environment_are_collected(host):
    audit = host.check_output('auditctl -l | grep system-locale')
    assert audit != ''

def test_discretionary_access_control_permission_modification_events_are_collected(host):
    audit = host.check_output('auditctl -l | grep perm_mod')
    assert audit != ''

def test_unsuccessful_unauthorized_file_access_attempts_are_collected(host):
    audit = host.check_output('auditctl -l | grep -E access')
    assert audit != ''

def test_events_that_modify_usergroup_information_are_collected(host):
    audit = host.check_output('auditctl -l | grep identity')
    assert audit != ''

def test_successful_file_system_mounts_are_collected(host):
    audit = host.check_output('auditctl -l | grep mounts')
    assert audit != ''

def test_file_deletion_events_by_users_are_collected(host):
    audit = host.check_output('auditctl -l | grep delete')
    assert audit != ''

def test_kernel_module_loading_and_unloading_is_collected(host):
    audit = host.check_output('auditctl -l | grep -E modules')
    assert audit != ''

def test_rsyslog_is_installed(host):
    rsyslog = host.package('rsyslog')
    assert rsyslog.is_installed

def test_rsyslog_is_enabled(host):
    rsyslog = host.service('rsyslog')
    assert rsyslog.is_enabled

def test_rsyslog_file_permissions_mode(host):
    file = host.check_output("grep -E '^\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    assert '0640' in file

def test_rsyslog_remote_log_host_config(host):
    send = host.check_output('grep "@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
    assert send != '' or send == ''

def test_remote_rsyslog_messages_only_accepted_on_designated_hosts(host):
    imtcp = host.check_output("grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    run = host.check_output("grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    assert '$ModLoad imtcp' in imtcp or imtcp == ''
    assert '$InputTCPServerRun' in run or run == ''

def test_journald_is_configured_to_send_logs_to_syslog(host):
    forward = host.check_output("grep -E '^ForwardToSyslog' /etc/systemd/journald.conf")
    assert 'ForwardToSyslog=yes' in forward

def test_journald_is_configured_to_compress_large_log_files(host):
    compress = host.check_output("grep -E '^Compress' /etc/systemd/journald.conf")
    assert 'Compress=yes' in compress

def test_journald_is_configured_to_write_logfiles_to_persistent_disk(host):
    storage = host.check_output("grep -E '^Storage' /etc/systemd/journald.conf")
    assert 'Storage=persistent' in storage

def test_permissions_on_all_logfiles_are_configured(host):
    log = host.check_output('find /var/log -type f -perm /037 -ls -o -type d -perm /026 -ls')
    assert log == ''

def test_logrotate_is_configured(host):
    logrotate = host.check_output("grep -E '^rotate' /etc/logrotate.conf /etc/logrotate.d/*")
    assert logrotate != ''