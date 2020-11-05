def test_cramfs_filesystems_is_disabled(host):
	cram1 = host.check_output ('modprobe -n -v cramfs')
	cram2 = host.check_output ('lsmod | grep cramfs')
	assert cram1 == 'install /bin/true'
	assert cram2 == '' 

def test_vfat_filesystems_is_limited(host):
	vfat1 = host.check_output ('grep -E -i vfat /etc/fstab')
	vfat2 = host.check_output ('modprobe -n -v vfat')
	vfat3 = host.check_output ('lsmod | grep vfat')
	assert vfat1 == ''
	assert vfat2 == 'install /bin/true'
	assert vfat3 == '' 

def test_squashfs_filesystems_is_disabled(host):
	squashfs1 = host.check_output ('modprobe -n -v squashfs')
	squashfs2 = host.check_output ('lsmod | grep squashfs')
	assert squashfs1 == 'install /bin/true'
	assert squashfs2 == '' 

def test_udf_filesystems_is_disabled(host):
	udf1 = host.check_output ('modprobe -n -v udf')
	udf2 = host.check_output ('lsmod | grep udf')
	assert udf1 == 'install /bin/true'
	assert udf2 == '' 

def test_tmp_partition_is_configured(host):
	tmp = host.check_output ('mount | grep -E /tmp')
	assert '/tmp' in tmp

def test_nodev_option_set_on_tmp_partition(host):
	tmp = host.check_output ('mount | grep -E /tmp | grep nodev')
	assert tmp == ''

def test_noexec_option_set_on_tmp_partition(host):
	tmp = host.check_output ('mount | grep -E /tmp | grep noexec')
	assert tmp == ''

def test_separate_var_partition_is_configured(host):
	var = host.check_output ('mount | grep -E /var')
	assert '/var' in var

def test_separate_vartmp_partition_is_configured(host):
	vartmp = host.check_output ('mount | grep -E /var/tmp')
	assert '/var/tmp' in vartmp

def test_nodev_option_set_on_vartmp_partition(host):
	vartmp = host.check_output ('mount | grep -E /var/tmp | grep nodev')
	assert vartmp == ''

def test_nosuid_option_set_on_vartmp_partition(host):
	vartmp = host.check_output ('mount | grep -E /var/tmp | grep nosuid')
	assert vartmp == ''

def test_noexec_option_set_on_vartmp_partition(host):
	vartmp = host.check_output ('mount | grep -E /var/tmp | grep noexec')
	assert vartmp == ''

def test_separate_varlog_partition_is_configured(host):
	varlog = host.check_output ('mount | grep -E /var/log')
	assert '/var/log' in varlog

def test_separate_varlogaudit_partition_is_configured(host):
	varlogaudit = host.check_output ('mount | grep -E /var/log/audit')
	assert '/var/log/audit' in varlogaudit

def test_separate_home_partition_is_configured(host):
	home = host.check_output ('mount | grep -E /home')
	assert '/home' in home

def test_nodev_option_set_on_home_partition(host):
	home = host.check_output ('mount | grep -E /home | grep nodev')
	assert home == ''

def test_nodev_option_set_on_devshm_partition(host):
	devshm = host.check_output ('mount | grep -E /dev/shm | grep nodev')
	assert devshm == ''

def test_nosuid_option_set_on_devshm_partition(host):
	devshm = host.check_output ('mount | grep -E /dev/shm | grep nosuid')
	assert devshm == ''

def test_noexec_option_set_on_devshm_partition(host):
	devshm = host.check_output ('mount | grep -E /dev/shm | grep noexec')
	assert devshm == ''

def test_nodev_option_set_on_removable_media_partition(host):
	cdrom = host.check_output ('mount | grep nodev')
	assert not 'cdrom' in cdrom
	assert not 'usb' in cdrom
	assert not 'floppy' in cdrom

def test_nosuid_option_set_on_removable_media_partition(host):
	cdrom = host.check_output ('mount | grep nosuid')
	assert not 'cdrom' in cdrom
	assert not 'usb' in cdrom
	assert not 'floppy' in cdrom

def test_noexec_option_set_on_removable_media_partition(host):
	cdrom = host.check_output ('mount | grep noexec')
	assert not 'cdrom' in cdrom
	assert not 'usb' in cdrom
	assert not 'floppy' in cdrom

def test_ensure_sticky_bit_is_set_on_world_writable_directory(host):
	cdrom = host.check_output ('mount | grep noexec')
	assert not 'cdrom' in cdrom
	assert not 'usb' in cdrom
	assert not 'floppy' in cdrom

def test_disable_Automounting(host):
	autofs = host.service ('autofs')
	assert not autofs.is_enabled

def test_disable_USB_storage(host):
	usb = host.check_output ('modprobe -n -v usb-storage')
	usb = host.check_output ('lsmod | grep usb-storage')
	assert cram1 == 'install /bin/true'
	assert cram2 == '' 

def test_xinetd_is_not_installed(host):
	xinetd = host.package ('xinetd')
	assert not xinetd.is_installed 

def test_time_chronization_is_in_used(host):
	chrony = host.package ('chrony')
	assert not chrony.is_installed 

def test_chrony_is_configured(host):
	chrony = host.check_output ('grep -E ^(server|pool) /etc/chrony.conf')
	assert '/var/tmp' in chrony

def test_x_window_system_is_not_installed(host):
	xwindow = host.check_output ('rpm -qa xorg-x11*')
	assert xwindow == ''

def test_rsync_is_not_enable(host):
	rsyncd = host.service ('rsyncd')
	assert not rsyncd.is_enabled

def test_avahi_is_not_enable(host):
	avahi = host.service ('avahi-daemon')
	assert not avahi.is_enabled

def test_snmp_server_is_not_enable(host):
	snmpd = host.service ('snmpd')
	assert not snmpd.is_enabled

def test_http_proxy_server_is_not_enable(host):
	squid = host.service ('squid')
	assert not squid.is_enabled

def test_samba_is_not_enable(host):
	smb = host.service ('smb')
	assert not smb.is_enabled

def test_imap_and_pop3_server_is_not_enable(host):
	dovecot = host.service ('dovecot')
	assert not dovecot.is_enabled

def test_http_server_is_not_enable(host):
	httpd = host.service ('httpd')
	assert not httpd.is_enabled

def test_ftp_server_is_not_enable(host):
	vsftpd = host.service ('vsftpd')
	assert not vsftpd.is_enabled

def test_dns_server_is_not_enable(host):
	named = host.service ('named')
	assert not named.is_enabled

def test_nfs_is_not_enable(host):
	nfs = host.service ('nfs')
	assert not nfs.is_enabled

def test_rpc_is_not_enable(host):
	rpc = host.service ('rpcbind')
	assert not rpc.is_enabled

def test_ldap_server_is_not_enable(host):
	ldap = host.service ('slapd')
	assert not ldap.is_enabled

def test_dhcp_server_is_not_enable(host):
	dhcp = host.service ('dhcpd')
	assert not dhcp.is_enabled

def test_cpus_is_not_enable(host):
	cpus = host.service ('cpus')
	assert not cups.is_enabled

def test_nis_server_is_not_enable(host):
	nis = host.service ('ypserv')
	assert not nis.is_enabled

def test_nis_client_is_not_installed(host):
	nis = host.package ('ypbind')
	assert not nis.is_installed 

def test_telnet_client_is_not_installed(host):
	telnet = host.package ('telnet')
	assert not telnet.is_installed 

def test_ldap_client_is_not_installed(host):
	ldap = host.package ('openldap-clients')
	assert not ldap.is_installed 

def test_auditd_is_installed(host):
	auditd = host.package ('auditd')
	auditdlibs = host.package ('auditd-libs')
	assert auditd.is_installed 
	assert auditdlibs.is_installed 

def test_auditd_is_enable(host):
	auditd = host.service ('auditd')
	assert auditd.is_enabled

def test_auditing_for_processes_that_start_prior_to_auditd_is_enabled(host):
	kaudit = host.check_output ('grep -ow audit=1 /boot/grub2/grubenv')
	assert kaudit == ''

def test_audit_log_storage_size_is_configured(host):
	storage = host.check_output ('grep max_log_file /etc/audit/auditd.conf')
	assert not storage == ''

def test_audit_are_not_automatically_deleted(host):
	delete = host.check_output ('grep max_log_file_action /etc/audit/auditd.conf')
	assert delete == 'keep_logs'

def test_audit_system_is_disabled_when_audit_logs_are_full(host):
	action = host.check_output ('grep space_left_action /etc/audit/auditd.conf')
	mail = host.check_output ('grep action_mail_acct /etc/audit/auditd.conf')
	admin = host.check_output ('grep admin_space_left_action /etc/audit/auditd.conf')
	assert action == 'email'
	assert mail == 'root'
	assert admin == 'halt'

def test_changes_to_system_administration_scope_is_collected(host):
	rule = host.check_output ('grep scope /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep scope')
	assert audit in rule

def test_session_initiation_information_is_collected(host):
	rule = host.check_output ('grep -E "(session|logins)" /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep -E "(session|logins)"')
	assert audit in rule

def test_events_that_modify_date_and_time_infrmation_are_collected(host):
	rule = host.check_output ('grep time-change /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep time-change')
	assert audit in rule

def test_events_that_modify_the_system_Mandatory_Access_controls_are_collected(host):
	rule = host.check_output ('grep MAC-policy /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep MAC-policy')
	assert audit in rule

def test_events_that_modify_the_system_network_environment_are_collected(host):
	rule = host.check_output ('grep system-locale /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep system-locale')
	assert audit in rule

def test_discretionary_access_control_permission_modification_events_are_collected(host):
	rule = host.check_output ('grep perm_mod /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep perm_mod')
	assert audit in rule

def test_unsuccessful_unauthorized_file_access_attempts_are_collected(host):
	rule = host.check_output ('grep access /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep -E access')
	assert audit in rule

def test_events_that_modify_usergroup_information_are_collected(host):
	rule = host.check_output ('grep identity /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep identity')
	assert audit in rule

def test_successful_file_system_mounts_are_collected(host):
	rule = host.check_output ('grep mounts /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep mounts')
	assert audit in rule

def test_file_deletion_events_by_users_are_collected(host):
	rule = host.check_output ('grep delete /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep delete')
	assert audit in rule

def test_kernel_module_loading_and_unloading_is_collected(host):
	rule = host.check_output ('grep modules /etc/audit/rules.d/*.rules')
	audit = host.check_output ('auditctl -l | grep -E modules')
	assert audit in rule

def test_rsyslog_is_installed(host):
	rsyslog = host.package ('rsyslog')
	assert rsyslog.is_installed 

def test_nis_syslog_is_enable(host):
	rsyslog = host.service ('rsyslog')
	assert rsyslog.is_enabled

def test_kernel_module_loading_and_unloading_is_collected(host):
	file = host.check_output ("grep FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf | awk '{print $2}' ")
	assert file <= '0640'

def test_rsyslog_is_configured_to_send_logs_to_a_remote_log_host(host):
	send = host.check_output ('grep "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf')
	assert send == ''

def test_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts(host):
	imtcp = host.check_output ("grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
	run = host.check_output ("grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
	assert imtcp == '$ModLoad imtcp'
	assert run == '$InputTCPServerRun 514'

def test_journald_is_configured_to_send_logs_to_a_remote_log_host(host):
	forward = host.check_output ('grep ForwardToSyslog /etc/systemd/journald.conf')
	assert forward == 'ForwardToSyslog=yes'

def test_journald_is_configured_to_compress_large_log_files(host):
	compress = host.check_output ('grep Compress /etc/systemd/journald.conf')
	assert compress == 'Compress=yes'

def test_journald_is_configured_to_write_logfiles_to_persistent_disk(host):
	storage = host.check_output ('grep Storage /etc/systemd/journald.conf')
	assert compress == 'Storage=persistent'

def test_permissions_on_all_logfiles_are_configured(host):
	log = host.check_output ('find /var/log -type f -perm /037 -ls -o -type d -perm /026 -ls')
	assert log == ''

def test_logrotate_is_configured(host):
	logrotate = host.check_output ('grep ^rotate /etc/logrotate.conf /etc/logrotate.d/*')
	assert not logrotate == ''
