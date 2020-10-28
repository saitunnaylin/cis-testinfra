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
	nis = host.check_output ('rpm -q ypbind')
	assert nis == 'package ypbind is not installed'

def test_telnet_client_is_not_installed(host):
	telnet = host.check_output ('rpm -q telnet')
	assert telnet == 'package telnet is not installed'

def test_ldap_client_is_not_installed(host):
	ldap = host.check_output ('rpm -q openldap-clients')
	assert ldap == 'package openldap-clients is not installed'








