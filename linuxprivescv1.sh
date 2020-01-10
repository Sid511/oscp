#!/bin/sh

echo "#####################################################"
echo "Printing file containing password or secret or passwd"
echo "#####################################################"

find /home -type f -readable  2> /dev/null | xargs egrep -lin "user|username|login|pass|password|pw|credential|cred|secret" 

echo "#####################################################"
echo "Credentials file in /etc/fstab"
echo "#####################################################"

grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null

echo "#####################################################"
echo "Checking readable mail"
echo "#####################################################"

find /var/mail/ -type f -readable 2> /dev/null

echo "#####################################################"
echo "Old passwords"
echo "#####################################################"

cat /etc/security/opasswd 2> /dev/null


echo "#####################################################"
echo "Last 10 min file edited"
echo "#####################################################"

find / -mmin -10 ! -path "/sys/*" -readable 2>/dev/null  | grep -Ev "^/proc"


echo "#####################################################"
echo "Others root users"
echo "#####################################################"

for u in $(cat /etc/passwd | cut -d: -f1 | grep -v root ); do if [ $(id -u $u) == 0 ] ; then echo $u; fi; done 

echo "#####################################################"
echo "Available shells"
echo "#####################################################"

cat /etc/shells 2> /dev/null

echo "#####################################################"
echo "Root readable files"
echo "#####################################################"

find /root -type f 2> /dev/null 

echo "#####################################################"
echo "/home readable files"
echo "#####################################################"

find /home -type f 2> /dev/null 


echo "#####################################################"
echo "In memory passwords"
echo "#####################################################"

strings /dev/mem -n10  2> /dev/null| grep -i PASS

echo "#####################################################"
echo "Writable files"
echo "#####################################################"

echo "In /etc/"
find /etc/ -writable -type f 2> /dev/null

echo "In others directories"

find / -writable ! -user $(whoami) -type f ! -path "/proc/*"  ! -path "/etc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null


echo "#####################################################"
echo "Writable file not by current user"
echo "#####################################################"


find / -writable ! -user $(whoami) -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null

echo "#####################################################"
echo "Checking hash in /etc/passwd"
echo "#####################################################"

grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null


echo "#####################################################"
echo "Non root process"
echo "#####################################################"

ps -eo comm | sort | uniq | xargs which |   xargs -n1 ls -l | grep -v root

echo "#####################################################"
echo "cron job readable"
echo "#####################################################"


find -L /etc/cron* /etc/anacron* /var/spool/cron -readable 2> /dev/null

echo "#####################################################"
echo "cron job writable"
echo "#####################################################"


find -L /etc/cron* /etc/anacron* /var/spool/cron -writable 2> /dev/null


echo "#####################################################"
echo "Sudo (List of suid program is stored in suid_program.txt more find https://gtfobins.github.io/"
echo "#####################################################"


sudo -l

#echo "apt apt-get aria2c arp ash awk base64 bash busybox cancel cat chmod chown cp cpan cpulimit crontab csh curl cut dash date dd diff dmesg dmsetup dnf docker dpkg easy_install ed emacs env expand expect facter file find finger flock fmt fold ftp gawk gdb gimp git grep head iftop ionice ip irb jjs journalctl jq jrunscript ksh ldconfig ld.so less logsave ltrace lua mail make man mawk more mount mtr mv mysql nano nawk nc nice nl nmap node od openssl perl pg php pic pico pip puppet python readelf red rlogin rlwrap rpm rpmquery rsync ruby run-mailcap run-parts rvim scp screen script sed service setarch sftp shuf smbclient socat sort sqlite3 ssh start-stop-daemon stdbuf strace systemctl tail tar taskset tclsh tcpdump tee telnet tftp time timeout tmux ul unexpand uniq unshare vi vim watch wget whois wish xargs xxd yum zip zsh zypper" > /tmp/sudo_list.txt


echo "#####################################################"
echo "System Timer"
echo "#####################################################"

type -a time
systemctl list-timers --all


echo "#####################################################"
echo "All SUID"
echo "#####################################################"

find / -uid 0 -perm -4000 -type f 2>/dev/null
echo "#####################################################"
echo "Uncommon SUID"
echo "#####################################################"

echo "/bin/fusermount
/bin/mount
/bin/ntfs-3g
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/lib64/dbus-1/dbus-daemon-launch-helper
/sbin/mount.ecryptfs_private
/sbin/mount.nfs
/sbin/pam_timestamp_check
/sbin/pccardctl
/sbin/unix2_chkpwd
/sbin/unix_chkpwd
/usr/bin/Xorg
/usr/bin/arping
/usr/bin/at
/usr/bin/beep
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/firejail
/usr/bin/fusermount
/usr/bin/fusermount-glusterfs
/usr/bin/gpasswd
/usr/bin/kismet_capture
/usr/bin/mount
/usr/bin/mtr
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/procmail
/usr/bin/staprun
/usr/bin/su
/usr/bin/sudo
/usr/bin/sudoedit
/usr/bin/traceroute6.iputils
/usr/bin/umount
/usr/bin/weston-launch
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/dbus-1/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/pt_chown
/usr/lib/snapd/snap-confine
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/xorg/Xorg.wrap
/usr/libexec/Xorg.wrap
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/gstreamer-1.0/gst-ptp-helper
/usr/libexec/openssh/ssh-keysign
/usr/libexec/polkit-1/polkit-agent-helper-1
/usr/libexec/pt_chown
/usr/libexec/qemu-bridge-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/sbin/exim4
/usr/sbin/grub2-set-bootflag
/usr/sbin/mount.nfs
/usr/sbin/mtr-packet
/usr/sbin/pam_timestamp_check
/usr/sbin/pppd
/usr/sbin/pppoe-wrapper
/usr/sbin/suexec
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/usernetctl
/usr/sbin/uuidd" > /tmp/common_suid

find / -uid 0 -perm -4000 -type f 2>/dev/null > /tmp/uncommon_suid_file

for i in  $(cat /tmp/uncommon_suid_file)
do 
        if ! $(grep -Fxq $i /tmp/common_suid) ; then
                echo $i
        fi
done

rm /tmp/uncommon_suid_file
rm /tmp/common_suid


echo "#####################################################"
echo "Find LD_PRELOAD"
echo "#####################################################"


cat /etc/sudoers | grep -i "LD_PRELOAD "

echo "#####################################################"
echo "Capabilities: Look for cap_dac_read_search or ep"
echo "#####################################################"

getcap -r / 2> /dev/null

echo "#####################################################"
echo "Checking no_root_squash in /etc/exports"
echo "#####################################################"

cat /etc/exports | grep -i "no_root_squash"

echo "#####################################################"
echo "Checking docker user"
echo "#####################################################"

cat /etc/passwd | grep docker

echo "#####################################################"
echo "Checking lxd user"
echo "#####################################################"

cat /etc/passwd | grep "lxc\|lxd"

echo "#####################################################"
echo "Checking Mysql with root and no pass credential"
echo "#####################################################"
mysqladmin -uroot version

echo "#####################################################"
echo "Checking Mysql with root/root and no pass credential"
echo "#####################################################"
mysqladmin -uroot -proot version

echo "#####################################################"
echo "Checking PostgreSql template0 as postgres and no pass"
echo "#####################################################"
psql -U postgres template0 -c "select version()" | grep version

echo "#####################################################"
echo "Checking PostgreSql template1 as postgres and no pass"
echo "#####################################################"
psql -U postgres template1 -c "select version()" | grep version

echo "#####################################################"
echo "Checking PostgreSql  template0 as psql and no pass"
echo "#####################################################"
psql -U pgsql template0 -c "select version()" | grep version

echo "#####################################################"
echo "Checking PostgreSql template1 as psql and no pass"
echo "#####################################################"
psql -U pgsql template1 -c "select version()" | grep version


echo "#####################################################"
echo "Echo user with shell"
echo "#####################################################"
grep -E "sh$" /etc/passwd

echo "#####################################################"
echo "Try su with default pass"
echo "#####################################################"
for i in $(grep -E "home" /etc/passwd | cut -d: -f1 ); do echo $i; su - $i -c id; done; 

echo "#####################################################"
echo "Check if root permitted to login via ssh"
echo "#####################################################"

grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"

echo "#####################################################"
echo "Last log user"
echo "#####################################################"
lastlog 2>/dev/null |grep -v "Never" 2>/dev/null



echo "#####################################################"
echo "Echo system info"
echo "#####################################################"

lse_arch="`uname -m`"
lse_linux="`uname -r`"
lse_hostname="`hostname`"
lse_distro=`command -v lsb_release >/dev/null 2>&1 && lsb_release -d | sed 's/Description:\s*//' 2>/dev/null`
[ -z "$lse_distro" ] && lse_distro="`(source /etc/os-release && echo "$PRETTY_NAME")2>/dev/null`"

echo "Architecture $lse_arch"
echo "Linux $lse_linux"
echo "Distibution $lse_distro"
echo "Hostname $lse_hostname"


echo "#####################################################"
echo "Listing installed compilers"
echo "#####################################################"

dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null

echo "Try linux suggester if nothing found"