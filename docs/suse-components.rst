
1) Disk partitioning

TODO!

2) Filesystem flags

TODO!

3) Backup client (include/exclude)

TODO!

4) sudoers

TODO!

5) sshd config

TODO! 

6) Rsyslog conf + Logging (remote)

/etc/rsyslog.conf
---------------------------------
$template CustomizedTemplate,"%TIMESTAMP% <%syslogfacility-text%.%syslogseverity-text%> %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n" 
$FileCreateMode 0640

*.info                  /var/log/messages;CustomizedTemplate       	# Log all informational
*.emerg                 :omusrmsg:*                                 # Everybody gets emergency messages
*.none                  /var/log/other.log;CustomizedTemplate       # "none" logs to other.logs

auth.*                  /var/log/messages;CustomizedTemplate

authpriv.*              /var/log/secure;CustomizedTemplate              # The authpriv file has restricted access.

cron.*                  /var/log/cron;CustomizedTemplate                # Log cron stuff

daemon.*                /var/log/daemon.log;CustomizedTemplate

kern.*                  /var/log/kern.log;CustomizedTemplate

local0.*                /var/log/other.log;CustomizedTemplate
local1.*                /var/log/other.log;CustomizedTemplate
local2.*                /var/log/other.log;CustomizedTemplate
local3.*                /var/log/other.log;CustomizedTemplate
local4.*                /var/log/other.log;CustomizedTemplate
local5.*                /var/log/other.log;CustomizedTemplate
local6.*                /var/log/other.log;CustomizedTemplate
local7.*                /var/log/boot.log;CustomizedTemplate   		# Save boot messages also to boot.log

lpr.*                   /var/log/other.log;CustomizedTemplate

mail.*                  -/var/log/maillog;CustomizedTemplate           # Log all the mail messages in one place.

news.*                  /var/log/other.log;CustomizedTemplate
news.crit               /var/log/spooler;CustomizedTemplate            # Save news errors of level crit and higher in a special file.

syslog.*                /var/log/syslog;CustomizedTemplate

user.*                  /var/log/messages;CustomizedTemplate

uucp.*                  /var/log/other.log;CustomizedTemplate
uucp.crit               /var/log/spooler;CustomizedTemplate            # Save news errors of level crit and highe

for i in messages secure maillog cron spooler boot.log kern.log daemon.log syslog other.log; do
  touch /var/log/$i;
        chown root:root /var/log/$i;
        chmod og-rwx /var/log/$i;
done

# Remove this rule to avoid double logging for some info messages
# TODO : need additional tuning 
sed -i 's/^\(\*.info;mail.none;authpriv.none;cron.none.*\/var\/log\/messages\)/\n\# Commented as part of customization, see \/etc\/rsyslog.d\/99-customized.conf\n\#\1/g' /etc/rsyslog.conf


7) Monitoring

TODO !

8) Auditing

Below restricts auditd to overflow filesystem with 16 logs * 50 MB = 900 MB on a 1 GB filesystem
Cron job rotate daily gzip logfiles and rename logfiles based on timestamp.
Keeps 14 days of auditd log files
Expected size with compression = 100 MB of 1:9 compression ratio
Forwarding auditd logs to syslog :
  Install on CentOS  : yum install audispd-plugins , SLES : zypper install audisp-plugins
  Enable in /etc/audit/plugins.d/syslog # set active=yes    # CENTOS = /etc/audit/plugins.d/syslog , SLES = /etc/audisp/plugins.d/syslog.conf
  Reconfigure auditd : service auditd reload
  Send testmessage : auditctl -m "Hello World"
  Message should get to : /var/log/messages
TODO : Auditing Rules .... 


sed -i 's/^admin_space_left_action.*/admin_space_left_action = SYSLOG/g' /etc/audit/auditd.conf
sed -i 's/^disk_full_action.*/disk_full_action = SYSLOG/g' /etc/audit/auditd.conf
sed -i 's/^disk_error_action.*/disk_error_action = SYSLOG/g' /etc/audit/auditd.conf
sed -i 's/^num_logs.*/num_logs = 16/g' /etc/audit/auditd.conf
sed -i 's/^max_log_file .*/max_log_file = 50/g' /etc/audit/auditd.conf


/etc/audit/auditd.conf
--------------------------
#
# This file controls the configuration of the audit daemon (v3.0)
#
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
#max_log_file = 8
max_log_file = 50
num_logs = 16 
priority_boost = 4
name_format = NONE
##name = mydomain
#max_log_file_action = ROTATE
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
#admin_space_left_action = SUSPEND
admin_space_left_action = SYSLOG
#disk_full_action = SUSPEND
disk_full_action = SYSLOG
#disk_error_action = SUSPEND
disk_error_action = SYSLOG
use_libwrap = yes
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
transport = TCP
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
q_depth = 400
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d


/etc/cron.daily/auditd          # SLES does not support "rotate" as a command to auditd
--------------------------
#!/bin/bash
export PATH=/sbin:/bin:/usr/sbin:/usr/bin

FORMAT="%Y%m%d%T" # Customize timestamp format as desired, per `man date`
                  # %Y%m%d will lead to standard logrotationformat: audit.log.2020222.gz
                  # %F_%T will lead to files like: audit.log.2015-02-26_15:43:46
COMPRESS=gzip     # Change to bzip2 or xz as desired
KEEP=14           # Number of compressed log files to keep
ROTATE_TIME=5     # Amount of time in seconds to wait for auditd to rotate its logs. Adjust this as necessary

rename_and_compress_old_logs() {
    for file in $(find /var/log/audit/ -name 'audit.log.[0-9]'); do
        timestamp=$(ls -l --time-style="+${FORMAT}" ${file} | awk '{print $6}')
        newfile=${file%.[0-9]}.${timestamp}
        # Optional: remove "-v" verbose flag from next 2 lines to hide output
        mv -v ${file} ${newfile}
        ${COMPRESS} -v ${newfile}
    done
}

delete_old_compressed_logs() {
    # Optional: remove "-v" verbose flag to hide output
    rm -rfv $(find /var/log/audit/ -regextype posix-extended -regex '.*audit\.log\..*(xz|gz|bz2)$' | sort -n | head -n -${KEEP})
}

rename_and_compress_old_logs

# service auditd rotate         # Centos/RHEL 8
kill -USR1 $(pidof auditd)      # SLES 15.2

sleep $ROTATE_TIME
rename_and_compress_old_logs
delete_old_compressed_logs


9) System Activity Reporting

TODO !

10) standard packages installation / removal

TODO !

11) Log rotation rules

TODO on SLES 15...

/etc/logrotate.d/syslog
---------------------------------
/var/log/other.log
/var/log/syslog
/var/log/daemon.log
/var/log/kern.log
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    missingok
    sharedscripts
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}


/etc/logrotate.conf
---------------------------------
# see "man logrotate" for details
# rotate log files daily 
daily

# keep 14 days worth of backlogs
rotate 14

# create new (empty) log files after rotating old ones
create

# use yesterday date as a suffix of the rotated file
dateyesterday

# uncomment this if you want your log files compressed
compress

# RPM packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may be also be configured here.

12) Crony / Time syncing

TODO

13) Persistent Journald logs

mkdir /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
systemctl restart systemd-journald
sed -i 's/.*Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
sed -i 's/.*Compress=.*/Compress=yes/' /etc/systemd/journald.conf
sed -i 's/.*SystemMaxUse=.*/SystemMaxUse=2G/' /etc/systemd/journald.conf


/etc/systemd/journald.conf
----------------------------
[Journal]
Storage=auto
Compress=yes
#Seal=yes
#SplitMode=uid
#SyncIntervalSec=5m
#RateLimitIntervalSec=30s
#RateLimitBurst=1000
SystemMaxUse=2G
#SystemKeepFree=
#SystemMaxFileSize=
#SystemMaxFiles=100
#RuntimeMaxUse=
#RuntimeKeepFree=
#RuntimeMaxFileSize=
#RuntimeMaxFiles=100
#MaxRetentionSec=
#MaxFileSec=1month
#ForwardToSyslog=yes
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
#TTYPath=/dev/console
#MaxLevelStore=debug
#MaxLevelSyslog=debug
#MaxLevelKMsg=notice
#MaxLevelConsole=info
#MaxLevelWall=emerg


14) Collect daily System status and Information

Example to use : cfg2html, LinEnum
PreReq cfg2html : lsof psmisc bind-utils
TODO : test, crontab, archive, logrotate


15) File Permission from CIS

TODO !

