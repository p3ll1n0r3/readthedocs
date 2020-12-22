
1) Disk partitioning

2) Filesystem flags

3) Backup client (include/exclude)

4) sudoers

5) sshd config

6) Rsyslog conf + Logging (remote)

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

8) Auditing 

9) Crony / Time syncing



9) System Activity Reporting

10) standard packages installation / removal

11) Log rotation rules

