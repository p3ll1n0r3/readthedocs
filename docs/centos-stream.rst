centos stream installation
==========================

1) Select installation Language (English) :  Next

2) Localization, select Keyboard : 
Add Keyboard : Swedish
Set Swedish as top priority

3) Set Time&Date
Select timezone : Stockholm

4) Network & Hostname
Enable Network interface
Next (we will set up hostname etc after installation)

5) Software
Installation source : 

On the network
http://mirror.centos.org/centos/8/BaseOS/x86_64/os/
URL type : repository URL

Software selection : 
Minimal (without GUI)

6) Partitioning

/boot       xfs                             1 GB

rootvg:
lv_home     /home           xfs             4 GB
lv_tmp      /tmp            xfs             2 GB      noexec,nodev,nosuid
lv_var      /var            xfs             4 GB
lv_log      /var/log        xfs             4 GB
lv_audit    /var/log/audit  xfs             2 GB
lv_root     /               xfs             8 GB

