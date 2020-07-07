Linux Commands
==============

.. |br| raw:: html

    <br>

		
=============== ======================================= ===========================================================
command         usage					syntax				
=============== ======================================= ===========================================================
audit2why       why is SELinux denied |br|              audit2why -i /var/log/audit/audit.log |br|
                  					grep 1573441241.893:21782 /var/log/audit/audit.log \| audit2why |br|
 
awk             pattern scanning and processing		ps aux \| awk '{ print $2 }' |br| 
 		language |br|

base64          base64 encode/decode |br|		echo "Hello World" \| base64 |br|
							echo "SGVsbG8gV29ybGQK" \| base64 -d |br|
							base64 -d encoded_b64.txt |br|
blkid           locate/print block device attributes
 		(requires sudo) |br|

cat             print content of file |br|		cat /etc/passwd |br|
							
chage           change/view aging rules for		chage -l jsnow |br| 
		userid |br|

chcon           change SE Linux labeling |br|		chcon -t samba_share_t /common |br|

chgrp           change group owner			chgrp team secret.txt |br| 
 		of file/directory |br|

chmod           change file permissions |br|		chmod +x file.sh |br|
							chmod u+x file.sh |br|
							chmod g+x file.sh |br|
							chmod o-rxw file.sh |br|
                  					chmod 0770 /sales			# all group members can add/delete from folder, can read/delete but not write to other's files |br|
                  					chmod 1770 /sales			# all group members can add/delete from folder, but only owner can delete its own files |br|
                  					chmod 2770 /sales			# all group members can add/delete from folder, read/write other's files |br|
                  					chmod 3770 /sales			# all group members can add/delete from folder, only owner can delete its own files  |br|
                  					chmod ug+rwxs /sales |br|

chown           change file owner |br|			chown root:root file.sh |br|
                 					chown -R root:root /root/secret |br|

chvt          	change virtual console |br|		chvt 2 |br|

crontab       	edit / view crontabs |br|		crontab -e |br|
              						crontab -el jsnow |br|
              						crontab -eu jsnow |br|

cryptsetup    	Setup and manager LUKS devices |br|	cryptsetup luksFormat -v -s 512 -h sha512 /dev/sda2 |br|
              						cryptsetup open /dev/sda2 luks_lvm |br|
	              					cryptsetup luksChangeKey <target device> -S <target key slot number> |br|
              						cryptsetup luksDump /dev/sda2 |br|
              						cryptsetup luksAddKey --key-slot 1 /dev/sda2 |br|
              						cryptsetup luksRemoveKey /dev/sda2 |br|

curl          	get data from url |br|			curl -Ok https://www.google.com |br|
              						curl --insecure  -L -v -s -o /dev/null https://www.google.com/ |br|

cut           	cut part of file |br|			cut -f 1 cities.txt |br|
              						cut -f 1 -d : /etc/passwd |br|

date          	print date |br|				date -d "+1month" |br|
              						date '+%Y%m%d-%H:%M' |br|

diff          	Produce a differenct between		diff /etc /backup/etc |br| 
		files/directories |br|			diff <(ls -a) <(ls -A)                # Difference of output between two ls commands |br|
            
dig           	dns lookup |br|				dig +dnssec +multi @8.8.8.8.8 www.google.com |br|
              						dig +short www.dn.se |br|
              						dig -x 2.18.74.134 |br|
              						dig @8.8.8.8 www.dn.se |br|
              						dig www.google.com SOA |br|

dd            	convert and copy a file (usually 	dd if=pfSense-CE-memstick-2.3.5-RELEASE-amd64.img of=/dev/sdb bs=1M |br|
		write to/from cdrom/iso/usb |br|	dd status=progress if=/dev/vda | ssh 172.16.11.10 dd of=/dev/vda |br|

df            	display filesystems |br|		df -h |br|

dmsetup       	Manage dm disks |br|			dmsetup info /dev/dm-5 |br|

drill         	nslookup dnssec |br|           		drill -DT www.google.com |br|

du            	files/directories size calculation |br|	du -sh * |br|
              						du -a \| sort -n -r \| head -n 5  |br|

egrep         	grep with regexp |br|              	egrep -v "^$\|^#" /etc/ssh/sshd_config |br|

grep            find string in file(s) |br|		grep -i 'DaRliNg' document.txt |br|
                  					grep 'Hello world' document.txt |br|
                  					grep -v ^root /etc/passwd |br|
 
sha1sum         calculate hash checksum |br|  
sha224sum       calculate hash checksum |br|
sha256sum       calculate hash checksum |br|
sha384sum       calculate hash checksum |br|
sha512sum       calculate hash checksum |br|		sha256sum /iso/archlinux.iso |br|
                					sha256sum *.tar > sha256sum.txt |br|
                					sha256sum -c sha256sum.txt |br|

ssh             secure shell connection |br|		ssh jsnow@secret.org |br|
                					ssh -vvv -i ~/.ssh/id_rsa jsnow@secret.org |br|
                					ssh -Xa jsnow@secret.org |br|
                  					ssh -p 2022 secret.org |br|
                  					ssh -Q {cipher|mac|kex} secret.org |br|
wget            get noninteractive network		wget http://www.google.com |br| 
		download |br|				wget -O save-as-helloworld.txt http://wwww.getfile.com/index.html |br|
                                    			wget --no-check-certificate https://site-without-signed-certificate.com/ |br|
=============== ======================================= ===========================================================
 

audit2allow   create an SELinux allow rule |br|
              grep 1573441241.893:21782 /var/log/audit/audit.log |audit2why



fallocate     preallocate a file
              fallocate-l 20MB helloworld

file          identify fileformat

find          find files
              find / -name *.log
              find / -user jsnow -exec cp -rfp {} /root/filesfound/ \;

firewall-cmd  firewalld managemant rules/zones
              firewall-cmd --list-all
              firewall-cmd --reload
              firewall-cmd --permanent --add-masquerade
              firewall-cmd --permanent --add-service={http,https}
              firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,464/tcp,53/tcp,88/udp,464/udp,53/udp,123/udp}
              firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.0.0/24 destination address=192.168.0.10/32 port port=22 protocol=tcp accept'
              firewall-cmd --permanent --list-rich-rules
              firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address=10.0.0.0/24 destination address=192.168.0.10/32 port port=22 protocol=tcp accept'
              firewall-cmd --permanent --zone=testing --add-rich-rule='rule family=ipv4 source address=192.168.0.10/24 reject'
              firewall-cmd --permanent --add-rich-rule='rule service name=ssh limit value=10/m accept'
              firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.0.0/24" service name="ssh" log prefix="ssh" level="info" limit value="50/m" accept'
              firewall-cmd --permanent --add-rich-rule 'rule family=ipv4 source address=192.168.0.0/24 forward-port=513 protocol=tcp to-port=132'
              firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport 9000 -j ACCEPT
              firewall-cmd --direct --get-all-rules

fc-list       list available fonts

fc-match      match available fonts
              fc-match monospace           # List what is declared as monospace font

free          available memory
              free -m
              free -h

getfacl       list file access list

getsebool     get SELinux boolean values
              getsebool -a

git           Distributed version control system.
              git --version
              git config --global user.name "BiBadWolf"
              git config --global user.email "bigbadwolf@hellden.se"
              git config --list
              git clone https://github.com/polygamma/aurman
              git clone https://github.com/polygamma/aurman aurman2
              git pull
              git status
              git add -A
              git status
              git commit -m "Updated file X"
              git push
              git init
              git add .Xresources
              git status
              git user.name p3ll1n0r3
              git commit -m "My first commit"
              git remote add origin https://github.com/p3ll1n0r3/dotfiles
              git push --mirror

grep          find string in file(s)
              cat /etc/passwd | grep jsnow
              grep -i linux *.txt
              grep -v ^#  /etc/ssh/sshd_config | grep .
              grep -B3 -A3 error /var/log/messages
              grep -v ^$ /etc/ssh/sshd_config

grubby        update boot parameters kernels
              grubby –update-kernel=ALL –args=”console=ttyS0″

head          show the first n lines in a file
              head -100 /var/log/messages

hostnamectl   set hostname for system
              hostnamectl set-hostname mycentos.example.com

httpd         apache web server
              httpd -t

ip            manipulate runtime ip configuration
              ip addr help
              ip route help
              ip link help
              ip a
              ip r
              ip -s link
              ip addr add 172.16.11.10 dev ens3
              ip route add 172.16.11.0/24 dev ens3
              ip route add default via 172.16.11.1 dev ens3
              ip route add 192.0.2.1/24 via 10.0.0.1 dev eth0

iscsiadm      iscsi initiator admin
              iscsiadm -m discovery -t st -p 192.168.1.75
              iscsiadm -m node T iqn.2015-02.se.hellden:system1 -p 192.168.1.75:3260 -l

journalctl    view system logs on systemd installation
              journalctl -f
              journalctl -b
              journalctl _PID=1
              journalctl --list-boots
              journalctl -u sshd.service
              journalctl -p err..emerg
              journalctl -u sshd.service -o json
              journalctl -u sshd.service -o json-pretty
              journalctl -u sshd.service -o verbose

ln            create links
              ln /etc/hosts computers
              ln -s /etc/hosts computers

localectl     set and view locale settings
              localectl list-keymaps
              localectl list-locales
              localectl set-keymap sv-latin1
              localectl set-locale LANG="en_US.utf8"

locate        find files in database

ls            list files/directories
              ls -latr
              ls -lah
              ls -d [!a-f]*
              ls -il *

lsblk         list block devices

lshw          list hardware

lscpu         list cpu info

lslocks       list system locks

lsmem         list memory

lsmod         list status current loaded modules

lsof          list open files
              lsof -p 616
              lsof /dev/sda2
              lsof /var/log/locked-logfile.log

lspci         list pci devices

lsscsi        list scsi devices

lsusb         list usb devices

lvcreate      create logical volume
              lvcreate -L 100GB -n backup rootvg
              lvcreate -l 100 -n lv_100extends rootvg
              lvcreate -l 100%FREE -n lv_100procent_available rootvg

lvdisplay	  list logical volumes with details

lvextend 	  logical volume extend
              lvextend -size 200M -r /dev/vg/lv_xfs
              lvextend -L +100M -r /dev/mapper/rootvg-root-100MB-lv
              lvextend -l 50 -r /dev/mapper/rootvg-my50extend-lv
              lvextend -l 100%FREE -r /dev/mapper/rootvg-home-rest-of-available-space-in-vg

lvmdiskscan   list devices that may be used as physical volumes

lvs			  list logical volumes

md5sum        calculate md5 checksum
              md5sum /iso/archlinux.iso

mkswap        create a swap partition
              makeswap /dev/vg/lv_swap2

man           man pages
              man nmcli-examples
              man teamd.conf
              man 5 firewalld.richlanguages
              man 7 signal
              man -k passwd 

mkdir         make directory
              mkdir /var/log/httpd
              mkdir -p /srv

mount         mount filesystem
              mount -a
              mount /www
              mount /dev/cdrom /mnt
              mount -o rw /srv/virtualmachines

nft           allows configuration of tables, chains and rules provided by the Linux kernel firewall.
              nft add table inet filter                             Add a new table with family "inet" and table "filter"
              nft add chain inet filter INPUT { type filter hook input 
                priority 0 \; policy accept \; }                     Add a new chain to accept all inbound traffic
              nft add rule inet filter INPUT tcp dport \{ ssh, http, 
                https\ } accept                                      Add a new rule to accept several TCP ports
              nft add rule inet filter INPUT drop                   Rule drop everything else
              nft list ruleset                                      View current configuration
              nft --handlr --numeric list chain                     Show rule handles
              nft delete rult inet filter  input handle 3           Delete a rule
              nft list ruleset > /etc/nftables.conf                 Save current configuration

nmcli         network manager CLI
              nmcli con show
              nmcli dev show
              nmcli con up TYR --ask
              nmcli con add con-name eth0 ifname eth0 type ethernet ip4 192.168.1.22/24 gw4 192.168.1.1
              nmcli con mod eth0 ipv4.dns 192.168.1.1
              nmcli con up eth0
              nmcli con add type team con-name team0 ifname team0 config '{ "runner": {"name":"activebackup"}}'
              nmcli con add type team-slave con-name team0-slave1 ifname eth0 master team0
              nmcli con add type team-slave con-name team0-slave2 ifname eth1 master team0
              nmcli con mod team0 config '{ "runner": {"name":"activebackup"}}'
              nmcli con add type team-slave ifname eno1 master team0
              nmcli con add type team-slave ifname eno2 master team0
              nmcli con mod team0 ipv4.addresses 10.52.220.72/26
              nmcli con mod team0 ipv4.gateway 10.52.220.65nm
              nmcli con mod team0 ipv4.method manual
              nmcli con mod team0 ipv4.dns 10.52.147.36
              nmcli con mod team0 +ipv4.dns 10.52.147.56
              nmcli con up team-slave-eno1
              nmcli con up team-slave-eno2
              nmcli con show team0
              nmcli con mod "enp0s3" ipv4.addresses '192.168.1.77/24 192.168.1.1' ipv4.dns 192.168.1.1 ipv4.method manual
              nmcli con mod "enp0s3" ipv6.addresses 'FDDB:FE2A:AB1E::C0A8:1/64' ipv6.method manual
              nmcli con reload
              nmcli dev wifi list
              nmcli dev wifi connect SSID password SSID_PASSWORD
              nmcli -p -f general,wifi-properties device show wlp3s0 
              nmcli general permissions
              nmcli general logging
              nmcli con delete uuid d49f78de-68d2-412d-80bc-0e238d380b8e

nmap          network / open ports scanner/mapper
              nmap -sV -p 22 localhost

nmtui         network manager text menu

osinfo-query  qemu-kvm tool identify correct identifier
              osinfo-query os

openssl       create / manipulate and get certificates
              openssl s_client -connect www.google.com:443 -showcerts < /dev/null 2> /dev/null |openssl x509 -outform PEM

passwd        set password for user
              passwd jsnow
              passwd -e 90 jsnow
              passwd -u
              passwd -L ?

pip           python module installer
              pip install -r requirements.txt
              pip install {package-name}
              pip install git+https://github.com/Gallopsled/pwntools.git@dev

pkaction      manage polkit actions
              pkaction --action-id org.freedesktop.NetworkManager.reload --verbose

ps            process viewer
              ps -ef
              ps fax
              ps aux | awk '{ print $2 }'

pvcreate      create lvm physical volume
              pvcreate /dev/sda1

pvdisplay     list physical volumes details

pvs           show physical volumes

pwd           print working directory

python        python programming language
              python -m venv django-project
              python -c 'import time;print(time.ctime(1565920843.452))'
			
renice        set new nice value for process
              renice -n -10 -p 1519
              renice +10 1519

repoquery     query package at repository
              repoquery -ql bind-utils

restorecon    restore SElinux labeling on files
              restorecon -R /xfs

rkhunter      root kit hunter
              rkhunter --update
              rkhunter --propugd
              rkhunter --check -sk

rm            remove files/directories
              rm -rf etcbackup.tar
              find . -inum 210666 -exec rm -i {} \;           # delete file with inodenummer

rpm           manage rpm packages
              rpm -qa
              rpm -qc chrony
              rpm -qf /etc/passwd
              rpm -qd chrony
              rpm -ql setup
              rpm -q --scripts setup

rsync         sync and copy tool
              rsync -aAXvS --info=progress2 --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found/*","/backup/*"} / /backup

sar           collect, report, or save system activity information
              sar -A

scp           secure copy files
              scp e603500@ix1-jmp03.ad.dcinf.se:~/test.sh .
              scp -P 2022 secret.txt michael@remote-server.com:/~

sed           string editor
              sed -Ei.bak '/^\s*(#|$)/d' /etc/sshd/sshd_config
              sed -n /^root/p /etc/passwd
              sed -i 's/linda/juliet/g' /etc/passwd

semanage      SELinux set labelling on functions/files/directories
              semanage fcontext -a -t user_home_dir_t "/xfs(/.*)?"
              semanage port -a -t http_port_t -p tcp 8999
              semanage port -d -t http_port_t -p tcp 
              semanage port -l
              semanage port -lC
              semanage permissive -l

setfacl       set file access list
              setfacl -R -m u:david:rwx /home/jsnow
              setfacl -m d:g:sales:rx /account
              setfacl -m d:g:david::- /account ????

setsebool	    set SELinux boolean value
              setsebool -P httpd_use_nfs on
              setsebool -P named_write_master_zones on

sha1sum
sha256sum
sha512sum     calculate checksum of file
              sha256sum /iso/archlinux.iso
              sha25sum *.iso > sha256sum.txt
              sha256sum -c sha256sum.txt

smbpasswd     set samba user password
              smbpasswd -a robby

socat         multipurpose relay (SOcket CAT
              exec socat tcp-connect:192.168.1.100:2604 file:`tty`,raw,echo=0

sort          sort input
              sort -n
              sort -f

# ssh           secure shell connection
#               ssh jsnow@ix1-jmp03.ad.dcinf.se
#               ssh -vvv -i ~/.ssh/id_rsa jsnow@ix1-jmp03.ad.dcinf.se
#               ssh -Xa jsnow@ix1-jmp03.ad.dcinf.se
#               ssh -p 2022 delta-echo.example.com
#               ssh -Q {cipher|mac|kex} server

sshfs         filesystem client based on ssh
              sshfs jsnow@10.1.1.1:/ /mnt

ssh-agent     start a ssh-agent
              ssh-agent -s

ssh-add       add a key to the ssh-agent
              ssh-add ~/.ssh/id_rsa

ssh-keygen    generate  SSH keypair (if copy/paste a key to Windows , save as UTF-8, NOT unicode)
              ssh-keygen -b 4096 -t rsa

ssh-copy-id   copy ssh key to server for user
              ssh-copy-id remote-server
              ssh-copy-id -p 2022 -i ~/.ssh/id_rsa.pub user@remote-server

sudo          run program as superuser
              sudo systemctl restart nginx.service
              sudo -i

swapoff       turn off swap on filesystem
              swapoff /dev/mapper/rootvg-swap

swapon        turn on swap on filesystem
              swapon -a
              swapon /dev/mapper/rootvg-swap

systemctl     systemd control
              systemctl list-unit-files --state=enabled
              systemctl list-timers
              systemctl -t help
              systemctl enable --now libvirtd
              systemctl disable libvirtd
              systemctl start libvirtd.service
              systemctl stop libvirtd.service
              systemctl mask sshd.service
              systemctl unmask sshd.service
              systemctl list-dependencies sshd.service
              systemctl is-enabled libvirtd.service
              systemctl get-default
              systemctl set-default graphical.target
              systemctl isolate multi-user.target
              systemctl --failed

tar           manage tarballs
              tar -xvf microcode-20180108.tgz -C /tmp
              tar -cf etcbackup.tar /etc/*
              tar -cvzf /tmp/tar.tgz /usr/local
              tar -tvf etc.tgz 
              tar -xvf etc.tgz -C / etc/hosts

targetcli     manage and setup iscsi targets
              targetcli /backstores/block create block1 /dev/iscsi_storage/iscsi_storage_lv                   
              targetcli /iscsi create iqn.2015-02.se.hellden:system1
              targetcli /iscsi/iqn.2015-02.se.hellden:system1/tpg1/acls create iqn.2015-02.se.hellden:system2
              targetcli /iscsi/iqn.2015-02.se.hellden:system1/tpg1/luns create /backstores/block/block1       
              targetcli /iscsi/iqn.2015-02.se.hellden:system1/tpg1/portals delete 0.0.0.0 3260
              targetcli /iscsi/iqn.2015-02.se.hellden:system1/tpg1/portals create 192.168.1.75 3260
              targetcli saveconfig

tail          display the last n lines in a file
              tail -200 /var/log/messages
              tail -f /var/log/messages

tcpdump       monitor/capture network data
              tcpdump "host 10.135.246.129 and port 601" -vvvv -A

teamdctl      team connections control - /usr/share/doc/teamd-1.27/example_configs
              teamdctl nm-team state

timedatectl   set and view time date
              timedatectl list-timezones
              timedatectl set-timezone Europe/Stockholm
              timedatectl status

touch         updates access / modification times
              touch helloworld.txt

tr            translate
              echo "Hello World" | tr a-z A-Z
              echo "Hello World" | tr [:lower:] [:upper:]

udevadm       monitor in realtime for udev watch system changes (add/remove devices or devices reporting changes)
              udevadm monitor

umount        unmount a filesystem
              umount /mnt

uname         print detailed information about kernel and system
              uname -a

updatedb      update the locate database

useradd       add linux user
              useradd -c "John Snow/IBM" -m jsnow
              useradd -u 2000 jsnow

usermod       modify user parameters
              usermod -aG sudousers jsnow
              usermod -e 2018-09-02 jsnow

vgcreate      create volume group
              vgcreate rootvg /dev/sda1
              vgcreate -s 16M vg_16M_extends /dev/sda2

vgs           show volume groups

vgdisplay     list volume group details

vgscan        scan for existing volume groups

virsh         qemu/kvm management
              virsh list --all
              virsh edit web2-server
              virsh start web2-server
              virsh autostart web2-server
              virsh autostart --disable web2-server
              virsh undefine web2-server

virt-install  create/install new qemu guest
              virt-install -n test -r 1024 --vcpus=1 --os-variant=centos7.5 --accelerate --nographics -v  --disk path=/var/lib/libvirt/shared-storage/test.img,size=20 --extra-args "console=ttyS0" --location /iso/CentOS-7.5-x86_64-netinstall.iso
              virt-install -n test -r 1024 --vcpus=1 --accelerate --nographics -v --disk path=/var/lib/libvirt/images/test.img,size=20 --console pty,target_type=serial --cdrom /iso/archlinux-2018.06.01-x86_64.iso

wc            count lines, words or bytes
              cat filename | wc - l                 # Count number of line for STDIN
              wc -c filename                        # Count number of characters in file
              wc -b filename                        # Count number of bytes in file
              wc -m filename                        # Count number of bytes in file (taking multibyte character sets into account)

# wget          get noninteracitve network download
#               wget http://www.google.com
#               wget -O /home/helloworld.txt http://wwww.getfile.com/index.html
#               wget --no-check-certificate https://site-without-signed-certificate.com/

whereis       find files in database

which         find files in database

xfs_admin	manage      xfs filesystems
              xfs_admin -L "my disklabel" /dev/mapper/rootvg-root

xrandr        manage output display for X11
              xrandr --output HDMI-2 --auto --output eDP-1 --auto --left-of HDMI-2
              xrandr --output Virtual-0 --mode 1920x1080

xrdb          import/process/reload .Xresources configuration
              xrdb -merge ~/.Xresources

xset          set keyboard speed
              xset r rate 300 50

xxd           hexdecimal conversions

yum           yum manager (http://cve.mitre.org/)
              yum repolist
              yum clean all
              yum update -y
              yum --disable=\* --enable=c7-media install bind-utils
              yum history
              yum install --downloadonly --downloaddir=/root/downloadpackages
              yum updateinfo list available
              yum updateinfo list security all
              yum updateinfo list security sec
              yum updateinfo list security installed
              yum info-sec
              yum update --security
              yum update-minimal --security
              yum update --cve CVE-2008-0947
              yum updateinfo list
              yum update --advisory=RHSA-2014:0159
              yum updateinfo RHSA-2014:0159
              yum updateinfo list cves


yum-config-manager    mange repos
            yum-config-manager --add-repo helloworld
            yum-config-manager --disable c7-media

zypper      SUSE package manager
            zypper in packagename
            zypper refresh
            zypper lu

