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

bzip2, bunzip2	bzip2 compression utility |br|

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

docker		manage docker containers		docker ps |br|
							docker images |br|
							docker build --tag reverseproxy:1.0 . |br|

chown           change file owner |br|			chown root:root file.sh |br|
                 					chown -R root:root /root/secret |br|

chsh		change shell |br|			chsh --shell /bin/fish bwolf |br|

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
							dig @ns2.mil.se mil.se TXT \| MX \| SPF |br|

dd            	convert and copy a file (usually |br| 	dd if=pfSense-CE-memstick-2.3.5-RELEASE-amd64.img of=/dev/sdb bs=1M |br|
		write to/from cdrom/iso/usb |br|	dd status=progress if=/dev/vda | ssh 172.16.11.10 dd of=/dev/vda |br|

df            	display filesystems |br|		df -h |br|

dmsetup       	Manage dm disks |br|			dmsetup info /dev/dm-5 |br|

dnf		next version of yum packet manager	dnf module list postgresql |br|
							dnf module enable postgresql:12 |br|
							dnf -y install postgresql-server |br|

docker-compose	Manager docker projects |br|		docker-compose -f docker-compose-postgres.yml up -d

drill         	nslookup dnssec |br|           		drill -DT www.google.com |br|

du            	files/directories size calculation |br|	du -sh * |br|
              						du -a \| sort -n -r \| head -n 5  |br|

egrep         	grep with regexp |br|              	egrep -v "^$\|^#" /etc/ssh/sshd_config |br|

fallocate     	preallocate a file |br|			fallocate-l 20MB helloworld |br|

ffmpeg		convert videos				ffmpeg -i installation.mkv -vcodec mpeg2video  -qscale 0 -acodec copy -f vob -copyts -y installation.mpg |br|

file          	identify fileformat |br|

find          	find files |br|				find / -name *.log |br|
              						find / -user jsnow -exec cp -rfp {} /root/filesfound/ \\; |br|
							for x in $(find /etc/zypp/repos.d/ -maxdepth 1 -name \*.repo);do mv $x $(echo $x|sed 's/SP2/SP3/g') ;done |br|
							for x in $(find /etc/zypp/repos.d/ -maxdepth 1 -name \*.repo);do sed -i 's/\/REPTIL\//\/REPTIL2\//g' ;done |br|

firewall-cmd  	firewalld managemant rules/zones |br|	firewall-cmd --list-all |br|
              						firewall-cmd --reload |br|
              						firewall-cmd --permanent --add-masquerade |br|
              						firewall-cmd --permanent --add-service={http,https} |br|
              						firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,464/tcp,53/tcp,88/udp,464/udp,53/udp,123/udp} |br|
              						firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.0.0/24 destination address=192.168.0.10/32 port port=22 protocol=tcp accept' |br|
              						firewall-cmd --permanent --list-rich-rules |br|
              						firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address=10.0.0.0/24 destination address=192.168.0.10/32 port port=22 protocol=tcp accept' |br|
              						firewall-cmd --permanent --zone=testing --add-rich-rule='rule family=ipv4 source address=192.168.0.10/24 reject' |br|
              						firewall-cmd --permanent --add-rich-rule='rule service name=ssh limit value=10/m accept' |br|
              						firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.0.0/24" service name="ssh" log prefix="ssh" level="info" limit value="50/m" accept' |br|
              						firewall-cmd --permanent --add-rich-rule 'rule family=ipv4 source address=192.168.0.0/24 forward-port=513 protocol=tcp to-port=132' |br|
              						firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport 9000 -j ACCEPT |br|
              						firewall-cmd --direct --get-all-rules |br|

fc-list       	list available fonts |br|

fc-match      	match available fonts |br|		fc-match monospace |br|

for 		loop in bash				for a in 's-master' 's-worker-1' 's-worker-2' 's-nfs' 's-pg'; do ssh -i .ssh/okd_rsa root@$a 'systemctl stop firewalld';done |br|

free          	available memory |br|			free -m |br|
              						free -h |br|

getfacl       	list file access list |br|

getsebool     	get SELinux boolean values |br|		getsebool -a |br|

git           	Distributed version control		git --version |br|
		system.  |br|				git config --global user.name "BiBadWolf" |br|
              						git config --global user.email "bigbadwolf@secretbunker.se" |br|
              						git config --list |br|
              						git clone https://github.com/polygamma/aurman |br|
              						git clone https://github.com/polygamma/aurman aurman2 |br|
              						git pull |br|
              						git status |br|
              						git add -A . |br|
              						git status |br|
              						git commit -m "Updated file X" |br|
              						git push |br|
              						git init |br|
              						git add .Xresources |br|
              						git status |br|
              						git user.name bigbadwolf |br|
              						git commit -m "My first commit" |br|
              						git remote add origin https://github.com/p3ll1n0r3/dotfiles |br|
              						git push --mirror |br|

grep            find string in file(s) |br|		grep -i 'DaRliNg' document.txt |br|
                  					grep 'Hello world' document.txt |br|
              						cat /etc/passwd \| grep jsnow |br|
              						grep -i linux *.txt |br|
              						grep -v ^#  /etc/ssh/sshd_config \| grep . |br|
              						grep -B3 -A3 error /var/log/messages |br|
              						grep -v ^$ /etc/ssh/sshd_config |br|
                  					grep -v ^root /etc/passwd |br|
grubby        	update boot parameters kernels |br|	grubby –update-kernel=ALL –args=”console=ttyS0″ |br|

gzip |br|	gzip compression utility |br|
gunzip 

head          	show the first n lines in a file |br|	head -100 /var/log/messages |br|

hostnamectl   	set hostname for system |br|		hostnamectl set-hostname mycentos.example.com |br|

httpd         	apache web server |br|			httpd -t |br|

ip            	manipulate runtime ip			ip addr help |br|
		configuration |br|			ip route help |br|
              						ip link help |br|
              						ip a |br|
              						ip r |br|
              						ip -s link |br|
              						ip addr add 172.16.11.10 dev ens3 |br|
              						ip route add 172.16.11.0/24 dev ens3 |br|
              						ip route add default via 172.16.11.1 dev ens3 |br|
              						ip route add 192.0.2.1/24 via 10.0.0.1 dev eth0 |br|

iscsiadm      	iscsi initiator admin |br|              iscsiadm -m discovery -t st -p 192.168.1.75 |br|
              						iscsiadm -m node T iqn.2015-02.org.bigbadwolf:system1 -p 192.168.1.75:3260 -l |br|

journalctl    	view system logs on systemd		journalctl -f |br|
		installation |br|			journalctl -b |br|
              						journalctl _PID=1 |br|
              						journalctl --list-boots |br|
              						journalctl -u sshd.service |br|
              						journalctl -p err..emerg |br|
              						journalctl -u sshd.service -o json |br|
              						journalctl -u sshd.service -o json-pretty |br|
              						journalctl -u sshd.service -o verbose |br|


ln            	create links |br|              		ln /etc/hosts computers |br|
              						ln -s /etc/hosts computers |br|

localectl     	set and view locale settings |br|	localectl list-keymaps |br|
              						localectl list-locales |br|
              						localectl set-keymap sv-latin1 |br|
              						localectl set-locale LANG="en_US.utf8" |br|

locate        	find files in database |br|

ls            	list files/directories |br|		ls -latr |br|
              						ls -lah |br|
              						ls -d [!a-f]* |br|
              						ls -il * |br|
							ls -la {*.conf,*rc} |br|
							ls -la *+(.conf|rc) |br|

lsblk         	list block devices |br|

lshw          	list hardware |br|

lscpu         	list cpu info |br|

lslocks       	list system locks |br|

lsmem         	list memory |br|

lsmod         	list status current loaded 
		modules |br|

lsof          	list open files |br|			lsof -p 616 |br|
              						lsof /dev/sda2 |br|
              						lsof /var/log/locked-logfile.log |br|

lspci         	list pci devices |br|

lsscsi        	list scsi devices |br|

lsusb         	list usb devices |br|

lvcreate      	create logical volume |br|		lvcreate -L 100GB -n backup rootvg |br|
              						lvcreate -l 100 -n lv_100extends rootvg |br|
              						lvcreate -l 100%FREE -n lv_100procent_available rootvg |br|

lvdisplay	list logical volumes with |br|
		details |br|

lvextend	logical volume extend |br|		lvextend -size 200M -r /dev/vg/lv_xfs |br|
              						lvextend -L +100M -r /dev/mapper/rootvg-root-100MB-lv |br|
              						lvextend -l 50 -r /dev/mapper/rootvg-my50extend-lv |br|
              						lvextend -l 100%FREE -r /dev/mapper/rootvg-home-rest-of-available-space-in-vg |br|

lvmdiskscan   	list devices that may be |br|
		used as physical volumes |br|

lvs		list logical volumes |br|

md5sum        	calculate md5 checksum |br|		md5sum /iso/archlinux.iso |br|

mkswap        	create a swap partition |br|		makeswap /dev/vg/lv_swap2 |br|

man           	man pages |br|				man nmcli-examples |br|
              						man teamd.conf |br|
              						man 5 firewalld.richlanguages |br|
              						man 7 signal |br|
              						man -k passwd  |br|

mkdir         	make directory |br|			mkdir /var/log/httpd |br|
              						mkdir -p /srv |br|

mount         	mount filesystem |br|            	mount -a |br|
              						mount /www |br|
              						mount /dev/cdrom /mnt |br|
              						mount -o rw /srv/virtualmachines |br|

nft           	allows configuration of tables, |br|	nft add table inet filter  # Add a new table with family "inet" and table "filter" |br| 
		chains and rules provided by the |br| 	nft add chain inet filter INPUT { type filter hook input priority 0 \\; policy accept \\; } # Add a new chain to accept all inbound traffic |br|
		Linux kernel firewall. |br|		nft add rule inet filter INPUT tcp dport \\{ ssh, http, https\\ } accept  # Add a new rule to accept several TCP ports |br|
              						nft add rule inet filter INPUT drop # Rule drop everything else |br|
              						nft list ruleset # View current configuration |br|
              						nft --handlr --numeric list chain # Show rule handles |br|
              						nft delete rult inet filter  input handle 3 # Delete a rule |br|
              						nft list ruleset > /etc/nftables.conf # Save current configuration |br|

nmcli         	network manager CLI |br|		nmcli con show |br|
              						nmcli dev show |br|
              						nmcli con up VPN --ask |br|
              						nmcli con add con-name eth0 ifname eth0 type ethernet ip4 192.168.1.22/24 gw4 192.168.1.1 |br|
              						nmcli con mod eth0 ipv4.dns 192.168.1.1 |br|
              						nmcli con up eth0 |br|
              						nmcli con add type team con-name team0 ifname team0 config '{ "runner": {"name":"activebackup"}}' |br|
              						nmcli con add type team-slave con-name team0-slave1 ifname eth0 master team0 |br|
              						nmcli con add type team-slave con-name team0-slave2 ifname eth1 master team0 |br|
              						nmcli con mod team0 config '{ "runner": {"name":"activebackup"}}' |br|
              						nmcli con add type team-slave ifname eno1 master team0 |br|
              						nmcli con add type team-slave ifname eno2 master team0 |br|
              						nmcli con mod team0 ipv4.addresses 192.168.1.10/24 |br|
              						nmcli con mod team0 ipv4.gateway 192.168.1.1 |br|
              						nmcli con mod team0 ipv4.method manual |br|
              						nmcli con mod team0 ipv4.dns 8.8.8.8 |br|
              						nmcli con mod team0 +ipv4.dns 8.8.4.4 |br|
              						nmcli con up team-slave-eno1 |br|
              						nmcli con up team-slave-eno2 |br|
              						nmcli con show team0 |br|
              						nmcli con mod "enp0s3" ipv4.addresses '192.168.1.77/24 192.168.1.1' ipv4.dns 192.168.1.1 ipv4.method manual |br|
              						nmcli con mod "enp0s3" ipv6.addresses 'FDDB:FE2A:AB1E::C0A8:1/64' ipv6.method manual |br|
              						nmcli con reload |br|
              						nmcli dev wifi list |br|
              						nmcli dev wifi connect SSID password SSID_PASSWORD |br|
              						nmcli -p -f general,wifi-properties device show wlp3s0 |br|
              						nmcli general permissions |br|
              						nmcli general logging |br|
              						nmcli con delete uuid d49f78de-68d2-412d-80bc-0e238d380b8e |br|

nmap          	network / open ports |br|		nmap -sV -p 22 localhost |br| 
		scanner/mapper|br|	

nmtui         	network manager text menu |br|

osinfo-query  	qemu-kvm tool identify |br|		osinfo-query os |br|
		correct identifier |br|

openssl       	create / manipulate and get |br|	openssl s_client -connect www.google.com:443 -showcerts < /dev/null 2> /dev/null \|openssl x509 -outform PEM |br|
		certificates |br|			openssl req -subj "/commonName=www.hellden.se/" -x509 -days 3650 -newkey rsa:4096 -keyout /etc/ssl/private/nginx-www.hellden.se.key - out /etc/ssl/certs/nginx-www.hellden.se.crt |br|			
              
passwd        	set password for user |br|		passwd jsnow |br|
							passwd -e 90 jsnow |br|
              						passwd -u |br|
              						passwd -L ?  |br|

pip           	python module installer |br|		pip install -r requirements.txt |br|
              						pip install {package-name} |br|
              						pip install git+https://github.com/Gallopsled/pwntools.git@dev |br|

pkaction      	manage polkit actions |br|              pkaction --action-id org.freedesktop.NetworkManager.reload --verbose |br|

ps            	process viewer |br|			ps -ef |br|
              						ps fax |br|
              						ps aux \| awk '{ print $2 }' |br|

pvcreate      	create lvm physical volume |br|		pvcreate /dev/sda1 |br|

pvdisplay     	list physical volumes details |br|

pvs           	show physical volumes |br|

pwd           	print working directory |br|

python        	python programming language |br|	python -m venv django-project |br|
              						python -c 'import time;print(time.ctime(1565920843.452))' |br|
			
renice        	set new nice value for process |br|     renice -n -10 -p 1519 |br|
              						renice +10 1519  |br|

repoquery     	query package at repository |br|	repoquery -ql bind-utils |br|

restorecon    	restore SElinux labeling on files |br|	restorecon -R /xfs |br|
							restorecon -R -v /var/www/mediawiki.secretbunker.org/www/ |br|

rkhunter      	root kit hunter |br|			rkhunter --update |br|
              						rkhunter --propugd |br|
              						rkhunter --check -sk |br|

rm            	remove files/directories |br|		rm -rf etcbackup.tar |br|
              						find . -inum 210666 -exec rm -i {} i\\; # delete file with inodenummer |br|

rpm           	manage rpm packages |br|		rpm -qa |br|
              						rpm -qc chrony |br|
              						rpm -qf /etc/passwd |br|
              						rpm -qd chrony |br|
              						rpm -ql setup |br|
              						rpm -q --scripts setup |br|

rsync         	sync and copy tool |br|			rsync -aAXvS --info=progress2 --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found/*","/backup/*"} / /backup |br|

sar           	collect, report, or save |br|		sar -A |br|
		system activity information

scp           	secure copy files |br|			scp bigbadwolf@secretbunker.se:~/test.sh .  |br|
              						scp -P 2022 secret.txt bigbadwolf@remote-server.com:/~  |br|

sed           	string editor  |br|			sed -Ei.bak '/^\\s*(#|$)/d' /etc/sshd/sshd_config |br|
              						sed -n /^root/p /etc/passwd  |br|
              						sed -i 's/linda/juliet/g' /etc/passwd |br|

semanage      	SELinux set labelling on |br|		semanage fcontext -a -t user_home_dir_t "/xfs(/.*)?" |br|
		functions/files/directories |br|	semanage port -a -t http_port_t -p tcp 8999 |br|
         						semanage port -d -t http_port_t -p tcp  |br|
              						semanage port -l |br|
              						semanage port -lC |br|
              						semanage permissive -l |br|
							semanage fcontext -a -t httpd_sys_content_t "/var/www/mediawiki.secretbunker.org/www/(/.*)?" |br|

setfacl       	set file access list |br|		setfacl -R -m u:david:rwx /home/jsnow |br|
              						setfacl -m d:g:sales:rx /account |br|
              						setfacl -m d:g:david::- /account ???? |br|

setsebool	set SELinux boolean value |br|		setsebool -P httpd_use_nfs on |br|
              						setsebool -P named_write_master_zones on |br|
							setsebool -P httpd_unified 1 |br|

sha1sum |br|	calculate hash checksum |br|  		sha256sum /iso/archlinux.iso |br|
sha224sum |br|						sha256sum *.tar > sha256sum.txt |br|
sha256sum |br|						sha256sum -c sha256sum.txt |br|
sha384sum |br|
sha512sum |br|		

smbpasswd	set samba user password	 |br|		smbpasswd -a robby |br|

socat         	multipurpose relay |br|			socat tcp-connect:192.168.1.100:2604 file:`tty`,raw,echo=0 |br|

sort          	sort input |br|				sort -n |br|
              						sort -f |br|

ssh             secure shell connection |br|		ssh jsnow@secret.org |br|
                					ssh -vvv -i ~/.ssh/id_rsa bigbadwolf@secretbunker.org |br|
                					ssh -Xa bigbadwolf@secretbunker.org |br|
                  					ssh -p 2022 secretbunker.org |br|
                  					ssh -Q {cipher|mac|kex} secretbunker.org |br|

sshfs         	filesystem client based on ssh |br|	sshfs bigbadwolf@10.1.1.1:/ /mnt |br|

ssh-agent     	start a ssh-agent |br|			ssh-agent -s |br|

ssh-add       	add a key to the ssh-agent |br|		ssh-add ~/.ssh/id_rsa |br|

ssh-keygen    	generate  SSH keypair |br|		ssh-keygen -b 4096 -t rsa |br|

ssh-copy-id   	copy ssh key to server |br|		ssh-copy-id secretbunker.org |br|
              						ssh-copy-id -p 2022 -i ~/.ssh/id_rsa.pub bigbadwolf@secretbunker.org |br|

sudo          	run program as superuser |br|		sudo systemctl restart nginx.service |br|
              						sudo -i |br|
							sudo -l |br|

swapoff       	turn off swap on filesystem |br|	swapoff /dev/mapper/rootvg-swap |br|

swapon        	turn on swap on filesystem |br|		swapon -a |br|
              						swapon /dev/mapper/rootvg-swap |br|

sysctl		configure kernel parameters |br|	sysctl -w net.ipv4.ip_forward=1 |br|
		at runtime |br|				sysctl -w net.ipv4.ip_forward=1 >> /etc/sysctl.d/net_ipforward.conf |br|
							sysctl -p |br|
		
systemctl     	systemd control |br|			systemctl list-unit-files --state=enabled |br|
              						systemctl list-timers |br|
              						systemctl -t help |br|
              						systemctl enable --now libvirtd |br|
              						systemctl disable libvirtd |br|
              						systemctl start libvirtd.service |br|
              						systemctl stop libvirtd.service |br|
              						systemctl mask sshd.service |br|
              						systemctl unmask sshd.service |br|
              						systemctl list-dependencies sshd.service |br|
              						systemctl is-enabled libvirtd.service |br|
              						systemctl get-default |br|
              						systemctl set-default graphical.target |br|
              						systemctl isolate multi-user.target |br|
              						systemctl --failed |br|

tar           	manage tarballs |br|			tar -xvf microcode-20180108.tgz -C /tmp |br|
              						tar -cf etcbackup.tar /etc/* |br|
              						tar -cvzf /tmp/tar.tgz /usr/local |br|
              						tar -tvf etc.tgz  |br|
              						tar -xvf etc.tgz -C / etc/hosts |br|
							tar -cvf my0.tar -g my.snar |br|
							tar -cvf my1.tar -g my,snar |br|
							tar -xvf my0.tar -g /dev/null |br|
							tar -xvf my1.tar -g /dev/null |br|

targetcli     	manage and setup iscsi targets |br|	targetcli /backstores/block create block1 /dev/iscsi_storage/iscsi_storage_lv |br|
              						targetcli /iscsi create iqn.2015-02.org.secretbunker:system1 |br|
              						targetcli /iscsi/iqn.2015-02.org.secretbunker:system1/tpg1/acls create iqn.2015-02.org.secretbunker:system2 |br|
              						targetcli /iscsi/iqn.2015-02.org.secretbunker:system1/tpg1/luns create /backstores/block/block1 |br|
              						targetcli /iscsi/iqn.2015-02.org.secretbunker:system1/tpg1/portals delete 0.0.0.0 3260 |br|
              						targetcli /iscsi/iqn.2015-02.org.secretbunker:system1/tpg1/portals create 192.168.1.75 3260 |br|
              						targetcli saveconfig |br|

tail          	display the last n lines  |br|		tail -200 /var/log/messages |br|
		in a file |br|				tail -f /var/log/messages |br|

tcpdump       	monitor/capture network data |br|	tcpdump "host 10.135.246.129 and port 601" -vvvv -A |br|

teamdctl      	team connections control |br|		teamdctl nm-team state |br|
		/usr/share/doc/teamd-x.xx  |br|
		/example_configs |br|
         
timedatectl   	set and view time date |br|		timedatectl list-timezones |br|
              						timedatectl set-timezone Europe/Stockholm |br|
             	 					timedatectl status |br|

touch         	updates access / |br|			touch helloworld.txt |br|
		modification times |br|
              
tr            	translate |br|				echo "Hello World" \| tr a-z A-Z |br|
              						echo "Hello World" | tr [:lower:] [:upper:] |br|

udevadm       	monitor in realtime for udev |br|	udevadm monitor |br|
		watch system changes (add/remove |br|
		devices or devices reporting |br|
		changes) |br|
              
umount        	unmount a filesystem |br|		umount /mnt

uname         	print detailed information  |br|	uname -a  |br|
		about kernel and system  |br|		uname -r  |br|

updatedb      	update the locate database |br|

useradd       	add linux user |br|			useradd -c "BigBadWolf/NSA" -m bwolf |br|
              						useradd -u 2000 bwolf |br|

usermod       	modify user parameters |br|		usermod -aG sudousers bwolf |br|
              						usermod -e 2018-09-02 bwolf |br|
							usermod --shell /bin/fish bwolf |br|

vgcreate      	create volume group |br|          	vgcreate rootvg /dev/sda1  |br|
              						vgcreate -s 16M vg_16M_extends /dev/sda2  |br|

vgs           	show volume groups |br|

vgdisplay     	list volume group details |br|

vgscan        	scan for existing volume |br|
		groups |br|

virsh         	qemu/kvm management |br|		virsh list --all |br|
              						virsh edit web2-server |br|
              						virsh start web2-server |br|
              						virsh autostart web2-server |br|
              						virsh autostart --disable web2-server |br|
              						virsh undefine web2-server |br|

virt-install  	create/install new qemu guest |br|	virt-install -n test -r 1024 --vcpus=1 --os-variant=centos7.5 --accelerate --nographics -v  --disk path=/var/lib/libvirt/shared-storage/test.img,size=20 --extra-args "console=ttyS0" --location /iso/CentOS-7.5-x86_64-netinstall.iso |br|
              						virt-install -n test -r 1024 --vcpus=1 --accelerate --nographics -v --disk path=/var/lib/libvirt/images/test.img,size=20 --console pty,target_type=serial --cdrom /iso/archlinux-2018.06.01-x86_64.iso |br|

watch		execute a executio update		watch ps -p 1104 |br|
							watch lsof -p 1104 |br|

wc            	count lines, words or bytes |br|	cat filename \| wc - l |br|
              						wc -c filename |br|
              						wc -b filename  |br|
              						wc -m filename  |br|
whereis       	find files in database |br|

which         	find files in database |br|

xfs_admin	manage xfs filesystems |br|		xfs_admin -L "my disklabel" /dev/mapper/rootvg-root |br|

xrandr        	manage output display for X11 |br|	xrandr --output HDMI-2 --auto --output eDP-1 --auto --left-of HDMI-2 |br|
              						xrandr --output Virtual-0 --mode 1920x1080 |br|
							xrandr --query |br|

xrdb          	xrdb tool configuration |br|		xrdb -merge ~/.Xresources |br|

xset          	set x tool |br|				xset r rate 300 50 |br|

xxd           	hexdecimal conversions |br|

yum           	yum manager |br|			yum repolist |br|
              						yum clean all |br|
              						yum update -y |br|
              						yum --disable=\\* --enable=c7-media install bind-utils |br|
             	 					yum history |br|
              						yum install --downloadonly --downloaddir=/root/downloadpackages |br|
              						yum updateinfo list available |br|
              						yum updateinfo list security all |br|
              						yum updateinfo list security sec |br|
              						yum updateinfo list security installed |br|
              						yum info-sec |br|
              						yum update --security |br|
              						yum update-minimal --security |br|
              						yum update --cve CVE-2008-0947 |br|
              						yum updateinfo list |br|
              						yum update --advisory=RHSA-2014:0159 |br|
              						yum updateinfo RHSA-2014:0159 |br|
              						yum updateinfo list cves |br|

yum-config-ma..	mange repos |br|			yum-config-manager --add-repo helloworld |br|
	 						yum-config-manager --disable c7-media |br|						

zypper      	SUSE package manager |br|		zypper in {packagename} |br|
            						zypper refresh |br|
            						zypper lu |br|
							zypper --releasever=15.2 ref |br|
							zypper --releasever=15.2 dup |br|
                                                        zypper wp /etc/passwd |br|
							zypper repos -d |br|
							zypper info --requires {packagename} |br|

wget            get noninteractive network |br|		wget http://www.google.com |br| 
		download |br|				wget -O save-as-helloworld.txt http://wwww.getfile.com/index.html |br|
                                    			wget --no-check-certificate https://site-without-signed-certificate.com/ |br|
=============== ======================================= ===========================================================
