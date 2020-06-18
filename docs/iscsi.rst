iSCSI
=====

iSCSI server
''''''''''''

.. code-block:: shell

   # yum install targetcli

   # systemctl enable target
   Created symlink /etc/systemd/system/multi-user.target.wants/target.service → /usr/lib/systemd/system/target.service.

   # systemctl start target

   # targetcli backstores/block create name=LUN_1 dev=/dev/vdb
   Created block storage object LUN_1 using /dev/vdb.

   # targetcli ls /backstores

   o- / .................................................................................................... [...]
     o- backstores ......................................................................................... [...]
     | o- block ............................................................................. [Storage Objects: 1]
     | | o- LUN_1 .................................................... [/dev/vdb (20.0GiB) write-thru deactivated]
     | |   o- alua .............................................................................. [ALUA Groups: 1]
     | |     o- default_tg_pt_gp .................................................. [ALUA state: Active/optimized]
     | o- fileio ............................................................................ [Storage Objects: 0]
     | o- pscsi ............................................................................. [Storage Objects: 0]
     | o- ramdisk ........................................................................... [Storage Objects: 0]
     o- iscsi ....................................................................................... [Targets: 0]

   # targetcli /iscsi create
   Created target iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef.
   Created TPG 1.
   Global pref auto_add_default_portal=true
   Created default portal listening on all IPs (0.0.0.0), port 3260.

   [root@scsi-server ~]# targetcli ls
   o- / .................................................................................................... [...]
     o- backstores ......................................................................................... [...]
     | o- block ............................................................................. [Storage Objects: 1]
     | | o- LUN_1 .................................................... [/dev/vdb (20.0GiB) write-thru deactivated]
     | |   o- alua .............................................................................. [ALUA Groups: 1]
     | |     o- default_tg_pt_gp .................................................. [ALUA state: Active/optimized]
     | o- fileio ............................................................................ [Storage Objects: 0]
     | o- pscsi ............................................................................. [Storage Objects: 0]
     | o- ramdisk ........................................................................... [Storage Objects: 0]
     o- iscsi ....................................................................................... [Targets: 1]
     | o- iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef ................................ [TPGs: 1]
     |   o- tpg1 .......................................................................... [no-gen-acls, no-auth]
     |     o- acls ..................................................................................... [ACLs: 0]
     |     o- luns ..................................................................................... [LUNs: 0]
     |     o- portals ............................................................................... [Portals: 1]
     |       o- 0.0.0.0:3260 ................................................................................ [OK]
     o- loopback .................................................................................... [Targets: 0]

   # firewall-cmd --permanent --add-service=iscsi-target
   success

   # firewall-cmd --reload
   success

   # targetcli /iscsi/iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef/tpg1/luns create /backstores/block/LUN_1
   Created LUN 0.

   Only on the iSCSI initiator, pull the /etc/iscsi/initiatorname.iscsi, then we have the 'acl' name. This is added to the iSCSI
   acl list
   # cat /etc/iscsi/initiatorname.iscsi
   InitiatorName=iqn.1994-05.com.redhat:aabb51a64012
   
   # targetcli /iscsi/iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef/tpg1/acls create iqn.1994-05.com.redhat:aabb51a64012
   Created Node ACL for iqn.1994-05.com.redhat:aabb51a64012
   Created mapped LUN 0.

   # targetcli ls
   o- / ................................................................................................................... [...]
     o- backstores ........................................................................................................ [...]
     | o- block ............................................................................................ [Storage Objects: 1]
     | | o- LUN_1 ..................................................................... [/dev/vdb (20.0GiB) write-thru activated]
     | |   o- alua ............................................................................................. [ALUA Groups: 1]
     | |     o- default_tg_pt_gp ................................................................. [ALUA state: Active/optimized]
     | o- fileio ........................................................................................... [Storage Objects: 0]
     | o- pscsi ............................................................................................ [Storage Objects: 0]
     | o- ramdisk .......................................................................................... [Storage Objects: 0]
     o- iscsi ...................................................................................................... [Targets: 1]
     | o- iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef ............................................... [TPGs: 1]
     |   o- tpg1 ......................................................................................... [no-gen-acls, no-auth]
     |     o- acls .................................................................................................... [ACLs: 1]
     |     | o- iqn.1994-05.com.redhat:aabb51a64012 ............................................................ [Mapped LUNs: 1]
     |     |   o- mapped_lun0 ........................................................................... [lun0 block/LUN_1 (rw)]
     |     o- luns .................................................................................................... [LUNs: 1]
     |     | o- lun0 ................................................................ [block/LUN_1 (/dev/vdb) (default_tg_pt_gp)]
     |     o- portals .............................................................................................. [Portals: 1]
     |       o- 0.0.0.0:3260 ............................................................................................... [OK]
     o- loopback ................................................................................................... [Targets: 0]

Authentication per ACLs

.. code-block:: shell
  
  # targetcli /iscsi/iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef/tpg1/acls/iqn.1994-05.com.redhat:aabb51a64012 set auth userid=c8

  # targetcli /iscsi/iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef/tpg1/acls/iqn.1994-05.com.redhat:aabb51a64012 set auth password=c8-password



iSCSI initiator
'''''''''''''''

.. code-block:: shell

   # yum install iscsi-initiator-utils

   # systemctl enable iscsid
   Created symlink /etc/systemd/system/multi-user.target.wants/iscsid.service → /usr/lib/systemd/system/iscsid.service.

   # systemctl start iscsid


Authentication is configured in /etc/iscsi/iscsid.conf

.. code-block:: shell

   node.session.auth.authmethod = CHAP
   node.session.auth.username = username
   node.session.auth.password = password



iSCSI Discovery
'''''''''''''''

.. code-block:: shell

   # iscsiadm -m discovery --type sendtargets -p 192.168.122.124
   192.168.122.124:3260,1 iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef

   # iscsiadm -m discovery --type sendtargets -p 192.168.122.124 --login
   Logging in to [iface: default, target: iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef, portal: 192.168.122.124,3260]
   Login to [iface: default, target: iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef, portal: 192.168.122.124,3260] successful.

   # ls /var/lib/iscsi/nodes
   iqn.2003-01.org.linux-iscsi.scsi-server.x8664:sn.436c9137cfef

   # ls /var/lib/iscsi/send_targets
   192.168.122.124,3260

   # iscsiadm -m node -l

   # yum install device-mapper-multipath

   # rescan-scsi-bus.sh

   # multipath -a /dev/sda

   # systemctl restart multipathd

   # multipath -ll
   
   # fdisk /dev/mapper/mpatha

   # mkfs.xfs /dev/mapper/mpatha1

   # blkid
   /dev/mapper/mpatha1: UUID="ec488eea-cf82-4040-ac9f-88b0b09e5102" TYPE="xfs" PARTUUID="c5ab7784-01"

   # vi /etc/fstab
   UUID=ec488eea-cf82-4040-ac9f-88b0b09e5102       /var/c8         xfs     _netdev         0 0

   # mount -a

   # df -h
   
      

   