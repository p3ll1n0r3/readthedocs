SUSE Manager 
============

SUSE SLES 15.1 server installation

.. code-block:: shell

      zypper install -t pattern suma_server

      zypper install spacewalk-utils


Setup Logical Volumes

Attach a 500 G hard disk
Create a Volume Group : vg_suma
And Logical Volumes

.. code-block:: shell

      VG          LV             Filesystem                Size         Filesystem

      vg_suma     lv_postgres    /var/lib/pgsql             50 G        xfs
      vg_suma     lv_spacewalk   /var/spacewalk            300 G        xfs
      vg_suma     lv_www         /srv/www                  100 G        xfs


.. code-block:: shell

   # pvcreate /dev/sdb

   # vgcreate vg_suma /dev/sdb

   # lvcreate -L 50G -n lv_postgres vg_suma
   # lvcreate -L 300G -n lv_spacewalk vg_suma
   # lvcreate -L 100G -n lv_www vg_suma

   # mkfs.xfs /dev/mapper/vg_suma-lv_postgres
   # mkfs.xfs /dev/mapper/vg_suma-lv_spacewalk
   # mkfs.xfs /dev/mapper/vg_suma-lv_www


Create directories

.. code-block:: shell

      mkdir -p /var/lib/pgsql /var/spacewalk /srv/www


Get the UUID information

.. code-block:: shell

      blkid


Mount in /etc/fstab

.. code-block:: shell

      UUID=abcdef1234.......     /var/lib/pgsql     xfs      defaults    0 0
      UUID=ABCDEF1234.......     /var/spacewalk     xfs      defaults    0 0
      UUID=AABBCC1122.......     /srv/www           xfs      defaults    0 0

   # mount -a


Installation with YAST
''''''''''''''''''''''

Before we run the installation program. Set filepermissions on postgres directory.
And set the UMASK to prevent any system hardening configuration issues.
Run the installation program via :

- YAST -> Network Services -> SUSE Manager Setup

.. code-block:: shell

      # chown postgres:postgres /var/lib/pgsql
      # umask 022      
      # yast

* Set up SUSE Manager from scratch
* Fill out the certificat information




