
BTRFS quota on file systems
===========================

.. code-block:: shell

  # btrfs subvolume list /
  ID 256 gen 36 top level 5 path @
  ID 258 gen 51 top level 256 path @/var/tmp
  ID 259 gen 39 top level 256 path @/var/opt
  ID 260 gen 133 top level 256 path @/var/log
  ID 261 gen 39 top level 256 path @/var/crash
  ID 262 gen 51 top level 256 path @/var/cache
  ID 263 gen 39 top level 256 path @/usr/local
  ID 264 gen 133 top level 256 path @/tmp
  ID 265 gen 39 top level 256 path @/srv
  ID 266 gen 133 top level 256 path @/root
  ID 267 gen 39 top level 256 path @/opt
  ID 268 gen 30 top level 256 path @/boot/grub2/x86_64-efi
  ID 269 gen 45 top level 256 path @/boot/grub2/i386-pc
  ID 270 gen 49 top level 256 path @/.snapshots
  ID 271 gen 133 top level 270 path @/.snapshots/1/snapshot
  ID 274 gen 47 top level 270 path @/.snapshots/2/snapshot


.. code-block:: shell

  Enable Quota feature on filesystems
  # btrfs quota enable /var/log
  # btrfs quota enable /tmp

.. code-block:: shell

  Create Qgroup for /var/log. Set quota to 6 GB
  # btrfs qgroup create 0/260 /var/log
  # btrfs qgroup limit 6G /var/log


.. code-block:: shell

  Create Qgroup for /tmp. Set quota to 2 GB
  # btrfs qgroup create 0/264 /tmp
  # btrfs qgroup limit 2G /tmp


.. code-block:: shell

  Show status and limits of qgroups
  # btrfs qgroup show -reF /var/log
  # btrfs qgroup show -reF /tmp


.. code-block:: shell

  Test filling up filesystem causing : Quota execeed
  # dd if=/dev/zero of=/tmp/abc bs=4G count=1
  dd: error writing '/tmp/abc': Disk quota exceeded


.. code-block:: shell

  Scan for updated quota
  # btrfs quota rescan /var/log
  # btrfs qgroup show -reF /var/log

