Emulate an IMG file as block device and write Image to SD card
==============================================================

Create a 2 GB image file

.. code-block:: shell 

  # qemu-img create sdcard.img 2G

Make a virtual block device with the emulated block device image file

.. code-block:: shell 

  # losetup -fP sdcard.img
 
Create partitions in the block device image file

.. code-block:: shell 

  # parted /dev/loop1 mklabel msdos
  # parted /dev/loop1 mkpart primary ext4 1MiB 512MiB
  # parted /dev/loop1 mkpart primary ext4 512MiB 100%
  
  # mkfs.vfat /dev/loop0p1
  # mkfs.ext4 /dev/loop0p2
  
Mount the file system and copy Raspberry PI image to the partitions

.. code-block:: shell 

  # mkdir sdcard
  # mkdir sdcard/root
  # mkdir sdcard/boot
  
  # mount /dev/loop0p1 sdcard/boot
  # mount /dev/loop0p2 sdcard/root
  
  # cd sdcard
  # wget http://os.archlinuxarm.org/os/ArchLinuxARM-rpi-4-latest.tar.gz
  # bsdtar -xpf ArchLinuxARM-rpi-4-latest.tar.gz -C root
  # sync
  # mv root/boot/* boot
  # cd
  # umount sdcard/boot sdcard/root
  
Write Image file to SDCARD block device (assuming the SD card is device /dev/sdc)

.. code-block:: shell 

  dd bs=4M if=sdcard.img of=/dev/sdc conv=fsync

QEMU emulation Start Raspberry Pi OS

.. code-block:: shell 

  # pacman -S qemu-extras
  ### https://www.raspberrypi.org/downloads/raspberry-pi-os/
  # wget https://downloads.raspberrypi.org/raspios_armhf_latest
  # unzip *raspios*armhf.zip
  # wget https://github.com/dhruvvyas90/qemu-rpi-kernel/raw/master/kernel-qemu-4.19.50-buster
  # wget https://github.com/dhruvvyas90/qemu-rpi-kernel/raw/master/versatile-pb-buster.dtb
  # qemu-system-arm -kernel kernel-qemu-4.19.50-buster -cpu arm1176 -m 256 -M versatilepb -serial stdio -append "root=/dev/sda2 rootfstype=ext4 rw" -hda 2020-05-27-raspios-buster-lite-armhf.img -display gtk,show-cursor=on -dtb versatile-pb-buster.dtb


