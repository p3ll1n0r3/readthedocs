grub repair from unbootable disk 
================================

from : 
https://www.suse.com/de-de/support/kb/doc/?id=000018770
https://www.suse.com/support/kb/doc/?id=000019909


Boot with a media/iso (might need LVM tools, ex. SLES 15).
At bootprompt mount a CHROOT environment.

.. code-block:: shell
  
  # vgdisplay

  # mount /dev/rootvg/lv_root /mnt
  # mount /dev/rootvg/lv_home /mnt/home
  # mount /dev/rootvg/lv_tmp /mnt/tmp
  # ...
  # ...
  # mount --rebind /proc /mnt/proc
  # mount --rebind /sys /mnt/sys
  # mount --rebind /dev /mnt/dev
  #
  ## if EFI boot partion is needed
  # mount /dev/sda1 /mnt/boot/efi
  #
  # chroot /mnt

  ## recreate a grub config
  # grub2-mkconfig -o /boot/grub2/grub.cfg
  #
  ## install grub bootloader on bootdevice (BIOS)
  # grub2-install /dev/sda
  #
  ## if SHIM (EFI needed partition)
  # shim-install --config-file=/boot/grub2/grub.cfg

  # exit

  # reboot
