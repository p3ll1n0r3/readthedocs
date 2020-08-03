Decompress initramfs image file
===============================

Decompress initramfs file (GZIP compressed and CPIO archive)

.. code-block:: shell

  # mkdir ~/initramfs
  # cp /boot/initramfs-linux.img initramfs-linux.img.gz
  # gunzip initramfs-linux.img.gz
  # cpio -i < initramfs-linux.img
  # rm initramfs-linux.img

Now the archive can be explored.
