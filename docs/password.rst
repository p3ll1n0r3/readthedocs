Password Tools
==============

Password Manager
''''''''''''''''

arch                 : pacman -S keepassxc

redhat/centos/fedora : yum install keepassxc

suse                 : zypper install keepassxc


Password Generator
''''''''''''''''''

arch                 : pacman -S pwgen


Generate 1 secure password with 16 char length and no misinterpreted chracters (i.e. 0,O,1,l,I)  

.. code-block:: shell

  # pwgen -s -B 16 1
  XurfLuHYLKLtY3sALdPe9vh3
  
