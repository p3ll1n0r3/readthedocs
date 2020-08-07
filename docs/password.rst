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


Generate a hash password 
''''''''''''''''''''''''
Generation of a sha512 password with a random salt value.
Note: passing -1 will generate an MD5 password, -5 a SHA256 and -6 SHA512 (recommended) 

.. code-block:: shell

  # openssl passwd -6 -salt $(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
  Password:
  $6$JNiDd4tVmKSDgazQ$RsJm0U.ixZ57l9CfHDznHwH8M8JQynEz3ccAa.yYi/JfoN9s0SIfzcR6A25bBk.oATYaYiD5Lkwuza.dV9wKK0
  
  
