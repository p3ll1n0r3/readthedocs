SUDOERS /etc/sudoers Configuration
----------------------------------
TODO: Combine best recommendations to one.

sudo su - 
sudo -i


CENTOS

.. code-block:: shell
  
  Defaults   !visiblepw
  Defaults    always_set_home
  Defaults    match_group_by_gid
  Defaults    always_query_group_plugin
  Defaults    env_reset
  Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
  Defaults    env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
  Defaults    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
  Defaults    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
  Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
  Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
  root	ALL=(ALL) 	ALL
  %wheel	ALL=(ALL)	ALL

OPENSUSE

.. code-block:: shell

  Defaults always_set_home
  Defaults secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
  Defaults env_reset
  Defaults env_keep = "LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_ATIME LC_ALL LANGUAGE LINGUAS XDG_SESSION_COOKIE"
  Defaults !insults
  Defaults targetpw   # ask for the password of the target user i.e. root
  ALL   ALL=(ALL) ALL   # WARNING! Only use this together with 'Defaults targetpw'!
  root ALL=(ALL) ALL

MYPERSONAL

.. code-block:: shell
  
  Defaults   !visiblepw
  Defaults   !insults
  Defaults    always_set_home
  Defaults    match_group_by_gid
  Defaults    always_query_group_plugin
  Defaults    env_reset
  Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
  Defaults    env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
  Defaults    env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
  Defaults    env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
  Defaults    env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
  Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin
  Defaults    editor = /bin/vim
  Defaults    logfile=/var/log/sudo.log
  Defaults    loglinelen=0
  Defaults    log_year
  Defaults    log_host
  Defaults    log_output
  Defaults!/usr/bin/sudoreplay !log_output
  Defaults!/sbin/reboot !log_output
  Defaults    ignore_dot

  Cmnd_Alias  USER_WRITEABLE = /home/*, /tmp/*, /var/tmp/*
  
  # Deny all users to run any sudo command
  ALL ALL = (ALL) PASSWD: !ALL

  # root can run any command as root
  root	ALL=(ALL) 	ALL

  # wheel group can run all commands as run, but not from insecure directories
  %wheel	ALL=(root)  	PASSWD:	ALL, !USER_WRITEABLE

  #includedir /etc/sudoers.d


We can restrict access to "/bin/su" so only group "wheel" can only execute "su" command.

Modify file permission of the SGID file to prevent "others/worldwide" execute "/bin/su"

Modify/Add file extended file ownership to the group "wheel"


.. code-block:: shell
  
  # sudo chmod 4750 /bin/su
  # sudo setfacl -m g:wheel:rx /bin/su

  # getfacl: Removing leading '/' from absolute path names
  # file: bin/su
  # owner: root
  # group: root
  # flags: s--
  user::rwx
  group::r-x
  group:wheel:r-x
  mask::r-x
  other::---

  [kalle@xwiki ~]$ /bin/su
  -bash: /bin/su: Permission denied

  
We can restrict access to "/bin/sudo" so only group "wheel" can execute "sudo" command.

We can restrict any "sudo" execution for normal users as well in similar manner, e.g. block "sudo -l".

.. code-block:: shell

  # sudo chmod 4750 /bin/sudo
  # sudo setfacl -m g:wheel:rx /bin/sudo

  # getfacl: Removing leading '/' from absolute path names
  # file: bin/sudo
  # owner: root
  # group: root
  # flags: s--
  user::rwx
  group::r-x
  group:wheel:r-x
  mask::r-x
  other::---

  [kalle@xwiki ~]$ /bin/sudo
  -bash: /bin/sudo: Permission denied
