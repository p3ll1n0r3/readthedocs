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