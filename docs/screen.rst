Screen
======

resource : https://linuxize.com/post/how-to-use-linux-screen/


start a new screen session

.. code-block:: shell

  $ screen


start a named screen session 

.. code-block:: shell

  $ screen -S a_long_process


quit/close a screen session (normal bash shortcut)

.. code-block:: shell

  CTRL + d


detach from a screen session

.. code-block:: shell

  CTRL + a d
  or
  CTRL + a  CTRL + d


list current screen sessions

.. code-block:: shell

  [root@ceasar ~]# screen -ls
  There are screens on:
    2892.pts-0.ceasar (Detached)
    2889.a_long_process  (Detached)
    2876.pts-0.ceasar (Detached)
  3 Sockets in /run/screens/S-root.


resume a screen session

.. code-block:: shell

  $ screen -r a_long_process
  

lock/password protect a screen session

.. code-block:: shell

  CTRL a + x


other:
To create a new window with shell type Ctrl+a c, the first available number from the range 0...9 will be assigned to it.

Below are some most common commands for managing Linux Screen Windows:

- Ctrl+a c Create a new window (with shell)
- Ctrl+a " List all window
- Ctrl+a 0 Switch to window 0 (by number )
- Ctrl+a A Rename the current window
- Ctrl+a S Split current region horizontally into two regions
- Ctrl+a | Split current region vertically into two regions
- Ctrl+a tab Switch the input focus to the next region
- Ctrl+a Ctrl+a Toggle between the current and previous region
- Ctrl+a Q Close all regions but the current one
- Ctrl+a X Close the current region
    
