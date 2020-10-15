Screen
======

resource : https://linuxize.com/post/how-to-use-linux-screen/

resource : https://www.cyberciti.biz/faq/unix-linux-apple-osx-bsd-screen-set-baud-rate/


start a new screen session

.. code-block:: shell

  $ screen


Close/Kill Screen/Serial connection

.. code-block:: shell

  CTRL A + k


detach from a screen session

.. code-block:: shell

  CTRL + a d
  or
  CTRL + a  CTRL + d


quit/close a screen session (normal Bash shortcut, may not work on serial connection)

.. code-block:: shell

  CTRL + d


list current screen sessions

.. code-block:: shell

  [root@ceasar ~]# screen -ls
  There are screens on:
    2892.pts-0.ceasar (Detached)
    2889.a_long_process  (Detached)
    2876.pts-0.ceasar (Detached)
  3 Sockets in /run/screens/S-root.


start a named screen session 

.. code-block:: shell

  $ screen -S a_long_process


resume a screen session

.. code-block:: shell

  $ screen -r a_long_process
  

lock/password protect a screen session

.. code-block:: shell

  CTRL a + x


Connect to a serial port
# screen /dev/ttySX baud_rate,cs8|cs7,ixon|-ixon,ixoff|-ixoff,istrip|-istrip

- /dev/ttySX: Linux serial port (e.g., /dev/ttyS0 [COM1] )
- baud_rate: Usually 300, 1200, 9600 (default), 19200, or 115200. This affects transmission as well as receive speed.
- cs8 or cs7: Specify the transmission of eight (or seven) bits per byte.
- ixon or -ixon: Enables (or disables) software flow-control (CTRL-S/CTRL-Q) for sending data.
- ixoff or -ixoff: Enables (or disables) software flow-control for receiving data.
- istrip or -istrip: Clear (or keep) the eight bit in each received byte.


.. code-block:: shell

  screen /dev/ttyUSB0 115200,cs8


other:
To create a new window with shell type Ctrl+a c, the first available number from the range 0...9 will be assigned to it.

Below are some most common commands for managing Linux Screen Windows:

- Ctrl+a c Create a new window (with shell)
- Ctrl+a " List all window
- Ctrl+a i Display Connection information
- Ctrl+a 0 Switch to window 0 (by number )
- Ctrl+a A Rename the current window
- Ctrl+a S Split current region horizontally into two regions
- Ctrl+a | Split current region vertically into two regions
- Ctrl+a tab Switch the input focus to the next region
- Ctrl+a Ctrl+a Toggle between the current and previous region
- Ctrl+a Q Close all regions but the current one
- Ctrl+a X Close the current region
    
