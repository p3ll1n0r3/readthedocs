NMAP scanning
=============

Scan all ports, detect version, detect OS

.. code-block:: shell

  # sudo nmap localhost -sV -sC -O -p-
  
  Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-28 10:00 CEST
  Nmap scan report for localhost (127.0.0.1)
  Host is up (0.00010s latency).
  rDNS record for 127.0.0.1: localhost.localdomain
  Not shown: 65533 closed ports
  PORT     STATE SERVICE VERSION
  22/tcp   open  ssh     OpenSSH 8.3 (protocol 2.0)
  5355/tcp open  llmnr?
  Device type: general purpose
  Running: Linux 2.6.X
  OS CPE: cpe:/o:linux:linux_kernel:2.6.32
  OS details: Linux 2.6.32
  Network Distance: 0 hops

  OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 149.21 seconds


UDP scan

.. code-block:: shell

  # sudo nmap 127.0.0.1 -sU
  # sudo unicornscan -mU -v -I 127.0.0.1
  

Output scan

.. code-block:: shell

  # sudo nmap localhost -sV -sC -O -p- -o nmap_scan.txt
  

Scan network segment

.. code-block:: shell

  # nmap -vvv -sn 192.168.122.0/24
  # nmap -vvv -sn 192.168.122.0-100
  
  
Nmap with Vuln Scripts

https://hakin9.org/vulscan-advanced-vulnerability-scanning-with-nmap-nse/

.. code-block:: shell

  # cd /usr/share/nmap/scripts/
  # git clone https://github.com/scipag/vulscan scipag_vulscan
  # nmap -sV --script=scipag_vulscan/vulscan.nse www.example.com
