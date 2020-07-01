
SNMP
====

Install SNMP agent
''''''''''''''''''

Install SNMP agent tools


.. code-block:: shell

   # yum -y install net-snmp-utils net-snmp
   # zypper install net-snmp


Create a snmp v3 user with authenticon protocol (-a MD5|SHA|SHA-512) and privacy protocol (-x DES|AES).

Centos seems to work with SHA-512, but SUSE SLES seems not to supprt SHA-512.


.. code-block:: shell
   
   # net-snmp-create-v3-user -a SHA-512 -A authpass -x AES -X privpass geekuser
   ## net-snmp-create-v3-user -a SHA -A authpass -x AES -X privpass geekuser


Open Firewalls to listen to 161

.. code-block:: shell

   # firewall-cmd --add-port=161/tcp --permanent
   ## firewall-cmd --add-port=161/udp --permanent
   # firewall-cmd --reload


Configure Location and Contact information for SNMP agent


.. code-block:: shell
   
   # cat /etc/snmp/snmpd.conf
   ...
   syslocation My Secret Nuclear Bunker
   systcontact The Basterd Operator from Hell (red@devil.net)
   ...



Start and enable the SNMP agent


.. code-block:: shell
   
   # systemctl start snmpd

   # systemctl enable snmpd
 
   
 

Test the SNMP agent functionality and listener. This should display all MIBs available.


.. code-block:: shell
 
   # snmpwalk -v3 -l authpriv -u geekuser -a SHA-512 -A authpass -x AES -X privpass localhost
   

Zabbix : Add Host
'''''''''''''''''

Add a host to Zabbix server: Main Menu -> Configuration -> Hosts

On top right corner, Create host

1) Set Host name

2) Groups : Add groups (e.g Linux Servers)

3) Interfaces : Add type SNMP

- set SNMPv3
- set set IP address and DNS name
- set Security name (e.g. created above as user "geekuser")
- set Security level to authPriv
- set Authentication protocol = SHA
- set the Authentication passphrase (created configuration of SNMP agent)
- set Privacy protocol = AES
- set the Privacy passphrase (created configuration of SNMP agent)
- Submit by selecting the "Add" button

5) Modify Host again

- Select Templates
- Link new template to correct type of device to monitor (e.g "Template OS Linux SNMPv2")
- Submit by select the "Update" button

6) Zabbix should start collection data in the Monitor "Hosts" view

7) Troubleshooting: Run the snmpwalk command from a the ssh terminal (zabbix server -> snmp agent ip)


