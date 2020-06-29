
SNMP
====

Install SNMP agent
''''''''''''''''''

Install SNMP agent tools

.. code-block:: shell

   # yum -y install net-snmp-utils net-snmp
   
   # net-snmp-create-v3-user -a SHA-512 -A authpass -x AES -X privpass geekuser
   
   # systemctl start snmpd

   # systemctl enable snmpd
 
   # snmpwalk -v3 -l authpriv -u geekuser -a SHA-512 -A authpass -x AES -X privpass localhost
   
   
