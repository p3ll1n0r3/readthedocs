
SNMP
====

Install SNMP agent
''''''''''''''''''

Install SNMP agent tools

.. code-block:: shell

   # yum -y install net-snmp-utils net-snmp
   
   # net-snmp-config --create-snmpv3-user -a MD5 -A geek123 geekuser
   
   # service snmpd start

   # service enable start
 
   # snmpwalk -v3 -u geekuser -l authNoPriv -a MD5 -A geek123 localhost
   
