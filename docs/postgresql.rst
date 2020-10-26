PostgreSQL server installation
==============================

Installation of PostgreSQL server on OpenSUSE:

.. code-block:: shell

  (root) # zypper install postgresql-server 


Enable and start PostgreSQL server

.. code-block:: shell

  (root) # systemctl enable postgresql
  (root) # systemctl start postgresql
  
  
Create a database and database role
.. code-block:: shell

  (root) # su - postgres
  (postgres) # createuser dbwwwuser -S -D -R -P
  Enter password for new role:
  Enter it again:
  (postgres) # createdb -O dbwwwuser -E UNICODE dbwww
  

Configure authentication to database

.. code-block:: shell

  (root) # vim /var/lib/pgsql/data/pg_hba.conf
  ...
  # TYPE  DATABASE        USER            ADDRESS                 METHOD
  # "local" is for Unix domain socket connections only
  local   all             all                                     peer
  # IPv4 local connections:
  host	 dbwww		        dbwwwuser		    127.0.0.1/32		        md5
  # host	all		          all		          127.0.0.1/32		        md5
  # host	xwiki		        xwiki		        127.0.0.1/32		        md5
  # host  all             all             127.0.0.1/32            ident
  # host	xwiki		        xwiki		        localhost		            md5
  # IPv6 local connections:
  # host  all             all             ::1/128                 ident
  # Allow replication connections from localhost, by a user with the
  # replication privilege.
  # local replication     all                                     peer
  # host  replication     all             127.0.0.1/32            ident
  # host  replication     all             ::1/128                 ident
  ...


Restart PostgreSQL server to deploy new authentication configuration, and test authentication.

.. code-block:: shell

  (root) # systemctl restart postgresql
  (root) # psql dbwww -U dbwwwuser -h 127.0.0.1
  Password:
  psql (12.4)
  Type "help" for help
  dbwww=>
  
  
PostgreSQL Java ODBC connector, install and file location.

.. code-block:: shell

  (root) # zypper install postgresql-jdbc
  (root) # ls -la /usr/share/java/postgresql-jdbc*.jar


PostgreSQL PHP library, install.

.. code-block:: shell

  (root) # zypper install php-pgsql
 
 
