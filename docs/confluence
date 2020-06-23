zypper refresh

zypper install postgresql postgresql-server

systemctl start postgresql
systemctl enable postgresql

su - postgres

psql
# CREATE USER confluencedbuser PASSWORD 'confluencedbpassword';
# CREATE DATABASE confluencedb WITH ENCODING 'UNICODE' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
# GRANT ALL PRIVILEGES ON DATABASE confluencedb to confluencedbuser;
# \q

exit

cat /var/lib/pgsql/data/pg_hba.conf
-----------------------------------------------
...
host    all             all             127.0.0.1/32            md5
...
-----------------------------------------------



-----------------------------------------------

linux-ilu2:~ # ./atlassian-confluence-7.4.1-x64.bin
WARNING: Please make sure fontconfig is installed in your Linux distribution for Confluence installation.
            Visit KB article for more information. https://confluence.atlassian.com/x/JP06OQ
Unpacking JRE ...
Starting Installer ...

This will install Confluence 7.4.1 on your computer.
OK [o, Enter], Cancel [c]

Click Next to continue, or Cancel to exit Setup.

Choose the appropriate installation or upgrade option.
Please choose one of the following:
Express Install (uses default settings) [1],
Custom Install (recommended for advanced users) [2, Enter],
Upgrade an existing Confluence installation [3]
2

Select the folder where you would like Confluence 7.4.1 to be installed,
then click Next.
Where should Confluence 7.4.1 be installed?
[/opt/atlassian/confluence]


Default location for Confluence data
[/var/atlassian/application-data/confluence]


Configure which ports Confluence will use.
Confluence requires two TCP ports that are not being used by any other
applications on this machine. The HTTP port is where you will access
Confluence through your browser. The Control port is used to Startup and
Shutdown Confluence.
Use default ports (HTTP: 8090, Control: 8000) - Recommended [1, Enter], Set custom value for HTTP and Control ports [2]


Confluence can be run in the background.
You may choose to run Confluence as a service, which means it will start
automatically whenever the computer restarts.
Install Confluence as Service?
Yes [y, Enter], No [n]


Extracting files ...


Please wait a few moments while we configure Confluence.

Installation of Confluence 7.4.1 is complete
Start Confluence now?
Yes [y, Enter], No [n]


Please wait a few moments while Confluence starts up.
Launching Confluence ...

Installation of Confluence 7.4.1 is complete
Your installation of Confluence 7.4.1 is now ready and can be accessed via
your browser.
Confluence 7.4.1 can be accessed at http://localhost:8090
Finishing installation ...
-----------------------------------------------------

firewall-cmd --add-port=8090/tcp --permanent
firewall-cmd --reload


Firefox : http://192.168.122.149:8090




