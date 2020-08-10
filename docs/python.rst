Python Hacks
============

Setup a temporary webserver on port 9999:

CentOS 8 and Python3: 

# firewall-cmd --add-port=9999/tcp

# python3 -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...


Python 2:

# python -m SimpleHTTPServer
