OpenSSL
=======

Generate a server key and self-signed certifcate. Hello World

.. code-block:: shell

  # openssl req -newkey rsa:4096 -nodes -keyout server.key -x509 -days 365 -out server.crt
  
  Generating a RSA private key
  ..........................++++
  .....................................................................................................................................++++
  writing new private key to 'server.key'
  -----
  You are about to be asked to enter information that will be incorporated
  into your certificate request.
  What you are about to enter is what is called a Distinguished Name or a DN.
  There are quite a few fields but you can leave some blank
  For some fields there will be a default value,
  If you enter '.', the field will be left blank.
  -----
  Country Name (2 letter code) [AU]:SE
  State or Province Name (full name) [Some-State]:Uppsala
  Locality Name (eg, city) []:EKG
  Organization Name (eg, company) [Internet Widgits Pty Ltd]:FMTIS SFE IT&SÄK
  Organizational Unit Name (eg, section) []:Infra
  Common Name (e.g. server FQDN or YOUR name) []:server.domain.org
  Email Address []:root@domain.org
  
..

Display details of certificate

.. code-block:: shell

   # openssl x509 -in server.crt -inform pem -noout -text
   
   Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            29:85:20:54:40:87:3f:29:2b:f6:f9:81:d3:9f:69:19:cf:29:88:d1
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = SE, ST = Uppsala, L = EKG, O = FMTIS SFE IT/&S\C3\83\C2\84K, OU = Infra, CN = server.domain.org, emailAddress = root@domain.org
        Validity
            Not Before: Jun 23 13:01:40 2020 GMT
            Not After : Jun 23 13:01:40 2021 GMT
        Subject: C = SE, ST = Uppsala, L = EKG, O = FMTIS SFE IT/&S\C3\83\C2\84K, OU = Infra, CN = server.domain.org, emailAddress = root@domain.org
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    00:ec:17:78:13:24:e9:e8:5c:24:f5:2b:d5:ae:98:
                    33:51:59:f7:dd:11:10:55:73:0f:c1:77:cd:48:50:
                    82:71:98:f2:a1:c0:7e:c9:13:22:e2:76:3d:1c:63:
                    51:91:8d:ad:7a:20:08:c7:ae:6c:f9:aa:8d:94:81:
                    c6:0b:07:c6:db:0d:3d:1e:6e:62:ab:cb:a5:de:8b:
                    66:73:00:9a:eb:9d:5a:8d:b5:7f:35:c7:4a:bb:45:
                    98:d7:c9:a3:0b:b6:ce:79:ba:b8:3a:71:59:78:97:
                    3e:54:48:ed:0a:f3:79:2e:c7:2a:02:18:45:05:26:
                    2a:89:41:f7:ed:60:96:29:fb:b3:30:d1:7f:65:05:
                    6f:dc:4c:79:2d:fa:fc:50:e7:62:5e:c4:d0:c7:78:
                    69:27:05:e8:ae:f2:ea:c7:cd:26:73:09:00:39:fb:
                    be:69:db:a4:41:b5:1f:ed:e4:68:5d:54:c9:fd:ec:
                    1b:25:44:7d:84:01:21:98:f0:63:74:a6:ab:79:89:
                    bf:5a:af:68:7c:a8:bf:61:23:96:e1:b3:78:68:28:
                    56:b6:e7:ac:bc:6d:ff:bc:72:d3:27:b8:e4:0d:14:
                    78:ce:70:56:77:c7:bd:f9:f9:86:57:4a:c5:71:90:
                    a4:81:db:35:5d:e7:f9:da:1c:f4:b3:f8:3d:ee:6d:
                    a5:92:65:78:ac:f5:11:1e:c9:85:3b:77:79:49:bd:
                    62:f4:23:68:cb:13:38:08:0d:e3:f6:61:4f:f4:48:
                    68:96:44:f6:ea:3a:c1:a1:de:75:eb:29:cf:1e:83:
                    6b:75:19:f3:7c:f5:37:fe:00:95:5e:0a:4d:de:93:
                    b8:08:49:09:24:e4:09:75:8e:b1:82:8a:c6:dd:02:
                    6e:88:86:6f:9d:2b:a8:25:c3:78:46:aa:49:91:f4:
                    fe:6e:2d:9a:54:dc:3f:02:19:cc:fc:1f:71:40:eb:
                    3e:e3:87:b5:03:b0:5a:bb:22:d8:68:af:e4:3f:32:
                    5e:e5:ea:f0:09:df:19:4a:a2:24:e3:69:fa:bb:44:
                    09:12:8a:b4:64:e8:d7:fa:27:d1:03:fd:1b:04:db:
                    37:52:3b:53:2d:94:dd:9a:ee:48:10:c1:54:8f:4f:
                    e1:a4:47:fd:75:1c:ea:05:f2:ed:9d:d7:1a:9e:b8:
                    06:e7:89:66:38:06:f3:04:90:c3:c8:83:20:ab:63:
                    4f:69:f2:0f:bf:48:c2:47:35:af:0d:a2:04:c7:df:
                    86:ef:23:28:03:b3:3e:aa:08:34:98:2a:41:60:85:
                    53:c6:cb:84:79:b1:c1:91:1e:3f:e9:09:a8:69:a2:
                    b1:8c:2c:f5:fc:7d:6e:aa:7b:54:61:62:e0:28:cb:
                    57:96:31
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                D2:3C:06:96:EF:20:BB:EA:B8:3D:49:A3:13:12:98:64:AC:94:73:E8
            X509v3 Authority Key Identifier:
                keyid:D2:3C:06:96:EF:20:BB:EA:B8:3D:49:A3:13:12:98:64:AC:94:73:E8

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         12:b4:e8:4e:78:23:1c:5d:dd:ba:86:50:80:6c:18:cf:68:39:
         bd:a9:60:ba:b2:f8:fc:05:82:cb:61:6e:36:5f:52:fb:ab:7e:
         5e:11:b2:bc:bf:47:c5:6a:7d:46:7e:88:bb:4e:a9:42:36:67:
         87:af:44:42:d3:d5:01:8c:41:cc:b7:36:27:5a:94:ce:f3:49:
         7d:0a:1d:ef:c5:18:3d:7e:fd:ad:cd:fa:cb:c2:6e:cd:0b:3b:
         16:3b:44:97:64:c1:b2:c2:d6:1d:56:1e:70:79:0f:7a:f7:0d:
         21:b8:1a:01:53:03:75:a9:67:1b:08:58:13:c0:7a:20:c2:8e:
         f3:e7:2e:76:dc:94:92:f7:3d:fd:cd:07:14:c6:92:92:b8:dd:
         4b:8a:f1:27:01:16:9a:0d:0c:23:e3:33:5e:1d:f5:a7:04:05:
         43:3c:55:ff:9e:e1:74:22:39:cd:69:9f:8d:0d:a7:41:e0:f4:
         53:28:8c:d6:a5:01:18:e0:77:fa:4e:bf:c6:48:95:b8:ec:d0:
         17:77:d9:de:47:6c:87:76:68:11:56:e8:25:23:90:40:63:f7:
         05:0d:30:6f:c7:72:43:19:c4:88:0d:91:ee:50:e2:7e:75:f7:
         a5:0a:f2:37:39:55:5c:46:ae:c4:8a:21:41:a1:81:6f:16:a4:
         ae:7a:fe:d3:7b:65:67:cb:0b:3e:da:b3:09:4f:d4:53:a2:c8:
         3a:38:74:b0:d3:53:e6:e9:04:02:ec:00:64:f8:9f:7b:85:d7:
         7d:88:93:18:c5:c1:59:f2:22:65:54:93:01:d4:e9:95:80:ba:
         54:8f:5a:91:a4:b5:69:cf:a7:21:9f:28:e0:d7:7d:83:8a:f2:
         ed:6c:64:d9:2a:2f:6d:a3:7d:3c:f5:b2:92:90:3f:46:dc:66:
         18:de:69:0c:1d:82:99:cc:93:03:12:6e:c4:15:30:82:15:3e:
         68:05:43:8c:e8:3b:f2:4a:e8:bf:03:d9:88:16:e4:a0:fa:45:
         52:7c:98:e5:f2:ba:b4:fe:45:a9:20:9d:d4:23:0b:47:e0:54:
         c9:41:d5:75:cd:c4:14:3e:2e:96:63:19:93:56:86:8b:bd:25:
         d0:bf:88:14:f9:37:90:8a:4b:d3:7f:1c:f2:76:13:f8:8b:fc:
         a6:56:f4:9a:a0:a9:07:08:70:c7:64:3d:d4:3d:e6:8d:37:d1:
         78:44:68:20:1e:af:c2:00:1b:35:87:b5:e4:a2:bc:67:89:91:
         2b:f5:66:08:72:ee:37:e6:69:01:65:46:df:db:3a:92:92:56:
         10:42:30:a8:ec:3b:db:14:b5:95:64:d1:a2:95:df:40:8e:4a:
         1e:e2:5b:b1:6a:23:41:3b
