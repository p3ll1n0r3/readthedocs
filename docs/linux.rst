Linux Commands
==============

.. |br| raw:: html

    <br>

================ =================================================================================================
 command          syntax
================ =================================================================================================
 audit2why        why is SELinux denied |br|
                  audit2why -i /var/log/audit/audit.log |br|
                  grep 1573441241.893:21782 /var/log/audit/audit.log \| audit2why |br|
 awk              pattern scanning and processing language |br|
                  ps aux \| awk '{ print $2 }' |br|
 blkid            locate/print block device attributes (requires sudo) |br|
 cat              print content of file |br|
                  cat /etc/passwd |br|
 grep             find string in file(s) |br|
                  grep -i 'DaRliNg' document.txt |br|
                  grep 'Hello world' document.txt |br|
                  grep -v ^root /etc/passwd |br|
 sha1sum          calculate hash checksum    
 sha224sum        calculate hash checksum
 sha256sum        calculate hash checksum
 sha384sum        calculate hash checksum
 sha512sum        calculate hash checksum |br|
                  sha256sum /iso/archlinux.iso |br|
                  sha256sum *.tar > sha256sum.txt |br|
                  sha256sum -c sha256sum.txt
 ssh              secure shell connection |br|
                  ssh jsnow@secret.org |br|
                  ssh -vvv -i ~/.ssh/id_rsa jsnow@secret.org |br|
                  ssh -Xa jsnow@secret.org |br|
                  ssh -p 2022 secret.org |br|
                  ssh -Q {cipher|mac|kex} secret.org
 wget             get noninteractive network download |br|
                  wget http://www.google.com |br|
                  wget -O save-as-helloworld.txt http://wwww.getfile.com/index.html |br|
                  wget --no-check-certificate https://site-without-signed-certificate.com/
================ =================================================================================================
                 
