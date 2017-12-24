# General info

### 192.168.10.7 
- had smb open
- machine seems offline currently
- seems to have migrated to 192.168.10.74

### 192.168.10.28
- alternate http port on 8000
- has directory listing available
- php webshell and certain exploits lying around
- nikto reveals that there is a login page at /login.php
- the login page has weak authentication
- all the sql strings checking is being done in javascript
- bypass it by typing username as admin and password ' or 1=1 -- and use firefox / <browser> developer tools to execute the javascript function to submit the form

#### Logged in to personel.php
- it provides uploading of an image
- again the file extension checking is being done at javascript.
- use developer tools to bypass javascript file extension checking
- upload a web shell script and get a shell to the machine
#### Priv Escalation
- Yet to be done
- Must try IFS and LD_PRELOAD as there is a vm.so file lying around in /tmp among other file.
- probably thats a hint


### 192.168.10.32 

- about.php accessing by get parameter. 
- probably get parameter is error based injectionable
- 192.168.10.32/phpmyadmin 
- Access is forbidden and is only available from local network (cannot say if its 127 or 192)
- has mysql on port 3306

### 192.168.10.57
- Rashi Hotels template

#### nikto output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.10.57
+ Target Hostname:    192.168.10.57
+ Target Port:        80
+ Start Time:         2017-12-24 22:48:19 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /index.php?page=../../../../../../../../../../etc/passwd: The PHP-Nuke Rocket add-in is vulnerable to file traversal, allowing an attacker to view any file on the host. (probably Rocket, but could be any index.php)
+ OSVDB-3268: /img/: Directory indexing found.
+ OSVDB-3092: /img/: This might be interesting...
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ Server leaks inodes via ETags, header found with file /icons/README, fields: 0x13f4 0x438c034968a80 
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ 7686 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2017-12-24 22:53:37 (GMT5.5) (318 seconds)
---------------------------------------------------------------------------



### 192.168.10.65
- SMB is enabled
- cannot get in SMB using guest account - NT_ACCOUNT_DISABLED
#### Nikto Report for 192.168.10.65
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.10.65
+ Target Hostname:    192.168.10.65
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=localhost
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /CN=localhost
+ Start Time:         2017-12-23 19:39:01 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Win32) OpenSSL/1.0.2l PHP/5.6.32
+ Server leaks inodes via ETags, header found with file /, fields: 0x1607 0x560b017a99f1e 
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Hostname '192.168.10.65' does not match certificate's names: localhost
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var, HTTP_NOT_FOUND.html.var
+ Allowed HTTP Methods: OPTIONS, HEAD, GET, POST, TRACE 
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3268: /images/?pattern=/etc/*&sort=name: Directory indexing found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /license.txt: License file found may identify site software.
+ OSVDB-3092: /LICENSE.TXT: License file found may identify site software.
+ 8347 requests: 0 error(s) and 15 item(s) reported on remote host
--------------------------------------------------------------------------



### 192.168.10.74
- used to be space now it shows port 445,135,139 open.
- must be windows machine with lots of port open now
- should be attackable using smb vulnerability
#### nmap report - 24 dec 2258
- nmap -A -v -p- 192.168.10.74

- Starting Nmap 7.60 ( https://nmap.org ) at 2017-12-24 22:56 IST
- NSE: Loaded 146 scripts for scanning.
- NSE: Script Pre-scanning.
- Initiating NSE at 22:56
- Completed NSE at 22:56, 0.00s elapsed
- Initiating NSE at 22:56
- Completed NSE at 22:56, 0.00s elapsed
- Initiating Ping Scan at 22:56
- Scanning 192.168.10.74 [4 ports]
- Completed Ping Scan at 22:56, 0.07s elapsed (1 total hosts)
- Initiating Parallel DNS resolution of 1 host. at 22:56
- Completed Parallel DNS resolution of 1 host. at 22:56, 13.00s elapsed
- Initiating SYN Stealth Scan at 22:56
- Scanning 192.168.10.74 [65535 ports]
- Discovered open port 445/tcp on 192.168.10.74
- Discovered open port 135/tcp on 192.168.10.74
- Discovered open port 139/tcp on 192.168.10.74
- Discovered open port 49671/tcp on 192.168.10.74
- Discovered open port 49665/tcp on 192.168.10.74
- Discovered open port 49667/tcp on 192.168.10.74
- Discovered open port 49670/tcp on 192.168.10.74
- Discovered open port 49664/tcp on 192.168.10.74
- Discovered open port 47001/tcp on 192.168.10.74
- Discovered open port 49669/tcp on 192.168.10.74
- Discovered open port 49666/tcp on 192.168.10.74
- Discovered open port 49668/tcp on 192.168.10.74
- Discovered open port 5985/tcp on 192.168.10.74
- Completed SYN Stealth Scan at 22:57, 56.07s elapsed (65535 total ports)
- Initiating Service scan at 22:57
- Scanning 13 services on 192.168.10.74
- Service scan Timing: About 46.15% done; ETC: 22:59 (0:01:03 remaining)
- Completed Service scan at 22:58, 54.14s elapsed (13 services on 1 host)
- Initiating OS detection (try #1) against 192.168.10.74
- Retrying OS detection (try #2) against 192.168.10.74
- Retrying OS detection (try #3) against 192.168.10.74
- Retrying OS detection (try #4) against 192.168.10.74
- Retrying OS detection (try #5) against 192.168.10.74
- Initiating Traceroute at 22:59
- Completed Traceroute at 22:59, 0.03s elapsed
- Initiating Parallel DNS resolution of 2 hosts. at 22:59
- Completed Parallel DNS resolution of 2 hosts. at 22:59, 13.00s elapsed
- NSE: Script scanning 192.168.10.74.
- Initiating NSE at 22:59
- Completed NSE at 22:59, 9.34s elapsed
- Initiating NSE at 22:59
- Completed NSE at 22:59, 0.01s elapsed
- Nmap scan report for 192.168.10.74
- Host is up (0.038s latency).
- Not shown: 65522 closed ports
- PORT      STATE SERVICE      VERSION
- 135/tcp   open  msrpc        Microsoft Windows RPC
- 139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
- 445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
- 5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
- |_http-server-header: Microsoft-HTTPAPI/2.0
- |_http-title: Not Found
- 47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
- |_http-server-header: Microsoft-HTTPAPI/2.0
- |_http-title: Not Found
- 49664/tcp open  msrpc        Microsoft Windows RPC
- 49665/tcp open  msrpc        Microsoft Windows RPC
- 49666/tcp open  msrpc        Microsoft Windows RPC
- 49667/tcp open  msrpc        Microsoft Windows RPC
- 49668/tcp open  msrpc        Microsoft Windows RPC
- 49669/tcp open  msrpc        Microsoft Windows RPC
- 49670/tcp open  msrpc        Microsoft Windows RPC
- 49671/tcp open  msrpc        Microsoft Windows RPC
- No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
- TCP/IP fingerprint:
- OS:SCAN(V=7.60%E=4%D=12/24%OT=135%CT=1%CU=34608%PV=Y%DS=2%DC=T%G=Y%TM=5A3FE
- OS:3F3%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=I%TS=A)OPS(O1=M5B4
- OS:NW8ST11%O2=M5B4NW8ST11%O3=M5B4NW8NNT11%O4=M5B4NW8ST11%O5=M5B4NW8ST11%O6=
- OS:M5B4ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=
- OS:Y%T=80%W=2000%O=M5B4NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q
- OS:=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(
- OS:R=N)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD
- OS:=G)IE(R=N)

- Uptime guess: 0.758 days (since Sun Dec 24 04:48:26 2017)
- Network Distance: 2 hops
- TCP Sequence Prediction: Difficulty=262 (Good luck!)
- IP ID Sequence Generation: Incremental
- Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

- Host script results:
- |_clock-skew: mean: -1s, deviation: 0s, median: -1s
- | smb-security-mode: 
- |   account_used: guest
- |   authentication_level: user
- |   challenge_response: supported
- |_  message_signing: disabled (dangerous, but default)
- | smb2-security-mode: 
- |   2.02: 
- |_    Message signing enabled but not required
- | smb2-time: 
- |   date: 2017-12-24 22:59:14
- |_  start_date: 2017-12-24 04:49:06




### 192.168.10.156
- asks to upload pic
- my guess is that we must upload a malicious pic
- 

  
