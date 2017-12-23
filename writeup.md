# General info

### 192.168.10.7 
- had smb open
- machine seems offline currently


### 192.168.10.28
- alternate http port on 8000
- has directory listing available
- php webshell and certain exploits lying around

### 192.168.10.32 

- about.php acceing by get parameter. 
- probably get parameter is error based injectionable
- 192.168.10.32/phpmyadmin 
- Access is forbidden and is only available from local network (cannot say if its 127 or 192)
- has mysql on port 3306

### 192.168.10.57
- Rashi Hotels template

### 192.168.10.65
- SMB is enabled
- cannot get in SMB using guest account - NT_ACCOUNT_DISABLED
#### Nikto Report for 192.168.10.65
- Nikto v2.1.6
+---------------------------------------------------------------------------
+ Target IP:          192.168.10.65
+ Target Hostname:    192.168.10.65
+ Target Port:        443
+---------------------------------------------------------------------------
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
+--------------------------------------------------------------------------



### 192.168.10.74
- space website

### 192.168.10.156
- asks to upload pic
- my guess is that we must upload a malicious pic
- 

  
