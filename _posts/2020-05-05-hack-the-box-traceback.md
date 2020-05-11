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