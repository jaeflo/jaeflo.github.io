---
title:  "Hack The Box - Remote"
date:   2020-03-21
categories: [ctf]
tags: [linux, Active Directory, Kali, Pentest, writeups, ctf, rdp, Remote-Desktop]
---
My write-up / walktrough for Remote on Hack The Box. 
![infocard](/images/remote/infocard.png)

`nmap -sTV -p 1-10000 -oN nmap_tcp_scan remote.htb`

![nmap](/images/remote/nmap.png)

NFS mounten (Port 2049 is openls -als )
```
faebu@kali:~$ showmount -e remote.htb
Export list for remote.htb:
/site_backups (everyone)
faebu@kali:~$ mkdir /tmp/infosec

faebu@kali:~$ sudo mount -t nfs remote.htb:/site_backups /tmp/infosec

```

Seitenbackup für spezielles Durchforsten

cms ist umbraco
backup ist gespeichert unter /tmp/infosec

  Database is in App_Data/Umbraco.sdf

couldn't load the file, inspected manually with notepadd++
found some hashes which I could crack online 

admin@htb.local b8be16afba8c314ad33d812f22a04991b90e2aaa -> 	baconandcheese

https://www.exploit-db.com/exploits/46153

modified poc 
started websesrver to publish nc.exe
started listener ```sudo nc -lvp 443```
started exploit in poc



