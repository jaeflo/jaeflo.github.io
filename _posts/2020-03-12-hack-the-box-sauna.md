---
title:  "Hack The Box - Sauna"
date:   2020-03-12
categories: [ctfs]
tags: [linux, Active Directory, Kali, Pentest]
---
My write-up / walktrough for Sauna on Hack The Box.

### Quick Summary
Sauna is now retired and I'm allowed to publish my write-up. Sauna was my first box ever, so I had a lot to learn and doing so, I got stuck a couple of times on loose ends! Neverthless, I just write down the walktrough which led me to the flags.
It's a Windows box, reachable on `10.10.10.175`. I added it to /etc/hosts as `sauna.htb`

![Info Card](/images/sauna/infocard.png)

### Nmap
I started with `nmap` to scan for open ports and services:
![Nmap-Scan](/images/sauna/nmap.png)

There are a couple of open ports and further infos about services, domain and so on.

### Web Enumeration
There is a Web-App hosted on `sauna.htb:80`. Unfortunately, it doesn't seem to be vulnerable to `sqli`, but on the site, I could gather some possible account-names due the fact that there was a team-section.

![webenum](/images/sauna/webenum.png)

### ASREPRoast
Playing a bit arround with username-combos like:
* fergus.smith
* f.smith
* smith.fergus
* and **fsmith**

and `GetNPUsers.py` from `impacket` gave me a ticket for the user **fsmith**  

![asreproast](/images/sauna/asreproast.png)

This ticket was crackable with a dictionary-attack and `hashcat`. I took `rockyou.txt` as wordlist. A few seconds later I was in possesion of the credentials **fsmith:Thestroke23**

![hashcat](/images/sauna/hashcat.png)

### Access with winrm
A quick attempt to access smb with the credentials didn't lead to valuable information. I deed a deeper inspect with `nmap -p 5985 10.10.10.175` to check, if maybe `winrm` is accessible. It is!
So the next step was to install `evil-winrm`, a neat Ruby-Application, which made it possible to get a shell on the target!

![winrm](/images/sauna/winrm.png)

### User-Flag
I could find the user-flag on desktop and owned my first user on HTB :-)

![userflag](/images/sauna/userflag.png)


### Enumerate System


