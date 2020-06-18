---
title:  "Hack The Box - Monteverde"
date:   2020-05-31
categories: [ctf]
tags: [Windows, writeups, ctf]
---
My write-up / walktrough for the machine `Monteverde` on Hack The Box, published now, as the box got retired.

To make things easier, I added `10.10.10.172` as `monteverde.htb` to my `/etc/hosts`

## Infocard

![info](/images/monteverde/info.png)

## Enumeration

Like allways on `Hack the box`, I started with a `nmap-scan`. I had to tweak a bit for the right params, as initially, `nmap` returned nothing. But 
`nmap -sTV -p 1-10000 -Pn -oN nmap_tcp_scan monteverde.htb` did a great job.

![nmap](/images/monteverde/nmap.png)

There were plenty of open ports to take a further look to. As it seems that there is `smb` reachable on port 139, I took `enum4linux -U monteverde.htb` to gather users for a foothold.

![enum4linux](/images/monteverde/enum4linux.png)

## Foothold
I tried to `Kerberoast` and tried a couple of other things as well, but no luck at all. I then checked if there were some lazy configurations in which the username is set as password as well. To do so, I executed the following command:

` ./acccheck/acccheck.pl -t monteverde.htb -U users.txt -P users.txt `

And YES! I got a match...

![acccheck](/images/monteverde/acccheck.png)
`SABatchJobs:SABatchJobs`

unfortunately, the user `SABatchJobs` could not be used to establish a `Winrm-Session`, so I had to enumerate the target a bit further....
Digging in the smb-shares with `smbclient \\\\monteverde.htb\\users$ -U SABatchJobs`, I found `azure.xml`

![smbmap](/images/monteverde/smbmap.png)

so getting and showing this file, I got the password `4n0therD4y@n0th3r$`.

![azure](/images/monteverde/azure_creds.png)

So lets try if this password belongs to the user `mhope`, as `azure.xml` was found in his home-directory.

## Userflag

I tried again to establish a `winrm-session` with `evil-winrm -i monteverde.htb -u mhope -p 4n0therD4y@n0th3r$` and could finally grab the userflag.

![userflag](/images/monteverde/userflag.png)

## Privilege Escalation

I quickly noted, that the user `mhope` is member of `Azure Admins`. So, may be there is a way of taking advantage of this.

![mhope_azure](/images/monteverde/mhope_azureadmin.png)

I did a bit of research how the synchronisation between the `Azure-AD` and `on-premises AD` works. The following image, found on
https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-accounts-permissions helped me a lot to understand the process.

![adazuresync](/images/monteverde/adazuresync_microsoft.png)

So, the next step was to check if someone wrote allready a script to extract the credentials, and indeed, I found on https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Azure-ADConnect.ps1 a working solution. 

![admin](/images/monteverde/administrator.png)
`administrator:d0m@in4dminyeah!`

## Rootflag

All I had to do now was to open another shell with `evil-winrm -i monteverde.htb -u administrator -p d0m@in4dminyeah!` to grab the root-flag.

![rootflag](/images/monteverde/rootflag.png)

## Conclusion
- summarized, the following steps and tools led me to the root-flag:
  - Detection of open ports with `nmap`, among others, 139 is open
  - enumeration of users with `enum4linux`, got 10 usernames
  - Dictionary-attack for snmb-users with `acccheck`, got SABatchJobs:SABatchJobs
  - searched the snmb-shares manually with `smbclient` for suspicous or interesting files, found azure.xml with credentials for user mhope:4n0therD4y@n0th3r$
  - established a shell with `evil-winrm` and got user-flag
  - enumerated mhopes groups with `whoami` and noted, that he is Azure Admin
  - searched and executed an existing exploit for ADSync (`Azure-ADConnect.ps1`), got administrator:d0m@in4dminyeah!
  - established a shell with `evil-winrm` as administrator and got root-flag
- I learned a couple of things about azure-AD and how it works together with on premises AD
- Box was great fun, thanks and respect to [Hack the Box](https://www.hackthebox.eu) and [egre55](https://www.hackthebox.eu/home/users/profile/1190) for providing this box!
