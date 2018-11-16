---
layout: post
title:  Simple Honeypot and Sandbox to catch and analyse malware.
tags:   malware honeypot sandbox analysis
---

A small source summary to set up a nice honeypot and a popular sandbox.

{{more}}

<br/>As I will be starting a new job very soon I want to be prepared for the new challenges. One part of the job will be to analyze malware. This was also part of my last job but I mainly analyzed already known malware samples for testing purposes of the dynamic malware analysis system we built.
To get in touch with malware in the wild I thought it would be a good idea to set up a honeypot. First I wanted to use [_Dionaea_](https://dionaea.readthedocs.io/en/latest/){:target="_blank"} as it looks very advanced and well documented. After a few hours trying to install it on an Ubuntu 16.04 system I realized that there must be a simpler way. _Dionaea_ was built for Ubunti 14.04 and therefore some dependencies were missing which made the installation quite complicated. <br>Thankfully I found [_T-Pot_](http://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html){:target="_blank"} which includes _Dionaea_ as well as many other honeypots. The whole system should be very easy to set up and also comes with very nice [_Kibana_](https://www.elastic.co/products/kibana){:target="_blank"} dashboards to analyze the happening.<br>
As I have an Ubuntu 16.04 machine I used the [_T-Pot-Autoinstallation_](https://github.com/dtag-dev-sec/t-pot-autoinstall){:target="_blank"} to install all the honeypots. As promised the installation went fairly well. The only problem I ran into was that my system wasn't using Grub and therefore the script crashed near the end. To resolve this problem I just executed the last few needed commands manually and rebooted the machine.<br>
After the reboot the honeypots are running in seperate Docker containers which can be monitored with _Portainer.io_. Also the _Kibana_ frontend is running which can be accessed on the port 64297. Visualizations and dashboards are already preconfigured.
<br/>The whole system looks absolutely amazing and the dashboards are very impressive but I first had to figure out how to make sense of all these fancy visualizations and how to use them.

![T-Pot Dashboard](/assets/images/honeypot/dashboard.png)

With the honeypot _Dionaea_ I receive nice malware binaries. Up to now around 10 per hour. As I don't want to manually analyze already well known samples I needed a preselection mechanism. My idea was to upload the caught binaries every hour to _www.virustotal.com_ and check the detection rate. Therefore I created an account  and wrote a small Python script which uploads my binaries every hour.<br/><br/>

```python
  import sys
  import requests
  import shutil
  from os import listdir
  from os.path import isfile, join
  onlyfiles = [f for f in listdir("/data/dionaea/binaries/")
                          if isfile(join("/data/dionaea/binaries/", f))]

  for f in onlyfiles:
      if f == "virustotal_scan.py":
              continue

      url = 'https://www.virustotal.com/vtapi/v2/file/scan'
      params = {'apikey': 'YOUR-API-KEY'}
      files = {'file': (str(f), open(join("/data/dionaea/binaries/", f), 'rb'))}
      response = requests.post(url, files=files, params=params)

      if response.json() is not None:
              with open("/home/user/virustotal_report.txt", "a") as myfile:
                      myfile.write(str(response.json()["permalink"]) + "\n")

              shutil.move(str(join("/data/dionaea/binaries/", f)),
                                      "/data/dionaea/analyzed_binaries/" + str(f))
```

<br/>On _www.virustotal.com_ you can log in and see the last 25 samples submitted via API. At the moment I try to check this page once or twice a day and pick out the samples with a low detection rate. A better method would be to extend the above script to retrieve the detection rates from time to time. It would have to be done this way because some files are not yet analyzed on _www.virustotal.com_ and therefore take a minute or two and the detection rate is not returned instantly.

![T-Pot Dashboard](/assets/images/honeypot/virustotal.png)

Now that we have a solid honeypot which catches a few binaries every hour I want to analyze some of them in a sandbox. For the sandbox my choice fell on [_Cuckoo_](https://cuckoosandbox.org/){:target="_blank"}. The Cuckoo Sandbox is a good open source dynamic malware analysis sandbox. A downside for me is the complicated and costly installation process. As I like simple and fast installations I searched for a viable solution. The solution I found and chose is a [_Docker container_](https://github.com/blacktop/docker-cuckoo){:target="_blank"} which contains the Cuckoo Sandbox installation.<br>
As I wanted to use VirtualBox as my guest virtualization this was the only difficulty. The [_suggested solution_](https://github.com/blacktop/docker-cuckoo/blob/master/docs/virtualbox.md){:target="_blank"} is to use VirtualBox Web Service to communicate from inside the Docker container with the VirtualBox installed on the host. To make the installation work I used the given installation instructions on Github as well as [_This_](http://xmodulo.com/how-to-manage-virtualbox-vms-on-remote-headless-server.html){:target="_blank"} website.<br>
Because the connection between the VirtualBox Web Service and Cuckoo should be HTTPS, certificates have to be generated. A simple guide for this task can be found in the  [_Documentation of RemoteBox_](http://www.balgau.net/files/2015-01/remotebox.pdf){:target="_blank"} on page 12 and 13.<br>
_Problem hint_: After starting the _vboxwebservice_ I was not able to connect to the configured port. The problem I ran into was that the installed honeypot _Honeytrap_ automatically tried to listen to the port I tried to connect to. Because I tried to connect to the port as the _vboxwebservice_ was not totally started, _Honeytrap_ was able to listed to the port and therefore blocked the actual service from listening.<br>
The generated certificate now has to be added to the CA-Certificates inside the docker container and therefore the Dockerfile has to be adjusted a little bit. First the certificate has to be copied and then the CA-Certificates must be updated. To do this I added the following lines to the end of the Dockerfile.

> COPY vbox_webservice.pem /usr/local/share/ca-certificates/
> RUN update-ca-certificates

After the _VirtualBox Web Service_ is installed and configured the Docker container can be started with _"docker-compose -f docker-compose.vbox.yml up -d"_<br>


 ![Cuckoo Dashboard](/assets/images/honeypot/cuckoo.png)

 As the Cuckoo Sandbox Dashboard is exposed on some port, I had the change the port because 80 was already taken by my honeypot, it can be advantageous if some sort of authentication is implemented. On Github I read that Cuckoo has an [_authentication possibility_](https://github.com/spender-sandbox/cuckoo-modified/issues/473){:target="_blank"} integrated. The other possibility would be to make Cuckoo listen on localhost and configure a proxy with nginx which forwards a certain port to the Cuckoo web Docker container. In this case a simple basic authentication can be configured.<br/><br/>

 **This whole setup would be amazing if it would work..**
 The server I chose to run this setup on does not deliver great performance. It is fairly good for the price but not good enough to run a honeypot system and a sandbox together on it. As soon as I start a sandbox analysis the server stops responding and the last thing that can be seen is a _Load average above 100_, which is not too good.<br>
 My next step will probably be to set up the Cuckoo Sandbox on a baremetal machine on its own while I keep my honeypot where it is. This way both systems should work fine and deliver viable results.
