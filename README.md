
# Introduction

Simple tool for ARP poisoning attack I made for fun. Invalidates the arp cache of one host and force it to identify us as the other host. Host then will try to connect to us, next, we will be able to caprute and forward all packets from it. 

```

 Example

 HOST:                                                Attack HOST:
    MAC: 10:10:20:00:00:00               	              MAC: 30:30:30:00:00:00
    IP: 192.168.22.101                                    IP: 192.168.21.100
		
 HOST sends:                                          Attack HOST reply:
	Sender IP: 192.168.22.101                             Sender IP: 192.168.22.100                   
	Sender MAC: 10:10:20:00:00:00                         Sender MAC: 30:30:30:00:00:00
    Target IP: 192.168.22.100                             Target IP: 192.168.22.101   
    Target MAC: ff:ff:ff:ff:ff:ff (Broadcast)             Target MAC: 10:10:20:00:00:00
	
Now HOST will forward all packet to 30:30:30:00:00:00. If needed, we can also perform man-in-the-middle attack by forwarding ARP packet to required HOST 192.168.22.100 and poison it too. 
		 
```

## Dependencies

`pcap` https://npcap.com/

`libnet` https://github.com/libnet/libnet

### Windows

#### npcap

Download and install `npcap` https://npcap.com/#download. `npcap-sdk` 

#### libnet

Place library directory near `npcap-sdk` — libnet requires `npcap-sdk` and search it specially with that name. Run `Developer Command Prompt for VS *your version* `. Then just type

```shell
git clone https://github.com/libnet/libnet.git
cd libnet
$env:Path += ";C:\Program Files (x86)\Microsoft Visual Studio\Installer"
$env:Path += ";C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin"
.\win32\msvcbuild.bat x64
.\win32\msvcbuild.bat x86
```

