# VulnHub - Kioptrix level 3 writeup 

![Kioptrix Level 3 Header](/Images/kioptrix3_header.png)

[VulnHub Image Link](https://www.vulnhub.com/entry/kioptrix-level-12-3,24)

:monocle_face: :clock11:

> As with the other two, this challenge is geared towards the beginner. It is however different. Added a few more steps and a new skill set is required. Still being the realm of the beginner I must add. The same as the others, there’s more then one way to “pwn” this one. There’s easy and not so easy. Remember… the sense of “easy” or “difficult” is always relative to ones own skill level. I never said these things were exceptionally hard or difficult, but we all need to start somewhere. And let me tell you, making these vulnerable VMs is not as easy as it looks…


## Initial VM Setup

This system requires that you add an entry into your /etc/hosts file if you are Kali Linux.

```
127.0.0.1	localhost
127.0.1.1	kali
10.0.2.7	kioptrix3.com
```

Under Windows, you would edit C:\Windows\System32\drivers\etc\hosts to look something like this:

```
# localhost name resolution is handled within DNS itself.
#   127.0.0.1 localhost
#   ::1 localhost127.0.0.1 static3.cdn.ubi.com
192.168.1.102 kioptrix3.com
```

## Initial recon
### Nmap scan

We start initial active recon with an fast (-T4) aggressive (-A) scan of all TCP ports (-p-) and output to all formats (-oA).
Very Verbose output (-vv) to see live scanning results
```
sudo nmap 10.0.2.7 -T4 -A -vv -p- -oA tcp_all_ports_fast_agg
```

We can also run a quick (-T4) version UDP scan (-sUV) of the top 1000 ports to see if there is any interesting UDP ports.
```
sudo nmap -sUV -T4 -vv 10.0.2.15 -oA udp_fast_scan
```

### Nmap results
#### TCP Scan

#### UDP Scan

## Enumeration

## Privilege Escalation

## Summary
