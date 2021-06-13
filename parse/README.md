# Parse miio traffic

This folder contains code to parse PCAP files containg miio traffic for the
Xiaomi Air Purifier 3. It might work for other devices which support the miio
protocol too.

### Usage

First of all, I'd like to state that I'm learning OCaml and am a total beginner
, so try not to laugh at the quality of my code :p

To build and run this code,
```bash
$ dune exec ./pcap_parse.exe /path/to/pcap
```

Sample output will look something like this,
```
...
src: [52:ec:50:83:5f:64] [192.168.4.1] -> dst: [14:7d:da:4c:ae:40] [192.168.4.2]
        magic  : 0x2131
        len    : 0x0020
        unknow : 0x00000000
        id     : 0x101dbfd4
        stamp  : 0x000000f7
        token  : 186daf3367cc573f3f6a7e09fb8e0cf4
src: [14:7d:da:4c:ae:40] [192.168.4.2] -> dst: [52:ec:50:83:5f:64] [192.168.4.1]
        magic  : 0x2131
        len    : 0x00a0
        unknow : 0x00000000
        id     : 0x101dbfd4
        stamp  : 0x000000f8
        token  : 2acf801d856483319dbfa34417a51d0c
{"id": 102, "method": "miIO.config_router", "params": {"ssid": "test", "passwd": "test@12345", "uid": 0}}
src: [52:ec:50:83:5f:64] [192.168.4.1] -> dst: [14:7d:da:4c:ae:40] [192.168.4.2]
        magic  : 0x2131
        len    : 0x0020
        unknow : 0x00000000
        id     : 0x101dbfd4
        stamp  : 0x000000f7
        token  : 186daf3367cc573f3f6a7e09fb8e0cf4
src: [52:ec:50:83:5f:64] [192.168.4.1] -> dst: [14:7d:da:4c:ae:40] [192.168.4.2]
        magic  : 0x2131
        len    : 0x0020
        unknow : 0x00000000
        id     : 0x101dbfd4
        stamp  : 0x000000f7
        token  : 186daf3367cc573f3f6a7e09fb8e0cf4
src: [52:ec:50:83:5f:64] [192.168.4.1] -> dst: [14:7d:da:4c:ae:40] [192.168.4.2]
        magic  : 0x2131
        len    : 0x0040
        unknow : 0x00000000
        id     : 0x101dbfd4
        stamp  : 0x000000f7
        token  : 5cdcf7e053d59dc2f34e84fdd32ffdcb
{"id":102,"result":["ok"]}
...
```

### Refernces:
- [Protol definition](https://github.com/OpenMiHome/mihome-binary-protocol/blob/master/doc/PROTOCOL.md)
- [python-miio project](https://github.com/rytilahti/python-miio)
