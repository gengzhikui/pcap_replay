# pcap_replay
replay pcap files, doesn't care about transport layer, only replay payload, support tcp/udp

## 1. List connections you have available
$ pcap_replay.py --pcap <pcap_file> --list

172.168.15.16:56675

172.168.15.10:80


## 2. Run server side instance
$ pcap_replay.py --pcap <pcap_file> --server 0.0.0.0:80 --connection 172.168.15.10:80

## 3. Run client side instance
$ pcap_replay.py --pcap <pcap_file> --client <real_server_ip>:80 --connection 172.168.15.10:80

