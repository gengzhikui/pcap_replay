# pcap_replay
replay pcap files, doesn't care about transport layer, only replay payload, support tcp/udp

# List connections you have available
$ pcap_replay.py --pcap <pcap_file> --list

172.168.15.16:56675

172.168.15.10:80


# Run server side instance
$ pcap_replay.py --pcap <pcap_file> --server 127.0.0.2:9999 --connection 10.0.0.20:59471

# Run client side instance
$ pcap_replay.py --pcap <pcap_file> --client 127.0.0.2:9999 --connection 10.0.0.20:59471
