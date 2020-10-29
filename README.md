# pcap_replay
replay pcap files, doesn't care about transport layer, only replay payload, support tcp/udp

# List connections you have available
$ pcap_replay.py --pcap <pcap_file> --list
10.0.0.20:59471 -> 192.168.132.1:80 (starting at frame 0)
192.168.132.1:80 -> 10.0.0.20:59471 (starting at frame 1)


# Run server side instance
$ pcap_replay.py --pcap <pcap_file> --server 127.0.0.2:9999 --connection 10.0.0.20:59471

# Run client side instance
$ pcap_replay.py --pcap <pcap_file> --client 127.0.0.2:9999 --connection 10.0.0.20:59471
