#!/usr/bin/env python3

import sys
import os
import socket
import time
import difflib
import re
import argparse
import fileinput
import binascii
import datetime
import tempfile
import json
import traceback
import platform

from select import select

have_scapy = False
have_colorama = False

option_dump_received_correct = False
option_dump_received_different = True
option_auto_send = 3

pcap_replay_version = "1.0.0"
title = 'pcap_replay - application payload player - %s' % (pcap_replay_version,)
pcap_replay_copyright = "written by gengzk <gengzhikui@gmail.com> (c) 2020"

try:
    from scapy.all import rdpcap
    from scapy.all import IP
    from scapy.all import TCP
    from scapy.all import UDP
    from scapy.all import Padding

    have_scapy = True
except ImportError as e:
    print('== No scapy, pcap files not supported.', file=sys.stderr)

## try to import colorama, indicate with have_ variable
try:
    import colorama
    from colorama import Fore, Back, Style

    have_colorama = True
except ImportError as e:
    print('== No colorama library, enjoy.', file=sys.stderr)

def str_time():
    t = None
    failed = False
    try:
        t = datetime.now()
    except AttributeError as e:
        failed = True

    if not t and failed:
        try:
            t = datetime.datetime.now()
        except Exception as e:
            t = "<?>"

    return socket.gethostname() + "@" + str(t)


def print_green_bright(what):
    if have_colorama:
        print(Fore.GREEN + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_green(what):
    if have_colorama:
        print(Fore.GREEN + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_yellow_bright(what):
    if have_colorama:
        print(Fore.YELLOW + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_yellow(what):
    if have_colorama:
        print(Fore.YELLOW + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_red_bright(what):
    if have_colorama:
        print(Fore.RED + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_red(what):
    if have_colorama:
        print(Fore.RED + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_white_bright(what):
    if have_colorama:
        print(Fore.WHITE + Style.BRIGHT + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


def print_white(what):
    if have_colorama:
        print(Fore.WHITE + what + Style.RESET_ALL, file=sys.stderr)
    else:
        print(what, file=sys.stderr)


__vis_filter = """................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""


def hexdump(xbuf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []

    buf = bytes(xbuf).decode('ascii', errors="ignore")

    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % ord(x) for x in line])
        line = line.translate(__vis_filter)
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)


def colorize(s, keywords):
    t = s
    for k in keywords:
        t = re.sub(k, Fore.CYAN + Style.BRIGHT + k + Fore.RESET + Style.RESET_ALL, t)

    return t


# print_green_bright("TEST%d:%s" % (12,54))


class Repeater:

    def __init__(self, fnm, server_ip, custom_sport=None):

        self.fnm = fnm

        self.packets = []
        self.origins = {}

        # write this data :)
        self.to_send = b''

        # list of indexes in packets
        self.origins['client'] = []
        self.origins['server'] = []

        self.sock = None
        self.sock_upgraded = None

        self.server_port = 0
        self.custom_ip = server_ip
        self.custom_sport = custom_sport  # custom source port (only with for client connections)

        self.whoami = ""

        # index of our origin
        self.packet_index = 0

        # index of in all packets regardless of origin
        self.total_packet_index = 0

        # packet read counter (don't use it directly - for read_packet smart reads)
        self.read_packet_counter = 0

        self.tstamp_last_read = 0
        self.tstamp_last_write = 0
        self._last_countdown_print = 0

        self.exitoneot = False
        self.nohexdump = False

        self.omexit = False

        self.is_udp = False

        # our peer (ip,port)
        self.target = (0, 0)

        # countdown timer for sending
        self.send_countdown = 0

    def list_pcap(self, verbose=False):

        flows = {}
        ident = {}
        frame = -1

        if verbose:
            print_yellow("# >>> Flow list:")

        s = rdpcap(self.fnm)
        for i in s:

            frame += 1

            try:
                sip = i[IP].src
                dip = i[IP].dst
            except IndexError as e:
                # not even IP packet
                continue

            proto = "TCP"

            sport = ""
            dport = ""

            # TCP
            try:
                sport = str(i[TCP].sport)
                dport = str(i[TCP].dport)
            except IndexError as e:
                proto = "UDP"

            # UDP
            if proto == "UDP":
                try:
                    sport = str(i[UDP].sport)
                    dport = str(i[UDP].dport)
                except IndexError as e:
                    proto = "Unknown"

            # Unknown
            if proto == "Unknown":
                continue

            key = proto + " / " + sip + ":" + sport + " -> " + dip + ":" + dport
            ident1 = sip + ":" + sport
            ident2 = dip + ":" + dport

            if key not in flows:
                if verbose:
                    print_yellow("%s (starting at frame %d)" % (key, frame))
                flows[key] = (ident1, ident2)

                if ident1 not in ident.keys():
                    ident[ident1] = []
                if ident2 not in ident.keys():
                    ident[ident2] = []

                ident[ident1].append(key)
                ident[ident2].append(key)

        print_yellow("\n# >>> Usable connection IDs:")
        if verbose:
            print_white("   Yellow - probably services")
            print_white("   Green  - clients\n")

        for unique_ident in ident.keys():

            port = unique_ident.split(":")[1]
            if int(port) < 1024:
                print_yellow(unique_ident + "\n# %d simplex flows" % (len(ident[unique_ident]),))
            else:
                flow_count = len(ident[unique_ident])

                if flow_count > 2:
                    # Fore.RED + Style.BRIGHT + what + Style.RESET_ALL
                    print_green(unique_ident + Fore.RED + "\n# %d simplex flows" % (len(ident[unique_ident]),))
                else:
                    print_green(unique_ident)

    def read_pcap(self, im_ip, im_port):

        s = rdpcap(self.fnm)

        for i in s:

            try:
                sip = i[IP].src
                dip = i[IP].dst
                sport = 0
                dport = 0
                proto = i[IP].proto

                # print_white("debug: read_pcap: ip.proto " +  str(i[IP].proto))
                if i[IP].proto == 6:
                    sport = str(i[TCP].sport)
                    dport = str(i[TCP].dport)
                elif i[IP].proto == 17:
                    sport = str(i[UDP].sport)
                    dport = str(i[UDP].dport)

            except IndexError as e:
                # IndexError: Layer [TCP|UDP|IP] not found
                continue

            # print ">>> %s:%s -> %s:%s" % (sip,sport,dip,dport)

            origin = None

            if sip == im_ip and sport == im_port:
                origin = "client"
                if self.server_port == 0:
                    self.server_port = dport

            elif dip == im_ip and dport == im_port:
                origin = "server"

            if origin:
                p = ""

                if proto == 6:
                    p = i[TCP].payload
                elif proto == 17:
                    p = i[UDP].payload
                else:
                    print_red("read_cap: cannot find payload in packet")
                    continue

                if len(p) == 0:
                    # print "No payload"
                    continue

                # print("--")
                # print("Len: %s",help(p))
                if isinstance(p, Padding) or type(p) == type(Padding):
                    print("... reached end of tcp, frame contains padding")
                    continue
                # print(hexdump(str(p)))

                current_index = len(self.packets)

                self.packets.append(bytes(p))
                self.origins[origin].append(current_index)

                # print "%s payload:\n>>%s<<" % (origin,p,)

    # for spaghetti lovers
    def impersonate(self, who):
        if who == "client":
            self.impersonate_client()
        elif who == "server":
            self.impersonate_server()

    def send_aligned(self):
        if self.packet_index < len(self.origins[self.whoami]):
            return self.total_packet_index >= self.origins[self.whoami][self.packet_index]
        return False

    def send_issame(self):
        if self.packet_index < len(self.origins[self.whoami]):
            return self.packets[self.origins[self.whoami][self.packet_index]] == self.to_send
        return False

    def ask_to_send(self, xdata=None):
        data = None
        if xdata is None:
            data = self.to_send
        else:
            data = xdata

        aligned = ''
        if self.send_aligned():
            aligned = '(in-sync'
        else:
            aligned = '(off-sync'

        if not self.send_issame():
            if aligned:
                aligned += ", modified"
            else:
                aligned += "(modified"

        if aligned:
            aligned += ") "

        out = "# [%d/%d]: %s" % (self.packet_index + 1, len(self.origins[self.whoami]), aligned)
        if self.send_aligned():
            print_green_bright(out)
        else:
            print_yellow(out)

        out = ''
        if self.nohexdump:
            out = "# ... offer to send %dB of data (hexdump suppressed): " % (len(data),)
        else:
            out = hexdump(data)

        if self.send_aligned():
            print_green(out)
        # 
        # dont print hexdumps of unaligned data
        # else:
        #    print_yellow(out)

        if option_auto_send < 0 or option_auto_send >= 3:

            out = ''
            if self.send_aligned():
                print_green_bright(out)
            else:
                print_yellow(out)


    def prepare_socket(self, s, server_side=False):
        return s

    def impersonate_client(self):
        try:
            self.whoami = "client"

            s = None
            if self.is_udp:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            ip = self.custom_ip
            port = int(self.server_port)

            t = ip.split(":")
            if len(t) > 1:
                ip = t[0]
                port = int(t[1])

            if port == 0:
                port = int(self.server_port)

            self.target = (ip, port)

            print_white_bright("IMPERSONATING CLIENT, connecting to %s:%s" % (ip, port))

            self.sock = s

            try:
                if self.custom_sport:
                    self.sock.bind(('', int(self.custom_sport)))

                self.sock.connect((ip, int(port)))
            except socket.error as e:
                print_white_bright(" === ")
                print_white_bright("   Connecting to %s:%s failed: %s" % (ip, port, e))
                print_white_bright(" === ")
                print(traceback.format_exc())
                return

            try:
                self.sock = self.prepare_socket(self.sock, False)
                self.packet_loop()

            except socket.error as e:
                print_white_bright(" === ")
                print_white_bright("   Connection to %s:%s failed: %s" % (ip, port, e))
                print_white_bright(" === ")
                print(traceback.format_exc())
                return


        except KeyboardInterrupt as e:
            print_white_bright("\nCtrl-C: bailing it out.")
            return


    def impersonate_server(self):
        try:
            ip = "0.0.0.0"
            port = int(self.server_port)

            if self.custom_ip:

                t = self.custom_ip.split(":")
                if len(t) > 1:
                    ip = t[0]
                    port = int(t[1])

                elif len(t) == 1:
                    # assume it's port
                    port = int(t[0])

                # if specified port is 0, use original port in the capture
                if port == 0:
                    port = int(self.server_port)

                # print("custom IP:PORT %s:%s" % (ip,port) )

            self.whoami = "server"
            print_white_bright("IMPERSONATING SERVER, listening on %s:%s" % (ip, port,))

            server_address = (ip, int(port))

            if self.is_udp:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if not self.is_udp:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            s.bind(server_address)

            if not self.is_udp:
                s.listen(1)

            while True:
                print_white("waiting for new connection...")

                conn = None
                client_address = ["", ""]

                if not self.is_udp:
                    while True:
                        readable, writable, errored = select([s, ], [], [], 0.25)
                        if s in readable:
                            break
                        else:
                            # timeout
                            if self.detect_parent_death():
                                self.on_parent_death()

                    conn, client_address = s.accept()
                    self.target = client_address
                    print_white_bright("accepted client from %s:%s" % (client_address[0], client_address[1]))
                else:
                    conn = s
                    client_address = ["", ""]

                conn = self.prepare_socket(conn, True)
                self.sock = conn

                try:
                    self.packet_loop()
                except KeyboardInterrupt as e:
                    print_white_bright(
                        "\nCtrl-C: hit in client loop, exiting to accept loop. Hit Ctrl-C again to terminate.")
                    self.sock.close()
                except socket.error as e:
                    print_white_bright(
                        "\nConnection with %s:%s terminated: %s" % (client_address[0], client_address[1], e,))
                    print(traceback.format_exc())

                    if self.exitoneot:
                        print_red("Exiting on EOT")
                        sys.exit(0)

                    if self.is_udp:
                        break

                # reset it in both cases when Ctrl-C received, or connection was closed
                self.packet_index = 0
                self.total_packet_index = 0

            # print_white("debug: end of loop.")

        except KeyboardInterrupt as e:
            print_white_bright("\nCtrl-C: bailing it out.")
            return
        except socket.error as e:
            print_white_bright("Server error: %s" % (e,))
            sys.exit(16)

    def read(self, blocking=True):
        self.tstamp_last_read = time.time()
        if not self.is_udp:
            self.sock.setblocking(True)
            return self.sock.recv(24096)
        else:
            data, client_address = self.sock.recvfrom(24096)
            self.target = client_address
            self.sock.setblocking(True)
            return data

    def write(self, data):

        if not data:
            return 0

        ll = len(data)
        l = 0

        self.tstamp_last_write = time.time()
        if not self.is_udp:
            while l < ll:
                r = self.sock.send(data[l:])
                l += r

                if r != ll:
                    print_red_bright("debug write: sent %d out of %d" % (l, ll))

            return l

        else:
            return self.sock.sendto(data, self.target)

    def load_to_send(self, role, role_index):
        who = self
        to_send_idx = who.origins[role][role_index]
        return who.packets[to_send_idx]

    def send_to_send(self):
        if self.to_send:
            self.packet_index += 1
            self.total_packet_index += 1

            total_data_len = len(self.to_send)
            total_written = 0

            while total_written != total_data_len:
                cnt = self.write(self.to_send)

                # not really clean debug, lots of data will be duplicated
                # if cnt > 200: cnt = 200

                data_len = len(self.to_send)

                if cnt == data_len:
                    print_green_bright("# ... %s [%d/%d]: has been sent (%d bytes)" % (
                        str_time(), self.packet_index, len(self.origins[self.whoami]), cnt))
                else:
                    print_green_bright("# ... %s [%d/%d]: has been sent (ONLY %d/%d bytes)" % (
                        str_time(), self.packet_index, len(self.origins[self.whoami]), cnt, data_len))
                    self.to_send = self.to_send[cnt:]

                total_written += cnt

            self.to_send = None

    def detect_parent_death(self):
        # mypid = os.getpid()
        # parpid = os.getppid()
        # print_red_bright("mypid %d, parent pid %d" % (mypid,parpid,))        

        return os.getppid() == 1

    def on_parent_death(self):
        sys.exit(-2)

    def select_wrapper(self, no_writes):
        inputs = [self.sock, ]
        outputs = [self.sock]
        if no_writes:
            outputs.remove(self.sock)

        # print(inputs, outputs, [], 0.2)
        r, w, e = select(inputs, outputs, [], 0.2)
        if self.detect_parent_death():
            self.on_parent_death()

        return r, w, e

    def is_eot(self):
        return self.total_packet_index >= len(self.packets)

    def packet_read(self):
        # print_red_bright("DEBUG: reading socket")
        d = self.read()

        # print_red_bright("DEBUG: read returned %d" % len(d))
        if not len(d):
            return len(d)

        expected_data = self.packets[self.total_packet_index]

        # wait for some time
        loopcount = 0
        len_expected_data = len(expected_data)
        len_d = len(str(d))
        t_start = time.time()

        while len_d < len_expected_data:
            # print_white("incomplete data: %d/%d" % (len_d,len_expected_data))
            loopcount += 1

            delta = time.time() - t_start
            if delta > 1:
                time.sleep(0.05)

            if delta > 10:
                break

            d += self.read()
            len_d = len(str(d))

        else:
            print_white("finished data: %d/%d" % (len_d, len_expected_data))

        # there are still some data to send/receive
        if self.total_packet_index < len(self.packets):
            # test if data are as we should expect
            aligned = False

            # if auto is enabled, we will not wait for user input when we received already some packet
            # user had to start pcap_replay on the other side
            if option_auto_send:
                self.auto_send_now = time.time()

            # to print what we got and what we expect
            # print_white_bright(hexdump(d))
            # print_white_bright(hexdump(self.packets[self.total_packet_index]))

            if d == self.packets[self.total_packet_index]:
                aligned = True
                self.total_packet_index += 1
                print_red_bright("# ... %s: received %dB OK" % (str_time(), len(d)))


            else:
                print_red_bright("# !!! /!\ DIFFERENT DATA /!\ !!!")
                smatch = difflib.SequenceMatcher(None, bytes(d).decode("ascii", errors='ignore'),
                                                 bytes(self.packets[self.total_packet_index]).decode("ascii",
                                                                                                     errors='ignore'),
                                                 autojunk=False)
                qr = smatch.ratio()
                if qr > 0.05:
                    print_red_bright(
                        "# !!! %s received %sB modified (%.1f%%)" % (str_time(), len(d), qr * 100))
                    self.total_packet_index += 1
                else:
                    print_red_bright("# !!! %s received %sB of different data" % (str_time(), len(d)))

            # this block is printed while in the normal packet loop (there are packets still to receive or send
            if aligned:
                if option_dump_received_correct:
                    print_red_bright("#-->")
                    print_red(hexdump(d))
                    print_red_bright("#<--")
            else:
                if option_dump_received_different:
                    print_red_bright("#-->")
                    print_red(hexdump(d))
                    print_red_bright("#<--")

        # this block means there is nothing to send/receive
        else:
            if option_dump_received_different:
                print_red_bright("#-->")
                print_red(hexdump(d))
                print_red_bright("#<--")

        # we have already data to send prepared!
        if self.to_send:
            #  print, but not block
            self.ask_to_send(self.to_send)

        return len(d)

    def packet_write(self):
        if self.packet_index >= len(self.origins[self.whoami]):
            print_yellow_bright("# [EOT]")
            # if we have nothing to send, remove conn from write set
            self.to_send = None
            self.write_end = True
            return
        else:
            if not self.to_send:
                self.to_send = self.load_to_send(self.whoami, self.packet_index)

                self.ask_to_send(self.to_send)

            else:
                # auto_send feature
                if option_auto_send > 0 and self.send_aligned():

                    now = time.time()
                    if self._last_countdown_print == 0:
                        self._last_countdown_print = now

                    delta = now - self._last_countdown_print
                    # print out the dot
                    if delta >= 1:

                        self.send_countdown = round(self.auto_send_now + option_auto_send - now)

                        # print dot only if there some few seconds to indicate
                        if option_auto_send >= 2:
                            # print(".",end='',file=sys.stderr)
                            # print(".",end='',file=sys.stdout)
                            if self.send_countdown > 0:
                                print("..%d" % (self.send_countdown,), end='\n', file=sys.stdout)
                                sys.stdout.flush()

                        self._last_countdown_print = now

                    if now - self.auto_send_now >= option_auto_send:

                        # indicate sending only when there are few seconds to indicate
                        if option_auto_send >= 2:
                            print_green_bright("  ... sending!")

                        been_sent = self.to_send
                        orig_index = self.packet_index

                        self.send_to_send()
                        self.auto_send_now = now

    def packet_loop(self):
        global option_auto_send
        running = 1
        self.write_end = False
        self.auto_send_now = time.time()
        eof_notified = False

        while running:
            # time.sleep(0.2)
            # print_red(".")

            if self.is_eot():

                # print_red_bright("DEBUG: is_eot returns true")

                if not eof_notified:
                    print_red_bright("### END OF TRANSMISSION ###")
                    eof_notified = True

                if self.exitoneot:
                    # print_red_bright("DEBUG: exitoneot true")

                    if self.whoami == "server":
                        if option_auto_send >= 0:
                            time.sleep(option_auto_send)
                        else:
                            time.sleep(0.5)

                    print_red("Exiting on EOT")

                    if not self.is_udp:
                        self.sock.shutdown(socket.SHUT_WR)
                    self.sock.close()
                    sys.exit(0)

            r, w, e = self.select_wrapper(self.write_end)

            # print_red_bright("DEBUG: sockets: r %s, w %s, e %s" % (str(r), str(w), str(e)))

            if self.sock in r and not self.send_aligned():

                l = self.packet_read()

                if l == 0:
                    print_red_bright("#--> connection closed by peer")
                    if self.exitoneot:
                        print_red("Exiting on EOT")
                        if not self.is_udp:
                            self.sock.shutdown(socket.SHUT_WR)
                        self.sock.close()
                        sys.exit(0)

                    break

            if self.sock in w:
                if not self.write_end:
                    self.packet_write()

def main():
    global option_auto_send, have_colorama

    parser = argparse.ArgumentParser(
        description=title,
        epilog=" - %s " % (pcap_replay_copyright,))

    schemes_supported = "file,"
    schemes_supported = schemes_supported[:-1]

    ds = parser.add_argument_group("Data Sources [%s]" % (schemes_supported,))
    group1 = ds.add_mutually_exclusive_group()
    if have_scapy:
        group1.add_argument('--pcap', nargs=1,
                            help='pcap where the traffic should be read (retransmissions not checked)')

    ac = parser.add_argument_group("Actions")
    group2 = ac.add_mutually_exclusive_group()
    group2.add_argument('--client', nargs=1,
                        help='replay client-side of the CONNECTION, connect and send payload to specified '
                             'IP address and port. Use IP:PORT or IP.')
    group2.add_argument('--server', nargs='?',
                        help='listen on port and replay server payload, accept incoming connections. '
                             'Use IP:PORT or PORT')
    group2.add_argument('--list', action='store_true',
                        help='rather than act, show to us list of connections in the specified sniff file')
    
    ac_sniff = ac.add_mutually_exclusive_group()
    ac_sniff.add_argument('--connection', nargs=1,
                          help='replay specified connection; use format <src_ip>:<sport>. '
                               'IMPORTANT: it\'s SOURCE based to match unique flow!')

    prot = parser.add_argument_group("Protocol options")
    
    prot.add_argument('--tcp', required=False, action='store_true',
                      help='toggle to override L3 protocol from file and send payload in TCP')
    prot.add_argument('--udp', required=False, action='store_true',
                      help='toggle to override L3 protocol from file and send payload in UDP')
    prot.add_argument('--sport', required=False, nargs=1, help='Specify source port')

    var = parser.add_argument_group("Various")
    prot.add_argument('--version', required=False, action='store_true', help='just print version and terminate')
    var.add_argument('--exitoneot', required=False, action='store_true',
                     help='If there is nothing left to send and receive, terminate. Effective only in --client mode.')
    var.add_argument('--nohex', required=False, action='store_true', help='Don\'t show hexdumps for data to be sent.')
    var.add_argument('--nocolor', required=False, action='store_true', help='Don\'t use colorama.')

    var.add_argument('--verbose', required=False, action='store_true', help='Print out more output.')

    args = parser.parse_args(sys.argv[1:])
    
    if have_colorama:
        if not args.nocolor:
            colorama.init(autoreset=False, strip=False)
        else:
            have_colorama = False

    if args.version:
        print_white_bright(title)
        print_white(pcap_replay_copyright)
        sys.exit(0)

    r = None
    if (have_scapy and args.pcap):

        fnm = ""
        is_local = False

        if args.pcap:
            fnm = args.pcap[0]
        else:
            print_red_bright("it should not end up this way :/")
            sys.exit(255)

        if fnm.startswith("file://"):
            fnm = fnm[len("file://"):]
            is_local = True
        else:
            is_local = True

        if fnm:
            if not os.path.isfile(fnm):
                print_red_bright("local file doesn't exist: " + fnm)
                sys.exit(3)

            r = Repeater(fnm, "")

    elif args.list:
        pass

    else:
        print_yellow_bright(title)
        print_yellow_bright(pcap_replay_copyright)
        print("")
        print_red("Colors support       : %d" % have_colorama)
        print_red("PCAP files support   : %d" % have_scapy)
        print_red_bright("\nerror: nothing to do!")
        sys.exit(-1)

    if r is not None:
        if args.tcp:
            r.is_udp = False

        if args.udp:
            r.is_udp = True

    if args.list:
        if have_scapy and args.pcap:
            r.list_pcap(args.verbose)

        sys.exit(0)

    if args.client or args.server:
        if args.connection:
            l = args.connection[0].split(":")
            im_ip = None
            im_port = None

            if len(l) != 2:
                print_red_bright("error: connection syntax!")
                sys.exit(-1)

            im_ip = l[0]
            im_port = l[1]

            if have_scapy and args.pcap:
                r.read_pcap(im_ip, im_port)

            if args.tcp:
                r.is_udp = False
            elif args.udp:
                r.is_udp = True

        # ok regardless data controlled by script or capture file read
        if args.client or args.server:
            if args.nohex:
                r.nohexdump = True

            if args.client:

                if args.sport:
                    r.custom_sport = args.sport[0]

                if len(args.client) > 0:
                    r.custom_ip = args.client[0]

                if args.exitoneot:
                    r.exitoneot = True

                r.impersonate('client')

            elif args.server:

                if args.exitoneot:
                    r.exitoneot = True

                if len(args.server) > 0:
                    # arg type is '?' so no list there, just string
                    r.custom_ip = args.server
                else:
                    r.custom_ip = None

                r.impersonate('server')

    else:
        print_white_bright(
            "No-op! You wanted probably to set either --client <target_server_ip> or --server arguments ... Hmm?")

if __name__ == "__main__":
    main()
