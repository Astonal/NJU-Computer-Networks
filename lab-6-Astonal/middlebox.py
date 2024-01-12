#!/usr/bin/env python3

import time
import threading
from random import randint
import random

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_debug("Received from blaster")
            log_info("get from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            random.seed(time.time())
            rand = randint(1,100)
            ipv4=packet.get_header(IPv4)
            # check whether we should drop
            if ipv4 is not None:
                if rand <=self.dropRate*100:
                    log_info(f"middlebox decides to drop the packet {packet}")
                    seq = int.from_bytes(packet[RawPacketContents].to_bytes()[:4],'big')
                    print(f"drop the seq:{seq}")
                else:
                    # send
                    packet[Ethernet].src = '40:00:00:00:00:02'
                    packet[Ethernet].dst = '20:00:00:00:00:01'
                    packet[IPv4].ttl -=1
                    log_info(f"middlebox sends packet {packet} to blastee")
                    self.net.send_packet("middlebox-eth1", packet)
        elif fromIface == "middlebox-eth1":
            log_debug("Received from blastee")
            log_info("get from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            ipv4=packet.get_header(IPv4)            
                # send
            if ipv4 is not None:
                packet[Ethernet].src = '40:00:00:00:00:01'
                packet[Ethernet].dst = '10:00:00:00:00:01'
                packet[IPv4].ttl -=1
                log_info(f"middlebox sends packet {packet} to blaster")
                self.net.send_packet("middlebox-eth0", packet)
        else:
            log_debug("Oops :))")

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
