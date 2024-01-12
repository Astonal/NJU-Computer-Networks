#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = IPv4Address(blasterIp)
        self.num=int(num)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        #print(f"seq::::{packet[RawPacketContents].to_bytes()[:4]}")
        #print(f"payload::::{packet[RawPacketContents].to_bytes()[6:]}")
        ackpkt = Ethernet() + IPv4(protocol = IPProtocol.UDP) + UDP()
        ackpkt[Ethernet].src = '20:00:00:00:00:01'
        ackpkt[Ethernet].dst = '40:00:00:00:00:02'
        ackpkt[IPv4].src = '192.168.200.1'
        ackpkt[IPv4].dst = self.blasterIp
        ackpkt[IPv4].ttl = 64

        seq = packet[RawPacketContents].to_bytes()[:4]
        payload = packet[RawPacketContents].to_bytes()[6:]
        print("blastee recv seq: {}".format(int.from_bytes(seq,'big')))
        # edit payload
        if len(payload) > 8:
            payload = payload[:8]

        ackpkt.add_header(RawPacketContents(seq))
        ackpkt.add_header(RawPacketContents(payload))
        # send ACK
        self.net.send_packet("blastee-eth0", ackpkt)





    def start(self):
        '''A running daemon of the blastee.
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
    blastee = Blastee(net, **kwargs)
    blastee.start()
