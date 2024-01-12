#!/usr/bin/env python3

'''
Ethernet hub in Switchyard.
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    ingress_packet_count = 0
    egress_packet_count = 0

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        ingress_packet_count += 1
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            #log_info(f"in:{ingress_packet_count} out:{egress_packet_count}")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
            #log_info(f"in:{ingress_packet_count} out:{egress_packet_count}")
        else:
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    egress_packet_count += 1
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    log_info(f"in:{ingress_packet_count} out:{egress_packet_count}")
                    net.send_packet(intf, packet)

    net.shutdown()
