'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table = {}
    #key is MAC & value is interface


    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)

        table[eth.src]=fromIface #record in my table
        log_info(f"Record MAC:{eth.src} to interface:{fromIface}")
        
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        #if eth.src not in table:
        #    table[eth.src]=fromIface
        #    log_info(f"Record MAC:{eth.src} to interface:{fromIface}")
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        elif eth.dst in table:
            log_info(f"Sending packet {packet} to {table[eth.dst]}")
            net.send_packet(table[eth.dst],packet)
        else:
            for intf in my_interfaces:
                if fromIface!= intf.name:
                    log_info (f"Flooding packet {packet} to {intf.name}")
                    net.send_packet(intf, packet)

    net.shutdown()
