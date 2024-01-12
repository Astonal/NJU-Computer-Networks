'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *

MAX = 2 

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    table = {}


    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)

        for key in table.keys():
            table[key][1]+=1 #age++
        

        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.src in table.keys():
                if (fromIface != table[eth.src][0]):
                    table[eth.src][0]=[fromIface]  #without modifying LRU order!
            else:  # src not in
                if (len(table)<MAX):#not full
                    table[eth.src]=[fromIface,0]
                else: #full,delete max_age
                    lru_key=list(table.keys())[0]
                    for key in table.keys():
                        if table[key][1]>table[lru_key][1]:
                            lru_key=key
                    del table[lru_key]
                    table[eth.src]=[fromIface,0]
            if eth.dst in table.keys():
                log_info(f"Sending packet {packet} to {table[eth.dst][0]}")
                table[eth.dst][1]=0
                net.send_packet(table[eth.dst][0],packet)
            else:    
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
