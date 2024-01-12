'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *
import time

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

        mytime = time.time()    
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)

        #table[eth.src]=[fromIface,mytime]   #record in my table
        #log_info(f"Record MAC:{eth.src} to interface:{fromIface} on time:{mytime}")
        
        for mac in list(table.keys()):      #time out
            if((mytime-table[mac][1])>10.0):
                del table[mac]


        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.src not in table:
                table[eth.src]=[fromIface,time.time()]
                log_info(f"Record MAC:{eth.src} to interface:{fromIface} on time:{mytime}")
            else:#in the table
                if(fromIface==table[eth.src][0]):
                    table[eth.src][1]=time.time()
                else:
                    table[eth.src]=[fromIface,time.time()]
                    log_info(f"Update MAC:{eth.src} to interface:{fromIface} on time:{mytime}")
        
            if eth.dst in table:
                log_info(f"Sending packet {packet} to {table[eth.dst][0]}")
                net.send_packet(table[eth.dst][0],packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
