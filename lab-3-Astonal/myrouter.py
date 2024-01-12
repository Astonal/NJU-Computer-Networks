#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces=net.interfaces()
        self.ip_list=[intf.ipaddr for intf in self.interfaces]
        self.mac_list=[intf.ethaddr for intf in self.interfaces]
        self.arp_table={}#key is IP & value is MAC

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp = packet.get_header(Arp)
        if arp is None:
            log_info("Receive a non-arp packet")
        else:
            self.arp_table[arp.senderprotoaddr]=arp.senderhwaddr#key is ip& value is mac
            #cache it regardless of opearation
            
            #print cache arp table
            log_info ("-------------------ARP TABLE-------------------")
            for myip,mymac in self.arp_table.items():
                log_info (f"    IP: {myip};     MAC: {mymac}")
            log_info ("---------------------------------------------------------")

            if arp.operation ==1:   #handling request
                log_info("arp request")
                num=-1
                for i in range(len(self.ip_list)):
                    if self.ip_list[i]==arp.targetprotoaddr:#if ip matches
                        num = i
                        break
                if num!= -1:    #if found one ip matches
                    log_info("arp match")
                    match_reply= create_ip_arp_reply(self.mac_list[num],arp.senderhwaddr,self.ip_list[num],arp.senderprotoaddr)
                    self.net.send_packet(ifaceName,match_reply)
            else:
                log_info("for now,not handled")

        
        


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

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
