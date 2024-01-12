#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *

class ForwardTableItem():
    def __init__(self,pref,mas,nex,inter):
        self.prefix=pref
        self.mask=mas
        self.nexthop=nex
        self.interfacename=inter

class QueueItem():
    def __init__(self,pkt,subnet,port,targetIP,ifacename):
        self.packet = pkt
        self.currentTime = time.time()
        self.retryTime = 0
        self.matchSubnet = subnet
        self.sendingPort = port
        self.targetIPAddr= targetIP
        self.ifacename = ifacename
        
class TargetIPQueue():
    def __init__(self,targetip,currentTime):
        self.targetip=targetip
        self.currentTime=currentTime
        self.retryTime=0
        self.targetiplist=[]

def Construct_ICMP_pingreply(packet,dstip):
    ether=Ethernet()
    ether.ethertype=EtherType.IP 
    ip=IPv4()
    ip.src=IPAddr(dstip)
    ip.dst=IPAddr(packet[IPv4].src)
    ip.protocol=IPProtocol.ICMP
    ip.ttl=64
    ip.ipid=0  
    icmp=ICMP()
    icmp.icmptype=ICMPType.EchoReply
    icmp.icmpcode=ICMPCodeEchoReply.EchoReply
    icmp.icmpdata.sequence=packet[ICMP].icmpdata.sequence
    icmp.icmpdata.identifier=packet[ICMP].icmpdata.identifier
    icmp.icmpdata.data=packet[ICMP].icmpdata.data  
    return ether+ip+icmp

def Construct_ICMP_error(origpkt, typeOfError, icmpCode, srcIP, dstIP):
    # the ICMP error message should not have an Ethernet header
    i = origpkt.get_header_index(Ethernet)
    del origpkt[i]
    eth = Ethernet()
    icmp = ICMP()
    icmp.icmptype = typeOfError
    icmp.icmpcode = icmpCode
    icmp.icmpdata.data = origpkt.to_bytes()[:28]
    ip = IPv4()
    ip.protocol = IPProtocol.ICMP
    ip.ttl = 64
    ip.src = srcIP
    ip.dst = dstIP
    pkt = eth + ip + icmp
    return pkt

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces=net.interfaces()
        self.arp_table={}#key is IP & value is MAC
        self.forwarding_table=[]
        self.myqueue=[]        
        #init forwarding_table
        #step 1:interfaces
        for i in self.interfaces:
            temp_prefix=IPv4Address(int(i.ipaddr)&int(i.netmask))
            temp_mask=IPv4Address(i.netmask)
            temp=ForwardTableItem(temp_prefix,temp_mask,'0.0.0.0',i.name)
            #log_info(f"  {temp_prefix}; {temp_mask}")
            self.forwarding_table.append(temp)
        #step 2:read file
        file=open("forwarding_table.txt")
        while (1):
            data = file.readline()
            if not data:
                break
            else:
                data = data.strip('\n')
                sp = data.split(" ")
                temp_prefix2=IPv4Address(sp[0])
                temp_netmask2=IPv4Address(sp[1])
                temp_item2=IPv4Address(sp[2])
                temp_name2=sp[3]
                temp2=ForwardTableItem(temp_prefix2,temp_netmask2,temp_item2,temp_name2)
                self.forwarding_table.append(temp2)

        log_info ("---------------FORWARDING TABLE----------------")
        for a in self.forwarding_table:
            log_info (f"{a.prefix}  ,{a.mask},  ,{a.nexthop},   ,{a.interfacename}")
        log_info ("-----------------------------------------------")    


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv

        log_info("receive a pkt {0}".format(str(packet)))
        # TODO: your logic here
        arp = packet.get_header(Arp)
        eth = packet.get_header(Ethernet)
        ipv4 =packet.get_header(IPv4)
        icmp = packet.get_header(ICMP)
        if  'Vlan' in packet.headers():
            return
        log_info ("-------------------ARP TABLE-------------------")
        for myip,mymac in self.arp_table.items():
            log_info (f"    IP: {myip};     MAC: {mymac}")
        log_info ("-----------------------------------------------")    
        #look up
        #step 1:check eth first
        port=self.net.interface_by_name(ifaceName)
        check=False
        if eth is not None:
            if (eth.dst != 'ff:ff:ff:ff:ff:ff'):                
                if port.ethaddr==eth.dst: #if eth mac matches
                    check = True
                    log_info("pass eth packet at step 1")
            else:
                log_info(f"eth.dst should be brocast: {eth.dst};")
                check=True
            if check == False:
                #drop it!
                    log_info("Drop an irrelevant packet at step 1")
                    return
        #try matching in the table
        if arp:
            if(eth is not None):
                if(check==False):
                    return
            #step 2:check arp dst and port
            check2 = False
            for intf in self.interfaces:
                if intf.ipaddr==arp.targetprotoaddr:
                    check2 = True
                    log_info("pass arp packet at step 2")
                    intfs=intf
                    break
            if check2 == False:  
                log_info("Drop an irrelevant packet at step 2")
                return
            if arp.operation ==ArpOperation.Request:   #handling request
                log_info("arp request")
                self.arp_table[arp.senderprotoaddr]=arp.senderhwaddr#key is ip& value is mac
                if check2 == True:    #if found one ip matches
                    log_info("arp match")
                    match_reply= create_ip_arp_reply(intfs.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                    self.net.send_packet(ifaceName,match_reply)
            elif arp.operation ==ArpOperation.Reply:                  
                if(arp.senderhwaddr!='ff:ff:ff:ff:ff:ff'):
                    self.arp_table[arp.senderprotoaddr]=arp.senderhwaddr#key is ip& value is mac
                    log_info("arp reply success!")
                else:
                    log_info("arp reply fail,broadcast!")
            else:
                log_info("for now,not handled")           

        if ipv4:
            head = packet[IPv4]
            for addr in self.interfaces:
                if head.dst == addr.ipaddr:
                    if (icmp is not None and icmp.icmptype == ICMPType.EchoRequest):
                        log_info("pingping")
                        packet = Construct_ICMP_pingreply(packet,addr.ipaddr)
                        log_info("now change to a pkt {0}".format(str(packet)))
                        head = packet[IPv4]
                        break
                    else:
                        #ICMP error 4 :Unsupported function
                        log_info("error 4,not a pingping")
                        icmps =packet.get_header(ICMP)
                        if icmps is not None and (icmps.icmptype==ICMPType.DestinationUnreachable or icmps.icmptype == ICMPType.TimeExceeded):
                            log_info("we dont need to handle icmp error 4")
                            return
                        for i in self.interfaces:
                            if i.name == ifaceName:
                                port4 = i
                                break
                        packet = Construct_ICMP_error(packet,ICMPType.DestinationUnreachable,3,port4.ipaddr,head.src)
                        log_info("now change to a pkt {0}".format(str(packet)))
                        head = packet[IPv4]
                        maxPrefixLen = 0
                        match = None
                        for b in self.forwarding_table:
                            if((int(head.dst)&int(b.mask))==int(b.prefix)):
                                networkAddr = IPv4Network(str(b.prefix)+"/"+str(b.mask))
                                if networkAddr.prefixlen>maxPrefixLen:
                                    maxPrefixLen = networkAddr.prefixlen
                                    match_subnet = IPv4Address(b.prefix)
                                    match_next_hop = b.nexthop
                                    match_interface = b.interfacename
                                    match = b
                        if match is None:
                            return
                        port4 = self.net.interface_by_name(match_interface)  #important, change the forward interface if necessary                  
                        packet[IPv4].src = port4.ipaddr                        
                        if(match_next_hop == '0.0.0.0'):#check next hop
                            match_destip= head.dst
                            log_info(f"next_hop should be 0: {match_next_hop};")
                        else:
                            match_destip = IPv4Address(match_next_hop)
                        log_info("enter enque from icmp error 1")
                        new_packet = QueueItem(packet,match_subnet,match_interface,match_destip,ifaceName)
                        judge = -1
                        for a in self.myqueue:
                            if a.targetip ==match_destip:
                                a.targetiplist.append(new_packet)
                                judge = a
                                break
                        if judge ==-1:
                            new_targetipqueue = TargetIPQueue(match_destip,time.time())
                            self.myqueue.append(new_targetipqueue)
                            for j in self.myqueue:
                                if j.targetip == match_destip:
                                    j.targetiplist.append(new_packet) 
                        return  #end ICMP error 4                     
            #start the prefix matching
            maxPrefixLen = 0
            match = None
            log_info(f"now have a ipv4.dst of {head.dst}")
            for i in self.forwarding_table:
                #if matches
                if((int(head.dst)&int(i.mask))==int(i.prefix)):
                    networkAddr = IPv4Network(str(i.prefix)+"/"+str(i.mask))
                    log_info(f"now we have a len of {networkAddr.prefixlen} for {networkAddr}")
                    if networkAddr.prefixlen>maxPrefixLen:
                        maxPrefixLen = networkAddr.prefixlen
                        match_subnet = IPv4Address(i.prefix)
                        match_next_hop = i.nexthop
                        match_interface = i.interfacename
                        match = i
            if match is None:
                #ICMP error 1 : No matching entries
                log_info("forwarding_table cannot match!")             
                icmps =packet.get_header(ICMP)
                if icmps is not None and (icmps.icmptype==ICMPType.DestinationUnreachable or icmps.icmptype == ICMPType.TimeExceeded):
                    log_info("we dont need to handle icmp error 1")
                    return
                for i in self.interfaces:
                    if i.name == ifaceName:
                        port = i
                        break
                packet = Construct_ICMP_error(packet,ICMPType.DestinationUnreachable,0,port.ipaddr,head.src)
                head = packet[IPv4]
                maxPrefixLen = 0
                match = None
                for b in self.forwarding_table:
                    if((int(head.dst)&int(b.mask))==int(b.prefix)):
                        networkAddr = IPv4Network(str(b.prefix)+"/"+str(b.mask))
                        if networkAddr.prefixlen>maxPrefixLen:
                            maxPrefixLen = networkAddr.prefixlen
                            match_subnet = IPv4Address(b.prefix)
                            match_next_hop = b.nexthop
                            match_interface = b.interfacename
                            match = b
                if match is None:
                    return      
                port = self.net.interface_by_name(match_interface)                    
                packet[IPv4].src = port.ipaddr
                log_info(f"the match port ip is :{packet[IPv4].src}")                          
                if(match_next_hop == '0.0.0.0'):#check next hop
                    match_destip= head.dst
                    log_info(f"next_hop should be 0: {match_next_hop};")
                else:
                    match_destip = IPv4Address(match_next_hop)
                log_info("enter enque from icmp error 1")
                new_packet = QueueItem(packet,match_subnet,match_interface,match_destip,ifaceName)
                judge = -1
                for a in self.myqueue:
                    if a.targetip ==match_destip:
                        a.targetiplist.append(new_packet)
                        judge = a
                        break
                if judge ==-1:
                    new_targetipqueue = TargetIPQueue(match_destip,time.time())
                    self.myqueue.append(new_targetipqueue)
                    for j in self.myqueue:
                        if j.targetip == match_destip:
                            j.targetiplist.append(new_packet)
            else:
                if(head.ttl>0):
                    head.ttl -=1
                if head.ttl <=0:
                    log_info("error 2 : ttl = 0 ")
                    #ICMP error 2 :the TTL becomes zero
                    icmps =packet.get_header(ICMP)
                    if icmps is not None and (icmps.icmptype==ICMPType.DestinationUnreachable or icmps.icmptype == ICMPType.TimeExceeded):
                        log_info("we dont need to handle icmp error 2")
                        return
                    log_info(f"the current ifacename is :{ifaceName}")
                    for i in self.interfaces:
                        log_info(f"-----{i.name}----{i.ipaddr}----")
                        if i.name == ifaceName:
                            port2 = i
                            break
                    packet = Construct_ICMP_error(packet,ICMPType.TimeExceeded,0,port2.ipaddr,head.src)
                    log_info("now change to a pkt {0}".format(str(packet)))
                    head = packet[IPv4]
                    maxPrefixLen = 0
                    match = None
                    for b in self.forwarding_table:
                        if((int(head.dst)&int(b.mask))==int(b.prefix)):
                            networkAddr = IPv4Network(str(b.prefix)+"/"+str(b.mask))
                            if networkAddr.prefixlen>maxPrefixLen:
                                maxPrefixLen = networkAddr.prefixlen
                                match_subnet = IPv4Address(b.prefix)
                                match_next_hop = b.nexthop
                                match_interface = b.interfacename
                                match = b
                    if match is None:
                        return
                    port2 = self.net.interface_by_name(match_interface)                    
                    packet[IPv4].src = port2.ipaddr
                    log_info("now change again to a pkt {0}".format(str(packet)))
                    if(match_next_hop == '0.0.0.0'):#check next hop
                        match_destip= head.dst
                        log_info(f"next_hop should be 0: {match_next_hop};")
                    else:
                        match_destip = IPv4Address(match_next_hop)
                    log_info("enter enque from icmp error 2")
                    new_packet = QueueItem(packet,match_subnet,match_interface,match_destip,ifaceName)
                    judge = -1
                    for a in self.myqueue:
                        if a.targetip ==match_destip:
                            a.targetiplist.append(new_packet)
                            judge = a
                            break
                    if judge ==-1:
                        new_targetipqueue = TargetIPQueue(match_destip,time.time())
                        self.myqueue.append(new_targetipqueue)
                        for j in self.myqueue:
                            if j.targetip == match_destip:
                                j.targetiplist.append(new_packet)
                else:#append to the queue  
                    if(match_next_hop == '0.0.0.0'):#check next hop
                        match_destip= head.dst
                        log_info(f"next_hop should be 0: {match_next_hop};")
                    else:
                        match_destip = IPv4Address(match_next_hop)
                        log_info(f"next_hop should be normal: {match_destip};")
                    log_info("______enter enque normally______")
                    log_info("now forward a pkt {0}".format(str(packet)))
                    new_packet = QueueItem(packet,match_subnet,match_interface,match_destip,ifaceName)
                    judge = -1
                    for a in self.myqueue:
                        if a.targetip ==match_destip:
                            a.targetiplist.append(new_packet)
                            judge = a
                            break
                    if judge ==-1:
                        new_targetipqueue = TargetIPQueue(match_destip,time.time())
                        self.myqueue.append(new_targetipqueue)
                        for j in self.myqueue:
                            if j.targetip == match_destip:
                                j.targetiplist.append(new_packet)
        #task 3:
    def forwarding(self):
        delete=[]
        log_info("entering forwarding")
        for i in range(len(self.myqueue)):
            targetIPAddr = self.myqueue[i].targetip        
            if(targetIPAddr in self.arp_table.keys()):#arp found
                for j in range(len(self.myqueue[i].targetiplist)):
                    senderPort = self.myqueue[i].targetiplist[j].sendingPort#interface name
                    routerPort = self.net.interface_by_name(senderPort)     #port
                    current_packet =self.myqueue[i].targetiplist[j]
                    mypacket=current_packet.packet
                    mypacket[Ethernet].src = routerPort.ethaddr
                    mypacket[Ethernet].dst = self.arp_table[targetIPAddr]
                    self.net.send_packet(senderPort,mypacket)
                    log_info(f"now we send eth packet from {routerPort.ethaddr} to {self.arp_table[targetIPAddr]} ")
                    log_info("send a packet")
                delete.append(self.myqueue[i])
                log_info("delete a full ip at empty list")                
            elif(self.myqueue[i].retryTime < 5): #arp retry              
                log_info("entering retrytime<5 plot:")
                senderPort = self.myqueue[i].targetiplist[0].sendingPort
                routerPort = self.net.interface_by_name(senderPort)
                if(self.myqueue[i].retryTime==0 ) or (time.time()-self.myqueue[i].currentTime>1.0):
                    log_info("trying to send again")
                    ether=Ethernet()
                    ether.src=routerPort.ethaddr
                    ether.dst='ff:ff:ff:ff:ff:ff'
                    ether.ethertype=EtherType.ARP
                    arp=Arp(operation=ArpOperation.Request,
                            senderhwaddr=routerPort.ethaddr,
                            senderprotoaddr=routerPort.ipaddr,
                            targethwaddr='ff:ff:ff:ff:ff:ff',
                            targetprotoaddr=targetIPAddr)
                    arppkt=ether+arp
                    log_info(f"now we send arp request from {routerPort.ipaddr} to {targetIPAddr} ")
                    self.net.send_packet(senderPort,arppkt)
                    self.myqueue[i].retryTime+=1
                    self.myqueue[i].currentTime=time.time()
            elif(self.myqueue[i].retryTime >=5):                                   
                if(time.time()-self.myqueue[i].currentTime>1.0):
                    log_info("retry time = 5:")                    
                    for j in range(len(self.myqueue[i].targetiplist)):
                        #ICMP error 3: ARP failure,the router should send an ICMP destination host unreachable back to the host
                        curpacket = self.myqueue[i].targetiplist[j].packet
                        log_info("now retry-judge a pkt {0}".format(str(curpacket)))
                        icmps = curpacket.get_header(ICMP)
                        if icmps is not None and (icmps.icmptype==ICMPType.DestinationUnreachable or icmps.icmptype == ICMPType.TimeExceeded):
                            log_info("we dont need to handle icmp error 3")
                            continue
                        for addr in self.interfaces:
                            if addr.name == self.myqueue[i].targetiplist[j].ifacename:
                                port3 = addr
                                break                        
                        errorsrcip = port3.ipaddr
                        errordstip = self.myqueue[i].targetiplist[j].packet[IPv4].src
                        errorpacket = Construct_ICMP_error(self.myqueue[i].targetiplist[j].packet,ICMPType.DestinationUnreachable,1,errorsrcip,errordstip)
                        head = errorpacket[IPv4]
                        maxPrefixLen=0
                        match = None
                        for b in self.forwarding_table:
                            if((int(head.dst)&int(b.mask))==int(b.prefix)):
                                networkAddr = IPv4Network(str(b.prefix)+"/"+str(b.mask))
                                if networkAddr.prefixlen>maxPrefixLen:
                                    maxPrefixLen = networkAddr.prefixlen
                                    match_subnet = IPv4Address(b.prefix)
                                    match_next_hop = b.nexthop
                                    match_interface = b.interfacename
                                    match = b
                        if match is None:
                            continue                        
                        if(match_next_hop == '0.0.0.0'):#check next hop
                            match_destip= head.dst
                            log_info(f"next_hop should be 0: {match_next_hop};")
                        else:
                            match_destip = IPv4Address(match_next_hop)
                        log_info("enter enque from icmp error 3")                        
                        new_packet = QueueItem(errorpacket,match_subnet,match_interface,match_destip,port3.name)                                               
                        judge = -1
                        for a in self.myqueue:
                            if a.targetip ==match_destip:
                                a.targetiplist.append(new_packet)
                                judge = a
                                break
                        if judge ==-1:
                            new_targetipqueue = TargetIPQueue(match_destip,time.time())
                            self.myqueue.append(new_targetipqueue)
                            for j in self.myqueue:
                                if j.targetip == match_destip:
                                    j.targetiplist.append(new_packet)
                delete.append(self.myqueue[i])
                log_info("delete a full ip at try>5")
        for k in delete:
            self.myqueue.remove(k)

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            self.forwarding()           
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
