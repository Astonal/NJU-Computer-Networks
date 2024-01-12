#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp=IPv4Address(blasteeIp)
        self.length=int(length)
        self.senderWindow=int(senderWindow)
        self.timeout=int(timeout)
        self.recvTimeout=int(recvTimeout) 
        self.num = int(num)

        self.LHS=1  # left
        self.RHS=0  # right
        self.sliding_window=[]  # the sliding window queue
        
        self.start_time=time.time()
        self.LHS_time=time.time()    # sliding window timer
        
        self.reTX_num=0 #the retransmit num
        self.suc_num=0  #succussful num
        self.timeout_num=0  #time out num
        self.total_num=0
        self.total_time=0   
        
        self.ack_queue=[]   # ACK queue
        self.nonack_queue=[]# non-ACK queue
        self.retrans_queue=[]
        self.retrans_state = False

        #statictics:Total TX time / Number of reTX / Number of coarse TOs
        #Throughput (Bps)/ Goodput (Bps)     

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")

        seq = int.from_bytes(packet[RawPacketContents].to_bytes()[:4], 'big')
        #print(f"blaster recv seq: {seq}")
        #print(f"get seq::::{packet[RawPacketContents].to_bytes()[:4]}")
        #print(f"get payload::::{packet[RawPacketContents].to_bytes()[6:]}")
        #print(f"now LHS is {self.LHS}")

        if seq in self.sliding_window:
            self.sliding_window.remove(seq)

        if seq in self.nonack_queue:
            self.nonack_queue.remove(seq)
            self.ack_queue.append(seq)
            self.total_time=time.time()-self.start_time
            self.suc_num += 1              
            ### important!
            self.LHS_time = time.time()

        if self.nonack_queue == []:           
            self.LHS = max(self.ack_queue) + 1
            #print(f"LHS has increase to {self.LHS}")
            self.LHS_time = time.time()
        else:
            self.LHS = min(self.nonack_queue)
            #print(f"LHS now is --- {self.LHS} ---")


    def handle_no_packet(self):
        log_debug("Didn't receive anything")

        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        pkt[1].protocol = IPProtocol.UDP

        # Do other things here and send packet
        pkt[Ethernet].src = '10:00:00:00:00:01'
        pkt[Ethernet].dst = '40:00:00:00:00:01'
        pkt[IPv4].src = '192.168.100.1'
        pkt[IPv4].dst = IPv4Address(self.blasteeIp)
        pkt[IPv4].ttl = 64

        #print(f"-----delta time: {float(time.time()-self.LHS_time)}with self.timeout:0.3-----")

        # if timeout, retransmit nonack packet
        if (float(time.time()-self.LHS_time) >0.3):
                  
            if self.retrans_state == False:
                assert self.retrans_queue==[]
                self.retrans_queue = self.nonack_queue.copy()
                self.retrans_state = True
                print(f"now the retrans list is: {self.retrans_queue}")

                    
        sendingOrNot = False # priority promise

        if self.retrans_state == True:
            #first, we will retrans when timeout
            #then, we consider sending new pkts
            if self.retrans_queue!=[]:
                self.reTX_num+=1
                seq = self.retrans_queue.pop(0)
                pkt.add_header(RawPacketContents(seq.to_bytes(4,'big')))
                pkt.add_header(RawPacketContents(self.length.to_bytes(2,'big')))
                pkt.add_header(RawPacketContents(int(123456789).to_bytes(self.length,'big')))
                self.total_num += 1
                #print(f"retrans a packet with seq of {seq}")
                self.net.send_packet("blaster-eth0",pkt) 
                sendingOrNot = True 
            else:                 
                self.retrans_state = False
                #update time and rows
                self.timeout_num +=1
                self.LHS_time = time.time()          

        if sendingOrNot == False:
            if self.RHS - self.LHS + 1 < self.senderWindow and self.RHS < self.num: 
                self.RHS += 1
                #print(f"when sending, RHS increase to {self.RHS}")
                self.sliding_window.append(self.RHS)
                self.nonack_queue.append(self.RHS)

            if self.sliding_window != []:
                seq = self.sliding_window.pop(0)
                pkt.add_header(RawPacketContents(seq.to_bytes(4,'big')))
                pkt.add_header(RawPacketContents(self.length.to_bytes(2,'big')))
                pkt.add_header(RawPacketContents(int(123456789).to_bytes(self.length,'big')))
                self.total_num += 1
                #print(f"normally send a packet with seq of {seq}")

                self.net.send_packet("blaster-eth0",pkt)

    def statistics(self):
        print("\nResults:")

        print("Total TX time is {} seconds.".format(self.total_time))
        
        #reTX_num1 = self.total_num - self.suc_num
        #print("Totalver:Number of reTX is {}.".format(reTX_num1))
        
        print("Number of reTX is {}.".format(self.reTX_num))
        
        # print Number of coarse TOs
        print("Number of coarse TOs is {}.".format(self.timeout_num))
        
        # print Throughput(Bps)
        Throughput = self.length * self.total_num / self.total_time
        print("Throughput is {} Bps.".format(Throughput))
        
        # print Goodput(Bps)
        Goodput = self.length * self.suc_num / self.total_time
        print("Goodput is {} Bps.".format(Goodput))                 

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout/1000)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

            if(self.LHS>self.length):
                break
        
        self.statistics()
        self.shutdown()

    def shutdown(self):
        self.net.shutdown()





def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
