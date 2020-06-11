#!/usr/bin/python

from scapy.all import *

dest_addr = "216.58.204.78" # google.com
dest_port = 80
source_port = 45678

pay = "abcdefgh"                # Change it your custom UDP payload
pay_len = len(pay) + 8

opt = b'\x02\x04\x05\xc0'   	# UDP MSS option
opt_len = len(opt)

cco_aligned = b'\xcc\x04\x2c\x2f'           # UDP CCO (if already 2-byte aligned)
cco_unaligned = b'\x01\xcc\x04\x6f\xe9'     # UDP CCO (if not 2-byte aligned)

pay_plus_opt = pay + opt

udp_pkt = (IP(dst=dest_addr)/UDP(sport=source_port, dport=dest_port)/Raw(load=pay))                             # contains UDPO correct CS
udpo_pkt = (IP(dst=dest_addr)/UDP(sport=source_port, dport=dest_port, len=pay_len)/Raw(load=pay_plus_opt))      # contains UDPO IP Pay CS 

del udp_pkt[UDP].chksum
udp_pkt = udp_pkt.__class__(bytes(udp_pkt))
del udpo_pkt[UDP].chksum
udpo_pkt = udpo_pkt.__class__(bytes(udpo_pkt))

# Correct CS
udpo_pkt_correct_cs = udpo_pkt.copy()               
udpo_pkt_correct_cs[UDP].len = udp_pkt[UDP].len             
udpo_pkt_correct_cs[UDP].chksum = udp_pkt[UDP].chksum       # Use CS from packet w/o Options but adds Options

# IP Payload CS
udpo_pkt_ippay_cs = udpo_pkt.copy()                         # Use CS computed on Payload and Options

# 3rd Checksum
udpo_pkt_3rd_cs = udpo_pkt.copy()           
third_chksum = udpo_pkt_ippay_cs[UDP].chksum + opt_len      # Offset with IP Payload CS and 
if (third_chksum>0):
	third_chksum = third_chksum / 0x10000 + third_chksum % 0x10000
udpo_pkt_3rd_cs[UDP].chksum = third_chksum
	
# 4th Checksum
udpo_pkt_4th_cs = udpo_pkt_correct_cs.copy()        
fourth_chksum = udp_pkt[UDP].chksum - opt_len               # Offset with Correct CS 
if (fourth_chksum<0):
	fourth_chksum += 0xffff
udpo_pkt_4th_cs[UDP].chksum = fourth_chksum

# CCO
pay_plus_opt_plus_cco = pay + opt + cco_aligned
if (pay_len%2):
	pay_plus_opt_plus_cco = pay + opt + cco_unaligned
udpo_pkt_cco = udp_pkt.copy()           
udpo_pkt_cco[Raw].load=pay_plus_opt_plus_cco                # Use CS from packet w/o Options but adds Options and CCO
udpo_pkt_cco[UDP].len = udp_pkt[UDP].len
udpo_pkt_cco[UDP].chksum = udp_pkt[UDP].chksum

# send
send(udpo_pkt_correct_cs)
send(udpo_pkt_ippay_cs)
send(udpo_pkt_3rd_cs)
send(udpo_pkt_4th_cs)
send(udpo_pkt_cco)

# For the meaning of Correct CS, IP Payload Checksum, 3rd Checksum, 4th Checksum please see 
# http://www.middleboxes.org/raffaelezullo/publications/tma2020-zullo-udp-options.pdf
