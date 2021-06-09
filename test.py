import dpkt
import socket
from decimal import *


file_1 = 'iperf-100k-1-3to1.pcap'

for fileCount in range(1,2):
	with open(file_1, 'rb') as fr:
		pcap = dpkt.pcap.Reader(fr)
		synCount = 0  # to get the 2nd connection
		conSrcPort = conDstPort = 0  #connection data send srcport, dstport
		lastTimeStamp = Decimal(0).quantize(Decimal('0.000001'))
		curTimeStamp = Decimal(0).quantize(Decimal('0.000001'))
		fctStartTimeStamp = Decimal(0).quantize(Decimal('0.000001'))
		fctEndTimeStamp = Decimal(0).quantize(Decimal('0.000001'))


		for timestamp, buffer in pcap:
			ethernet = dpkt.ethernet.Ethernet(buffer)
			ip = ethernet.data
			# we need tcp pkt
			tcp = ip.data
			
			# iperf control connection takes 2 syn, data connection takes 3rd 4th syn
			# tcp.tcp_flags_to_str(tcp.flags)    this cannot be invoked directly
			# tcp.flags = 0x02  SYN
			if tcp.flags & 0x02:
				synCount = synCount + 1

			if synCount < 4:
				continue

			if synCount == 4:
				synCount = 5
				continue

			#with handshake ack pkt, get iperf data connection port
			if synCount == 5:
				synCount = 6
				conSrcPort = tcp.sport
				conDstPort = tcp.dport
				curTimeStamp = Decimal(timestamp).quantize(Decimal('0.000001'))
				continue
			
			srcport = tcp.sport
			dstport = tcp.dport
			# data connection no matter direction, get lastTimeStamp && currentTimeStamp
			if srcport == conSrcPort or dstport == conSrcPort:
				lastTimeStamp = curTimeStamp
				curTimeStamp = Decimal(timestamp).quantize(Decimal('0.000001'))

				# time gap over 0.01s, data transportion begins
				if (curTimeStamp - lastTimeStamp).compare(Decimal('0.01'))==1  and  (srcport == conSrcPort):
					fctStartTimeStamp = curTimeStamp


			# tcp.flags = 0x04 RST or tcp.flags & 0x01 FIN from server end
			if ((tcp.flags & 0x04) or (tcp.flags & 0x01)) and (srcport == conDstPort):
				fctEndTimeStamp = curTimeStamp
				break;


		FCT = fctEndTimeStamp - fctStartTimeStamp
		print "FCT is " 
		print FCT








 
