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
		fctEndTimeStamp = Decimal(0).quantize(Decimal('0.000001')). 
		#可以在声明时候限制精度，quantize里面，Decimal里面，必须用字符串，直接用小数会报错quantize result has too many digits for current context
		#quantize是一个运算符，如果‘0.000001’返回的是小数点后6位，但如果是0.000001，返回的是小数点后72位，超出64位限制
		
		#python2 print float默认显示到0.01，但是其实存储的精度还是比较大的，
		#python3 print float默认显示到0.000001，存储和python2应该是相同的
		#显示格式，print "%.6f" % FCT 来控制显示到小数点后6位
		#endtime-starttime>0.01可以直接这么写，这个表面测试起来没有什么错误，可能是因为timestamp精度本身只有小数点后6位，要求还不是很高，如果小数点后很多位，python自动填充或计算可能会发生错误


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
				#但是这里就可以把timestamp直接放在Decimal里面，可能应为timestamp本身是小数后两位
				continue
			
			srcport = tcp.sport
			dstport = tcp.dport
			# data connection no matter direction, get lastTimeStamp && currentTimeStamp
			if srcport == conSrcPort or dstport == conSrcPort:
				lastTimeStamp = curTimeStamp
				curTimeStamp = Decimal(timestamp).quantize(Decimal('0.000001'))

				# time gap over 0.01s, data transportion begins
				#涉及到浮点比较大小的，都要用compare
				if (curTimeStamp - lastTimeStamp).compare(Decimal('0.01'))==1  and  (srcport == conSrcPort):
					fctStartTimeStamp = curTimeStamp


			# tcp.flags = 0x04 RST or tcp.flags & 0x01 FIN from server end
			if ((tcp.flags & 0x04) or (tcp.flags & 0x01)) and (srcport == conDstPort):
				fctEndTimeStamp = curTimeStamp
				break;


		FCT = fctEndTimeStamp - fctStartTimeStamp
		print "FCT is " 
		print FCT








 
