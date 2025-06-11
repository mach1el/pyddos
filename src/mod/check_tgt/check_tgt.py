import sys
from socket import gethostbyname
from termcolor import cprint
def check_tgt(args):
	tgt = args.d
	try:
		ip = gethostbyname(tgt)
	except:
		sys.exit(cprint('[-] Can\'t resolve host:Unknown host!','red'))
	return ip