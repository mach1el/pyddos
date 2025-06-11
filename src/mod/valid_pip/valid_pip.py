from os import name, system
from sys import exit
import signal
if name == 'posix':
	c = system('which pip')
	if c == 256:
		system('sudo apt-get install python-pip')
	else:
		pass
else:
	print ('[-] Check your pip installer')

try:
	signal.signal(signal.SIGFPE,signal.SIG_DFL)
	from ...ddos import main
	main()
except:
	try:
		if name == 'posix':
			system('sudo pip install colorama termcolor requests')
			exit('[+] I have installed necessary modules for you')
		elif name == 'nt':
			system('pip install colorama requests termcolor')
			exit('[+] I have installed nessecary modules for you')
		else:
			exit('[-] Download and install necessary modules')
	except Exception as e:
		print ('[-]',e)
