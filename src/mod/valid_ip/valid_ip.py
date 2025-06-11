from random import randrange


def fake_ip():
	while True:
		ips = [str(randrange(0,256)) for i in range(4)]
		if ips[0] == "127":
			continue
		fkip = '.'.join(ips)
		break
	return fkip