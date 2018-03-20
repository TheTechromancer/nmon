# nmon

A script which monitors, detects, and records changes in the network, such as new hosts or new open ports. Includes the option to run a custom script/program on hosts which have changed.

Run as often as necessary (for example, every hour on a cron job).  Nmon will inspect the network, compare to existing database, record changes, and then exit.

<br>

#### Usage:

~~~~
    usage: nmon.py [-h] [-t TARGET] [-s SAVEDIR] [-d] [-r RUN] [-l] [--log]
                   [--debug]

    Monitors and logs network changes                                                            
                                                                                                 
    optional arguments:                                                                          
      -h, --help            show this help message and exit                                      
      -t TARGET, --target TARGET                                                                 
                            target hosts or subnets (comma-separated)                            
      -s SAVEDIR, --savedir SAVEDIR                                                              
                            directory in which to save log file, etc.                            
      -d, --delete          delete saved cache
      -r RUN, --run RUN     run this command on new/changed hosts (host ip is
                            appended)
      -l, --list            list all recorded hosts
      --log                 open log
      --debug               print debugging information
~~~~


#### Example:

~~~~

# ./nmon.py
[+] Loading database /home/groot/.cache/nmon/10.20.0.0-24/db
[+] No existing database found - starting fresh
[+] Running Nmap scan: "nmap 10.20.0.0/24"
[+] Saved 4 new host(s) and 3 new port(s)

# ./nmon.py -l
10.0.0.1
  PORTS
   22

10.0.0.115
  PORTS
   22
   443

10.0.0.116

10.0.0.200

~~~~