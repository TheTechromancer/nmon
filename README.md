# nmon

A script which monitors, detects, and records additions to network(s), such as new hosts or new open ports. Includes the option to run a custom script/program on new or changed hosts.

Run as often as necessary (for example, every hour on a cron job).  Nmon will inspect the network, compare to existing database, record changes, and then exit.

<br>

#### Usage:

~~~~
    usage: nmon.py [-h] [-t TARGET] [-s SAVEDIR] [-d] [-r RUN] [-l] [--log]
                   [--debug]

    Monitors and logs additions to network(s)                                                          
                                                                                                 
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
Simply run nmon and view the log to see additions to the network.  (target defaults to local subnet if none is specified)

~~~~
# ./nmon.py 
[+] Loading database /root/.cache/nmon/10.0.0.0-24/db
[+] No existing database found - starting fresh
[+] Running Nmap scan: "nmap 10.0.0.0/24"
[+] Saved 3 new host(s) and 1 new open port(s)


# ./nmon.py 
[+] Loading database /root/.cache/nmon/10.0.0.0-24/db
[+] Running Nmap scan: "nmap 10.0.0.0/24"
[+] Saved 1 new host(s) and 2 new open port(s)

# ./nmon.py --log
[Mon Mar 19 22:11:10 2018] New host on network:

10.0.0.1
 00:0C:29:45:30:AF (VMware)
  PORTS
   22


[Mon Mar 19 22:11:10 2018] New host on network:

10.0.0.200
 F0:9F:C2:64:50:22 (Ubiquiti Networks)


[Mon Mar 19 22:11:10 2018] New host on network:

10.0.0.116
 0E:B4:B2:7E:A4:12


[Mon Mar 19 22:11:36 2018] New host on network:

10.0.0.115
 0E:B4:40:FE:A3:86
  PORTS
   22
   443

[+] Log can be found at /root/.cache/nmon/10.0.0.0-24/log
~~~~

#### Tips:

* Use the '-r' option to run a custom script/program on new or changed hosts.  For example:<br> `nmon.py -r 'nmap -A'` or `nmon.py -r enum4linux`
* To start fresh, delete the cache for the current target with `-d`