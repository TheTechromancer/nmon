#!/usr/bin/env python3

'''
TODO:
Multiple script functionality
Add UDP ports
'''

import sys
import pickle
import logging
import ipaddress as ip
import subprocess as sp
from pathlib import Path
import xml.etree.ElementTree as xml     # for parsing Nmap output
from tempfile import NamedTemporaryFile # for Nmap temp file
from argparse import ArgumentParser, ArgumentError


### DEFAULTS ###

# file paths / names
SaveDir     = Path.home() / '.cache/nmon'
Logfile     = 'log'
Database    = 'db'
NmapFlags   = []



### CLASSES ###


class NetworkMonitor():

    def __init__(self, target, save_dir=None, run=None, delete=False, debug=False):

        # input validation on custom script
        if type(run) == str:
            run = which(run)

        self.run        = run

        self.target     = target
        self.target.sort()

        if save_dir:
            self.dir    = Path(save_dir).resolve()
        else:
            self.dir    = SaveDir / str(' '.join(target)).replace('/','-')

        if delete:
            self.delete()

        # make sure save dir exists
        if not self.dir.is_dir():
            try:
                self.dir.mkdir(parents=True)
            except:
                raise AssertionError("Save directory ({}) not accessible\n".format(str(self.dir)))

        self.db         = str(self.dir / Database)
        self.db_loaded  = False
        self.log        = str(self.dir / Logfile)
        logging.basicConfig(filename=self.log, level=(logging.DEBUG if debug else logging.INFO), format="\n[%(asctime)s] %(message)s", datefmt="%c")

        # network map which contains host info, etc.
        self.map        = {}

        self.new_hosts  = 0
        self.new_ports  = 0


    def update(self):

        try:
            print('[+] Loading database {}'.format(self.db))
            self.load()
        except:
            print('[+] No existing database found - starting fresh')

        scan = Nmap(self.target)

        for host in scan.start():
            self.add(host)

        self.save()
        if self.new_hosts or self.new_ports:
            print('[+] Saved {} new host(s) and {} new open port(s)'.format(self.new_hosts, self.new_ports))
        else:
            print('[+] No network changes detected')


    def save(self):

        with open(self.db, 'wb') as f:
            pickle.dump(self.map, f)


    def delete(self):

        print('[+] Deleting cache at {}'.format(str(self.dir)))
        sp.run(['rm', '-r', str(self.dir)], stdout=sp.DEVNULL, stderr=sp.DEVNULL)


    def load(self):

        with open(self.db, 'rb') as f:
            self.map = pickle.load(f)
            self.db_loaded = True


    def list(self):

        if not self.db_loaded:
            try:
                self.load()
            except FileNotFoundError:
                sys.stderr.write('[!] Cannot find {}\n'.format(self.db))
                sys.exit(1)

        for host in self.map.values():
            print(host)


    def open_log(self):

        sp.run(['less', '+G', self.log])
        print('[+] Log can be found at {}'.format(self.log))


    def add(self, host):

        if host.ip in self.map:

            new_ports = False

            new = host
            #old = self.map[host.ip]

            if not host.mac == self.map[host.ip].mac:
                logging.warning("Merging hosts\n\nOLD:\n{}\nNEW:\n{}".format(str(self.map[host.ip]), str(new)))

            for port in new.ports:
                if not port in self.map[host.ip].ports:
                    new_ports = True
                    logging.info("New open port on {}: {}".format(new.ip, port))
                    self.new_ports += 1
                    self.map[host.ip].ports.append(port)

            if new_ports:
                self.run_script(host)

            self.map[host.ip].ports.sort()
            if new.mac: self.map[host.ip].mac = new.mac
            if new.man: self.map[host.ip].man = new.man
            if new.hostname: self.map[host.ip].hostname = new.hostname


        else:
            logging.info('New host on network:\n\n{}'.format(str(host)))
            self.new_hosts += 1
            self.new_ports += len(host.ports)
            self.map[host.ip] = host
            self.run_script(host)


    def run_script(self, host):

        if self.run:
            cmd = self.run + [host.ip]
            cmd_str = 'Running script "{}"'.format(' '.join(cmd))
            logging.info(cmd_str + '\n')
            print('[+] ' + cmd_str)
            custom_script = sp.run(cmd, stdout=sp.PIPE, stderr=sp.STDOUT)
            script_output = custom_script.stdout.decode()
            logging.info('Script output:\n{}'.format(script_output))
            print(script_output)




class Host():
    '''
    basic class for storing nmap results
    '''
    
    def __init__(self, ip=None, mac=None, man=None, hostname=None, ports=[]):
        self.ip         = ip
        self.mac        = mac
        self.man        = man
        self.hostname   = hostname
        self.ports      = ports


    def __str__(self):

        s = self.__repr__()

        if self.mac:
            s += '\n {}'.format(self.mac)
            if self.man:
                s += ' ({})'.format(self.man)

        if self.ports:
            s += '\n  PORTS\n   {}'.format('\n   '.join(self.ports))

        return s + '\n'


    def __repr__(self):

        s  = self.ip
        if self.hostname: 
            s += ' ({})'.format(self.hostname)

        return s

        



class Nmap():
    '''
    basic Nmap wrapper
    '''

    def __init__(self, targets, ports=None, args_list=NmapFlags):
        '''
        translates function parameters into shell arguments
        '''

        self.args_list = args_list

        # accepts either string or list
        if type(targets) == str: targets = [targets]

        if ports:
            if type(ports) == str:
                self.args_list.append("-p {}".format(ports))
            else:
                self.args_list.append("-p {}".format(','.join(ports)))


        self.targets    = ' '.join(targets)
        self.data       = []


    def start(self):

        # temp file used for xml output
        self.tmpfile = NamedTemporaryFile(delete=True)

        # build nmap command
        cmd_list = ['nmap', '-oX', self.tmpfile.name]
        cmd_list.extend(self.args_list)
        cmd_list.append(self.targets)

        # run nmap command
        debug_str = 'Running Nmap scan "' + ' '.join(cmd_list) + '"'
        friendly_str = '[+] Running Nmap scan: "' + ' '.join(cmd_list[:1] + cmd_list[3:]) + '"'
        logging.debug(debug_str)
        print(friendly_str)
        self.process = sp.Popen(cmd_list, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        
        return self.results()


    def results(self):
        '''
        generates:  self.data - dictionary in form { 'ip_address': (open_tcp_ports) }
        '''

        if self.data:
            return self.data

        # wait for process to finish
        try:
            self.process.wait()
            # print(type(self.process.returncode))
        except sp.TimeoutExpired:
            self.process.terminate()

        if self.process.returncode == 0:

            # parse xml
            try:

                tree = xml.parse(self.tmpfile.name)
                hosts = tree.findall('host')

                for host in hosts:

                    h = Host()
                    ports = []

                    for address in host.findall('address'):
                        if address.attrib['addrtype'] == 'mac':
                            h.mac = address.attrib['addr']
                            try:
                                h.man = address.attrib['vendor']
                            except:
                                pass
                        elif address.attrib['addrtype'].startswith('ip'):
                            h.ip = address.attrib['addr']
                        

                    try:
                        h.hostname = host.find('hostnames').find('hostname').attrib['name']
                    except AttributeError:
                        pass

                    # put ports in set like { '80', '443', ... }
                    for p in host.find('ports').findall('port'):

                        # if port is open
                        if p.find('state').attrib['state'] == 'open':
                            # add port to list
                            ports.append(p.attrib['portid'])

                    if ports:
                        h.ports = ports
                    
                    self.data.append( h )

            finally:
                self.tmpfile.close()

        return self.data




### FUNCTIONS ###


def get_subnets():

    # used for finding local subnet
    interface_keywords = ['enp', 'wlp', 'eth', 'wlan']
    subnets = []

    output = sp.run(['ip', '-o', 'address'], stdout=sp.PIPE).stdout.decode().split('\n')

    for line in output:
        line = line.split()

        try:
            if any(line[1].startswith(kw) for kw in interface_keywords) and line[1] != 'lo' and line[2] == 'inet':
                subnets.append(str(ip.ip_network(line[3], strict=False)))

        except (IndexError, ValueError):
            # keep moving if no IP is found
            continue

    return subnets


def which(command):

    command = command.split()

    try:
        command = [sp.run(['which', command[0]], check=True, stdout=sp.PIPE).stdout.decode().strip()] + command[1:]

        # make sure custom script exists and is executable
        exec_path = Path(command[0])
        assert exec_path.is_file() and (exec_path.stat().st_mode & 0o755) != 0

        return command

    except:
        raise AssertionError("{} does not exist or is not executable".format(command[0]))



if __name__ == '__main__':

    ### ARGUMENTS ###

    parser = ArgumentParser(description="Monitors and logs additions to network(s)")

    parser.add_argument('-t', '--target',   default=get_subnets(),      help="target hosts or subnets (comma-separated)")
    parser.add_argument('-s', '--savedir',  type=Path,                  help="directory in which to save log file, etc.")
    parser.add_argument('-d', '--delete',   action='store_true',        help="delete saved cache")
    parser.add_argument('-r', '--run',      type=which,                 help="run this command on new/changed hosts (host ip is appended)")
    parser.add_argument('-l', '--list',     action='store_true',        help="list all recorded hosts")
    parser.add_argument('--log',            action='store_true',        help="open log")
    parser.add_argument('--debug',          action='store_true',        help="print debugging information")

    try:

        options = parser.parse_args()

        if type(options.target) == str:
            options.target = options.target.split(',')

        nmon = NetworkMonitor(options.target, save_dir=options.savedir, run=options.run, delete=options.delete, debug=options.debug)

        if options.list:
            nmon.list()
        elif options.log:
            nmon.open_log()
        elif not options.delete:
            nmon.update()

    except ArgumentError:
        sys.stderr.write("\n[!] Check your syntax. Use -h for help\n")
        sys.exit(2)
    except AssertionError as e:
        sys.stderr.write("[!] {}\n".format(str(e)))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Stopping\n")
        sys.exit(1)