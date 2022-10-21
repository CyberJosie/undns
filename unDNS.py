import os
import sys
import json
import time
from weakref import ProxyType
import socks
import socket
import sqlite3
import argparse
import textwrap
import threading
from threading import Lock
from datetime import datetime
from numpy import divide

'''
~ Scan Modes ~

One or more scan modes can be used. Scan modes are just
different ways to determine if the host is responsive at
a given domain name. Depending on this user preferences
this can be done differently

DNS  - Performs a DNS lookup using the host system. Different
        for windows/linux. Not exactly private.

TCP - Attempts to open a TCP client socket connection at the host
        at one or more ports (which the user will specify).
        Proxied and Tor connections are available.
    
UDP - Attempts to open a UDP client socket connection at the host
        at one or more ports (which the user will specify).
        Proxied and Tor connections are available.

8==D
'''

LOGO = '''
{red} ▄▀▀▄ ▄▀▀▄  ▄▀▀▄ ▀▄{white}   ▄▀▀█▄▄   ▄▀▀▄ ▀▄  ▄▀▀▀▀▄ {reset}
{red}█   █    █ █  █ █ █ {white} █ ▄▀   █ █  █ █ █ █ █   ▐ {reset}
{red}▐  █    █  ▐  █  ▀█  {white}▐ █    █ ▐  █  ▀█    ▀▄   {reset}
{red}  █    █     █   █    {white} █    █   █   █  ▀▄   █  {reset}
{red}   ▀▄▄▄▄▀  ▄▀   █    {white} ▄▀▄▄▄▄▀ ▄▀   █    █▀▀▀   {reset}
{red}           █    ▐   {white} █     ▐  █    ▐    ▐      {reset}
{red}           ▐         {white}▐        ▐                {reset}

    '''.format(red="\u001b[31m",reset="\u001b[0m",white='\u001b[37m')


TIME_FORMAT = '%d-%m-%y %H:%M:%S'

SUPPORTED_SCAN_MODES = [
    'DNS',
]

HOST_TABLE = """CREATE TABLE IF NOT EXISTS `host` (
    `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `domain` VARCHAR(64) NOT NULL,
    `resolved` INTEGER NOT NULL DEFAULT 0,
    `address` VARCHAR(16)
);
"""
workloads = []

# == BEGIN SUPPORT FUNCTIONS
lock = Lock()

def console_log(title, message):
    print(' [ {} ] {}'.format(title,message))

# Sometimes functions describe themsevles
def verify_mode(mode: str):
    if mode.upper() not in SUPPORTED_SCAN_MODES:
        mode = SUPPORTED_SCAN_MODES[0]
    return mode.upper()

def remove_invalid_ports(ports: list):
    for i in range(len(ports)):
        # Ports are numbers so yeahh
        if type(ports[i]) != int:
            ports.pop(i)
            continue
        
        # 1-65535
        if ports[i] < 1 or ports[i] > 65535:
            ports.pop(i)
    return ports

# Split a list into a number of (somewhat) evenly sized chunks
def split(a: list, n):
    import numpy as np
    return [list(e) for e in np.array_split(a, n)]

def process_workloads(paths, workers=1):
    subdomains = []

    # Read lines from all wordlists into one list
    for wordlist_path in paths:
        if not os.path.isfile(wordlist_path):
            print('Error!\n Path to wordlist was not found: \'{}\''.format(wordlist_path))
            continue
        
        try:
            with open(wordlist_path, 'r', encoding='utf8', errors='ignore') as wf:
                [subdomains.append(line.replace('\n','')) for line in wf.readlines() if line not in ['',' ','\n','\t']]
        except Exception as err:
            print('Error!\n An error was encountered while reading from wordlist file: \'{}\'\n{}'.format(wordlist_path, str(err)))
            continue

    # Create worker workloads
    workloads = split(subdomains, workers)
    return workloads, len(subdomains)

def decomma(comma_separated_stuff: str):
    return [e.strip().replace('\n','') for e in comma_separated_stuff.split(',')]

# Generate an unused log file
def generate_new_log():
    filename = ''
    while True:
        filename = 'scan_log_{}.txt'.format(str(round(time.time())))
        if not os.path.isfile(filename):
            break
    return filename

# Returns True if a given list of threads are all completed.
# If one or more are not completed, False is returned.
def all_dead(workers):
    all_dead = True
    for w in workers:
        if w.is_alive():
            all_dead = False
    return all_dead


class Database:
    def __init__(self, db):
        self.database_name = db
        self.conn = sqlite3.connect(self.database_name, check_same_thread=False)
        self.cursor = self.conn.cursor()

    def table_length(self, table):
        lock.acquire(True)
        sql_statement = 'SELECT COUNT(*) FROM {}'.formatt(table)
        self.cursor.execute(sql_statement)
        res = []
        
        try:
            res = self.cursor.fetchall()
        except:
            pass
        lock.release()
        count = int(res[0][0])
        return count

    def resolved_count(self):
        lock.acquire(True)
        sql_statement = 'SELECT * FROM `host` WHERE `resolved` == 1;'
        self.cursor.execute(sql_statement)
        res = []
        
        try:
            res = self.cursor.fetchall()
        except:
            pass
        lock.release()
        
        count = 0
        if len(res) >= 1:
            count = len(res)
        
        return count
    
    def failed_count(self):
        lock.acquire(True)
        sql_statement = 'SELECT * FROM `host` WHERE `resolved` == 0;'
        self.cursor.execute(sql_statement)
        res = []
        try:
            res = self.cursor.fetchall()
        except:
            pass
        lock.release()
        
        count = 0
        if len(res) >= 1:
            count = len(res)
        
        return count
    
    def create_schema(self):
        print(" Creating database schema in \'{}\'".format(self.database_name), end='', flush=True)
        # Create host table
        lock.acquire(True)
        self.cursor.execute(HOST_TABLE)
        self.conn.commit()
        lock.release()
        print(' Done!')
    
    def get_stored_domains(self):
        lock.acquire(True)
        sql_statement = 'SELECT * FROM `host`'
        self.cursor.execute(sql_statement)
        res = []
        try:
            res = self.cursor.fetchall()
        except:
            pass
        lock.release()
        
        if len(res) == 1:
            if len(res[0]) >= 1:
                res = [e[1] for e in res]
        return res

    def commit_result(self, domain: str, address: str, resolved: bool, verbose=False):
        if domain in self.get_stored_domains():
            return
        sql_statement = 'INSERT INTO `host` (`domain`,`resolved`,`address`) VALUES (?,?,?);'
        
        lock.acquire(True)
        self.cursor.execute(sql_statement, (
            str(domain),
            int(resolved),
            str(address)
        ))
        self.conn.commit()
        lock.release()
        

# == END SUPPORT FUNCTIONS

class SubdomainBruteforce:
    def __init__(self, hosts: list=[]):
        self.hosts = hosts
        self.database_name = 'scan_{}.db'.format(str(round(time.time())))
        self.db = Database(self.database_name)


    def _brute_worker(self, group_begin: float, workload: list, scan_mode: list, proxy_host: str, proxy_port: int,  port: int=443):
        subdomain_count = len(workload)
        begin_time = group_begin

        # Iterate through domains in job
        for sdns_idx in range(0, subdomain_count):
            
            # Try each subdomain with each host 
            for host_idx in range(0, len(self.hosts)):
                
                # Build the domain name with subdomain
                full_domain_name = '{}.{}'.format(
                    workload[sdns_idx], self.hosts[host_idx])
                
                # Scan Mode: DNS
                if scan_mode.upper() == 'DNS':
                    result = ''
                    try:
                        result = socket.gethostbyname(full_domain_name)
                    except Exception as err:
                        self.db.commit_result(full_domain_name, 'None', 0, verbose=False)
                        continue
                    
                    # Log Successful lookup
                    self.db.commit_result(full_domain_name, result, 1, True)
                    console_log('Resolved (DNS)', 'Got connection from \'{}\' -> {}'.format(full_domain_name, result))

                time.sleep(.1)


    def run_scan(self, wordlists:list, thread_count: int, scan_mode: list, proxy_host, proxy_port, port: int=443):
        workers = []
        BAR = '************************************'

        print(" Processing wordlists and distributing workloads...", end=' ', flush=True)
        begin_time=time.time()
        workloads, d_count = process_workloads(wordlists, workers=thread_count)
        time2=time.time()
        print("Finished! ({}s)".format(round(time2-begin_time,2)))

        scan_options = """
 {bar}

        Scan Options

  Mode: {scan_mode}
  Target Host(s): {targets}\n
  Wordlist(s): {wordlists}\n
  Total Words: {word_count}
  Proxy Host: {phost}
  Proxy Port: {pport}
  Worker Count: {worker_count}

  INFO: Type '?' at any time to view
        live scan statistics.

 {bar}
        """.format(
            bar=BAR,
            wordlists='\n\t       '.join(wordlists),
            scan_mode=scan_mode.upper(),
            targets='\n\t\t  '.join(self.hosts),
            word_count=d_count,
            worker_count=thread_count,
            phost=proxy_host if proxy_host != None else 'No Proxy',
            pport=proxy_port if proxy_port != None else 'No Proxy',
            )
        
        print(scan_options)
        input(' Press \'Enter\' to begin...')

        # Spawn workers
        for i in range(thread_count):
            print(" Starting new worker...", end='', flush=True)
            wt = threading.Thread(target=self._brute_worker, args=(
                begin_time,
                workloads[i],
                scan_mode,
                proxy_host,
                proxy_port,
                port
                ))
            wt.daemon = True
            wt.start()
            pid = int(wt.native_id)
            workers.append(wt)
            print(" Done! (PID: {}, Workload Size: {})".format(str(pid), str(len(workloads[i]))))
            time.sleep(2)
        
        while not all_dead(workers):
            if input(' ').lower() == '?':
                stats = """
 Start Time: {start}
 Elapsed: ~{elapsed} Seconds 
 Progress: {checked} / {total}

 Resolved Hosts: {resolved_count}
 Unique Hosts: {unique_count}
 Failed Attempts: {failed_count}
        """.format(
            start=datetime.fromtimestamp(begin_time).strftime(TIME_FORMAT),
            elapsed=str(round(time.time()-begin_time)),
            resolved_count=str(self.db.resolved_count()),
            failed_count=str(self.db.failed_count()),
            unique_count=str(len([*set(self.db.get_stored_domains())])),
            checked=str(len(self.db.get_stored_domains())),
            total=d_count,
            )
                print(stats)

        
        
        finish=time.time()
        console_log('Finished', 'Scan completed ({})'.format(str(round(finish-begin_time,2))))

        scan_summary = """
 {bar}

        Scan Summary
 
  Start Time: {start}
  Finish Time: {finish}
  Elapsed: ~{elapsed} Seconds
  
  Resolved Hosts: {resolved_count}
  Unique Hosts: {unique_count}
  Failed Attempts: {failed_count}

 {bar}
        """.format(
            bar=BAR,
            start=datetime.fromtimestamp(begin_time).strftime(TIME_FORMAT),
            finish=datetime.fromtimestamp(finish).strftime(TIME_FORMAT),
            elapsed=str(round(finish-begin_time)),
            resolved_count=str(self.db.resolved_count()),
            failed_count=str(self.db.failed_count()),
            unique_count=str(len([*set(self.db.get_stored_domains())]))
            )
        print(scan_summary)


# App Main
def main(args: argparse.Namespace):

    hosts = []
    wordlists = []
    mode = 'DNS'
    port = 443
    proxy_host=None
    proxy_port=None
    threads = 1

    # Store hosts from arguments
    if args.hosts != None:
        hosts = decomma(args.hosts)
    else:
        console_log('Error', 'At least one host is required.')
        exit(1)
    
    # Store wordlists from arguments
    if args.wordlists != None:
        wordlists = decomma(args.wordlists)
    else:
        console_log('Error', "At least one wordlist is required.")
        exit(1)
    
    # Store thread count from arguments
    if args.threads != None:
        threads = args.threads if type(args.threads) == int else 1
    
    # Store scan mode from arguments
    if args.mode != None:
        mode = verify_mode(str(args.mode))
        
    
    subdns = SubdomainBruteforce(hosts)
    subdns.db.create_schema()
    subdns.run_scan(
        wordlists=wordlists,
        thread_count=threads,
        scan_mode=mode,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        port=port,
    )

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        prog='unDNS.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent(f'''        
         Scan modes are the connection method used to determine
         whether or not a host is available at a given domain name.

            * DNS - Use host DNS client to attempt domain resolution
                    Not compatible with proxies. See operating system
                    manual for more.
            
            * More sometime in the future lol

        '''),

        epilog=textwrap.dedent('''
        https://github.com/CyberJosie/undns
        ''')
    )

    parser.add_argument('--hosts', '-H',
        action = 'store',
        type=str,
        help=textwrap.dedent('''
        One or more host domains to prefix with subdomains.
        (Separate multiple elements with commas)

        Required: True
        Default: None
        ''')
    )

    parser.add_argument('--wordlists', '-W',
        action = 'store',
        type=str,
        help=textwrap.dedent('''
        Path to one or more wordlists filled with newline separated subdomains.
        Any non UTF-8 compatible elements will be ignored.
        (Separate multiple elements with commas)

        Required: True
        Default: None
        \n''')
    )

    parser.add_argument('--threads', '-T',
        action = 'store',
        type=int,
        help=textwrap.dedent('''
        Number of concurrent threads to use.
        Subdomains will be (somewhat) evenly distributed amongst threads.

        Required: False
        Default: 1
        \n''')
    )
  
    parser.add_argument('--mode', '-M',
        action = 'store',
        type=str,
        help=textwrap.dedent('''
        Scan modes to use for analysis.
        All options: DNS (Work in progress)
        (Separate multiple elements with commas)

        Required: False
        Default: DNS
        \n''')
    )

    print(LOGO)
    main(parser.parse_args())
