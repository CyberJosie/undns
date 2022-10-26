import os
import time
import socket
import random
import sqlite3
import requests
import textwrap
import argparse
import threading
from queue import Queue
from numpy import divide
from threading import Lock
from datetime import datetime

LOGO = '''
{red} ▄▀▀▄ ▄▀▀▄  ▄▀▀▄ ▀▄{white}   ▄▀▀█▄▄   ▄▀▀▄ ▀▄  ▄▀▀▀▀▄ {reset}
{red}█   █    █ █  █ █ █ {white} █ ▄▀   █ █  █ █ █ █ █   ▐ {reset}
{red}▐  █    █  ▐  █  ▀█  {white}▐ █    █ ▐  █  ▀█    ▀▄   {reset}
{red}  █    █     █   █    {white} █    █   █   █  ▀▄   █  {reset}
{red}   ▀▄▄▄▄▀  ▄▀   █    {white} ▄▀▄▄▄▄▀ ▄▀   █    █▀▀▀   {reset}
{red}           █    ▐   {white} █     ▐  █    ▐    ▐      {reset}
{red}           ▐         {white}▐        ▐                {reset}

    '''.format(red="\u001b[31m",reset="\u001b[0m",white='\u001b[37m')

# This format is used for time and date
# https://docs.python.org/3/library/datetime.html#strftime-strptime-behavior
TIME_FORMAT = '%d-%m-%y %H:%M:%S'   

BAR = '************************************'    # its a bar

SUPPORTED_SCAN_MODES = [
    'DNS',
    'WEBSOCKET'
]

# SQL statement for creating host table
HOST_TABLE = """CREATE TABLE IF NOT EXISTS `host` (
    `id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    `domain` VARCHAR(64) NOT NULL,
    `resolved` INTEGER NOT NULL DEFAULT 0,
    `address` VARCHAR(16)
);
"""

MODE_SUMMARY = '''
Scan Modes:

 Scan modes are different methods used to determine if a host is available
 at a given domain. By default this program uses DNS which is dependant on
 the host system. All options are below.

  * DNS - Makes DNS requests via the host DNS resolver. See '/etc/resolv.conf' 
          for Linux.
  
  * Web Socket - Attempts to connect to the host as if it were a webserver. 
                 Proxied requests are available with this mode.
'''

lock = Lock()
qp = Queue(64)

# Prints a formatted message to the console with no buffers (im lazy sometimes ok...)
def console_log(title, message):
    print(' [ {} ] {}'.format(title,message))

# Sometimes functions describe themsevles
def verify_mode(mode: str):
    if mode.upper() not in SUPPORTED_SCAN_MODES:
        mode = SUPPORTED_SCAN_MODES[0]
    return mode.upper()

# Split a list into a number of (somewhat) evenly sized chunks
def split(a: list, n):
    import numpy as np
    return [list(e) for e in np.array_split(a, n)]

# Read all wordlists and prepare workloads for workers
def process_workloads(paths, workers=1, shuffle=False):
    subdomains = []

    # Read lines from all wordlists into one list
    for wordlist_path in paths:
        # Make sure the wordlist is a file
        if not os.path.isfile(wordlist_path):
            print('Error!\n Path to wordlist was not found: \'{}\''.format(wordlist_path))
            continue
        
        # Read from the wordlist and skip if failed
        try:
            with open(wordlist_path, 'r', encoding='utf8', errors='ignore') as wf:
                [subdomains.append(line.replace('\n','')) for line in wf.readlines() if line not in ['',' ','\n','\t']]
        except Exception as err:
            print('Error!\n An error was encountered while reading from wordlist file: \'{}\'\n{}'.format(wordlist_path, str(err)))
            continue
    
    # Shuffle the order 
    if shuffle:
        random.shuffle(subdomains)

    # Create worker workloads
    workloads = split(subdomains, workers)
    return workloads, len(subdomains)

# Simply creates a list from a string of comma delimeted items
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

# Quick DB queries for reading
class Queries:
    # Returns resolved hosts from database
    def resolved_hosts(self, cursor, threaded=False):
        res = []
        query = 'SELECT * FROM `host` WHERE resolved = 1;'

        if threaded:
            lock.acquire(True)
        
        try:
            cursor.execute(query)
            res = cursor.fetchall()
        except Exception as err:
            console_log('Error', str(err))
        
        if threaded:
            lock.release()

        return res
    
    # Count of resolved hosts 
    def resolved_count(self, cursor, threaded=False):
        return len(self.resolved_hosts(cursor, threaded))
    
    # Reads failed hosts from database
    def failed_hosts(self, cursor, threaded=False):
        res = []
        query = 'SELECT * FROM `host` WHERE resolved = 0;'

        if threaded:
            lock.acquire(True)
        
        try:
            cursor.execute(query)
            res = cursor.fetchall()
        except Exception as err:
            console_log('Error', str(err))

        if threaded:
            lock.release()
        
        return res

    # Count of failed hosts 
    def failed_count(self, cursor, threaded=False):
        return len(self.failed_hosts(cursor, threaded))
    
    # Reads all records from database
    def retrieve_all(self, cursor, threaded=False):
        res = []
        query = 'SELECT * FROM `host`;'

        if threaded:
            lock.acquire(True)
        
        try:
            cursor.execute(query)
            res = cursor.fetchall()
        except Exception as err:
            console_log('Error', str(err))
        
        if threaded:
            lock.release()
        
        return res
    
    # Return the length of a table
    def table_length(self, cursor, table, threaded=False):
        res = []
        sql_statement = 'SELECT COUNT(*) FROM {}'.format(table)

        if threaded:
            lock.acquire(True)
        
        try:
            cursor.execute(sql_statement)
            res = cursor.fetchall()
        except Exception as err:
            console_log('Error', str(err))

        if threaded:
            lock.release()
        
        count = int(res[0][0])
        return count
     
    # Returns a full list of all domains in database
    def domains(self, cursor, threaded=False):
        domains = [row[1] for row in self.retrieve_all(cursor, threaded)]
        return domains
    
    # Returns a list of all unique hosts in database
    def hosts(self, cursor, threaded=False):
        domains = self.domains(cursor, threaded)
        hosts = []
        for i in range(len(domains)):
            hosts.append('.'.join(domains[i].split('.')[-2:]))
        return [*set(hosts)]
    
    # Returns all resolved addresses in database
    def addresses(self, cursor, threaded=False):
        domains = [row[3] for row in self.retrieve_all(cursor, threaded) if row[3] != 'None']
        return domains

# Use this mode to inspect a DB file or recover data from a crashed scan
def inspect_mode(db_file):
    help_menu = '''

Command             Action

resolved, .r        List all resolved hosts
failed, .f          List all failed hosts
domains, .d         List all domains
hosts, .h           List unique host domains
addresses, .a       List resolved addresses
everything, .e      Show everything
length, .l          Show database length
.q                  Exit
'''
    if not os.path.isfile(db_file):
        console_log('Error', 'Unable to find file: \'{}\''.format(db_file))
        return
    
    db = None
    try:
        db = sqlite3.connect(db_file)
    except Exception as err:
        console_log('Error', 'Unable to open database.\n{}'.format(str(err)))
        return
    
    if not db:
        console_log('Error', 'Unexpected Error')
        return
    
    cursor = db.cursor()
    q = Queries()

    print('Type \'help\' to show help.')
    
    while not None:
        user_input = input('inspect> ')
        output = ''
        
        if len(user_input) < 1 or user_input in ['',' ','\n']:
            continue

        args = [a.strip().replace('\n','') for a in user_input.split(' ')]

        if len(args) >= 1:
            if args[0] == 'resolved' or args[0] == '.r':
                resolved = ['{}  {}\t{}'.format(row[0] if int(row[0]) >= 100 else str(row[0])+' ', row[3] if row[2] == 1 else 'None', row[1]) for row in q.resolved_hosts(cursor)]
                output = 'Resolved Hosts\n\n' + '\n'.join(resolved)

            elif args[0] == 'failed' or args[0] == '.f':
                failed = ['{}  {}\t{}'.format(row[0] if int(row[0]) >= 100 else str(row[0])+' ', row[3] if row[2] == 1 else 'None', row[1]) for row in q.failed_hosts(cursor)]
                output = 'Failed Hosts\n\n' + '\n'.join(failed)

            elif args[0] == 'domains' or args[0] == '.d':
                domains = q.domains(cursor)
                output = 'Domains\n\n' + '\n'.join(domains)

            elif args[0] == 'hosts' or args[0] == '.h':
                hosts = q.hosts(cursor)
                output = 'Hosts\n\n' + '\n'.join(hosts)

            elif args[0] == 'addresses' or args[0] == '.a':
                addresses = q.addresses(cursor)
                output = 'Addresses\n\n' + '\n'.join(addresses)

            elif args[0] == 'length' or args[0] == '.l':
                output = '{} Entries'.format(len(q.retrieve_all(cursor)))
            
            elif args[0] == 'everything' or args[0] == '.e':
                all = ['{}  {}\t{}'.format(row[0] if int(row[0]) >= 100 else str(row[0])+' ', row[3] if row[2] == 1 else 'None', row[1]) for row in q.retrieve_all(cursor)]
                output = '{} Entries'.format('All Records\n' + '\n'.join(all))
            
            elif args[0] == '.q':
                break
            
            else:
                print(help_menu)
        
        if output != '':
            print(output)


class Database:
    '''
    Database connector

    This thread holds the database connection and functions that add records
    For database reading and parsing, see class 'Queries'
    '''
    def __init__(self, db):
        self.database_name = db
        self.conn = sqlite3.connect(self.database_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
    
    def create_schema(self):
        print(" Creating database schema in \'{}\'".format(self.database_name), end='', flush=True)
        lock.acquire(True)
        self.cursor.execute(HOST_TABLE)
        self.conn.commit()
        lock.release()
        print(' Done!')

    def commit_result(self, domain: str, address: str, resolved: bool, verbose=False):
        q = Queries()
        if domain in q.domains(self.cursor, True):
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

class SubdomainBruteforce:
    def __init__(self, hosts: list=[]):
        self.hosts = hosts
        self.database_name = 'scan_{}.db'.format(str(round(time.time())))
        self.db = Database(self.database_name)

    # Function that works as each child process
    def _brute_worker(self, process_id, group_begin: float, workload: list, scan_mode: list, proxy: str, port: int=443):
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
                    self.db.commit_result(
                        full_domain_name,
                        result,
                        1,
                        True )
                    console_log('Resolved (DNS)', 'Got connection from \'{}\' -> {}'.format(full_domain_name, result))
                
                elif scan_mode.upper() == 'WEBSOCKET':

                    if port == 443:
                        url = 'https://{}'.format(full_domain_name)
                    elif port == 80:
                        url = 'http://{}'.format(full_domain_name)
                    else:
                        url = 'https://{}:{}'.format(full_domain_name, port)

                    try:
                        response = requests.get(url, proxies=proxy)
                        console_log('Resolved (WebSocket)', 'Got connection from \'{}\' -> {}'.format(full_domain_name, ))
                        result = response.status_code or 'None'
                        self.db.commit_result(
                            full_domain_name,
                            result,
                            1,
                            True )
                        
                    except:
                        self.db.commit_result(full_domain_name, 'None', 0, verbose=False)
                        continue

                time.sleep(.1)
            
            # Commit suicide if daddy says so
            if not qp.empty():
                if 'die' in qp.get_nowait():
                    console_log('Thread {}'.format(process_id), 'Dying...')
                    break
                
    
    # Initiated the scan with the available parameters
    # This function waits for all child processes to finish and controls the console interface in between
    def run_scan(self, wordlists:list, thread_count: int, scan_mode: list, proxy, port: int=443, shuffle: bool=False):
        workers = []
        query = Queries()
        begin_time=time.time()
        
        # Create workloads for all workers without duplicated
        print(" Processing wordlists and distributing workloads...", end=' ', flush=True)
        workloads, d_count = process_workloads(wordlists, workers=thread_count, shuffle=shuffle)
        time2=time.time()
        print("Finished! ({}s)".format(round(time2-begin_time,2)))

        # Scan Options for initial summary (Basically what you set at the cli)
        scan_options = """
 {bar}

        Scan Options

  Mode: {scan_mode}
  Shuffle: {shuffle}
  Target Host(s): {targets}\n
  Wordlist(s): {wordlists}\n
  Total Words: {word_count}
  Proxy: {proxy}
  Worker Count: {worker_count}

  INFO: Type '?' at any time to view
        live scan statistics.

        Type 'quit' to end threads 
        properly and then exit.

 {bar}
        """.format(
            bar=BAR,
            shuffle='Yes' if shuffle else 'No',
            wordlists='\n\t       '.join(wordlists),
            scan_mode=scan_mode.upper(),
            targets='\n\t\t  '.join(self.hosts),
            word_count=d_count,
            worker_count=thread_count,
            proxy=proxy if proxy != None else 'No Proxy',
            )
        
        print(scan_options)
        input(' Press \'Enter\' to begin...')

        # Spawn workers
        for i in range(thread_count):
            print(" Starting new worker...", end='', flush=True)
            # Create a new thread
            wt = threading.Thread(target=self._brute_worker, args=(
                str(i+1),
                begin_time,
                workloads[i],
                scan_mode,
                proxy,
                port,
                ))
            wt.daemon = True
            wt.start()
            # Store PID and add to worker set
            pid = int(wt.native_id)
            workers.append(wt)
            print(" Done! (PID: {}, Workload Size: {})".format(str(pid), str(len(workloads[i]))))
            time.sleep(1)
        
        # Console active during scan
        while not all_dead(workers):

            # Show live statistics
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
            resolved_count=str(query.resolved_count(self.db.cursor, True)),
            failed_count=str(query.failed_count(self.db.cursor, True)),
            unique_count=str(len([*set(query.domains(self.db.cursor, True))])),
            checked=str(query.table_length(self.db.cursor, 'host', True)),
            total=d_count,
            )
                print(stats)
            
            # Safely kill all workers
            elif 'quit' in input(' ').lower() or 'q' in input(' ').lower():
                console_log('Console', 'Killing Workers...')
                while not all_dead(workers):
                    if not qp.full():
                        qp.put_nowait('die')
                console_log('Console', 'All workers have moved on to a better place.')
    
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
            resolved_count=str(query.resolved_count(self.db.cursor, True)),
            failed_count=str(query.failed_count(self.db.cursor, True)),
            unique_count=str(len([*set(query.domains(self.db.cursor, True))]))
            )
        print(scan_summary)


# App Main
def main(args: argparse.Namespace):

    hosts = []
    wordlists = []
    mode = 'DNS'
    port = 443
    proxy=None
    shuffle=False
    threads = 1

    # Enter inspect mode if specified by user
    if args.inspect != None:
        file_db = str(args.inspect)
        if file_db[-3:] == '.db':
            console_log('Info', 'Inspecting: \'{}\''.format(file_db))
            inspect_mode(file_db)
            exit()

    # Store hosts from arguments
    if args.domains != None:
        hosts = decomma(args.domains)
    else:
        console_log('Error', 'At least one host is required.')
        exit(1)
    
    # Store wordlists from arguments
    if args.wordlists != None:
        wordlists = decomma(args.wordlists)
    else:
        console_log('Error', "At least one wordlist is required.")
        exit(1)
    
    # Set web socket mode
    if args.web_socket != None and args.web_socket != False:
        mode = 'WebSocket'
    
    # Web socket port
    if args.port != None:
        try:
            port = int(args.port)
        except:
            pass
    
    # Store proxy information
    if args.proxy != None:
        if type(args.proxy) == str:
            if 'tor' in args.proxy.strip().lower():
                proxy = 'socks5h://127.0.0.1:9050'
            else:
                proxy = args.proxy
    
    # Store thread count from arguments
    if args.threads != None:
        threads = args.threads if type(args.threads) == int else 1

    if args.shuffle != None:
        if args.shuffle != False:
            shuffle = True
    
    # begin
    subdns = SubdomainBruteforce(hosts)
    subdns.db.create_schema()
    subdns.run_scan(
        wordlists=wordlists,
        thread_count=threads,
        scan_mode=mode,
        proxy=proxy,
        port=port,
        shuffle=shuffle,
    )

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        prog='unDNS.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent('''
         {ms}
        '''.format(
            ms=MODE_SUMMARY,
        )),

        epilog=textwrap.dedent('''
        https://github.com/CyberJosie/undns
        ''')
    )

    parser.add_argument('--domains', '-d',
        action = 'store',
        type=str,
        help=textwrap.dedent('''
        One or more host domains to prefix with subdomains.
        (Separate multiple domains with commas)

        Required: True
        Default: None
        \n''')
    )

    parser.add_argument('--wordlists', '-w',
        action = 'store',
        type=str,
        help=textwrap.dedent('''
        Path to one or more wordlists filled with newline separated subdomains. 
        Any non UTF-8 compatible elements will be ignored.
        (Separate multiple paths with commas)

        Required: True
        Default: None
        \n''')
    )

    parser.add_argument('--web-socket', '-ws',
        action='store_true',
        help=textwrap.dedent('''
        Set this flag to use web socket mode.

        Required: False
        \n''')
    )

    parser.add_argument('--port', '-p',
        action='store',
        type=int,
        help=textwrap.dedent('''
        Port to use with web socket

        Required: False
        Default: 443
        \n''')
    )

    parser.add_argument('--proxy', '-x',
        action='store',
        help=textwrap.dedent('''
        Proxy server to use for forwarding requests in web socket mode.
        Set 'tor' to use: socks5h://127.0.0.1:9050 (local Tor proxy).

        Required: False
        Default: None
        \n''')
    )

    parser.add_argument('--threads', '-t',
        action = 'store',
        type=int,
        help=textwrap.dedent('''
        Number of concurrent threads to use.
        Subdomains will be (somewhat) evenly distributed among threads.

        Required: False
        Default: 1
        \n''')
    )

    parser.add_argument('--inspect', '-i',
        action='store',
        type=str,
        help=textwrap.dedent('''
        Inspect Sqlite3 database output file.

        Required: False
        Default: None
        \n''')
    )

    parser.add_argument('--shuffle', '-s',
        action='store_true',
        help=textwrap.dedent('''
        Randomize the order of subdomains (no value)

        Required: False
        \n''')
    )

    print(LOGO)
    main(parser.parse_args())
