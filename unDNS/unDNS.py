import os
import time
import socket
import random
import sqlite3
import argparse
import textwrap
import ipaddress
import threading
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

TIME_FORMAT = '%d-%m-%y %H:%M:%S'
BAR = '************************************'
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

lock = Lock()

def console_log(title, message):
    print(' [ {} ] {}'.format(title,message))

# Sometimes functions describe themsevles
def verify_mode(mode: str):
    if mode.upper() not in SUPPORTED_SCAN_MODES:
        mode = SUPPORTED_SCAN_MODES[0]
    return mode.upper()

def is_valid_ip_address(ipv4):
    yus = False
    try:
        ipaddress.IPv4Address(ipv4)
        yus = True
    except:
        pass
    return yus

# Split a list into a number of (somewhat) evenly sized chunks
def split(a: list, n):
    import numpy as np
    return [list(e) for e in np.array_split(a, n)]

def process_workloads(paths, workers=1, shuffle=False):
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
    
    if shuffle:
        random.shuffle(subdomains)

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


    def run_scan(self, wordlists:list, thread_count: int, scan_mode: list, proxy_host, proxy_port, port: int=443, shuffle: bool=False):
        workers = []
        query = Queries()
        begin_time=time.time()
        
        print(" Processing wordlists and distributing workloads...", end=' ', flush=True)
        workloads, d_count = process_workloads(wordlists, workers=thread_count, shuffle=shuffle)
        time2=time.time()
        print("Finished! ({}s)".format(round(time2-begin_time,2)))

        scan_options = """
 {bar}

        Scan Options

  Mode: {scan_mode}
  Shuffle: {shuffle}
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
            shuffle='Yes' if shuffle else 'No',
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
            time.sleep(1)
        
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
            resolved_count=str(query.resolved_count(self.db.cursor, True)),
            failed_count=str(query.failed_count(self.db.cursor, True)),
            unique_count=str(len([*set(query.domains(self.db.cursor, True))])),
            checked=str(query.table_length(self.db.cursor, 'host', True)),
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
    proxy_host=None
    proxy_port=None
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
    
    # # Store proxy information
    # if args.proxy_host != None:
    #     # Ensure host is a valid IPv4 address
    #     if is_valid_ip_address(args.proxy_host):
    #         # Only continue if port is also set
    #         if args.proxy_port != None:
    #             proxy_host = str(args.proxy_host)
    #             proxy_port = int(args.proxy_port)
    #     # print error if no port is set
    #     else:
    #         console_log('Error', 'A port must also be specified if \'--proxy-host\' is set.')
    #         exit(1)
    
    # Store thread count from arguments
    if args.threads != None:
        threads = args.threads if type(args.threads) == int else 1

    if args.shuffle != None:
        if args.shuffle != False:
            shuffle = True
    
    subdns = SubdomainBruteforce(hosts)
    subdns.db.create_schema()
    subdns.run_scan(
        wordlists=wordlists,
        thread_count=threads,
        scan_mode=mode,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        port=port,
        shuffle=shuffle,
    )

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        prog='unDNS.py',
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent(f'''        
         Scan modes are the connection method used to determine
         whether or not a host is available at a given domain name.
        '''),

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
