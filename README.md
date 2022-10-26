# unDNS

unDNS is a Python tool used to discover subdomains that may not have been found elsewhere. Sometimes subdomans go without being indexed in search engines and are generally hidden (accidentily or on purpose), but a DNS request would reveal otherwise.

# Features
* **Parallel DNS resolution** - Discover subdomains faster using multiple threads working concurrently
* **Test multiple targets at once** - Apply subdomains to multiple hosts with the same scan
* **Persistent database** - Records are written to a SQLlite3 database regularly throughout scanning process so crashes/timeouts never result in lost progress

# Download
```
wget https://raw.githubusercontent.com/CyberJosie/undns/main/unDNS/unDNS.py

# Or

curl -O https://raw.githubusercontent.com/CyberJosie/undns/main/unDNS/unDNS.py
```

# Install
```
python3 -m pip install numpy
```

# Usage
```
    usage: unDNS.py [-h] [--domains DOMAINS] [--wordlists WORDLISTS] [--web-socket] [--port PORT] [--proxy PROXY] [--threads THREADS] [--inspect INSPECT] [--shuffle]

Scan Modes:

 Scan modes are different methods used to determine if a host is available
 at a given domain. By default this program uses DNS which is dependant on
 the host system. All options are below.

  * DNS - Makes DNS requests via the host DNS resolver. See '/etc/resolv.conf' 
          for Linux.

  * Web Socket - Attempts to connect to the host as if it were a webserver. 
                 Proxied requests are available with this mode.

optional arguments:
  -h, --help            show this help message and exit
  --domains DOMAINS, -d DOMAINS
                        
                        One or more host domains to prefix with subdomains.
                        (Separate multiple domains with commas)
                        
                        Required: True
                        Default: None
                        
  --wordlists WORDLISTS, -w WORDLISTS
                        
                        Path to one or more wordlists filled with newline separated subdomains. 
                        Any non UTF-8 compatible elements will be ignored.
                        (Separate multiple paths with commas)
                        
                        Required: True
                        Default: None
                        
  --web-socket, -ws     
                        Set this flag to use web socket mode.
                        
                        Required: False
                        
  --port PORT, -p PORT  
                        Port to use with web socket
                        
                        Required: False
                        Default: 443
                        
  --proxy PROXY, -x PROXY
                        
                        Proxy server to use for forwarding requests in web socket mode.
                        Set 'tor' to use: socks5h://127.0.0.1:9050 (local Tor proxy).
                        
                        Required: False
                        Default: None
                        
  --threads THREADS, -t THREADS
                        
                        Number of concurrent threads to use.
                        Subdomains will be (somewhat) evenly distributed among threads.
                        
                        Required: False
                        Default: 1
                        
  --inspect INSPECT, -i INSPECT
                        
                        Inspect Sqlite3 database output file.
                        
                        Required: False
                        Default: None
                        
  --shuffle, -s         
                        Randomize the order of subdomains (no value)
                        
                        Required: False
                        

https://github.com/CyberJosie/undns


```

# Example Usage

Scan for all subdomains in `wordlist1.txt` and `wordlist2.txt` for host `google.com` using a web socket proxied over a local Tor connection. Subdomain order will be shuffled first.
```
$ python3 unDNS.py \
> --domains google.com \
> --wordlists ~/path/to/wordlist1.txt,~/path/to/wordlist2.txt \
> --web-socket --proxy tor \
> --threads 4 \
> --shuffle
```

Scan all subdomains in `wordlist1.txt` for hosts `example.com` and `example2.com` using a proxies web socket on port 80 (HTTP) over a local Tor connection. Subdomain order will be shuffled first.
```
$ python3 unDNS.py \
> --domains example.com,example2.com \
> -w ~/path/to/wordlist1.txt \
> --web-socket --port 80 \
> --proxy tor \
> --threads 4 \
> -s
```

## Inspect an output Sqlite file without knowing SQL
```
python3 unDNS.py --inspect scan_1666XXXXXX.db
```
