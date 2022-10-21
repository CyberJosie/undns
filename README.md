# unDNS

unDNS is a Python tool used to discover subdomains that may not have been found elsewhere. Sometimes subdomans go without being indexed in search engines and are generally hidden (accidentily or on purpose), but a DNS request would reveal otherwise.

# Features
* **Parallel DNS resolution** - Discover subdomains faster using multiple threads working concurrently
* **Test multiple targets at once** - Apply subdomains to multiple hosts with the same scan
* **Persistent database** - Records are written to a SQLlite3 database regularly throughout scanning process so crashes/timeouts never result in lost progress

# Usage
```
    
usage: unDNS.py [-h] [--hosts HOSTS] [--wordlists WORDLISTS] [--threads THREADS] [--mode MODE]

Scan modes are the connection method used to determine
whether or not a host is available at a given domain name.

   * DNS - Use host DNS client to attempt domain resolution
           Not compatible with proxies. See operating system
           manual for more.

   * More sometime in the future lol

optional arguments:
  -h, --help            show this help message and exit
  --hosts HOSTS, -H HOSTS
                        
                        One or more host domains to prefix with subdomains.
                        (Separate multiple elements with commas)
                        
                        Required: True
                        Default: None
  --wordlists WORDLISTS, -W WORDLISTS
                        
                        Path to one or more wordlists filled with newline separated subdomains.
                        Any non UTF-8 compatible elements will be ignored.
                        (Separate multiple elements with commas)
                        
                        Required: True
                        Default: None
                        
  --threads THREADS, -T THREADS
                        
                        Number of concurrent threads to use.
                        Subdomains will be (somewhat) evenly distributed amongst threads.
                        
                        Required: False
                        Default: 1
                        
  --mode MODE, -M MODE  
                        Scan modes to use for analysis.
                        All options: DNS (Work in progress)
                        (Separate multiple elements with commas)
                        
                        Required: False
                        Default: DNS
                        

```

