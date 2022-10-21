# unDNS

unDNS is a Python tool used to discover subdomains that may not have been found elsewhere. Sometimes subdomans go without being indexed in search engines and are generally hidden (accidentily or on purpose), but a DNS request would reveal otherwise.

# Features
* *Prallel DNS resolution* - Discover subdomains faster using multiple threads working cnocurrently
* **Test multiple targets at once** - Apply subdomains to multiple hosts at the same time
* **Persistent database** - Records are written to a SQLlite3 database regularly throughout scanning process so crashes/timeouts never result in lost progress/
