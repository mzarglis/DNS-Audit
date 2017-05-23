# DNS-Audit
Python script that takes a list of ips and will preform reverse lookup to resolve hostnames.

Wrote this to ensure all networking devices have correct reserse lookups populated in DNS

--Future--
-Integrate w/ HPNA (pull list of active devices)
-Ping hosts with no reverse records to see if alive
-Check for forward DNS records aswell
-email nicely formatted output on completion so i can make a cron job to run this monthly 






##USAGE##

DNS-Audit.py [iplist] [nameserver ip]

iplist should be a file with ips 1 per line
depends on dnspython package (pip install dnspython)
