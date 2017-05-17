#!/usr/bin/python3

import dns.resolver
import os
import argparse


def parser():
    parser = argparse.ArgumentParser(
        description="simple dns_auditing script"
    )
    parser.add_argument(
        "file",
        type=str,
        help="input file with list of IP's"

    )
    parser.add_argument(
        "dns_server",
        type=str,
        help="IP adress of dns server"
    )
    return parser.parse_args()


ARGS = parser()


# Format Query for Reverse Lookup
def format(ip):
    req = '.'.join(reversed(ip.split("."))) + ".in-addr.arpa"
    return req


# Returns True if host responds to a ping request
def ping(host):
    import os, platform
    # Ping parameters as function of OS
    ping_str = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    # Ping
    return os.system("ping " + ping_str + " " + host) == 0


# Query Dns Server
def query(request):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ARGS.dns_server]

    try:

        answers = resolver.query(request, "PTR")
        if len(answers) > 1:
            global dnsDuplicates
            dnsDuplicates += 1
            print("Resolving  " + request)
            with open(os.path.normpath("duplicates.txt"), 'a') as file:
                file.write(request + "\n")
            for rdata in answers:
                with open(os.path.normpath("duplicates.txt"), 'a') as file:
                    file.write(str(rdata) + '\n')
                print(rdata)
            with open(os.path.normpath("duplicates.txt"), 'a') as file:
                file.write('\n')
    except dns.resolver.NXDOMAIN:
        print("No hostname present for " + request)
    except Exception as e:
        global dnsErrors
        dnsErrors += 1
        print("Resolving  " + request)
        s = repr(e)
        print("Query Failed with error:  " + s)
        with open(os.path.normpath("errors.txt"), 'a') as file:
            file.write("Query Failed for " + request + " with error:  " + s + "\n")


dnsErrors = 0
dnsDuplicates = 0


def main():
    file = open(os.path.normpath(ARGS.file))
    for line in file:
        line = line.strip()
        line = line.strip('\n')
        req = format(line)
        query(req)

    print("Total Dns Errors:  " + str(dnsErrors))
    print("Total Dns Duplicates:  " + str(dnsDuplicates))


if __name__ == '__main__':
    main()
