import dns.
import os

dnsErrors = 0
dnsDuplicates = 0

def main():

    file = open(os.path.normpath("C:/Users/mzarglis/Desktop/python/ip_list.txt"))
    for line in file:
        line = line.strip()
        line = line.strip('\n')
        req = format(line)
        query(req)

    print("Total Dns Errors:  " + str(dnsErrors))
    print("Total Dns Duplicates:  " + str(dnsDuplicates))


#Format Query for Reverse Lookup
def format(ip):
    req = '.'.join(reversed(ip.split("."))) + ".in-addr.arpa"
    return req
#Returns True if host responds to a ping request
def ping(host):
  import os, platform
  # Ping parameters as function of OS
  ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1"
  # Ping
  return os.system("ping " + ping_str + " " + host) == 0

#Query Dns Server
def query(request):
    resolver = dns
    resolver.nameservers = ['10.105.105.100']

    try:

        answers = resolver.query(request,"PTR")
        if len(answers) > 1:
            global dnsDuplicates
            dnsDuplicates += 1
            print("Resolving  " + request)
            with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/duplicates.txt"), 'a') as file:
                file.write(request + "\n")
            for rdata in answers:
                with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/duplicates.txt"), 'a') as file:
                    file.write(str(rdata) + '\n')
                print(rdata)
            with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/duplicates.txt"), 'a') as file:
                 file.write( '\n')

    except Exception as e:
        global dnsErrors
        dnsErrors += 1
        print("Resolving  " + request)
        s = repr(e)
        print("Query Failed with error:  "+s)
        with open(os.path.normpath("C:/Users/mzarglis/Desktop/python/errors.txt"), 'a') as file:
            file.write("Query Failed for "+request+ " with error:  "+s + "\n")


main()
