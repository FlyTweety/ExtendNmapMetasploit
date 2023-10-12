import nmap
import json
import time
import re
import multiprocessing


CONCURRENCY_LEVEL = 10
NMAP_SCAN_INTERVAL = 300

# {mac1-port1:scan_time1, mac1-port2:scan_time2} 
last_scan_time_record = {}


def scan(ip_port_list, arguments = "-sV --script vuln", timeout = 180):

    scanner = nmap.PortScanner()

    # Restruct target by ip
    target_ports_by_ip = {}
    for entry in ip_port_list:
        ip, port = entry
        if ip in target_ports_by_ip:
            target_ports_by_ip[ip].append(port)
        else:
            target_ports_by_ip[ip] = [port]
    
    target_ips = target_ports_by_ip.keys()
    results_by_ip = {} 

    # Launch scan on each ip
    for ip in target_ips:
        
        # Launch scan for this ip
        ports_str = ",".join(str(port) for port in target_ports_by_ip[ip]) 
        scanner.scan(hosts = ip, ports = ports_str, arguments = arguments)
        
        # Save result of this ip
        result_for_this_ip = {}
        # If this device is down
        if ip not in scanner.all_hosts():
            for port in target_ports_by_ip[ip]:
                result_for_this_ip[port] = "Device Down"
        else:
            for port in target_ports_by_ip[ip]:
                result_for_this_ip[port] = scanner[ip]['tcp'][port]
        results_by_ip[ip] = result_for_this_ip

    # store results respect to the order in ip_port_list
    results = []
    for entry in ip_port_list:
        ip, port = entry
        results.append(results_by_ip[ip][port])

    return results 


# 现在改成不用async 就传多个地址和端口给nmap
"""
>>> import nmap
>>> nm = nmap.PortScanner()
>>> nm.scan('127.0.0.1', '22-443')
>>> nm.command_line()
'nmap -oX - -p 22-443 -sV 127.0.0.1'
>>> nm.scaninfo()
{'tcp': {'services': '22-443', 'method': 'connect'}}
>>> nm.all_hosts()
['127.0.0.1']
>>> nm['127.0.0.1'].hostname()
'localhost'
>>> nm['127.0.0.1'].state()
'up'
>>> nm['127.0.0.1'].all_protocols()
['tcp']
>>> nm['127.0.0.1']['tcp'].keys()
[80, 25, 443, 22, 111]
>>> nm['127.0.0.1'].has_tcp(22)
True
>>> nm['127.0.0.1'].has_tcp(23)
False
>>> nm['127.0.0.1']['tcp'][22]
{'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
>>> nm['127.0.0.1'].tcp(22)
{'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
>>> nm['127.0.0.1']['tcp'][22]['state']
'open'
"""

if __name__ == '__main__':

    list = [("127.0.0.1", 135),("127.0.0.1", 445),("127.0.0.1", 902),("127.0.0.1", 912),("127.0.0.1", 135),("127.0.0.1", 69)]
    results = scan(list, arguments = "-sV")
    for result in results:
        print(result)
    #results= scan(list, arguments = "-sV --version-all --script vuln", timeout = 180)

    #results= scan(list, arguments = "-sV", timeout = 180)
    #print(results)

    """
    print("##############################")
    
    nm = nmap.PortScanner()
    #nm.scan(hosts="127.0.0.1", ports = "135,445,902", arguments = "-sV --version-all --script vuln")
    nm.scan(hosts="127.0.0.1", ports = "135,445,902,9999", arguments = "-sV")
    print(nm.scaninfo())
    print(nm.all_hosts())
    print(nm['127.0.0.1']['tcp'][135])
    print(nm['127.0.0.1']['tcp'][445])
    print(nm['127.0.0.1']['tcp'][902])
    print(nm['127.0.0.1']['tcp'][9999])
    """


