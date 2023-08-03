import nmap

import utils

class PyNmapWrapper:

    def single_scan(ip_port, arguments = None, timeout = 180):
        print("into single for %s, timeout = %s", ip_port, timeout)

        nm = nmap.PortScanner()
        ip, port = ip_port
        strp = str(port)

        if arguments:
            nm.scan(ip, strp, arguments = arguments, timeout = timeout)
        else:
            nm.scan(ip, strp, timeout = timeout)

        print(nm.command_line())
        print(nm[ip])


        print(nm.get_nmap_last_output())

        for key, value in nm[ip]['tcp'].items(): #因为只有一个，也就会直接返回唯一的一个
            return (ip, key, value['name'], value['version'])

    # 多次调用single_scan
    def scan(ip_port_list, arguments = None, timeout = 180):
        result_collect = []

        for ip_port in ip_port_list:
            if timeout:
                try:
                    result = PyNmapWrapper.single_scan(ip_port, arguments = arguments, timeout = timeout)
                    result_collect.append(result)
                except Exception as e:
                    result_collect.append((ip_port[0], ip_port[1], "", ""))
                    print(e)
            else:
                result = PyNmapWrapper.single_scan(ip_port)
                result_collect.append(result)

        return result_collect


if __name__ == '__main__':
    ip_port_list = utils.getDannyIPandPorts()
    #results = PyNmapWrapper.scan(ip_port_list[0:5], timeout = 10)
    results = PyNmapWrapper.scan([("192.168.87.1", 8080)], arguments = "-sV --script vuln", timeout = 300)
    for item in results:
        print(item)


