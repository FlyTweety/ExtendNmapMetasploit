import nmap

import utils

class PyNmapWrapper:

    def single_scan(ip_port, timeout = None):
        print("into single for %s", ip_port)
        nm = nmap.PortScanner()
        ip, port = ip_port
        if timeout:
            nm.scan(ip, str(port), timeout = timeout)
        else:
            nm.scan(ip, port)
        print(nm.command_line())
        print(nm[ip])
        for key, value in nm[ip]['tcp'].items(): #因为只有一个，也就会直接返回唯一的一个
            return (ip, key, value['name'], value['version'])

    # 多次调用single_scan
    def scan(ip_port_list, timeout = None):
        result_collect = []

        for ip_port in ip_port_list:
            if timeout:
                try:
                    result = PyNmapWrapper.single_scan(ip_port, timeout)
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
    results = PyNmapWrapper.scan(ip_port_list[0:5], timeout = 10)
    for item in results:
        print(item)

