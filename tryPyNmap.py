import nmap
import json

import utils

def callback_print_and_record(host, scan_result):
    print("--------------------")
    print(host)
    print(scan_result)

class PyNmapWrapper:

    def __init__(self):
        self.result_collect = []

    def single_scan(self, ip_port, arguments = None, timeout = 180, keep_record_file = None):
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
        print(nm.get_nmap_last_output().decode())

        for key, value in nm[ip]['tcp'].items(): #因为只有一个，也就会直接返回唯一的一个
            
            if keep_record_file:
                with open(keep_record_file, "a") as file:
                    file.write("\n###########################################################################\n")
                    file.write(ip)
                    file.write(str(port))
                    json_nmip = json.dumps(nm[ip])
                    file.write(json_nmip)
                    file.write("\n")
                    file.write(nm.get_nmap_last_output().decode())

            return (ip, key, value['name'], value['version'], nm.get_nmap_last_output().decode())

 
    def scan(self, ip_port_list, arguments = "-sV", timeout = 180, keep_record_file = None):

        result_collect = []
        print("Many targets: ", str(len(ip_port_list)))
        async_scanner_pool = []

        #先不分批
        for i in range(0, len(ip_port_list)):

            ip, port = ip_port_list[i]
            print("No.", str(i))
            # 默认有arguments和timeout

            # 每轮里面都新建一个异步扫描器
            this_async_scanner = nmap.PortScannerAsync()
            async_scanner_pool.append(this_async_scanner)

            #运行扫描，这不会被阻塞
            this_async_scanner.scan(hosts = ip, ports = str(port), arguments = arguments, sudo = True, callback = callback_print_and_record, timeout = timeout)


            #写文件的事晚点再说

        #阻塞直到全部完成
        running_sanner_count = len(async_scanner_pool)
        while running_sanner_count > 0:
            for scanner in async_scanner_pool:
                if not scanner.still_scanning():
                    running_sanner_count = running_sanner_count - 1
                    async_scanner_pool.remove(scanner)
            time.sleep(2)

        print("All finished")

        return result_collect


if __name__ == '__main__':

    #要导入端口扫描的结果来运行，最后输出结果到文件
    danny_ip_port_list = utils.getDannyIPandPorts()
    PyNmapWrapperInst = PyNmapWrapper()
    keep_record_file = "quickResult.txt"
    results = PyNmapWrapperInst.scan(danny_ip_port_list, arguments = "-sV --version-all --script vuln", timeout = 300, keep_record_file = keep_record_file)
    


