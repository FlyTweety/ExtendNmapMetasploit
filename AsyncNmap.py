import PythonNmap as nmap
import json
import datetime
import time

import utils

def callback_print_and_record(host, ports, scan_data, output_file):
    print("--------------------")
    print(host)
    print(ports)
    print(scan_data)

    if output_file:
            with open(output_file, "a") as file:
                file.write("----------------------------------------------------\n")
                file.write(host)
                file.write(" ")
                file.write(ports)
                file.write("\n")
                if scan_data:
                    json_scan_data = json.dumps(scan_data)
                    file.write(json_scan_data)
                else:
                    file.write("PortScannerError")
                file.write("\n")

class PyNmapWrapper:

    def __init__(self):
        self.result_collect = []
        self.batch_size = 4
 
    def scan(self, ip_port_list, arguments = "-sV", timeout = 180, output_file = None):
        start_time = time.time()
        print("开始时间：", datetime.datetime.now())

        result_collect = []
        print("Many targets: ", str(len(ip_port_list)))
        async_scanner_pool = []

        batch_ip_port_list_collect = utils.split_array(ip_port_list, self.batch_size)
        for batch_index in range(0, len(batch_ip_port_list_collect)):
            print("batch = ", str(batch_index))

            batch_ip_port_list = batch_ip_port_list_collect[batch_index]
            for i in range(0, len(batch_ip_port_list)):

                ip, port = batch_ip_port_list[i]
                print("No.", str(i), ip, str(port))
                # 默认有arguments和timeout

                # 每轮里面都新建一个异步扫描器
                this_async_scanner = nmap.PortScannerAsync()
                async_scanner_pool.append(this_async_scanner)

                #运行扫描，这不会被阻塞
                this_async_scanner.scan(hosts = ip, ports = str(port), arguments = arguments, callback = callback_print_and_record, timeout = timeout, output_file = output_file)

            #阻塞直到这个batch全部完成
            running_sanner_count = len(async_scanner_pool)
            while running_sanner_count > 0:
                for scanner in async_scanner_pool:
                    if not scanner.still_scanning():
                        running_sanner_count = running_sanner_count - 1
                        async_scanner_pool.remove(scanner)
                print("waiting for", str(running_sanner_count), "running scan in this batch")
                time.sleep(2)

        print("All finished")
        print("结束时间：", datetime.datetime.now())
        print("运行用时：", str(time.time()-start_time))
        
        for result in result_collect:
            print(result)

        return result_collect


if __name__ == '__main__':

    #要导入端口扫描的结果来运行，最后输出结果到文件
    danny_ip_port_list = utils.getDannyIPandPorts()
    PyNmapWrapperInst = PyNmapWrapper()
    keep_record_file = "asyncResultvulscanvulscan0809.txt"
    #results = PyNmapWrapperInst.scan([('172.19.219.32', 7676), ('172.19.219.14', 8009), ('172.19.219.11', 631), ('172.19.221.34', 443)], arguments = "-sV --version-all --script vuln", timeout = 300, keep_record_file = keep_record_file)
    results = PyNmapWrapperInst.scan(utils.getDannyIPandPorts0809(), arguments = "-sV --version-all --script=vulscan/vulscan.nse", timeout = 480, output_file = keep_record_file)
    


