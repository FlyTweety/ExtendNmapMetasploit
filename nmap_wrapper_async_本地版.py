import python_namp as nmap
import json
import datetime
import time
import re

import utils

def callback_store_to_database(host, scan_data):
    print("--------------------")
    ip = host
    port = int(re.search(r"-p\s+(\S+)", scan_data['nmap']['command_line']).group(1)) # It seems dangerous but it is safe
    try:
        if type(scan_data) == dict:
            if scan_data["nmap"]["scanstats"]["uphosts"] == "1":
                if scan_data["scan"][ip]["tcp"][port]["state"] == "open":
                    result = scan_data["scan"][ip]["tcp"][port]
                else:
                    result = "Port Down"
            else:
                result = "Device Down"
    except:
        result = "Exception"

    print(ip, str(port), result)

    # 结果存到DB



def scan(ip_port_list, arguments, timeout = 180):

    start_time = time.time()
    print("开始时间：", datetime.datetime.now())

    batch_size = 4
    # 建立worker pool
    async_scanner_pool = []
    for i in range(0, batch_size):
        async_scanner_pool.append(nmap.PortScannerAsync())

    split_ip_port_lists = utils.split_array(ip_port_list, batch_size)
    for batch_index in range(0, len(split_ip_port_lists)):
        print("batch = ", str(batch_index))
        batch_ip_port_list = split_ip_port_lists[batch_index]
        # 启动本批扫描
        for i in range(0, len(batch_ip_port_list)):
            ip, port = batch_ip_port_list[i]
            print("No.", str(i), ip, str(port))
            async_scanner_pool[i].scan(hosts = ip, ports = str(port), arguments = arguments, callback = callback_store_to_database, timeout = timeout)

        # 等待这一批结束再下一批
        still_running_count = 4
        while(still_running_count > 0):
            still_running_count = 0
            for scanner in async_scanner_pool:
                if scanner.still_scanning():
                    still_running_count += 1
            if still_running_count > 0:
                print(f"waiting for {still_running_count} running scan in this batch")
                time.sleep(3.0)

    print("All finished")
    print("结束时间：", datetime.datetime.now())
    print("运行用时：", str(time.time()-start_time))

if __name__ == '__main__':

    list = [("127.0.0.1", 135),("127.0.0.1", 445),("127.0.0.1", 902),("127.0.0.1", 912),("127.0.0.1", 135),("127.0.0.1", 69)]
    scan(list, arguments = "-sV --version-all --script vuln", timeout = 180)



