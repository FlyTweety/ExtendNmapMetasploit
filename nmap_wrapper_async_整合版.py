import core.python_nmap as nmap
import json
import time
import re
import multiprocessing

import core.model as model
import core.common as common
import core.global_state as global_state
import core.config as config

CONCURRENCY_LEVEL = 4
NMAP_SCAN_INTERVAL = 300

# {mac1-port1:scan_time1, mac1-port2:scan_time2} 
last_scan_time_record = {}

def extract_result_from_scan_data(ip, port, scan_data):
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
    return result
 
def callback_extract_result(host, scan_data, result_queue):

    ip = host
    # It seems dangerous but it will be fine
    port = int(re.search(r"-p\s+(\S+)", scan_data['nmap']['command_line']).group(1)) 
    raw_result = extract_result_from_scan_data(ip, port, scan_data)

    key = ip + "-" + str(port)
    result_queue.put({key:raw_result})

    common.log(f"[Nmap Scan] Result {ip}:{port} {raw_result}")


def split_array(array, batch_size):
    result = []
    for i in range(0, len(array), batch_size):
        result.append(array[i:i+batch_size])
    return result

def build_async_scanner_pool(size):
    async_scanner_pool = []
    for i in range(0, size):
        async_scanner_pool.append(nmap.PortScannerAsync())
    return async_scanner_pool

def wait_this_batch_to_finish(async_scanner_pool, batch_size):
    still_running_count = batch_size
    while(still_running_count > 0):
        still_running_count = 0
        for i in range(0, batch_size):
            if async_scanner_pool[i].still_scanning():
                still_running_count += 1
                    
        if still_running_count > 0:
            common.log(f"[Nmap Scan] waiting for {still_running_count} running scan in this batch")            
        time.sleep(5.0)

def scan(ip_port_list, arguments = "-sV --script vuln", timeout = 180):

    batch_size = CONCURRENCY_LEVEL
    results = []

    # Build scanner worker pool
    async_scanner_pool = build_async_scanner_pool(batch_size)

    # Set up each batch
    split_ip_port_lists = split_array(ip_port_list, batch_size)
    for batch_index in range(0, len(split_ip_port_lists)):
        common.log(f"[Nmap Scan] batch = {batch_index}")
        batch_ip_port_list = split_ip_port_lists[batch_index]
        batch_queue = multiprocessing.Queue()

        # Launch scan for this batch
        for i in range(0, len(batch_ip_port_list)):
            ip, port = batch_ip_port_list[i]
            common.log(f"[Nmap Scan] No.{i} {ip}:{port}")
            async_scanner_pool[i].scan(hosts = ip, ports = str(port), arguments = arguments, callback = callback_extract_result, timeout = timeout, result_queue = batch_queue)

        # Wait for this batch to finish
        # Here the batch size is not fixed
        wait_this_batch_to_finish(async_scanner_pool, len(batch_ip_port_list))

        # Get the result from the queue and make it follows the same sequence as the input
        queue_results = {}
        for i in range(0, len(batch_ip_port_list)):
            queue_results.update(batch_queue.get()) 

        for i in range(0, len(batch_ip_port_list)):
            ip, port = batch_ip_port_list[i]
            key = ip + "-" + str(port)
            results.append(queue_results[key])

    return results 


# The rests are similar to banner_grab

def get_current_devices():
    """Get known valid devices. Same as that one in banner_grab"""

    target_device_list = []
    criteria = (model.Device.is_inspected == 1) & (model.Device.ip_addr != '')

    with model.db:
        for device in model.Device.select().where(criteria):
            target_device_list.append(device)

    return target_device_list

def build_ip_port_list(device, target_port_list):
    """ Build target ip:port list for a given device """

    target_ip_port_list = []

    with model.db:
        ip = device.ip_addr

    if target_port_list == None:

        with model.db:
            ports = json.loads(device.open_tcp_ports)
            for port in ports:

                if (device.mac_addr+"-"+str(port)) in last_scan_time_record:
                    if time.time() - last_scan_time_record[(device.mac_addr+"-"+str(port))] < NMAP_SCAN_INTERVAL:
                        common.log(f"[Banner Grab] Give up too frequent scan {device.mac_addr} {ip}:{str(port)}")
                        continue

                target_ip_port_list.append((ip, port))
                common.log(f"[Banner Grab] Set target port {device.mac_addr} {ip}:{str(port)}")
                last_scan_time_record[(device.mac_addr+"-"+str(port))] = time.time()
    else:
        for port in target_port_list:
            target_ip_port_list.append((ip, port))
            last_scan_time_record[(device.mac_addr+"-"+str(port))] = time.time()

    return target_ip_port_list


def store_result_to_database(device, target_ip_port_list, result):

    # Build result Dict.
    result_dict = {}
    for i in range(0, len(target_ip_port_list)):
        ip, port = target_ip_port_list[i]
        result_dict[port] = result[i]

    # Store to DB (simply use dict.update)
    with model.write_lock:
        with model.db:

            known_port_nmap_results = json.loads(device.port_nmap_results)
            common.log(f"[Nmap Scan] From database get IP:{device.ip_addr} Known Nmap Results:{known_port_nmap_results}")

            known_port_nmap_results.update(result_dict)
            device.port_nmap_results = json.dumps(known_port_nmap_results)

            device.save()
            common.log(f"[Nmap Scan] Store to database IP:{device.ip_addr} Nmap Results:{device.port_nmap_results}")



def run_nmap_scan(target_device_list = None, target_ports_list = None, arguments = "-sV --version-all --script vuln", timeout = 180):
    common.log("[Nmap Scan] Start")
    nm = nmap.PortScanner()
    nm.scan('127.0.0.1', '22-443')
    common.log(f"[Nmap Scan] {nm.scaninfo()}")
    """
    if not global_state.is_inspecting:
        return

    # Check the consent
    if not config.get('has_consented_to_overall_risks', False):
        return

    # target_ports_list is List[List], each list for each device
    # port_list and device_list must be one-to-one relation
    if target_ports_list != None:
        if (target_device_list == None) or (len(target_device_list) != len(target_ports_list)):
            common.log("[Nmap Scan] Args not qualified!")
            return

    # Define target devices to scan
    if target_device_list == None:
        target_device_list = get_current_devices()
    
    if len(target_device_list) == 0:
        common.log("[Nmap Scan] No valid target device to scan")
        return


    # Run Nmap scan on each device one by one
    for i in range(0, len(target_device_list)):
        device = target_device_list[i]

        # Make sure that the device is in the ARP cache; if not, skip
        try:
            global_state.arp_cache.get_ip_addr(device.mac_addr)
        except KeyError:
            continue

        # Build target ip_port list
        if target_ports_list == None:
            target_ip_port_list = build_ip_port_list(device, None)
        else:
            target_ip_port_list = build_ip_port_list(device, target_ports_list[i])

        if len(target_ip_port_list) == 0:
            common.log(f"[Nmap Scan] No target ports to scan for {device.mac_addr} {device.ip_addr}")


        # Run the Nmap Scan
        result = scan(target_ip_port_list)

        # Store the result of this device to database
        if len(result) > 0:
            store_result_to_database(device, target_ip_port_list, result)

    common.log("[Nmap Scan] Exit nmap scan")


if __name__ == '__main__':

    list = [("127.0.0.1", 135),("127.0.0.1", 445),("127.0.0.1", 902),("127.0.0.1", 912),("127.0.0.1", 135),("127.0.0.1", 69)]
    #results= scan(list, arguments = "-sV --version-all --script vuln", timeout = 180)
    results= scan(list, arguments = "-sV", timeout = 180)
    print(results)
    """


