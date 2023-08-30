import json

#filename = '”--script nmap-vulners“Danny.txt'  # 文件名
filename = '“--script vuln”Danny.txt'  # 文件名

# 读取数据
with open(filename, 'r') as file:
    lines = file.readlines()
data = []
i = 0
while i < len(lines):
    if lines[i].startswith('----'):
        ip_address, port = lines[i+1].split()
        try:
            error_message = json.loads(lines[i+2].strip())
        except:
            error_message = lines[i+2].strip()
        data.append({'ip': ip_address, 'port': port, 'scan_data': error_message})
    i += 3



def read_for_nmap_vulners(data):
    
    count_cpe = 0
    count_name = 0
    count_product = 0

    for item in data:
        
        json_str = json.dumps(item['scan_data'], indent=4) 
        if type(item['scan_data']) == dict:
            #print(json_str)
            #先看设备在不在
            if item['scan_data']["nmap"]["scanstats"]["uphosts"] == "1":
            #再看端口是不是关的 
                info = item['scan_data']["scan"][item['ip']]["tcp"][item['port']]
                if info["state"] == "open":
                    #说明有效扫描
                    if info["cpe"] != "":
                        print(item['ip'])
                        print(item['port'])
                        print(info["cpe"])
                        count_cpe = count_cpe + 1
                        if "script" in info:
                            if "vulners" in info["script"]:
                                print(info["script"]["vulners"])
                        print()
                    elif info["version"] != "":
                        count_product = count_product + 1
                        print(item['ip'])
                        print(item['port'])
                        print(info['product'])
                        print(info['version'])
                        if "script" in info:
                            if "vulners" in info["script"]:
                                print(info["script"]["vulners"])
                        print()
                    if info["name"] != "":
                        count_name = count_name + 1
                    if "script" in info:
                        #print(info["script"])
                        print()
                    
    print("len(data)", str(len(data)))
    print("count_cpe", str(count_cpe))
    print("count_product", str(count_product))


def read_for_nmap_vuln(data):
    
    count_cpe = 0
    count_name = 0
    count_product = 0

    for item in data:
        
        json_str = json.dumps(item['scan_data'], indent=4) 
        if type(item['scan_data']) == dict:
            #print(json_str)
            #先看设备在不在
            if item['scan_data']["nmap"]["scanstats"]["uphosts"] == "1":
            #再看端口是不是关的 
                info = item['scan_data']["scan"][item['ip']]["tcp"][item['port']]
                if info["state"] == "open":
                    #说明有效扫描
                    print(item['ip'])
                    print(item['port'])
                    if "script" in info:
                        script_info = info["script"]
                        for key, value in script_info.items():
                            if key != "fingerprint-strings":
                                print(key)
                                print(value)
                    print()

                    """
                    if info["cpe"] != "":
                        print(item['ip'])
                        print(item['port'])
                        print(info["cpe"])
                        count_cpe = count_cpe + 1
                        if "script" in info:
                            if "vulners" in info["script"]:
                                print(info["script"]["vulners"])
                        print()
                    elif info["version"] != "":
                        count_product = count_product + 1
                        print(item['ip'])
                        print(item['port'])
                        print(info['product'])
                        print(info['version'])
                        if "script" in info:
                            if "vulners" in info["script"]:
                                print(info["script"]["vulners"])
                        print()
                    if info["name"] != "":
                        count_name = count_name + 1
                    if "script" in info:
                        #print(info["script"])
                        print()"""
                    
    print("len(data)", str(len(data)))
    print("count_cpe", str(count_cpe))
    print("count_product", str(count_product))


#read_for_nmap_vulners(data)
read_for_nmap_vuln(data)