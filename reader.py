import json

filename = '“--script=vulscanvulscan.nse”NYU.txt'  # 文件名

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

# 解析数据
count_cpe = 0
count_name = 0

for item in data:

    
    json_str = json.dumps(item['scan_data'], indent=4) 
    if type(item['scan_data']) == dict:
        print(json_str)
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
                    print()
                if info["name"] != "":
                    count_name = count_name + 1
                if "script" in info:
                    #print(info["script"])
                    print()
                
print(len(data))
print(count_cpe)