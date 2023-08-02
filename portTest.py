import socket

def is_port_open(ip, port):
    try:
        # 创建一个TCP套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 设置超时时间为1秒
        sock.settimeout(3)
        # 连接到指定的IP和端口
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True
        else:
            return False
    except Exception as e:
        print(f"发生异常：{e}")
        return False
    finally:
        sock.close()

# 要检测的IP和端口
ip = "192.168.87.1"
port = 80

if is_port_open(ip, port):
    print(f"{port} open")
else:
    print(f"{port} close")
