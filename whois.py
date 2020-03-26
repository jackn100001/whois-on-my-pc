#####################################################
#
# 	Loop all non-local connections and run whois on each connection
# 	Output the data in some way
#	Add command line functionality that accepts switches	
#
#####################################################

import psutil
import json
from ipwhois import IPWhois

connections = psutil.net_connections()
for conn in connections:
	if (conn.raddr):
		print("Local: {}, Remote: {}".format(conn.laddr[0], conn.raddr[0]))
		obj = json.dumps(IPWhois(str(conn.raddr[0])).lookup_whois(), indent=4)
		print(obj)