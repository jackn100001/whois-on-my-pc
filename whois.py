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
countries = {}

for conn in connections:
	if (conn.raddr):
		raddr = conn.raddr[0]
		if (not raddr.startswith('192') and not raddr.startswith(":") and not raddr.startswith("127")):
			print("Local: {}, Remote: {}".format(conn.laddr[0], conn.raddr[0]))
			netstat = IPWhois(str(conn.raddr[0])).lookup_whois()
			jsonOut = json.dumps(netstat, indent=4)
			# print(json.dumps(netstat["nets"][0], indent=4))
			country = netstat["nets"][0]["country"]
			if (country in countries):
				countries[country] += 1
			else:
				countries[country] = 1

for country in countries:
	print(country, countries.get(country))