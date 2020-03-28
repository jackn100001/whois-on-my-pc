"""
Description: Combines netstat and who is in the command line
Switches:
	--description
	--country
	--state
	--city
	--address
	--cidr
	-v, --verbose (outputs all of the above)
	-d, --default (output the local and remote ip with country next to remote ip, e.g. 8.8.8.8 (US))
	-c <country> (output all connections where remote ip is located in specified country)
Example: python3 whois.py -c US --country --state --cidr
Output:	???


Make a dictrionary called data that is dynamically populated based on arguments passed in at the command line

"""

import psutil
import json
import sys, getopt
from ipwhois import IPWhois

def count_countries(conn):
	countries = {}
	netstat = IPWhois(str(conn.raddr[0])).lookup_whois()
	jsonOut = json.dumps(netstat, indent=4)
	# print(json.dumps(netstat["nets"][0], indent=4))
	# print(json.dumps(netstat, indent=4))
	country = netstat["nets"][0]["country"]
	if (country in countries):
		countries[country] += 1
	else:
		countries[country] = 1

	return countries

def perform_whois(ip):
	whois = IPWhois(str(ip)).lookup_whois()
	return whois

def not_local(remote_ip):
	if (not remote_ip.startswith('192') and not remote_ip.startswith(":") and not remote_ip.startswith("127")):
		return True

def get_arguments():
	argv = sys.argv[1:]

	try:
	  	return getopt.getopt(argv,"vdc:",["description","country","state","city","address","cidr"])
	except getopt.GetoptError:
	  	print(getopt.GetoptError.msg)
	  	sys.exit(2)

def build_connection_data(opts, args):
	connection_data = {}

	for opt, arg in opts:
		key = opt[2:]

		if (key in whois):
			print("{}: {}".format(key.capitalize(), whois[key]))
			connection_data[key.capitalize()] = whois[key]
		elif (key in whois["nets"]):
			print("{}: {}".format(key.capitalize(), whois["nets"][key]))
			connection_data[key.capitalize()] = whois["nets"][key]
		elif (key in whois["nets"][0]):
			print("{}: {}".format(key.capitalize(), whois["nets"][0][key]))
			connection_data[key.capitalize()] = whois["nets"][0][key]
		elif (opt == "-c"):
			country = arg
		elif (opt == 'd'):
			print("default")
		elif (opt == 'v'):
			print("verbose")
		else:
			print("{} not a valid option".format(opt))

	return connection_data

opts, args = get_arguments()

connection_data = {}
connections = psutil.net_connections()

for conn in connections:
	if (conn.raddr):
		raddr = conn.raddr[0]

		if (not_local(raddr)):
			print("Showing details for connection to {}:".format(raddr))
			countries = count_countries(conn)
			whois = perform_whois(str(raddr))

			# print(json.dumps(whois, indent=4))
			connection_data[raddr] = build_connection_data(opts, args)
			
		print()


"""for country in countries:
	print(country, countries.get(country))"""

print(json.dumps(connection_data, indent=4))








