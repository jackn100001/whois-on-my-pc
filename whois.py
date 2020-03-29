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

long_options = ["description","country","state","city","address","cidr"]

def main():
	opts, args = get_arguments()
	all_connection_data = []
	connections = psutil.net_connections()

	# TODO: move all of below into its own function

	for conn in connections:
		if conn.raddr:
			addresses = {"laddr": conn.laddr[0], "raddr": conn.raddr[0]}

			if not_local(addresses['raddr']):
				countries = count_countries(conn)
				whois = perform_whois(str(addresses['raddr']))
				all_connection_data.append(build_connection_data(opts, args, whois, addresses))

	print(json.dumps(all_connection_data, indent=4))

def get_arguments():
	argv = sys.argv[1:]

	try:
	  	return getopt.getopt(argv,"vdc:",long_options)
	except getopt.GetoptError:
		if getopt.GetoptError.msg:
		  	print(getopt.GetoptError.msg)
		else:
			print("Invalid options, please try again")

		sys.exit(2)

def not_local(remote_ip):
	if not remote_ip.startswith('192') and not remote_ip.startswith(":") and not remote_ip.startswith("127"):
		return True

def perform_whois(ip):
	whois = IPWhois(str(ip)).lookup_whois()
	return whois

def build_connection_data(opts, args, whois, addresses):
	connection_data = {}
	connection_data['addresses'] = addresses

	for opt, arg in opts:
		key = opt[2:]

		# print(json.dumps(whois["nets"][0], indent=4))

		if opt == '-d' or opt == '':
			continue
		elif opt == '-v':
			for long_option in long_options:
				connection_data[long_option] = get_long_option(long_option, whois)
		elif key in long_options:
			connection_data[key] = get_long_option(key, whois)
		elif opt == "-c":
			country = arg
		else:
			print("{} not a valid option".format(opt))

	return connection_data

def get_long_option(key, whois):
	if whois.get(key) != None:
		return whois[key]
	elif whois["nets"][0].get(key) != None:
		return whois["nets"][0][key]

# possibly use for the -c <country> option
def count_countries(conn):
	countries = {}
	netstat = IPWhois(str(conn.raddr[0])).lookup_whois()
	jsonOut = json.dumps(netstat, indent=4)
	country = netstat["nets"][0]["country"]

	if country in countries:
		countries[country] += 1
	else:
		countries[country] = 1

	return countries

if __name__ == "__main__":
	main()









