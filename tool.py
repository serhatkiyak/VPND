#!/usr/bin/python

from geopy.distance import vincenty
from scapy.all import *
import time
import subprocess

filter = "tcp port 80" # HTTP packets

rttThresh = -1.0

sTime = -1.0

currIp = ""

#Nick
def check_RTT_timing(pkt):
        if pkt.haslayer(TCP):
                pktStr = pkt.sprintf('%TCP.flags%')
		#SYN: Send ICMP Ping to get RTT
                if pktStr == 'S':
                        time1 = time.Clock()
                        ans,unans = sr(IP(dst = pkt[IP].src)/ICMP())
                        time2 = time.Clock()
                        rttThresh = 2 * (time2 - time1)
                        currIp = pkt[IP].src
		#SYNACK: Get start time from send of SYNACK
                elif pktStr == 'SA' and currIp == pkt.src:
                        sTime = time.Clock()
		#ACK: Get end time, look for bad behavior(2xRTT)
                elif pktStr == 'A' and currIp == pkt.src:
                        if (time.Clock() - sTime) > rttThresh:
                                print(pkt[IP].src + " has broken the RTT threshold")
                        currIp = ""


#Chase
def check_HTTP_headers(pkt):
	ip_src=pkt[IP].src

	#Default browser HTTP header orderings
	chrome_list=['Host','Connection','Pragma','Cache-Control','Accept','User-Agent','DNT','Referer','Accept-Encoding','Accept-Language']
	firefox_list=['Host','User-Agent','Accept','Accept-Language','Accept-Encoding','Connection']

	#Returns List of HTTP Header Fields for Comparison
	rcvd_hdr=pkt[0].getlayer(Raw).load				#Loads HTTP header fields
	header_split=rcvd_hdr.splitlines()				#Splits each header field into list
	header_split=[i.split(':')[0] for i in header_split]		#Removes header load
	del header_split[0]						#Removes GET request field
#	print header_split						#Print header fields
	
	#Compare Recieved header fields against expected header field list
	header_split_chrome = [c for c in header_split if c in chrome_list]
	header_split_firefox = [c for c in header_split if c in firefox_list]
	if header_split_chrome == sorted(header_split_chrome, key=lambda c: chrome_list.index(c)):
		print "No VPN"
	elif header_split_firefox == sorted(header_split_firefox, key=lambda c: firefox_list.index(c)):
		print "No VPN"
	else:
		print "HTTP Header Check Failed: VPN Traffic Detected From IP address: " + ip_src
	
	#Unique HTTP Header Field Check
	if "X-Hola" in rcvd_hdr:
		print "Unique HTTP Header Check Failed: VPN traffic from IP address: " + ip_src

#Serhat
def check_geolocation(par):
	found1 = False
	found2 = False
	lat_ip = 0
	lon_ip = 0
	lat = 0
	lon = 0
	ip = ""

	for line in par.splitlines():
		if "IP:" in line:
			split1 = line.split()
			ip = split1[1]
#			print "IP: " + ip 
			req_str = "curl -s ipinfo.io/" + ip
			proc = subprocess.Popen(req_str, stdout=subprocess.PIPE, shell=True)
			ip_res = proc.stdout.read()
			
			for inner_line in ip_res.splitlines():
				if "\"loc\":" in inner_line:
					inner_split1 = inner_line.split()
					inner_split2 = inner_split1[1].split('\"')
					inner_split3 = inner_split2[1].split(',')
					lat_ip = float(inner_split3[0])
					lon_ip = float(inner_split3[1])
					found1 = True
		
		if "GET" in line and "geolocation" in line:
			split1 = line.split()
			split2 = split1[1].split('?')
			split3 = split2[1].split('&')
			split4 = split3[0].split('=')
			split5 = split3[1].split('=')
			lat = float(split4[1])
			lon = float(split5[1])
			found2 = True

	if found1 and found2:
		dist = distance(lat_ip, lon_ip, lat, lon)
#		print "Distance: " + str(dist) + " miles"
		if dist > 100:
			print "Geolocation Check Failed: VPN traffic from IP address: %s" % (ip)
#		print "Pair 1: " + str(lat_ip) + "," + str(lon_ip)	
#		print "Pair 2: " + str(lat) + "," + str(lon)
	if found1 == False:
		print "No location information from the lookup service"
	if found2 == False:
		print "No location information from the browser"

def distance(lat1,lon1,lat2,lon2):
	point_a = (lat1, lon1)
	point_b = (lat2, lon2)
	return vincenty(point_a, point_b).miles

def handler(pkt):
	req = str(pkt[TCP].payload)
	if "GET" in req and "geolocation" in req:
		ip_info = "IP: %s -> %s\n%s\n" % (pkt[IP].src, pkt[IP].dst, pkt[TCP].payload)
		check_geolocation(ip_info)
	elif "GET" in req:
		check_HTTP_headers(pkt)
	check_RTT_timing(pkt, dt)
                
sniff(filter=filter, prn=handler, store=0)
