'''
Author: Ravi Nayyar

In Progress:    	Step 1: Create database and store clients connected to nearby SSIDS
Not Yet Started 	Step 2: Create fake AP from that list
Not Yet Started 	Step 3: Disconnect everyone from their respective ssids
Not Yet Started 	Step 4: Force reconnect to the pwnedAP
'''

import sys
import os
import sqlite3
from scapy.all import *
from random import randint
import threading
import subprocess
import netifaces
from time import sleep

iface = ""

clientprobesSet = set()
ssidsSet = set()

ssidsNameList = []
ssidsAddrList = []
ssidsDict = {}
ssidCount =0

count = 0
channelNumber = 0

def startMonitorMode(cmd):
	print(cmd)
	os.system(cmd)

	while(True):
		interface_list = netifaces.interfaces()
		if "wlan0mon" in interface_list:
			break

		sleep(1)


def getInterface():
	print("Wifi Interface List")
	interface_list = netifaces.interfaces()
	list_len = len(interface_list)
	for i in range(list_len):
		print("   [{}]\t{}".format(i, interface_list[i]))
	
	print("\n")	
	
	while(True):
		iface_num = input("Choose a Wifi Interface (0 - {}): ".format(list_len-1))
		
		try:
			iface_num = int(iface_num)
		except Excepton as e:
			print("Input was not a valid number\nPlease try again\n")

		if (iface_num > list_len-1):
			print("Invalid interface number selected\nPlease try again\n")
			continue

		break 

	return interface_list[iface_num]


def create_connection(db_file):
    try:
        return sqlite3.connect(db_file)
    except Error as e:
        print(e)

    return None


def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except TableError as e:
        print(e)


def create_databases():
	sql_create_ssidInfo_table = """CREATE TABLE IF NOT EXISTS ssidInfo (
	                            id integer primary key autoincrement,
	                            probedssid text not null,
	                            ssidMacaddr char(50));"""

	sql_create_clientInfo_table = """CREATE TABLE IF NOT EXISTS clientsInfo (
	                            id integer primary key autoincrement,
	                            location char(100) not null,
	                            macaddr char(50) not null,
	                            probedssid text not null,
	                            ssidMacaddr char(50));"""

	try:
		ssid_conn = create_connection("SsidInfo.db")
		create_table(ssid_conn, sql_create_ssidInfo_table)
	
		clients_conn = create_connection("ClientsInfo.db")	
		create_table(clients_conn, sql_create_clientInfo_table)
		
		return [ssid_conn, clients_conn]

	except Excepton as e:
		print("Database Error - Unable to continue\n", e)


def validate_packet_count():
	packet_number = ""
	
	while(True):
		packet_number = input("\nChoose the number of packets to process: ")

		if packet_number == "max":
			packet_number = 10000
			break

		try:
			packet_number = int(packet_number)
		except:
			print("Please pick a valid number")
			continue

		if (packet_number < 1):
			print("Please pick a valid number greater than 0")
			continue
		
		break

	return packet_number


def print_client_list():
	counter = 1
	print("-----------------CLIENT TABLE---------------------"+str(count))
	for probe in clientprobesSet :
		[client, ssid] = probe.split('---')
		print(counter, client, ssid)
		counter = counter + 1
	print("--------------------------------------------------")	


def client_sniffer(conn):
	def client_packet_handler(pkt):
		global count
		count = count+1
		i = randint(1,13)
		os.system("iwconfig wlan0mon channel "+str(i))
		if pkt.haslayer(Dot11ProbeReq):
			if len(pkt.info) > 0 :
				testcase = str(pkt.addr2) + '---' + str(pkt.info)
				if testcase not in clientprobesSet :
					clientprobesSet.add(testcase)
					msg =  "\nNew Probe Found:  " + str(pkt.addr2) + ' ' + str(pkt.info)
					print(msg + " "+str(pkt.addr3)+ "\t\t" +str(count))

					#Inserting Client mac and ssid data into client database
					conn.execute("insert into clientsInfo (location, macaddr, probedssid) values (?,?,?)", ("HomeBase", pkt.addr2, pkt.info))
					conn.commit()

	return client_packet_handler


def ssid_sniffer(conn):
	def ssid_packet_handler(pkt):
		global ssidCount
		ssidCount = ssidCount +1
		i = randint(1,13)
		os.system("iwconfig wlan0mon channel "+str(i))

		if pkt.haslayer(Dot11Beacon):
			if (pkt.info not in ssidsSet) and pkt.info:

				#Removing invalid SSIDs
				if b'\x00' in pkt.info:
					return

				ssidsSet.add(pkt.info)
				ssidsDict.update({pkt.info: pkt.addr3})
				#Inserting SSID data into ssid database
				conn.execute("insert into ssidInfo (probedssid, ssidMacaddr) values (?,?)", (pkt.info, pkt.addr3))
				conn.commit()	
				print("\nNew SSID  Found:  "+pkt.addr3, pkt.info, "            "+str(ssidCount))
	
	return ssid_packet_handler


def ssid_wrapper(pkt_count):
	ssid_conn = create_connection("SsidInfo.db")
	sniff(iface = iface, count = pkt_count, prn = ssid_sniffer(ssid_conn))


def clients_wrapper(pkt_count):
	clients_conn = create_connection("ClientsInfo.db")	
	sniff(iface = iface, count = pkt_count, prn = client_sniffer(clients_conn))


def start_packet_sniff_threading():
	pkt_count = validate_packet_count()

	x = threading.Thread(target=ssid_wrapper, args=(pkt_count,))
	y = threading.Thread(target=clients_wrapper, args=(pkt_count,))

	x.start()
	y.start()
	x.join()
	y.join()


def start_packet_sniff(conn):
	#Generating SSID and Client lists
	packet_number = validate_packet_count("SSIDs")
	sniff(iface = iface, count = packet_number, prn = ssid_sniffer(conn[0]))

	packet_number = validate_packet_count("Client Probes")
	sniff(iface = iface, count = packet_number, prn = client_sniffer(conn[1]))


def combine_dbs(conn):
	print("======================= COMBINE DBS =======================")
	#Inserting SSIDS Into ClientInfo Database
	for ssids in ssidsDict:
		ssids = ssids.decode('utf-8')

		conn[0].text_factory = str
		c = conn[0].cursor()
		query = "SELECT id FROM clientsInfo WHERE probedssid="+ "\"" +ssids+"\";"
		try:
			c.execute(query)
		except:
			print("SSID: "+ssids + "Not Found In Client Table")
			continue

		rows = c.fetchall()
		for row in rows:
			print(row)
			for id in row:
				id_str = str(id)
				query = "UPDATE clientsInfo SET ssidMacaddr="+ "\""+ ssidsDict[ssids] + "\"" +"WHERE Id= "+str(id)+";"
				#print query
				conn[1].execute(query)
				conn[1].commit()


def main():
	global iface
	iface = getInterface()

	#Setting Wifi interface to monitor mode
	airmon_cmd = "sudo airmon-ng start {}".format(iface)
	startMonitorMode(airmon_cmd)

	db_conn = create_databases()

	start_packet_sniff_threading()
	combine_dbs(db_conn)


if __name__ == '__main__':
	main()


# Step 1: Create database and store Client and SSID information

