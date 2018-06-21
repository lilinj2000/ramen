#!/usr/bin/env python

"""
"""

import sys, getopt
import dpkt
import datetime
import socket
import json

def read_config(configfile):
    with open(configfile) as f:
        return json.load(f)

def ip_to_str(address):
    """Print out an IP address given a string

    Args:
        address: the string representation of a MAC address
    Returns:
        printable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)

def filter_packets(pcap, config):

    f_output = open(config["output_file"], "w") 

    # For each packet in the pcap process the contents
    for ts, buf in pcap:

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

        # Make sure the Ethernet frame contains an IP packet
        # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        # Now unpack the data within the Ethernet frame (the IP packet) 
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        
        ip = eth.data
        ip_src = ip_to_str(ip.src)
        ip_dst = ip_to_str(ip.dst)

        if ip_src != config["pack"]["source"] or ip_dst != config["pack"]["destination"]:
           continue

        # if ip.p != config["pack"]["protocol"]:
        #     continue

        # data = ip.data
        # if data.dport != config["pack"]["dst_port"]:
        #     continue

        size = len(ip.data.data)
        if size != config["pack"]["size"] :
            continue
        
        # Print out the ts in UTC
        # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts))
        f_output.write('%.9f\n' % ts)
        f_output.flush()
        # print hw_ts

def main(argv):
    try:
      opts, args = getopt.getopt(argv,"hc:",["config="])
    except getopt.GetoptError:
      print('pod.py -c <configfile>')
      sys.exit(2)
    
    for opt, arg in opts:
      if opt == '-h':
         print('pod.py -c <configfile>')
         sys.exit()
      elif opt in ("-c", "--config"):
         configfile = arg
      else:
         print('pod.py -c <configfile>')
         sys.exit()

    config = read_config(configfile)

    with open(config["pcap_file"]) as f:
        pcap = dpkt.pcap.Reader(f)
        filter_packets(pcap, config)


if __name__ == '__main__':
    main(sys.argv[1:])
