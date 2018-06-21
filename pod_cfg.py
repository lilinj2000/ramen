#!/usr/bin/env python

import json

pack = { 
    "source": "192.168.230.22", 
    "destination": "192.168.230.42",
    "size": 512
    }

prefix_file = 'ens1d1_20180621_022'
config = {"pcap_file": ''.join([prefix_file,'.pcap']), 
          "pack": pack, 
          "output_file": ''.join([prefix_file, '.output'])}

with open(''.join(['pod_', prefix_file, '.cfg']), 'w') as f:
    json.dump(config, f, sort_keys=True, indent=4)
