#!/usr/bin/env python

import argparse
import os
import sys
import pandas as pd
import csv
from scapy.all import *


packet_counter = 0


# Mapping Device Name: Device MAC (and vice versa)
devices_name_mac = {    
        # Gruppe 1   
        "LDR TUYA":"D8:F1:5B:D8:08:0C",\
        "GARAGE_DOOR":"48:E1:E9:44:4C:52",\
        "LDR TAPO": "6C:5A:B0:7D:E2:25",\
        # Gruppe 2
        "LDR": "D8:1F:12:65:89:97",\
        "SmartSocket1":"54:AF:97:7C:5E:F0",\
        "Lampe1":"A8:03:24:B1:35:60",\
        "Lampe2":"60:01:94:C7:69:AC"
        }
devices_mac_name = {v:k for (k,v) in devices_name_mac.items()}

# Callback applied to captured packets
    # Show counter to stdout
def packet_callback(_):
    global packet_counter
    packet_counter += 1
    print(f"Captured {packet_counter:8} packets.")

# Capture filters
def get_bpf_filter():
    return " ".join([
        # EtherType blacklist:
        # 0x88e1 == Homeplug AV
        # 0x8912 == Unknown
        "not (ether proto 0x88e1 or ether proto 0x8912)",
        #"and",
        # MAC address whitelist:
        #"ether host 80:4E:70:13:01:8A",
    ])


def annotate(cap):

    # Append device names
    cap['device_name_src'] = cap['eth_src'].map(devices_mac_name)
    cap['device_name_dst'] = cap['eth_dst'].map(devices_mac_name)

    # ----ANNOTATION ACTION----

    # filter vor packets sent by microcontroller to indicate device action
    filter_action = cap.query('payload_utf8.str.contains("{.device", regex=True)')[['frame_time_epoch', 'payload_utf8']]

    # filter criteria for device action (with t = frame_time_epoch of microcontroller packet, mac = MAC adress of IoT device)
        # frame_time_epoch in [t- 2s, t + 5s]
        # eth_src == mac OR eth_dst == mac
    filter_action = filter_action\
            .assign(start=lambda df: df.frame_time_epoch - 2000000)\
            .assign(end = lambda df:df.frame_time_epoch + 5000000)
    filter_action['sensor'] = filter_action['payload_utf8'].map(lambda x: x[str(x).find("sensor")+9:str(x).find("value")-3])
    filter_action['mac'] = filter_action['sensor'].map(devices_name_mac)

    # extract value for annotation
    filter_action['value'] = filter_action['payload_utf8'].map(lambda x: x[str(x).find("value")+7:-1])

    # Remove duplicate packets sent by microcontroller
    for filter_number, filter_row in filter_action.iterrows():
            if (((filter_number+1) in filter_action.index) and (filter_action.at[filter_number+1,'mac']==filter_row.mac) and (filter_action.at[filter_number+1,'value']==filter_row.value)):
                    filter_action.drop(filter_number+1, inplace=True)

    # annotate action (all packets of the relevant MAC adresses with frame_time_epoch within [t-2s, t+5s] with t = frame_time_epoch of microcontroller packet)
    cap['action'] = ''
    for filter_number, filter_row in filter_action.iterrows():

            relevant_indices =  cap[(cap.frame_time_epoch >= filter_row.start) & (cap.frame_time_epoch <= filter_row.end) & ((cap.eth_src == filter_row.mac) | (cap.eth_dst == filter_row.mac))].index
            cap.loc[relevant_indices, 'action'] = filter_row.value


    # ----ANNOTATION ATTACK----

    # filter for packets sent by attacker to indicate start / stop of attack
    filter_attack = cap.query('payload_utf8.str.contains("{.attack",regex=True)')[['frame_number', 'payload_utf8']] 

    filter_attack['mac'] = filter_attack['payload_utf8'].map(lambda x: x[str(x).find("MAC")+7:str(x).find("type")-4])
    filter_attack['attack_type'] = filter_attack['payload_utf8'].map(lambda x: x[12:str(x).find("target")-4])
    filter_attack['switch'] = filter_attack['payload_utf8'].map(lambda x: x[str(x).find("type")+8:str(x).find("time")-4])

    # annotate attack (all packets between relevant "start" and "stop" sent by attacker with corresponding MAC address)
    cap['attack'] = ''
    for filter_number, filter_row in filter_attack.iterrows():
        relevant_indices = cap[(cap.frame_number > filter_number) & (cap['eth_src'] == filter_row.mac) | (cap['eth_dst'] == filter_row.mac)].loc[filter_row.frame_number:].index 

        if filter_row.switch == 'start':
            cap.loc[relevant_indices,'attack'] = filter_row.attack_type
        else:
            cap.loc[relevant_indices,'attack'] = ''
    
    return cap

def pcap_to_df(pcap_path):

    cptr = rdpcap(pcap_path)

    data = []

    for packet, frame_number in zip(cptr, range(1, len(cptr) + 1)):
        data.append({
                'frame_number': frame_number,
                'frame_time_epoch': int(packet.time * 1000000),
                'no_layers': len(packet.layers()),
                'frame_len': len(packet),
                'eth_src': str(packet.src).upper() if hasattr(packet, "src") else "NULL",
                'eth_dst': str(packet.dst).upper() if hasattr(packet, "dst") else "NULL",
                'eth_type': hex(packet.type) if hasattr(packet, "type") else "NULL",
                'ip_src': packet["IP"].src if "IP" in packet else "NULL",
                'ip_dst': packet["IP"].dst if "IP" in packet else "NULL",
                'ip_proto': packet["IP"].proto if "IP" in packet else "NULL",
                'srcport': packet.sport if hasattr(packet, "sport") else "NULL",
                'dstport': packet.dport if hasattr(packet, "dport") else "NULL",
                'payload_utf8_tcp': bytes(packet[TCP].payload).decode("utf_8", "ignore").replace(r'\n', r' ') if packet.haslayer(TCP) else "",
                'payload_utf8_udp': bytes(packet[UDP].payload).decode("utf_8", "ignore").replace(r'\n', r' ') if packet.haslayer(UDP) else "",
                'payload_len': len(packet.load) if hasattr(packet, "load") else 0
            })

    cap_df = pd.DataFrame(data)
    cap_df = cap_df.assign(payload_utf8 = lambda df: df.payload_utf8_tcp + df.payload_utf8_udp)
    cap_df['payload_utf8'] = cap_df['payload_utf8'].map(lambda x: "NULL" if x == '' else x)

    return cap_df

def dump_config(fname):
    with open(fname, "w") as f:
        f.write(str(conf))
    os.chown(fname, 1000, 1000)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--in_pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
    parser.add_argument('--out_csv', metavar='<csv file name>', help='output csv file', required=True)
    
    args = parser.parse_args()

    in_file = args.in_pcap
    out_file = args.out_csv

    if not os.path.isfile(in_file):
        print('"{}" does not exist'.format(in_file), file=sys.stderr)
        sys.exit(-1)

    cap = pcap_to_df(in_file)
    
    # Annotate with action & attack
    cap = annotate(cap)

    # Export 
    cap.to_csv(out_file, escapechar='\\', index=False, quotechar="'", sep="\t", quoting=csv.QUOTE_ALL,\
                columns = ['frame_number',
                            'frame_time_epoch',
                            'no_layers',
                            'frame_len',
                            'eth_src',
                            'device_name_src',
                            'eth_dst',
                            'device_name_dst',
                            'eth_type',
                            'ip_src',
                            'srcport',
                            'ip_dst',
                            'dstport',
                            'ip_proto',
                            'payload_utf8',
                            'payload_len',
                            'action',
                            'attack'
                            ]
                    )
    os.chown(out_file, 1000, 1000)
    

    # Dump config for debugging
    dump_config("config.txt")


if __name__ == '__main__':
    main()
