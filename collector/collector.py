#!/bin/env python3
from scapy.all import Packet, rdpcap, sniff, bind_layers, Raw, BitField, ByteField, FieldListField
from scapy.layers.l2 import Ether

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

import argparse, sys, time

# Define constants for PTPv2 protocol
# EtherType for PTPv2 over Ethernet
PTP_ETHERTYPE = 0x88F7

PTP_MSG_TYPE_SYNC           = 0x0
PTP_MSG_TYPE_FOLLOW_UP      = 0x8
PTP_MSG_TYPE_DELAY_REQUEST  = 0x1
PTP_MSG_TYPE_DELAY_RESPONSE = 0x9

# standard size of each message
PTP_MSG_LEN_FOLLOW_UP = 44
# 44 bytes + 10 bytes of request IDs (8bytes of clockId + 2 bytes of portId)
PTP_MSG_LEN_DELAY_RESPONSE = 54

class PTP(Packet):
    fields_desc = [ 
        BitField("transportSpecific", 0, 4),
        BitField("messageType", 0, 4),
        BitField("reserve_1", 0, 4),
        BitField("versionPTP", 0, 4),
        BitField("messageLength", 0, 16),
        BitField("domainNumber", 0, 8),
        BitField("reserve_2", 0, 8),
        BitField("flagField", 0, 16),
        BitField("correctionNs", 0, 48),
        BitField("correctionSubNs", 0, 16),
        BitField("reserve_3", 0, 32),
        BitField("clockId", 0, 64),
        BitField("portId", 0, 16),
        BitField("sequenceId", 0, 16),
        BitField("controlField", 0, 8),
        BitField("logMessageInterval", 0, 8),
        BitField("tsSeconds", 0, 48),
        BitField("tsNanoSeconds", 0, 32),
    ]

class PtpDelayResponse(Packet):
    fields_desc = [ 
        BitField("requestClockId", 0, 64),
        BitField("requestPortId", 0, 16)
    ]

PTP_TLV_INT_TYPE  = 0x0010
class TLV(Packet):
    fields_desc = [ 
        BitField("tlvType", 0, 16),
        BitField("tlvLength", 0, 16),
        # Value field will be dynamically parsed based on the length
        FieldListField("tlvData", [], ByteField("", 0), length_from=lambda pkt: pkt.tlvLength)  # Value (variable length)
    ]

class INT(Packet):
    fields_desc = [ 
        BitField("switchId", 0, 16),
        BitField("ingressTstamp", 0, 64), #timestamp in nanosecond
        BitField("egressTstamp", 0, 64),  #timestamp in nanosecond
        BitField("correctionNs", 0, 48)   #correction time in nanosecond
    ]


bind_layers(Ether, PTP, type=PTP_ETHERTYPE)
bind_layers(PTP, PtpDelayResponse, messageType=PTP_MSG_TYPE_DELAY_RESPONSE)

# Parse multiple TLVs to retrieve INT reports from the raw payload
def parse_int_reports(rawPayload):
    offset  = 0
    reports = []
    # parse all TLV extension elements
    while offset < len(rawPayload):
        # Extract the current TLV
        tlv = TLV(rawPayload[offset:])
        
        #print(f"TLV type: {tlv.tlvType}")
        
        # Move the offset by the TLV header size (4 bytes) + TLV length
        offset += 4 + tlv.tlvLength
        
        #parse our inband-network telemetry report
        if tlv.tlvType == PTP_TLV_INT_TYPE:
            report = INT(bytes(tlv.tlvData))
            #print(report.switchId, report.ingressTstamp, report.egressTstamp)
            if report.ingressTstamp >= report.egressTstamp:
                print(f"IMPOSSIBLE: ingressTs >= egressTs at switchId={report.switchId}")
            reports.append( report )

    return reports

# Function to analyze the packet
def analyze_packet(packet):
    if Ether in packet:
        eth = packet[Ether]
        if eth.type == PTP_ETHERTYPE:  # Check for PTPv2 EtherType
            #print("-" * 50)
            #print("PTPv2 Packet Detected!")
            #print(f"Source MAC: {eth.src}")
            #print(f"Destination MAC: {eth.dst}")
            #print(f"EtherType: {hex(eth.type)}")
            
            # no PTP
            if PTP not in packet:
                return
                
            ptp = packet[PTP]
                
            #print(f"PTP length : {ptp.messageLength}")

            # no more data
            if not Raw in packet:
                return

            # we are interested in only follow_up and delay_response messages
            if ptp.messageType not in [PTP_MSG_TYPE_FOLLOW_UP, PTP_MSG_TYPE_DELAY_RESPONSE]:
                return
            
            ptpMsgLen = PTP_MSG_LEN_FOLLOW_UP
            if ptp.messageType == PTP_MSG_TYPE_DELAY_RESPONSE:
                ptpMsgLen = PTP_MSG_LEN_DELAY_RESPONSE
            
            
            # there is no TLV extensions
            if ptpMsgLen >= ptp.messageLength:
                return
            
            tlvRawLen = ptp.messageLength - ptpMsgLen
            rawPayload = packet[Raw].load
            reports = parse_int_reports( rawPayload[0:tlvRawLen] )
            analyse_reports(ptp, reports)

# threshold of IAT of each switch
iatThresholds = dict()
NB_SAMPLES_TO_LEARN = 20
# delta to compare
DELTA = {"sync" : 100000, "delay_req": 100000}
def attack_detection( tag, elem ):
    global iatThresholds

    #for the first time
    if tag not in iatThresholds:
        threshold = dict()
        threshold["count"] = 1
        for s in elem["nodes"]:
            node = elem["nodes"][s]
            if "iat-master" not in node:
                continue
            threshold[s] = node["iat-master"]
            iatThresholds[tag] = threshold
        return

    
    threshold = iatThresholds[tag]
    threshold["count"] += 1
    
    #wait for x benign samples
    if threshold["count"] < NB_SAMPLES_TO_LEARN:
        for s in elem["nodes"]:
            node = elem["nodes"][s]
            if "iat-master" not in node:
                continue
            val = node["iat-master"]
            if abs(val) > abs(threshold[s]): 
                threshold[s] = abs(val)
        return

    if threshold["count"] == NB_SAMPLES_TO_LEARN:
        print(f"\n=====start TDA monitoring on {tag}=======\n")
        #notify to GUI
        for s in elem["nodes"]:
            node = elem["nodes"][s]
            if "iat-master" not in node:
                continue
            node["under-attack"] = 0

    # detection
    for s in elem["nodes"]:
        node = elem["nodes"][s]
        if "iat-master" not in node:
            continue
        val = node["iat-master"]
        if abs(val) > abs(threshold[s]) + DELTA[tag]:
            node["under-attack"] = 1



lastElement = dict()
def analyse_reports(ptp, reports):
    global lastElement

    tag = "sync"
    # if current ptp msg is a delay_res ==> we are analysing its delay_req
    if ptp.messageType == PTP_MSG_TYPE_DELAY_RESPONSE:
        tag = "delay_req"

    sequenceId = ptp.sequenceId

    # store the info
    if tag not in lastElement:
        lastElement[tag] = (sequenceId, ptp, reports)
        return
    
    # get the last element
    lsequenceId, lptp, lreports = lastElement[tag]
    lastElement[tag] = (sequenceId, ptp, reports)

    # need to ensure that lsequenceId + 1 == sequenceId
    # ensure len(lreports) == len(reports)
    if lsequenceId + 1 != sequenceId:
        print(f"Error: two {tag} messages are not consecutive ({lsequenceId}, {sequenceId})")
        return
    if len(lreports) != len(reports):
        print(f"Error: two {tag} messages are not same size ({len(lreports)}, {len(reports)})")
        return

    #print("-----")
    #print(lreports)
    #print(reports)
    #if tag == "sync":
    #    print(f"{sequenceId}   -  {ptp.tsNanoSeconds}")
    elem = dict()
    elem["sequence-id"] = sequenceId
    elem["nodes"] = dict()

    NS_SEC = 1000*1000*1000
    masterTime = (ptp.tsSeconds * NS_SEC + ptp.tsNanoSeconds)
    
    #IAT between 2 sync messages at the master side
    iatMaster =  masterTime - (lptp.tsSeconds * NS_SEC + lptp.tsNanoSeconds)

    elem["nodes"]["master"] = {"iat": iatMaster, "ingressTstamp": masterTime, "egressTstamp": masterTime}

    # get delay of each switch
    for i in range(len(reports)):
        report  = reports[i]
        lreport = lreports[i]

        # if msg is a delay_res ==> we are analysing its delay_req
        #  delay_res is in drection from slave --> to --> master
        #  => we need to base on the moment it is sent out
        if ptp.messageType == PTP_MSG_TYPE_DELAY_RESPONSE:
            iat = report.egressTstamp - lreport.egressTstamp
            
            # delay_req packet towards: switch ----> master
            # => the extra delay will be introduced after the packet went out of the switch
            # => we need to add this delay when comparing with IAT at the master
            iat += (report.correctionNs - lreport.correctionNs)
        else:
            #different between 2 consecutive messages
            iat  = report.ingressTstamp - lreport.ingressTstamp
            
            # sync packet towards:   master ----> switch
            # => when packet arrived at the switch, it experienced extra delay
            # => we need to minus this delay when comparing with IAT at the master
            iat -= (report.correctionNs - lreport.correctionNs)

        #iat -= ptp.logMessageInterval
        elem["nodes"][ f"switch-{report.switchId}" ] =  {
                "iat": iat,
                "iat-master": iat - iatMaster, 
                "ingressTstamp": report.ingressTstamp, 
                "egressTstamp": report.egressTstamp,
                "ingressTstamp-master": report.ingressTstamp - masterTime, 
                "egressTstamp-master": report.egressTstamp - masterTime,
                "delay": report.egressTstamp - report.ingressTstamp
        }
    
    attack_detection( tag, elem)
    
    push_stat_to_http_server( tag, elem )

# Lock to safely update the shared number
number_lock = threading.Lock()
# Global variables for tracking statistics
database = {}  # List to store historical bandwidth data points
MAX_HISTORY_LENGTH = 20  # Maximum number of data points to store

def push_stat_to_http_server( tag, elem ):

    with number_lock:
        # initialise an array to contain this tag for the first time
        if tag not in database:
            database[tag] = [elem]
            return

        data = database[tag]
        # append element to tail of queue
        data.append( elem )
            # Trim history to the maximum length
        if len(data) > MAX_HISTORY_LENGTH:
            data.pop(0)


## HTTP server to expose data to grafana
# Custom HTTP handler
class CustomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global data_history
        
        # remove the first /
        # format: tag/metric
        paths = self.path.split("/")
        tag = paths[1]

        json_data = None
        # Read the shared number safely
        with number_lock:
            if tag in database:
                data = database[tag]

                #get detail of each metric of each node
                # return a 2D array containing metric, e.g,:
                # sequence-id, master, switch-1, switch-2, ...
                #  seq1      , v1,     v2,       v3,       ...
                if len(paths) > 2:
                    metricName = paths[2]

                    ret = [] 
                    for elem in data:
                        newE = dict()
                        newE["sequence-id"] = elem["sequence-id"]
                        for n in elem["nodes"]:
                            node = elem["nodes"][n]
                            if metricName in node:
                                newE[n] = node[metricName]

                        ret.append(newE)

                    data = ret
                    
                json_data = json.dumps( data )

        if json_data == None:
            # Respond with 404 for unknown paths
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
        else:
            # Respond with the current number in JSON format
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json_data.encode("utf-8"))

# Function to run the HTTP server in a separate thread
def run_http_server(ip, port):

    server = HTTPServer((ip, port), CustomHandler)
    print(f"HTTP server is running on port {port}...")
    server.serve_forever()

def start_http_server_thread(ip, port):
    # Start the HTTP server in a separate thread
    server_thread = threading.Thread(target=run_http_server, args=(ip, port))
    # Allow the program to exit even if the thread is running
    server_thread.daemon = True
    server_thread.start()
    return server_thread
## end HTTP server

# Main entry point
if __name__ == "__main__":
        # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Sniff packets from a given network and extract its PTP protocol.")
    parser.add_argument("--nic", default=None, help="Network interface to be sniffed")
    parser.add_argument("--pcap-file", default=None, help="Path to the pcap file to analyse")
    parser.add_argument("--ip",   default="127.0.0.1", help="IP of HTTP server to expose stats to Grafana")
    parser.add_argument("--port", default=4000, help="Port number of HTTP server to expose stats to Grafana")
    parser.add_argument("--nb-learning-samples", default=50, help="First X samples to learn")
    parser.add_argument("--sigma", default=15000, help="Sensitive detection sigma parameter")


    args = parser.parse_args()
    NB_SAMPLES_TO_LEARN = int(args.nb_learning_samples)

    DELTA = {"sync" : int(args.sigma), "delay_req": int(args.sigma)}

    try:
        http_server = start_http_server_thread( args.ip, args.port )

        if args.nic:
            print(f"Sniffing on interface: {args.nic}")
            # Filter for Ethernet frames with PTP EtherType
            sniff(iface=args.nic, filter=f"ether proto {PTP_ETHERTYPE}", prn=analyze_packet)
        elif args.pcap_file:
            #read the pcap file and extract the features for each packet
            all_packets = rdpcap( args.pcap_file )
            # for each packet in the pcap file
            for packet in all_packets:
                analyze_packet(packet)

            #wait for the server
            http_server.join()
        else:
            print("Error: you need to provide either --nic or --pcap-file parameter")
    except KeyboardInterrupt:
        None
    except:
        raise
    finally:
        print("\nBye!.")
