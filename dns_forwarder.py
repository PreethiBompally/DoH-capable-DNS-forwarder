import requests
import base64
import _thread
import threading
import argparse
import socket
from scapy.all import *
 
DNS_PORT = 53
Lock = 0
mutex = threading.Lock()
 
def check_deny_list(domain, deny_list_file):
    deny_list = []
    deny_list = open(deny_list_file, 'r').readlines()
    for i in range(len(deny_list)):
        deny_list[i] = deny_list[i].strip()
    if domain in deny_list:
        return True
    else:
        return False
 
def write_log(log_file, domain, query_type, status):
    file = None
    if log_file is not None:
        file = open(log_file, 'a')
        mutex.acquire(1)
        file.write(f"{domain} {query_type if query_type is not None else ''} {status}\n")
        file.flush()
        mutex.release()
    return
 
def dns_application(dns_server_ip, ip_address, skt, data, args):
    parsed_dns_request = IP(dst=dns_server_ip) / UDP(dport=DNS_PORT) / DNS(data)
    transaction_id = parsed_dns_request[DNS].id
    host_name = parsed_dns_request[DNSQR].qname
    host_name = host_name.decode()[:-1].encode()
    query_type = parsed_dns_request[DNSQR].qtype
    query_types = {28: "AAAA",1: 'A', 15: 'MX', 2: 'NS', 5: 'CNAME',6: 'SOA'}
    query_type = query_types.get(query_type)
    status = ''
 
    if check_deny_list(host_name.decode(), args.DENY_LIST_FILE):
        skt.sendto(bytes(DNS(id=transaction_id, qd=DNSQR(qname=host_name, qtype=query_type), rcode=3)), ip_address)
        status = 'DENY'
    else:
        forwarder_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forwarder_udp_socket.connect((dns_server_ip, DNS_PORT))
        forwarder_udp_socket.send(data)
        data = forwarder_udp_socket.recv(2048)
        skt.sendto(data, ip_address)
        status = 'ALLOW'
    write_log(args.LOG_FILE, host_name.decode(), query_type, status)
    return
 
def doh_application(doh_server, ip_address, skt, data, args):
    parsed_dns_request = IP(dst=doh_server) / UDP(dport=DNS_PORT) / DNS(data)
    transaction_id = parsed_dns_request[DNS].id
    host_name = parsed_dns_request[DNSQR].qname
    host_name = host_name.decode()[:-1].encode()
    query_type = parsed_dns_request[DNSQR].qtype
    query_types = {28: "AAAA", 1: 'A', 15: 'MX', 2: 'NS', 5: 'CNAME',6: 'SOA'}
    query_type = query_types.get(query_type)
    status = ''
    if check_deny_list(host_name.decode(), args.DENY_LIST_FILE):
        skt.sendto(bytes(DNS(id=transaction_id, qd=DNSQR(qname=host_name, qtype=query_type), rcode=3)), ip_address)
        status = 'DENY'
    else:
        refined = str(base64.urlsafe_b64encode(data))[2:-1].strip("=")
        response = requests.get(f"https://{doh_server}/dns-query?dns={refined}")
        skt.sendto(response.content, ip_address)
        status = 'ALLOW'
    write_log(args.LOG_FILE, host_name.decode(), query_type, status)
    return
 
def create_socket():
    IP = '0.0.0.0'
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.bind((IP, DNS_PORT))
    return skt
 
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--DST_IP", help="Destination DNS server IP", required=False)
    parser.add_argument("-f", "--DENY_LIST_FILE", help="File containing domains to block", required=False)
    parser.add_argument("-l", "--LOG_FILE", help="Append-only log file", required=False)
    parser.add_argument("--doh", help="Use default upstream DoH server", required=False)
    parser.add_argument("--doh_server", help="Use this upstream DoH server", required=False)
    arguments = parser.parse_args()
 
    if arguments.doh_server is not None:
        doh_server = arguments.doh_server
        skt = create_socket()
        while True:
            data, ip_address = skt.recvfrom(2048)
            _thread.start_new_thread(doh_application, (doh_server, ip_address, skt, data, arguments))
    elif arguments.doh is not None:
        doh = '8.8.8.8'
        skt = create_socket()
        while True:
            data, ip_address = skt.recvfrom(2048)
            _thread.start_new_thread(doh_application, (doh, ip_address, skt, data, arguments))
    elif arguments.DST_IP is not None:
        skt = create_socket()
        dns_server = arguments.DST_IP
        while True:
            data, ip_address = skt.recvfrom(2048)
            _thread.start_new_thread(dns_application, (dns_server, ip_address, skt, data, arguments))
    else:
        dns_server = '8.8.8.8'
        skt = create_socket()
        while True:
            data, ip_address = skt.recvfrom(2048)
            _thread.start_new_thread(dns_application, (dns_server, ip_address, skt, data, arguments))
 
if __name__ == "__main__":
    main()