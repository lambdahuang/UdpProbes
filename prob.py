import socket
import argparse
import ipaddress
import redis
import json
import random
import time
from termcolor import colored

ADDR_MASK = 24
SENT_PORT = 55543
OUTGOING_TTL = 64

def send_udp(UDP_IP, UDP_PORT):
    MESSAGE = ''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, OUTGOING_TTL)
    sock.sendto(bytes(MESSAGE, "utf-8"), (UDP_IP, UDP_PORT))


def get_network_by_ip(ip, mask):
    """ Get the network object by ip
        :params ip: the ip address
        :params mask: the network mask in format of 24 or 18
    """
    ip_int = int(ipaddress.IPv4Address(ip))
    mask_int = 0x0000
    for i in range(0, mask):
        mask_int = mask_int | int(2**(32-i))
    network_ip = str(ipaddress.IPv4Address(ip_int & mask_int))
    return ipaddress.IPv4Network("{}/{}".format(network_ip, mask))


def listen(redis_connection):
    """ Catch the icmp data packet
        :params redis_connection: the redis connection
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    cont = 0
    while 1:
        try:
            data, addr = s.recvfrom(1508)

            icmp_type = data[20]
            icmp_code = data[21]
            icmp_ttl = data[8]
            orig_ttl = data[36]
            orig_src_ip = socket.inet_ntoa(data[40:44])
            orig_dst_ip = socket.inet_ntoa(data[44:48])
            orig_dst_port = data[50]<<8|data[51]

            if icmp_type != 3 or orig_dst_port != SENT_PORT:
                continue

            icmp_ip_network = get_network_by_ip(addr[0], ADDR_MASK)
            icmp_network_addr = str(icmp_ip_network.network_address)
            icmp_ip_addr = addr[0]

            orig_dst_network = get_network_by_ip(orig_dst_ip, ADDR_MASK)
            orig_dst_network_addr = str(orig_dst_network.network_address)

            hop_distance = OUTGOING_TTL - orig_ttl

            if icmp_ip_addr == orig_dst_ip:
                ip_match_str = "Matched"
                ip_match_color = "green"
                ip_match_sign = 1
            else:
                ip_match_str = "Unmatched"
                ip_match_color = "red"
                ip_match_sign = 0

            print("{cont}\t{icmp_ip}\t{orig_dst_ip}\t{icmp_type} {icmp_code}\t{hop_distance}\t".format(
                cont=cont,
                icmp_ip=icmp_ip_addr,
                orig_dst_ip=orig_dst_ip,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                hop_distance=hop_distance
                ),
                colored(ip_match_str, ip_match_color))

            data_dict = dict()
            data_dict = {
                "icmp_assets": {
                    "icmp_ip_addr": icmp_ip_addr,
                    "icmp_ip_network": icmp_network_addr,
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                    "icmp_ttl": icmp_ttl
                },
                "origin_packet": {
                    "orig_src_ip": orig_src_ip,
                    "orig_dst_ip": orig_dst_ip,
                    "orig_dst_network_addr": orig_dst_network_addr,
                    "orig_ttl": orig_ttl,
                },
                "ip_matched": ip_match_sign,
                "hop_distance": hop_distance
            }
            data_str = json.dumps(data_dict)
            redis_connection.lpush("result", data_str)
            redis_connection.sadd("visited", orig_dst_network_addr)
            # redis_connection.sadd("visited", icmp_network_addr)
            if ip_match_sign == 0:
                redis_connection.sadd("unmatched", orig_dst_network_addr)
            if icmp_type == 3 and icmp_code == 3:
                redis_connection.sadd("port_unreachable", icmp_network_addr)
            if icmp_type == 3 and icmp_code == 2:
                redis_connection.sadd("protocol_unreachable", icmp_network_addr)
            if icmp_type == 3 and icmp_code == 1:
                redis_connection.sadd("address_unreachable", icmp_network_addr)

            cont += 1
        except Exception as e:
            pass


def add_record_redis(
        icmp_ip,
        icmp_type,
        icmp_code,
        icmp_ttl,
        orig_ip,
        orig_ttl):
    """ Add scan result to redis
        :params icmp_ip: the ip address in the icmp packet
        :params icmp_type: an integer telling icmp type
        :params icmp_code: an integer telling icmp code
        :params icmp_ttl: the ttl of icmp packet
        :params orig_ip: the ip address of the original packet
        :params orig_ttl: the ttl of the original packet
    """
    pass


def get_redis_connection(host, port, db):
    """ Create a redis connection
        :params host: ip address to redis server
        :params port: port number of redis service
        :params db: specify which redis db to use
    """
    return redis.Redis(host=host, port=port, db=db)


def send_random_probes(redis_connection):
    """ send random probes """
    while 1:
        try:
            random_ip = '.'.join('%s' % random.randint(0, 255) for i in range(4))
            # avoid brodcast address
            ip = ipaddress.IPv4Address(random_ip)
            # avoid reserved, private, unspecified ip address
            if ip.is_multicast or ip.is_reserved or ip.is_private or\
                    ip.is_unspecified:
                continue
            ip_network = get_network_by_ip(str(ip), ADDR_MASK)
            # continue if we already probed
            if redis_connection.sismember("visited", str(ip_network.network_address)):
                continue
            print(random_ip)
            send_udp(random_ip, SENT_PORT)
            redis_connection.sadd("sent", str(ip_network.network_address))
            time.sleep(0.001)
        except Exception:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('behavior', metavar='N', nargs='+',
                        help='an integer for the accumulator')

    args = parser.parse_args()
    if 'listen' in args.behavior:
        print('We\'r waiting for the icmp packet')
        listen(get_redis_connection("127.0.0.1", 6379, 2))
    elif 'udp' in args.behavior:
        send_random_probes(get_redis_connection("127.0.0.1", 6379, 2))
