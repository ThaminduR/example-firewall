
# interface1.txt contains incoming packets
file1 = open('interface1.txt', 'r')

# interface1.txt contains outgoing packets
file2 = open('interface2.txt', 'r')

# config.txt file contains the rules of the firewall
configfile = open('config.txt', 'r')

# get the lines from file
Lines1 = file1.readlines()
Lines2 = file2.readlines()
Line3 = configfile.readlines()

# Inside network, network address
inside_ip = [192, 168, 8, 0]
subnet = 16

# Ethernet header size in 4bits
ethernet_header = 28

# protocol number for TCP and UDP
tcp_number = 6
udp_number = 17

# index of the headers in the list containing single packet
ip_index = 1
tcp_udp_index = 0

# return the rules as a list and dictionary is defined for each rule


def readConfig(Lines):
    Rules = []
    defRules = []
    for line in Lines:

        rule = {}
        line = line.strip()
        rule_parts = line.split(" ")

        if(rule_parts[0] == 'DEFAULT-1'):
            for part in rule_parts:
                temp = part.split("-")
                rule[temp[0]] = temp[1]

            defRules.append(rule)
        else:
            for part in rule_parts:
                temp = part.split("-")

                if(temp[0] == "IP"):
                    tempip = temp[1].split("/")
                    ip = list(map(int, tempip[0].split(".")))
                    rule[temp[0]] = ip
                    rule['SUBNET'] = int(tempip[1])

                elif(temp[0] == "PORT"):
                    port = int(temp[1])
                    rule[temp[0]] = port

                else:
                    rule[temp[0]] = temp[1]

            Rules.append(rule)
    return Rules, defRules


def compareIP(ip1, ip2):
    if(ip1 == ip2):
        return True
    else:
        return False


def comparePorts(port1, port2):
    if(port1 == port2):
        return True
    else:
        return False


def isTCP(ipheader):
    protonum = ipheader['protocol']
    if(protonum == tcp_number):
        return True
    else:
        return False


def checkRules(readpacket, rules, defRules, isIncoming):
    ipheader = readpacket[1]
    tcpudpheader = readpacket[0]
    istcp = isTCP(ipheader)
    print("TCP: ", istcp)

    defIn = defRules[0]
    defOut = defRules[1]
    isAccepted = None

    for rule in rules:
        # default incoming action is allow.
        if((isIncoming) & (rule['DIR'] == "IN")):
            if((rule['IP'][:3] == ipheader['source address'][:3]) & (rule['PORT'] == tcpudpheader['source port'])):
                if((rule['PROTO'] == 'TCP') & istcp):
                    if(rule['ACTION'] == 'ALLOW'):
                        isAccepted = True
                    elif(rule['ACTION'] == 'REJECT'):
                        isAccepted = False
                elif((rule['PROTO'] == 'UDP') & (not istcp)):
                    if(rule['ACTION'] == 'ALLOW'):
                        isAccepted = True
                    elif(rule['ACTION'] == 'REJECT'):
                        isAccepted = False

        # default outgoing action is reject
        elif((not isIncoming) & (rule['DIR'] == "OUT")):
            if((rule['IP'][:3] == ipheader['destination address'][:3]) & (rule['PORT'] == tcpudpheader['destination port'])):
                if((rule['PROTO'] == 'TCP') & istcp):
                    if(rule['ACTION'] == 'ALLOW'):
                        isAccepted = True
                    elif(rule['ACTION'] == 'REJECT'):
                        isAccepted = False
                elif((rule['PROTO'] == 'UDP') & (not istcp)):
                    if(rule['ACTION'] == 'ALLOW'):
                        isAccepted = True
                    elif(rule['ACTION'] == 'REJECT'):
                        isAccepted = False
                
    if(isAccepted == None):
        if(isIncoming):
            isAccepted = defIn
            print("going for default: ", defIn)
        else:
            print("going for default x: ", defOut)
            isAccepted = defOut
    return isAccepted
# Function return a dictionary containing necessary IP headers of a given packet


def getIPheader(packet):
    ipheader = {}
    ipheader['version'] = int(packet[:1], 16)
    ipheader['header length'] = int(packet[1:2], 16)
    ipheader['total length'] = int(packet[4:8], 16)
    ipheader['ttl'] = int(packet[16:18], 16)
    ipheader['protocol'] = int(packet[18:20], 16)
    ipheader['source address'] = [int(packet[24:26], 16), int(
        packet[26:28], 16), int(packet[28:30], 16), int(packet[30:32], 16)]
    ipheader['destination address'] = [int(packet[32:34], 16), int(
        packet[34:36], 16), int(packet[36:38], 16), int(packet[38:40], 16)]
    return ipheader

# Function return a dictionary containing necessary UDP headers of a given packet


def getUDPheader(packet):
    udpheader = {}
    udpheader['source port'] = int(packet[:4], 16)
    udpheader['destination port'] = int(packet[4:8], 16)
    udpheader['udp length'] = int(packet[8:12], 16)
    return udpheader

# Function return a dictionary containing necessary TCP headers of a given packet


def getTCPheader(packet):
    tcpheader = {}
    tcpheader['source port'] = int(packet[:4], 16)
    tcpheader['destination port'] = int(packet[4:8], 16)
    tcpheader['tcp length'] = int(packet[24:25], 16)
    return tcpheader

# returns a list containing all packets as lists. Each list contains two dictionaries,
# first one for tcp/udp header
# second one for ip header


def readPackets(Lines, rules, defRules, isIncoming):
    i = 0
    packets = []
    for line in Lines:
        readpacket = []

        # Ethernet header is removed from packet
        packet = line[ethernet_header:]
        ipheader = getIPheader(packet)
        ipheader_length = 4*ipheader['header length']*2

        if(ipheader['protocol'] == 17):
            packet = packet[ipheader_length:]
            udpheader = getUDPheader(packet)
            readpacket.append(udpheader)

        elif(ipheader['protocol'] == 6):
            packet = packet[ipheader_length:]
            tcpheader = getTCPheader(packet)
            readpacket.append(tcpheader)

        else:
            continue
        i += 1
        # if(i == 5):
        #     break
        readpacket.append(ipheader)
        print(readpacket)
        if(checkRules(readpacket, rules, defRules, isIncoming)):
            print("Allowed")
            packets.append(readpacket)
        else:
            print("Rejected")
    return packets

# get the default action for packets


def getDefRules(defRules):
    for rule in defRules:
        if(('DIR' in rule) & ('IN' == rule['DIR'])):
            if(rule['ACTION'] == 'ALLOW'):
                defIn = True
            elif(rule['ACTION'] == 'REJECT'):
                defIn = False
        elif(('DIR' in rule) & ('OUT' == rule['DIR'])):
            if(rule['ACTION'] == 'ALLOW'):
                defOut = True
            elif(rule['ACTION'] == 'REJECT'):
                defOut = False
    return [defIn, defOut]


# Read rules from config.txt file
Rules, defRules = readConfig(Line3)
# get default rule
defrules = getDefRules(defRules)
# Read incoming packets from Interface 1 (interface1.txt)
print("Incoming Packets")
incoming_packets = readPackets(Lines1, Rules, defrules, True)
# Read outgoing packets from Interface 2 (interface2.txt)
print('Outgoing Packets')
outgoing_packets = readPackets(Lines2, Rules, defrules, False)