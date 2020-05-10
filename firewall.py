
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


def isTCP(ipheader):
    protonum = ipheader['protocol']
    if(protonum == tcp_number):
        return True
    else:
        return False

# check a packet against firewall rules


def checkRules(readpacket, rules, defRules, isIncoming):
    ipheader = readpacket[1]
    tcpudpheader = readpacket[0]
    istcp = isTCP(ipheader)

    # default action for packets
    defIn = defRules[0]
    defOut = defRules[1]
    isAccepted = None

    for rule in rules:

        # apply rules for incoming packets
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

        # apply rules for outgoing packets
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

     # if no rule is applicable default action given will be executed
    if(isAccepted == None):
        if(isIncoming):
            isAccepted = defIn
        else:
            isAccepted = defOut
    return isAccepted


def writeToLog(isAccepted, isIncoming, readpacket):
    logfile = open("log.txt", "a")
    if(isIncoming):
        dirstr = "Incoming "
    else:
        dirstr = "Outgoing "
    ipadd = readpacket[1]['source address']
    ipaddress = str(ipadd[0])+"."+str(ipadd[1])+"." + \
        str(ipadd[2])+"."+str(ipadd[3])
    port = str(readpacket[0]['source port'])
    if (isTCP(readpacket[1])):
        tcpudp = "TCP "
    else:
        tcpudp = "UDP "
    if(isAccepted):
        acceptreject = "accepted.\n"
    else:
        acceptreject = "rejected.\n"

    string = dirstr + tcpudp + "packet " + "from IP Addresss: " + \
        ipaddress + " and Port: " + port + " was " + acceptreject

    logfile.write(string)
    logfile.close()


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
    total = len(Lines)
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
        isAccepted = checkRules(readpacket, rules, defRules, isIncoming)
        if(isAccepted):
            writeToLog(isAccepted, isIncoming, readpacket)
            packets.append(readpacket)
        else:
            writeToLog(isAccepted, isIncoming, readpacket)
    return packets, total

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

# #uncomment to clear the log file for each session
# logfile = open('log.txt','w')
# logfile.write("")

# Read incoming packets from Interface 1 (interface1.txt)
in_accepted_packets, in_total_packets = readPackets(
    Lines1, Rules, defrules, True)
print("Interface-1 received {} packets. {} packets forwared to interface-2. ".format(
      in_total_packets, len(in_accepted_packets)))


# Read outgoing packets from Interface 2 (interface2.txt)
out_accepted_packets, out_total_packets = readPackets(
    Lines2, Rules, defrules, False)
print("Interface-2 eceived {} packets. {} packets forwarded to interface-1.".format(
    out_total_packets, len(out_accepted_packets)))
