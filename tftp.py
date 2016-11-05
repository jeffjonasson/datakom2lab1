#! /usr/bin/python

import sys,socket,struct,select

BLOCK_SIZE= 512

OPCODE_RRQ=   1
OPCODE_WRQ=   2
OPCODE_DATA=  3
OPCODE_ACK=   4
OPCODE_ERR=   5

MODE_NETASCII= "netascii"
MODE_OCTET=    "octet"
MODE_MAIL=     "mail"

TFTP_PORT= 6969

# Timeout in seconds
TFTP_TIMEOUT= 2

ERROR_CODES = ["Undef",
               "File not found",
               "Access violation",
               "Disk full or allocation exceeded",
               "Illegal TFTP operation",
               "Unknown transfer ID",
               "File already exists",
               "No such user"]

# Internal defines
TFTP_GET = 1
TFTP_PUT = 2

small_checksum = '667ff61c0d573502e482efa85b468f1f'
medium_checksum = 'ee98d0524433e2ca4c0c1e05685171a7'
large_checksum = 'f5b558fe29913cc599161bafe0c08ccf'


def make_packet_rrq(filename, mode):
    # Note the exclamation mark in the format string to pack(). What is it for?
    return struct.pack("!H", OPCODE_RRQ) + filename + '\0' + mode + '\0'

def make_packet_wrq(filename, mode):
    return struct.pack("!H", OPCODE_WRQ) + filename + '\0' + mode + '\0'

def make_packet_data(blocknr, data):
    return struct.pack("!HH", OPCODE_DATA, blocknr) + data

def make_packet_ack(blocknr):
    return struct.pack("!HH", OPCODE_ACK, blocknr) 

def make_packet_err(errcode, errmsg):
    return struct.pack("!H", OPCODE_ERR) + errcode + errmsg + '\0'

def parse_packet(msg):
    #"""This function parses a recieved packet and returns a tuple where the
    #    first value is the opcode as an integer and the following values are
    #    the other parameters of the packets in python data types"""
    opcode = struct.unpack("!H", msg[:2])[0]
    if opcode == OPCODE_RRQ:
        l = msg[2:].split('\0')
        if len(l) != 3:
            return None
        return opcode, l[1], l[2]
    elif opcode == OPCODE_WRQ:
        l = msg[2:].split('\0')
        if len(l) != 3:
            return None
        return opcode, l[1], l[2]
    elif opcode == OPCODE_DATA:
        return opcode, struct.unpack("!H", msg[2:4])[0], msg[4:] 
    elif opcode == OPCODE_ACK:
        return opcode, struct.unpack("!H", msg[2:4])[0]
    elif opcode == OPCODE_ERR:
        #TODO
        return opcode, msg[2:4], msg[4:].split('\0')[0]
    # TODO: Something is wrong
    else: 
        return None

def get_opcode(msg):
    opcode = struct.unpack("!H", msg[:2])[0]
    return opcode

def tftp_transfer(fd, hostname, direction):
    # Implement this function
    
    # Open socket interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    addrinfo = socket.getaddrinfo(hostname, TFTP_PORT)
    (family, socktype, proto, canonname, (address,port)) = addrinfo[1]
    
    # Check if we are putting a file or getting a file and send
    #  the corresponding request.
    if direction == TFTP_GET:
        packet = make_packet_rrq(fd.name, MODE_OCTET)
        print "RRQ: " + packet
        s.sendto(packet, (address, TFTP_PORT))
        print "Please wait..."
    else:
        packet = make_packet_wrq(fd.name, MODE_OCTET)
        print "WRQ: " + packet
        s.sendto(packet, (address, TFTP_PORT))
        print "Please wait..."

    ref = ""
    blockref = -1
    packloss = 0
    # Put or get the file, block by block, in a loop.
    while True:
        # Wait for packet, write the data to the filedescriptor or
        # read the next block from the file. Send new packet to server.
        # Don't forget to deal with timeouts and received error packets.

        (rl,wl,xl) = select.select([s], [], [], 10)

        if s in rl:
            (packet, dest) = s.recvfrom(BLOCK_SIZE + 4)
            opcode = get_opcode(packet)
            
            # if opcode == 3: 
            #     print "opcode = DATA"
            # elif opcode == 4: 
            #     print "opcode = ACK"
            # elif opcode == 5:
            #     print "opcode = ERROR"

            if opcode == OPCODE_DATA:
                (opcode, p1, p2) = parse_packet(packet)
                # p1 = Blocknr
                # p2 = Data
                if p1 != blockref:
                    blockref = p1
                    ref += p2
                    ack = make_packet_ack(p1)
                    #print str(len(p2))
                    if len(p2) == BLOCK_SIZE:
                        s.sendto(ack, dest)
                    else:
                        fd.write(ref)
                        s.sendto(ack, dest)
                        print "Wrote to FD and sent ACK"
                        print "Packets resent: " + str(packloss)
                        return
                else:
                    # Received same packet again
                    #print "Packet loss, resend."
                    packloss += 1
                    ack = make_packet_ack(blockref)
                    s.sendto(ack, dest)

            elif opcode == OPCODE_ACK:
                # TODO
                # If we get p1 = 0, they want next packet to have blocknr 1
                (opcode, p1) = parse_packet(packet)
                # p1 = Blocknr
                # blockref initially -1
                # Packet loss: Server didn't get last transmission. Resend
                if p1 != blockref:
                    ref = fd.read(BLOCK_SIZE)
                    #print str(len(ref))
                    blockref = p1
                    datapkt = make_packet_data(p1+1, ref)
                    s.sendto(datapkt, dest)
                    if len(ref) < BLOCK_SIZE:
                        print "End of file reached"
                        print "Packets resent: " + str(packloss)
                        return
                else:
                    # Packet loss, resend.
                    datapkt = make_packet_data(blockref+1, ref)
                    #print "Packet loss, resend"
                    packloss += 1
                    s.sendto(datapkt, dest)

            elif opcode == OPCODE_ERR:
                # TODO
                print "Error"
        else:
            pass
            
        


def usage():
    """Print the usage on stderr and quit with error code"""
    sys.stderr.write("Usage: %s [-g|-p] FILE HOST\n" % sys.argv[0])
    sys.exit(1)


def main():
    # No need to change this function
    direction = TFTP_GET
    if len(sys.argv) == 3:
        filename = sys.argv[1]
        hostname = sys.argv[2]
    elif len(sys.argv) == 4:
        if sys.argv[1] == "-g":
            direction = TFTP_GET
        elif sys.argv[1] == "-p":
            direction = TFTP_PUT
        else:
            usage()
            return
        filename = sys.argv[2]
        hostname = sys.argv[3]
    else:
        usage()
        return

    if direction == TFTP_GET:
        print "Transfer file %s from host %s" % (filename, hostname)
    else:
        print "Transfer file %s to host %s" % (filename, hostname)

    try:
        if direction == TFTP_GET:
            fd = open(filename, "wb")
        else:
            fd = open(filename, "rb")
    except IOError as e:
        sys.stderr.write("File error (%s): %s\n" % (filename, e.strerror))
        sys.exit(2)

    tftp_transfer(fd, hostname, direction)
    fd.close()

if __name__ == "__main__":
    main()