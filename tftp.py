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
TFTP_TIMEOUT= 0.5

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


def make_packet_rrq(filename, mode):
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
        return opcode, msg[2:4], msg[4:].split('\0')[0]
    else:
        return None

def get_opcode(msg):
    opcode = struct.unpack("!H", msg[:2])[0]
    return opcode

def tftp_transfer(fd, hostname, direction):

    addrinfo = socket.getaddrinfo(hostname, 69, socket.AF_INET, socket.SOCK_DGRAM)
    (family, socktype, proto, canonname, (address,_)) = addrinfo[0]

    s = socket.socket(family, socktype)
    dest = (address, TFTP_PORT)   
    
    if direction == TFTP_GET:
        packet = make_packet_rrq(fd.name, MODE_OCTET)
        s.sendto(packet, (address, TFTP_PORT))
    else:
        packet = make_packet_wrq(fd.name, MODE_OCTET)
        s.sendto(packet, (address, TFTP_PORT))

    ref = ""
    blockref = -1
    timeout_counter = 0

    while True:
        (rl,wl,xl) = select.select([s], [], [], TFTP_TIMEOUT)
        if s in rl:
            (packet, dest) = s.recvfrom(BLOCK_SIZE + 4)
            
            opcode = get_opcode(packet)
            timeout_counter = 0
            if opcode == OPCODE_DATA and direction == TFTP_GET:
                (opcode, packet_number, packet_data) = parse_packet(packet)
                if packet_number != blockref:
                    blockref = packet_number
                    fd.write(packet_data)
                    packet = make_packet_ack(packet_number)
                    if len(packet_data) == BLOCK_SIZE:
                        s.sendto(packet, dest)
                    else:
                        s.sendto(packet, dest)
                        return
                else:
                    packet = make_packet_ack(blockref)
                    s.sendto(packet, dest)
            elif opcode == OPCODE_ACK and direction == TFTP_PUT:
                (opcode, packet_number) = parse_packet(packet)
                if packet_number == blockref+1:
                    ref = fd.read(BLOCK_SIZE)
                    blockref = packet_number
                    packet = make_packet_data(packet_number+1, ref)
                    s.sendto(packet, dest)
                    if len(ref) < BLOCK_SIZE:
                        return
                else:
                    s.sendto(packet, dest)
            elif opcode == OPCODE_ERR:
                (opcode, errcode, errmsg) = parse_packet(packet)
                print "Error! : " + errmsg
        else:
            if timeout_counter > 10:
                print "Timeout"
                break
            else:
                s.sendto(packet, dest)
                timeout_counter += 1
            
def usage():
    """Print the usage on stderr and quit with error code"""
    sys.stderr.write("Usage: %s [-g|-p] FILE HOST\n" % sys.argv[0])
    sys.exit(1)


def main():
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
