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

TFTP_PORT= 10069

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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    addrinfo = socket.getaddrinfo(hostname, TFTP_PORT)
    (family, socktype, proto, canonname, (address,port)) = addrinfo[1]
    
    if direction == TFTP_GET:
        packet = make_packet_rrq(fd.name, MODE_OCTET)
        s.sendto(packet, (address, TFTP_PORT))
    else:
        packet = make_packet_wrq(fd.name, MODE_OCTET)
        s.sendto(packet, (address, TFTP_PORT))

    ref = ""
    blockref = -1
    while True:

        (rl,wl,xl) = select.select([s], [], [], TFTP_TIMEOUT)

        if s in rl:
            (packet, dest) = s.recvfrom(BLOCK_SIZE + 4)
            opcode = get_opcode(packet)

            if opcode == OPCODE_DATA:
                (opcode, p1, p2) = parse_packet(packet)
                if p1 != blockref:
                    blockref = p1
                    ref += p2
                    packet = make_packet_ack(p1)
                    
                    if len(p2) == BLOCK_SIZE:
                        s.sendto(packet, dest)
                    else:
                        fd.write(ref)
                        s.sendto(packet, dest)
                        return
                else:
                    packet = make_packet_ack(blockref)
                    s.sendto(packet, dest)

            elif opcode == OPCODE_ACK:
                (opcode, p1) = parse_packet(packet)
                if p1 != blockref:
                    ref = fd.read(BLOCK_SIZE)
                    blockref = p1
                    packet = make_packet_data(p1+1, ref)
                    s.sendto(packet, dest)
                    if len(ref) < BLOCK_SIZE:
                        return
                else:
                    s.sendto(packet, dest)

            elif opcode == OPCODE_ERR:
                # TODO
                (opcode, errcode, errmsg) = parse_packet(packet)
                print "Error! : " + errmsg
        else:
            s.sendto(packet, dest)
            
            
        


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