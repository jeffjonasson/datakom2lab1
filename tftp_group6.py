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

# read request
def make_packet_rrq(filename, mode):
    # Note the exclamation mark in the format string to pack(). What is it for?
    # It tells us that we want network byte order (htons).
    return struct.pack("!H", OPCODE_RRQ) + filename + '\0' + mode + '\0'

def make_packet_wrq(filename, mode):
    return struct.pack("!H", OPCODE_WRQ) + filename + '\0' + mode + '\0'

def make_packet_data(blocknr, data):
    return struct.pack("!H", OPCODE_DATA + blocknr) + data

def make_packet_ack(blocknr):
    return struct.pack("!H", OPCODE_ACK + blocknr)

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

def tftp_transfer(fd, hostname, direction):
    # Implement this function
    
    # Open socket interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    (family, socktype, proto, canonname, (address,port)) = socket.getaddrinfo(hostname, TFTP_PORT)[1]
    # Will automatically bind.
    # connect, DNS lookup once
        
    # Check if we are putting a file or getting a file and send
    #  the corresponding request.
    if direction == TFTP_GET:
        # Get file from server
        # fd.read(fd,n bytes) -> string containing bytes read. empty if fully read.
        # s.send("...")
        # We send a read request, and then get datablocks from server, and send acks each time we get a block.
        s.sendto((make_packet_rrq(fd.name, MODE_OCTET)), (address,TFTP_PORT))
        print address
        # We told the server we want a read. We get "DATA" with block nr = 1.
        # To handle duplicates or errors, we must keep track of last received transmission.
        
        ret = ""
        while True:
            
            (rl,wl,xl) = select.select([s], [], [], 10)
            if s not in rl:
                print "not in rl"
            else:
                (packet, dest) = s.recvfrom(BLOCK_SIZE+4)
                print dest
                (opcode1, p1, p2) = parse_packet(packet)
                print "a"
                if opcode1 == OPCODE_DATA:
                    # Data packet received
                    # parameter1 = blocknr
                    # parameter2 = data string (0-512)
                    # p1 = (1,)
                    print "meh"

                    if len(p2) == BLOCK_SIZE:
                        ret += p2
                        ack = make_packet_ack(p1)
                        print p1
                        print p2
                        s.sendto(ack,dest)
                        print "Full size"
                    else:
                        ret += p2
                        ack = make_packet_ack(p1)
                        s.sendto(ack,dest)
                        fd.write(ret)
                        print "Less size"
                        return

                    # if p1 == blocknr:
                    #     if blocknr == 1:
                    #         if data == "":
                    #             # Initialize
                    #             data = p2
                    #             ret += p2
                    #             ack = make_packet_ack(p1)
                    #             s.sendto(ack, dest)
                    #             print "1"
                    #         else:
                    #             # Dupe, send ack again
                    #             ack = make_packet_ack(p1)
                    #             s.sendto(ack, dest)
                    #             print "2"
                    #     else:
                    #         if data == p2:
                    #             # Dupe
                    #             ack = make_packet_ack(p1)
                    #             s.sendto(ack, dest)
                    #             print "3"
                    # else:
                    #     if len(p2) == BLOCK_SIZE:
                    #         # Full length packet
                    #         blocknr += 1
                    #         data = p2
                    #         ret += p2
                    #         ack = make_packet_ack(p1+1)
                    #         s.sendto(ack, dest)
                    #         print "4"
                    #     else:
                    #         # Less than full, end of file reached
                    #         ret += p2
                    #         fd.write(ret)
                    #         print "5"
                    #         break


                        
                
                    
                elif opcode1 == 5:
                    # Received an error
                    # TODO
                    a = 3
                else:
                    # Received an opcode not {DATA, ERR}, something is wrong. Try again
                    ack1 = make_packet_ack(p1)
                    s.sendto((ack1), (address,port))

                

                # Wait for response from server with select
                # Get the most recently sent packet from server
                #response = s.recvfrom(BLOCK_SIZE)
                # response contains string, data sent, and address (where it got it from)
                    
                



    else:
        # Put file on server
        # fd.write (fd, string) -> bytes written
        # data = s.recv(BLOCK_SIZE) 
        
        s.sendto(make_packet_wrq(fd.name, MODE_OCTET), (address,port))
        blocknr = 0
        data = ""
        # We told the server we want to write. We get an ACK with blocknr = 0
        while True:
            (rl,wl,xl) = select.select([s], [], [], 10)
            if s in rl:
                (packet, dest) = s.recvfrom(BLOCK_SIZE)
                (opcode1, p1, p2) = parse_packet(packet)
                if opcode1 == 4:
                    # Received an ACK containing blocknr the server is expecting, last transmission was successful
                    if blocknr == 0:
                        if data == "":
                            # Initialize
                            data = fd.read(BLOCK_SIZE)
                        datapkt = make_packet_data(blocknr, data)
                    else:
                        if blocknr == p1:
                            # Transmission failed, retry
                            datapkt = make_packet_data(blocknr, data)
                        else:
                            blocknr = p1
                            data = fd.read(BLOCK_SIZE)
                            datapkt = make_packet_data(blocknr, data)
                elif opcode == 5:
                    # Something went wrong
                    a = 3
                else:
                    # Some other thing, retry
                    datapkt = make_packet_data(blocknr, data)
            else:
                print("Timeout")
                return None
            pass        
    
    
    # Put or get the file, block by block, in a loop.
    #while True:
        # Wait for packet, write the data to the filedescriptor or
        # read the next block from the file. Send new packet to server.
        # Don't forget to deal with timeouts and received error packets.
        #pass



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