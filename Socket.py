from Constants import PacketDirection

# Class to represent information extracted from a packet
class SocketInfo:
    
    def __init__(self, s_addr, d_addr, source_port, dest_port, protocol, direction):
        self.destIP = d_addr
        self.destPort = dest_port
        self.protocol = protocol
        self.srcIP = s_addr
        self.srcPort = source_port
        self.packetDirection = direction
        
    def __repr__(self):
        if self.packetDirection == PacketDirection.PKT_IN:
            return "%s,%d,%s,%s,%d" % (self.destIP, self.destPort, self.protocol, self.srcIP, self.srcPort)
        else:
            return "%s,%d,%s,%s,%d" % (self.srcIP, self.srcPort, self.protocol, self.destIP, self.destPort)
    
    # Don't compare packetDirection as 5-tuple is enough to identify same sockets
    def __eq__(self, other):
        if isinstance(other, SocketInfo):
            if ((self.destIP == other.destIP) and (self.destPort == other.destPort) 
                    and (self.protocol == other.protocol) and (self.srcIP == other.srcIP)
                    and (self.srcPort == other.srcPort)):
                return True
            elif ((self.destIP == other.srcIP) and (self.destPort == other.srcPort) 
                    and (self.protocol == other.protocol) and (self.srcIP == other.destIP)
                    and (self.srcPort == other.destPort)):
                return True
            else:
                return False
        else:
            return False
    
    def __ne__(self, other):
        return (not self.__eq__(other))
    
    def __hash__(self):
        return hash(self.__repr__())