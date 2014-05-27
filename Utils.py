import os
import struct
import commands

from Constants import PacketDirection

# Method to get the mac addresses of all the interfaces attached to the machine
def getMacAddresses():
    # Execute the ifconfig command
    mac_addresses = set()
    try:
        interfaces = commands.getoutput("ifconfig ").split("\n")
        
        # Parse the output and search for "HWaddr"
        for interface in interfaces:
            if "HWaddr" in interface:
                line = interface.split()
                mac_addresses.add(line[line.index("HWaddr") + 1])
    except Exception as ex:    
        print 'DEBUG: Exception in getMacAddresses()', ex
        return None
    return mac_addresses


# Wrapper over os.popen()
def execute(command):
    print 'DEBUG: Executing command (', command, ')'
    output = os.popen(command)
    return output


# Get pid of the process to which this packet belongs. 
# Return -1 to indicate that no process maps this packet
def getPacketPid(socketInfo):
    command = ""
    if socketInfo.packetDirection == PacketDirection.PKT_IN:
        command = "netstat -penet | grep " + socketInfo.destIP + ":" + str(socketInfo.destPort)
    else:
        command = "netstat -penet | grep " + socketInfo.srcIP + ":" + str(socketInfo.srcPort)
        
    try:
        output = os.popen(command)
        ''' This command return output with following columns:
        <Proto> <Recv-Q> <Send-Q> <Local_Address> <Foreign_Address> <State> <User> <Inode> <PID/Program name>
        '''
        contents = output.read().split()
        print 'getPacketPid', contents
        pid = contents[8].split("/")[0]
        return int(pid)
    except Exception as ex:
        print 'DEBUG', ex
        return -1
    
    
# Convert a network mac address into a string
def eth_ntoa(buf):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", buf)