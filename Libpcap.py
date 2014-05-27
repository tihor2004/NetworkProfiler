import dpkt
import pcapy
import socket
import psutil
import threading

import Utils
import NetworkProfiler

from Socket import SocketInfo
from Constants import PacketDirection
from Process import ProcessInfo
from psutil import NoSuchProcess
from NetworkProfiler import globalLock

class PacketFilter(threading.Thread):
    
    def __init__(self, sem1_pktFilter_GC, sem2_pktFilter_GC, configParams):
        threading.Thread.__init__(self)
        
        self.configParams = configParams
        
        # Store the MAC address of all interfaces on local machine in a hashset 
        self.local_MAC_AddressesSet = Utils.getMacAddresses()
        if self.local_MAC_AddressesSet is None or len(self.local_MAC_AddressesSet) == 0:
            raise Exception("Exception while fetching local mac_addresses.")
        
        print "Sniffing device " + configParams.INTERFACE
        # Open the device. Arguments are:
        # device, snaplen (maximum number of bytes to capture per packet)
        # promiscious mode (1 for true), timeout (in milliseconds)
        self.cap = pcapy.open_live(configParams.INTERFACE , 65536 , 0 , 0)
         
        # To  select  the start and end packets (the SYN, FIN and RST packets) of each
        # TCP conversation that involves a non-local host.
        filter = "tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"
        
        # bfp = pcapy.compile(cap, 65536, filter, 0, 1)
        self.cap.setfilter(filter)
        self.sem1_pktFilter_GC = sem1_pktFilter_GC
        self.sem2_pktFilter_GC = sem2_pktFilter_GC
         
          
    def run(self):
        # start sniffing packets
        while(1):
            
            try:
                (header, packet) = self.cap.next()
            except pcapy.PcapError:
                print 'ERROR: while fetching the packet.'
                continue
            
            socketInfo, tcp_flags = self.parse_packet(packet)

            if socketInfo is not None:
                
                # Find the pid to which this socket belongs
                pid = Utils.getPacketPid(socketInfo)
                print 'pid is ', pid         
                process = None
                
                try: 
                    globalLock.acquire()

                    if pid == -1:
                        # No current executing process matches this socket
                        # check in already stored mapping created when TCP SYN was received
                        process = NetworkProfiler.socketToProcessDict.get(socketInfo)
                        if process is None:
                            print 'DEBUG: No mapping found in socketToProcessMap'
                            # No need to track this connection
                            continue
                        else:
                            print 'Mapping found for pid:', process.pid 
                
                    if process is None:
                        # Using psutil library find the owner and starttime of this process
                        proc = psutil.Process(pid)
                        process = ProcessInfo(pid, proc.username(), proc.create_time())
                        
                    # Get JobId to which this process belongs. If a match is found,
                    # it indicates that the process needs to be profiled.
                    
                    jobId = NetworkProfiler.processToJobIdDict.get(process)
                    
                    if jobId is not None:
                        print 'DEBUG: Found match for process', process.pid, 'with jobId:', jobId
                        
                        # Check for TCP FIN/RST                        
                        if (tcp_flags & dpkt.tcp.TH_FIN or tcp_flags & dpkt.tcp.TH_RST):
                            print 'DEBUG: Found a FIN/RST packet. Process', process.pid
                            # Get stats for this rule and add entry to log
                            NetworkProfiler.LogStats(socketInfo, process, jobId)
                            NetworkProfiler.DeleteRule(socketInfo, process)
                            
                        elif tcp_flags & dpkt.tcp.TH_SYN:
                            print 'DEBUG: Found a SYN packet. Process', process.pid
                            # Implies that it is a TCP SYN packet                             
                            
                            if NetworkProfiler.INSTALLED_RULES_COUNT >= self.configParams.RULES_THRESHOLD:
                                # Release the globalLock so that GC can make modifications to data structures
                                globalLock.release()
                                
                                # Signal the semaphore so that GC can start                                
                                self.sem1_pktFilter_GC.release()
                                
                                # Wait till GC signals
                                self.sem2_pktFilter_GC.acquire()
                                
                                # Acquire the globalLock again
                                globalLock.acquire()
                            
                            # Check the counter again to see if GC freed up some resources
                            if NetworkProfiler.INSTALLED_RULES_COUNT < self.configParams.RULES_THRESHOLD:
                                NetworkProfiler.InsertRule(socketInfo, process)
                            
                                print 'Map Contents:'
                                print NetworkProfiler.socketToProcessDict
                            else:
                                print 'DEBUG: Rule cannot be installed. Threshold crossed.'                            
                    else:
                        print 'DEBUG: jobId is None. No mapping in processToJobIdMap'
                        print 'DEBUG: Entries in processToJobIdMap', NetworkProfiler.processToJobIdDict.items()
                except NoSuchProcess:
                    print 'Process %d does not exist anymore.' % pid
                finally:
                    globalLock.release()

    
    # Find whether the packet is an incoming packet or an outgoing packet
    def getPacketDirection(self, srcMAC):        
        if srcMAC in self.local_MAC_AddressesSet:
            return PacketDirection.PKT_OUT
        else:
            return PacketDirection.PKT_IN

  
    # function to parse a packet
    def parse_packet(self, packet) :
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            
            # Extract source MAC address from  the packet
            srcMAC = Utils.eth_ntoa(eth.src)
            
            # Check if it is an IP packet, parse it.
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip_pkt = eth.data
                srcIP = socket.inet_ntoa(ip_pkt.src)
                dstIP = socket.inet_ntoa(ip_pkt.dst)
                
                transport_packet = ip_pkt.data
    
                # TCP protocol
                if ip_pkt.p == dpkt.ip.IP_PROTO_TCP:
                    # Implies a TCP packet
                    socketInfo = SocketInfo(srcIP, dstIP, transport_packet.sport, transport_packet.dport,
                                            "tcp", self.getPacketDirection(srcMAC));
                    return socketInfo, transport_packet.flags
                
                # UDP protocol
                elif ip_pkt.p == dpkt.ip.IP_PROTO_UDP:
                    # Implies UDP packet
    #                 source_port = transport_packet.sport
    #                 dest_port = transport_packet.dport
                    return None
        except Exception as ex:
            print 'ERROR: Exception while parsing packet', ex
        return None
