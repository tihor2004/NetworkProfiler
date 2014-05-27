#!/usr/bin/env python
import os
import web

import Constants
import Iptables
import NetworkProfiler

from GC import GC
from Process import ProcessInfo
from Constants import ConfigParams
from Iptables import IptableCommands
from Logger import LogHandler
from Libpcap import PacketFilter
from threading import Semaphore

# Global variable
packetFilter = None
gc = None

# APIs exposed by the web-service
class StartProfile:
    def GET(self, jobId, pid, owner, birthDate):
        process = ProcessInfo(pid, owner, birthDate)
        return NetworkProfiler.StartProfile(jobId, process)

class EndProcessProfile:
    def GET(self, jobId, pid, owner, birthDate):
        return NetworkProfiler.EndProcessProfile(jobId, pid, owner, birthDate)

class EndJobProfile:
    def GET(self, jobId):
        return NetworkProfiler.EndJobProfile(jobId)

class ShutDown:
    def GET(self):
        return NetworkProfiler.ShutDown(packetFilter, gc)


# Main method. Execution starts from here
if __name__ == "__main__":
    
    try:
        # Check if not executed as root
        if os.getuid() != 0:
            raise AssertionError("root privileges are required for execution.")
        
        # Load config params from ini file
        configParams = ConfigParams()
        
        print 'INPUT chain', IptableCommands.inputChainName
        
        # Initialize the Logger
        LogHandler.initLogger(configParams)
        
        # Cleaup the rules left over before last shutdown
        Iptables.CleanUpIptables()
                
        # Create new Iptable chain to which rules will be added later
        Iptables.Initialize()
                 
        # Initalize sempahores for synchronization, with 0 as initial value
        sem1_pktFilter_GC = Semaphore(0)
        sem2_pktFilter_GC = Semaphore(0)
        
        # Initialize Libpcap to start monitoring traffic in a separate thread
        print "Starting packet filter...\n"
        packetFilter = PacketFilter(sem1_pktFilter_GC, sem2_pktFilter_GC, configParams)
        packetFilter.start()         
        
        # Initialize Garbage collector in a separate thread
        print "Starting GC...\n"
        gc = GC(sem1_pktFilter_GC, sem2_pktFilter_GC)
        gc.start()
        
        # Start the web application to accept request for tracking traffic
        app = web.application(Constants.Urls, globals())
        print "Starting web server..."
        app.run()
    except AssertionError as ex:
        print 'ERROR:', ex
    except Exception as ex:
        print 'ERROR:', ex
        NetworkProfiler.ShutDown(packetFilter, gc)       
