import psutil
import threading

import NetworkProfiler

from NetworkProfiler import processToJobIdDict
from NetworkProfiler import globalLock
from psutil import NoSuchProcess
from Process import ProcessInfo

# A basic implementation of a Garbage Collector.
# The collector kicks-in when the number of installed iptable rules
# crosses the threshold ConfigParams.RULES_THRESHOLD

# The collector checks each process that is being tracked to see if it
# is still running or not. If not then the rules associated with that
# process are removed.


# GC runs in its own thread and synchronizes with packet filter using
# 2 semaphores.
class GC(threading.Thread):
    
    def __init__(self, sem1_pktFilter_GC, sem2_pktFilter_GC):
        threading.Thread.__init__(self)
        
        # Initialize semaphores
        self.sem1_pktFilter_GC = sem1_pktFilter_GC
        self.sem2_pktFilter_GC = sem2_pktFilter_GC
        
        
    def run(self):
        while True:            
            try:
                # Wait till a signal is received from packet filter
                self.sem1_pktFilter_GC.acquire()
                
                # Acquire the global lock as some global data structures might be modified
                globalLock.acquire()
                
                print 'DEBUG: GC triggered...'
                
                # Iterate over each trackedProc that we are tracking
                for trackedProc in processToJobIdDict.keys():
                    
                    # Get jobId for this process
                    jobId = processToJobIdDict.get(trackedProc)
                    
                    # Check if the trackedProc is still running
                    try:
                        proc = psutil.Process(trackedProc.pid)
                        runningProc = ProcessInfo(trackedProc.pid, proc.username(), proc.create_time())
                    except NoSuchProcess:
                        runningProc = None
                    
                    # If no such process is running or birthdate are different
                    # Remove all rules and mapping associated with this process
                    if (runningProc is None) or (not trackedProc.__eq__(runningProc)):
                        NetworkProfiler.RemoveProcess(jobId, trackedProc)
            finally:
                print 'DEBUG: GC completed...'
                globalLock.release()
                # Signal packet filter using the semaphore
                self.sem2_pktFilter_GC.release()
                