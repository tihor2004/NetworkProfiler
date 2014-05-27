import sys
import threading

import Iptables
from Logger import LogHandler
from Process import ProcessInfo
from Constants import PacketDirection

# Create a map to store mapping between jobId and its processes
jobIdToProcessDict = {}
# Create a map to store mapping from Process to it jobId
processToJobIdDict = {}
# Create a map to store mapping between process and list of its sockets/rules
processToRulesDict = {}
# Create a map to store mapping between socket and its corresponding process
socketToProcessDict = {}
# Counter to keep a track of installed rules. This is modified in
# InsertRule() and DeleteRule() only
INSTALLED_RULES_COUNT = 0
# Lock
globalLock = threading.RLock()
        

# Delete all the installed rules and chains, stop packetFilter and logger
def ShutDown(packetFilter, gc):
    print 'DEBUG: Shutting down the server...'
    
    # Stop Libpcap profiling
    if packetFilter is not None:
        packetFilter._Thread__stop()
        print 'Stopped lipcap filtering...'
        
    # Stop GC
    if gc is not None:
        gc._Thread__stop()
        print 'Stopped Garbage Collector...'
    
    # Cleanup the already installed iptables rules     
    Iptables.CleanUpIptables()   

    # Shutdown logger
    LogHandler.shutDown()
    
    # shutdown the web service
    sys.exit()


# This method performs the following tasks:
# 1. Fetches the stats of the specified rule from iptables
# 2. Insert stats into the log file
def LogStats(socketInfo, process, jobId):
    dataIn, dataOut = Iptables.GetRuleStats(socketInfo)
                            
    # Log the stats in the log file
    if dataIn != 0:
        LogHandler.insertEntry(socketInfo, process.pid, jobId, dataIn, PacketDirection.PKT_IN)
                                
    if dataOut != 0:    
        LogHandler.insertEntry(socketInfo, process.pid, jobId, dataOut, PacketDirection.PKT_OUT)


def StartProfile(jobId, process):
    global jobIdToProcessDict
    global processToJobIdDict
    
    # Keep a track of specified process    
    try:
        globalLock.acquire()
        processSet = jobIdToProcessDict.get(jobId)

        if processSet is None:
            processSet = set()
            jobIdToProcessDict[jobId] = processSet
        
        # Add this process to the set of processes associated with specified jobId
        processSet.add(process)
        
        # Add the mapping of Process to its jobId in the map
        processToJobIdDict[process] = jobId
        print 'DEBUG: Started Tracking Job...', processToJobIdDict.get(process)
    except Exception as ex:
        print 'ERROR', ex
        return 1, ex
    finally:
        globalLock.release()
    # Return Success
    return 0


# Method checks if the rule already exists. If it does, then
# it does not install a new rule. Stores the rule in a map.

# In reality when a request to InsertRule comes, 2 rules are installed in
# iptables. One in the incoming direction and the other in the outgoing
# direction, but both are for the same socket. In the ruleSet we just add 
# one entry and that is for that single rule/socket, because the same entry
# denotes both incoming and outgoing rules.
def InsertRule(rule, process):
    global processToRulesDict
    global socketToProcessDict
    
    ret_value = 0
    
    # Get the list of rules for this process
    ruleSet = processToRulesDict.get(process)
        
    if ruleSet is None:
        ruleSet = set()
        processToRulesDict[process] =  ruleSet
            
    # Check whether the rule is already installed or not
    if not ruleSet.__contains__(rule):
        ret_code = Iptables.InstallIptableRule(rule)
        
        if ret_code == 0:

            # Add the rule to the list of rules for this process
            ruleSet.add(rule)
            
            # Create a mapping of socket to process
            socketToProcessDict[rule] = process
        else:
            print 'ERROR: Rule installation failed', rule
            
        ret_value = ret_code
    else:
        print 'DEBUG: Rule already exists', rule
    return ret_value


# Remove the specified process from the list of processes associated with this appId
def EndProcessProfile(jobId, pid, owner, birthDate):
    process = ProcessInfo(pid, owner, birthDate)
    
    try:
        globalLock.acquire()
        
        retVal = RemoveProcess(jobId, process)
    finally:
        globalLock.release()
    return retVal


# Remove the specified process from the list of processes associated with this appId
def EndJobProfile(jobId):
    global jobIdToProcessDict
    global processToJobIdDict
    global socketToProcessDict
    global processToRulesDict
    
    ret_value = 0
    
    try:
        globalLock.acquire()
        
        processSet = jobIdToProcessDict.pop(jobId)
        
        # Remove each process associated with this job
        while processSet:
            try:
                process = processSet.pop()            
                    
                # Fetch all rules associated with this process, get stats and remove them
                rules = processToRulesDict.pop(process)
                        
                if rules is not None:
                    for rule in rules:
                        # 1. Fetch the stats of the specified rule from iptables
                        # 2. Insert stats into the log file
                        # 3. Delete the rules from iptables
                        # 4. Remove the mapping between socket and corresponding process
                        LogStats(rule, process, jobId)
                        ret_value = Iptables.UninstallIPtableRule(rule)
                        
                        # Remove the mapping of socket to process
                        socketToProcessDict.pop(rule)
                              
                # remove the entry from processToJobIdDict
                processToJobIdDict.pop(process)
            except KeyError as ex:
                print 'ERROR', ex
                continue    
    except Exception as e:
        print 'ERROR', e
        ret_value = 1
    finally:
        globalLock.release()
    return ret_value

# In reality when a request to DeleteRule comes, 2 rules are deleted from
# iptables. One in the incoming direction and the other in the outgoing
# direction, but both are for the same socket. From the ruleSet, we just remove 
# one entry and that is for that single rule/socket, because the same entry
# denotes both incoming and outgoing rules.    
def DeleteRule(rule, process):
    global processToRulesDict
    global socketToProcessDict
    
    ret_value = 0
    
    try:
        # Get the list of rules for this process
        ruleSet = processToRulesDict.get(process)
        
        if ruleSet is not None:
            print 'DEBUG: Deleting Rule', rule
            
            # Check whether the rule is already installed or not
            if ruleSet.__contains__(rule):
                ret_value = Iptables.UninstallIPtableRule(rule)
                
                # Remove the rule from the list of rules associated with this process
                ruleSet.remove(rule)                    
        else:
            print 'DEBUG: No rule for process', process.pid
            
        # Remove the mapping of socket to process
        socketToProcessDict.pop(rule)
    except KeyError as ex:
        print ex
        ret_value = 1
    return ret_value



# This method provides mutual exclusion over removal of all
# the mappings associated with a process. All the rules associated 
# with the process are deleted and stats for each one of them is
# also logged.
def RemoveProcess(jobId, process):
    global jobIdToProcessDict
    global processToRulesDict
    global socketToProcessDict
    global processToJobIdDict
    
    ret_value = 0
    
    try:
        print 'DEBUG: Removing process', process.pid, 'from jobId', jobId    
        # Get list of process's associated with this application
        processSet = jobIdToProcessDict.get(jobId)
        
        # Iterate over each process associated with this jobId
        if processSet is not None:            
            if process in processSet:
                # remove the process from set of processes associated with this jobId
                processSet.remove(process)
                    
        # Fetch all rules associated with this process, get stats and remove them
        ruleSet = processToRulesDict.pop(process)
                
        if ruleSet is not None:
            while ruleSet:
                rule = ruleSet.pop()
                # 1. Fetch the stats of the specified rule from iptables
                # 2. Insert stats into the log file
                # 3. Delete the rules from iptables
                # 4. Remove the mapping between socket and corresponding process
                LogStats(rule, process, jobId)
                ret_value = Iptables.UninstallIPtableRule(rule)
                # Remove the mapping of socket to process
                socketToProcessDict.pop(rule)
                      
        # remove the entry from processToJobIdDict
        processToJobIdDict.pop(process)
    except Exception as ex:
        print 'ERROR', ex
        ret_value = 1
    return ret_value