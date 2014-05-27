# This files contains methods which perform operations on Iptables

import Utils
import ConfigParser
import NetworkProfiler

from Constants import PacketDirection

class IptableCommands:
    # Read the interface name from the config file to use it in
    # input and output user-defined chains
    config = ConfigParser.ConfigParser()
    config.readfp(open('config.ini'))
    
    INTERFACE = config.get('CONFIG', 'INTERFACE')
    
    inputChainName = "CONDOR_IN_" + INTERFACE
    outputChainName = "CONDOR_OUT_" + INTERFACE
    
    flushInputChain = "iptables -F " + inputChainName
    flushOutputChain = "iptables -F " + outputChainName
    
    resetCountersInputChain = "iptables -Z " + inputChainName
    resetCountersOutputChain = "iptables -Z " + outputChainName
    
    createUserDefinedInputChain = "iptables -N " + inputChainName
    createUserDefinedOutputChain = "iptables -N " + outputChainName
    
    deleteInputChain = "iptables -X " + inputChainName
    deleteOutputChain = "iptables -X " + outputChainName
    
    attachToInputChain = "iptables -A INPUT -j " + inputChainName
    attachToOutputChain = "iptables -A OUTPUT -j " + outputChainName
    
    detachFromInputChain = "iptables -D INPUT -j " + inputChainName
    detachFromOutputChain = "iptables -D OUTPUT -j " + outputChainName
        
    appendInRule = "iptables -A " + inputChainName + " -p %s -s %s -d %s --sport %d --dport %d"
    appendOutRule = "iptables -A " + outputChainName + " -p %s -s %s -d %s --sport %d --dport %d"
    
    deleteInRule = "iptables -D " + inputChainName + " -p %s -s %s -d %s --sport %d --dport %d"
    deleteOutRule = "iptables -D " + outputChainName + " -p %s -s %s -d %s --sport %d --dport %d"
    
    # iptables -vnL gives output in this form:
    #  pkts bytes target   prot opt in  out source     destination
    #   0     0            tcp  --  *    *  10.0.0.2   10.0.0.1     tcp spt:1025 dpt:1024
    inputStats = "iptables -vnL " + inputChainName + " | grep " + "%s.*%s.*%s.*%d.*%d"
    outputStats = "iptables -vnL " + outputChainName + " | grep " + "%s.*%s.*%s.*%d.*%d"
    

# Create user-defined chains and attach them to INPUT or OUTPUT chain
def Initialize():
    # Create a user defined input chain
    Utils.execute(IptableCommands.createUserDefinedInputChain)
    
    # Create a user defined output chain
    Utils.execute(IptableCommands.createUserDefinedOutputChain)
    
    # Attach user defined chain to Input chain
    Utils.execute(IptableCommands.attachToInputChain)
    
    # Attach user defined chain to Output chain
    Utils.execute(IptableCommands.attachToOutputChain)


#cleanup rules and remove the user-defined chains
def CleanUpIptables():
    print 'Chain', IptableCommands.inputChainName
    # Cleanup input chain and all associated rules
    Utils.execute(IptableCommands.flushInputChain)
    Utils.execute(IptableCommands.detachFromInputChain)    
    Utils.execute(IptableCommands.deleteInputChain)
    
    # Cleanup output chain and all associated rules
    Utils.execute(IptableCommands.flushOutputChain)    
    Utils.execute(IptableCommands.detachFromOutputChain)    
    Utils.execute(IptableCommands.deleteOutputChain)
    
    print 'Cleaned iptables...'


# Method to delete all rules from user-defined Input and Output chains
def FlushRules(self):
    Utils.execute(IptableCommands.flushInputChain)
    Utils.execute(IptableCommands.flushOutputChain)


# Reset counters for all installed iptables rules to 0
def ResetCounters(packetFilter):
    if packetFilter is not None:
        print 'DEBUG: Resetting counters for all iptable rules...'
        Utils.execute(IptableCommands.resetCountersInputChain)
        Utils.execute(IptableCommands.resetCountersOutputChain)
    return 0

# TODO: Return proper error code in case rule is not installed
# Method to install an iptables rule
def InstallIptableRule(rule):
    
    if rule.packetDirection == PacketDirection.PKT_IN:
        command = IptableCommands.appendInRule % (rule.protocol, rule.srcIP, 
                                           rule.destIP, rule.srcPort, rule.destPort)
        p = Utils.execute(command)
        
        command = IptableCommands.appendOutRule % (rule.protocol, rule.destIP, 
                                            rule.srcIP, rule.destPort, rule.srcPort)
        p = Utils.execute(command)
    else:
        command = IptableCommands.appendInRule % (rule.protocol, rule.destIP, 
                                           rule.srcIP, rule.destPort, rule.srcPort)
        p = Utils.execute(command)
        command = IptableCommands.appendOutRule % (rule.protocol, rule.srcIP, 
                                            rule.destIP, rule.srcPort, rule.destPort)
        p = Utils.execute(command)
    
    NetworkProfiler.INSTALLED_RULES_COUNT = NetworkProfiler.INSTALLED_RULES_COUNT + 1
    return 0

# Method to uninstall an iptables rule
def UninstallIPtableRule(rule):
    
    if rule.packetDirection == PacketDirection.PKT_IN:
        command = IptableCommands.deleteInRule % (rule.protocol, rule.srcIP, 
                                           rule.destIP, rule.srcPort, rule.destPort)
        p = Utils.execute(command)
        command = IptableCommands.deleteOutRule % (rule.protocol, rule.destIP, 
                                            rule.srcIP, rule.destPort, rule.srcPort)
        p = Utils.execute(command)
    else:
        command = IptableCommands.deleteInRule % (rule.protocol, rule.destIP, 
                                           rule.srcIP, rule.destPort, rule.srcPort)
        p = Utils.execute(command)
        command = IptableCommands.deleteOutRule % (rule.protocol, rule.srcIP, 
                                            rule.destIP, rule.srcPort, rule.destPort)
        p = Utils.execute(command)         
    
    NetworkProfiler.INSTALLED_RULES_COUNT = NetworkProfiler.INSTALLED_RULES_COUNT - 1
    return 0
    
# Collect and return the stats for the specified Iptables rule
def GetRuleStats(rule):
    dataIn = 0
    dataOut = 0
    
    try:
        if rule is not  None:
            if rule.packetDirection == PacketDirection.PKT_IN:                    
                # Get incoming data stats
                command = IptableCommands.inputStats % (rule.protocol, rule.srcIP, 
                                               rule.destIP, rule.srcPort, rule.destPort)
                output = Utils.execute(command)
                contents = output.read().split()                    
                # 2nd field in output is the data transferred
                dataIn = contents[1] 
                                    
                # Get outgoing data stats
                command = IptableCommands.outputStats % (rule.protocol, rule.destIP, 
                                                    rule.srcIP, rule.destPort, rule.srcPort)
                output = Utils.execute(command)
                contents = output.read().split()                    
                # 2nd field in output is the data transferred
                dataOut = contents[1]                 
                                   
            else:
                # Get outgoing data stats
                command = IptableCommands.inputStats % (rule.protocol, rule.destIP, 
                                                 rule.srcIP, rule.destPort, rule.srcPort)
                output = Utils.execute(command)
                contents = output.read().split()                    
                # 2nd field in output is the data transferred
                dataIn = contents[1]                    
                
                # Get outgoing data stats
                command = IptableCommands.outputStats % (rule.protocol, rule.srcIP, 
                                                  rule.destIP, rule.srcPort, rule.destPort)
                output = Utils.execute(command)
                contents = output.read().split()                    
                # 2nd field in output is the data transferred
                dataOut = contents[1]               
    except Exception as ex:
        print 'ERROR in GetStats(). Exception:', ex    
    return dataIn, dataOut