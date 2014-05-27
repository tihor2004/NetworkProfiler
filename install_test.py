import os
import sys, time
import shlex, subprocess
from subprocess import Popen

# This file contains a basic set of tests that we want to run of the target machine
# to verify whether the profiler tool can run successfully on it or not.


# This methods verifies whether the required python package are
# installed on the machine or not.
def verifyPythonPackages():
	# Expected list of python packages
	pythonPackageList = ['web', 'psutil', 'dpkt', 'pcapy']

	for pythonPackage in pythonPackageList:
		try:
			__import__(pythonPackage)
			print "SUCCESS: python package " + pythonPackage + " found Installed."
		except ImportError, e:
			print "ERROR:", e,  "The package is not installed or not in sys.path."


# List of commands that we want to test
class Constants:
	iPerfPort = "2001"
    	chainName = "CONDO"
    	createChain = "iptables -N " + chainName    
	deleteChain = "iptables -X " + chainName
    	attachToChain = "iptables -A INPUT -j " + chainName
    	detachFromChain = "iptables -D INPUT -j " + chainName
    	appendRule = "iptables -A " + chainName + " -p tcp --dport " + iPerfPort
    	deleteRule = "iptables -D " + chainName + " -p tcp --dport " + iPerfPort
    
    	# iptables -vnL gives output in this form:
    	#  pkts bytes target   prot opt in  out source     destination
    	#   0     0            tcp  --  *    *  10.0.0.2   10.0.0.1     tcp spt:1025 dpt:1024
    	stats = "iptables -vnL " + chainName + " | grep tcp"
	
	iPerfServerCommand = "iperf -s -p " + iPerfPort
	iperfClientCommand = "iperf -c 127.0.0.1 -p " + iPerfPort


# Verify whether all IPTABLES commands can be executed successfull 
# on the machine or not
def verifyIptables():
	try:
		print 'Create user defined chain using IPTABLES'
		output = os.popen(Constants.createChain)	
		time.sleep(1)

		print 'Linking user defined chain to INPUT chain'
		output = os.popen(Constants.attachToChain)	
		time.sleep(1)

		print 'Appending a rule to the user defined chain'
		output = os.popen(Constants.appendRule)	

	        # Start iPerf server at port 2001 as a separate process
	       	print '\nStarting iPerf Server at port', Constants.iPerfPort

        	args = shlex.split(Constants.iPerfServerCommand)
	        iPerfServerProc = subprocess.Popen(args, stdout=None)
	        #iPerfServerProc = subprocess.Popen(args, stdout=None)

	       	print '\nStarting iPerf client...'
		args = shlex.split(Constants.iperfClientCommand)
        	# Start iPerf client. Control returns back only when iPerf client completes
	        output = subprocess.call(args, stdout=None)
        	# Kill iPerf server
	        iPerfServerProc.kill()
		
		print 'Collecting stats from IPTABLES'
		output = os.popen(Constants.stats)
		time.sleep(2)
		
		# Get the amount of data transferred
		output = output.read().split()

		if len(output) == 0 or output[1] == 0:
			print 'ERROR: Stats cannot be fetched from Iptables.'
		else:
			print 'SUCCESS: IPtables working properly'
		# check 2nd field of the output, it should be not None and have some value
	except Exception:
		pass
	iptableCleanup()


# Cleanup iptables rules created during execution of this script
def iptableCleanup():
	print 'Cleaning up IPTABLES'
	output = os.popen(Constants.deleteRule)	
	time.sleep(1)
	output = os.popen(Constants.detachFromChain)	
	time.sleep(1)
	output = os.popen(Constants.deleteChain)	


if __name__ == "__main__":

	# Check if not executed as root
        if os.getuid() != 0:
        	print 'ERROR: root privileges are required for execution.'
		sys.exit(-1)

	# Verify if all the required python packages are installed
	print 'TEST 1: Verifying installation of required python packages'
	verifyPythonPackages()
	print '**********************************************************'
	
	# Verify if Iptables exists and whether rules can be inserted in it
	print '\n\nTEST 2: Verifying working of IPTABLES'
	verifyIptables()
	print '**********************************************************'
