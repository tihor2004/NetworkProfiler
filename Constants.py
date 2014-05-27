import ConfigParser

Urls = (
        '/startprofile/jobid=(.*),pid=(.*),owner=(.*),birthdate=(.*)', 'StartProfile',
        '/endprocessprofile/jobid=(.*),pid=(.*),owner=(.*),birthdate=(.*)', 'EndProcessProfile',
        '/endjobprofile/jobid=(.*)', 'EndJobProfile',
        '/shutdown', 'ShutDown'
        )


class PacketDirection:
    PKT_IN = 0
    PKT_OUT = 1


# Class to load params from config file.
# No need to catch exceptions here, they will be caught in main()
class ConfigParams:
    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.readfp(open('config.ini'))
        
        # Interface to be monitored
        self.INTERFACE = config.get('CONFIG', 'INTERFACE')
        
        # Max size of each log file
        self.MAX_BYTES = long(config.get('CONFIG', 'MAX_BYTES'))
        
        # Number of separate backup files that will be created before file deletions
        self.BACKUP_COUNT = int(config.get('CONFIG', 'BACKUP_COUNT'))
        
        # Maximum number of rules that can be installed
        self.RULES_THRESHOLD = int(config.get('CONFIG', 'RULES_THRESHOLD'))
    
        self.LOG_FILENAME = self.INTERFACE + '.log'
