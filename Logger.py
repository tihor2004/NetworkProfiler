import logging.handlers

from Constants import PacketDirection
   
class LogHandler:
    my_logger = None
    
    @staticmethod
    def insertEntry(socketInfo, pid, jobId, dataTransferred, direction):
        try:
            if direction == PacketDirection.PKT_IN:
                LogHandler.my_logger.info('%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s', jobId, pid, socketInfo.srcIP,
                                          socketInfo.srcPort, socketInfo.destIP, socketInfo.destPort,
                                          "IN", dataTransferred)
            elif direction == PacketDirection.PKT_OUT:
                LogHandler.my_logger.info('%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s', jobId, pid, socketInfo.destIP,
                                          socketInfo.destPort, socketInfo.srcIP, socketInfo.srcPort,
                                          "OUT", dataTransferred)
        except Exception as ex:
            print 'ERROR. Exception while adding an entry to the log:', ex
            return 1
        return 0
            
    @staticmethod
    def initLogger(configParams): 

        # create a logging format
        formatter = logging.Formatter('%(asctime)s \t %(message)s')
        
        handler = logging.handlers.RotatingFileHandler(configParams.LOG_FILENAME,
                                                       maxBytes=configParams.MAX_BYTES, 
                                                       backupCount=configParams.BACKUP_COUNT)
        handler.setFormatter(formatter)
            
        # Set up a specific logger with our desired output level
        LogHandler.my_logger = logging.getLogger('agentlogger')
        LogHandler.my_logger.level = logging.DEBUG
        LogHandler.my_logger.addHandler(handler)
    
    @staticmethod    
    def shutDown():
        logging.shutdown()
        print 'Stopped logging...'
