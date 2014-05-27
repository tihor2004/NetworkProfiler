# Class to represent a Process

class ProcessInfo:
    
    def __init__(self, pid, owner, birthDate):
        self.pid = int(pid)
        self.owner = str(owner)
        # Condor should send the birthDate as a floating point value
        # expressed in seconds since epoch, in UTC.
        self.birthdate = str(birthDate)
    
    def __repr__(self):
        return "%s,%s,%s" % (self.pid, self.owner, self.birthdate)
    
    def __eq__(self, other):
        if isinstance(other, ProcessInfo):
            return ((self.pid == other.pid) and (self.owner == other.owner) 
                    and self.birthdate == other.birthdate)
        else:
            return False
    
    def __ne__(self, other):
        return (not self.__eq__(other))
    
    def __hash__(self):
        return hash((self.pid, self.owner, self.birthdate))
