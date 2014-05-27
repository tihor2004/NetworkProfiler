import threading

# Implementation of a thread safe dictionary where only
# 1 thread can be reading or writing to the dictionary.
# Thread safety is guaranteed because of a re-entrant lock
class ThreadSafeDictionary():
    
    # Constructor
    def __init__(self):
        self.dict = {}
        self.lock = threading.RLock()
        
    # Method to get the value corresponding to the specified key.
    def get(self, key):
        try:
            self.lock.acquire()
            value = self.dict.get(key)
        finally:
            self.lock.release()
            
        return value
    
    # Method to set the value of the specified key.
    def set(self, key, value):
        try:
            self.lock.acquire()
            self.dict[key] = value
        finally:
            self.lock.release()

    # Method to remove the key-value from the dictionary.
    # It returns the value associated with the key if key exists.
    # Else, it returns None
    def pop(self, key):
        try:
            self.lock.acquire()
            value = self.dict.pop(key, None)
        finally:
            self.lock.release()
            
        return value
    
    # Wrapper over items()
    def items(self):
        try:
            self.lock.acquire()
            items = self.dict.items()
        finally:
            self.lock.release()
            
        return items
    
    # Wrapper over keys()
    def keys(self):
        try:
            self.lock.acquire()
            keys = self.dict.keys()
        finally:
            self.lock.release()
            
        return keys