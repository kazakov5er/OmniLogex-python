from datetime import datetime

class Logger:  
    def __init__(self, name: str = __name__, formatting: str = "{level}: [{name}] {text}"):
        self.name = name
        self.format_string = formatting  
        

    def _log(self, text: str, level: str):
        now = datetime.now()
        response = {
            "text": text,
            "message": text,
            "name": self.name,
            "level": level,
            "unix_timestamp": int(now.timestamp()),
            "statdart_timestamp": now,
            "iso_timestamp": now.isoformat() + "Z",
            "date": now.strftime("%d.%m.%Y"),
            "time": now.strftime("%H:%M:%S"),
            
        }
        print(self.format_string.format(**response))  

    def info(self, text: str):
        self._log(text = text, level = "INFO")
    
    def error(self, text: str):
        self._log(text = text, level = "ERROR")

    def debug(self, text: str):
        self._log(text = text, level = "DEBUG")

    def warning(self, text: str):
        self._log(text = text, level = "WARNING")
    
    def critical(self, text: str):
        self._log(text = text, level = "CRITICAL")

    

