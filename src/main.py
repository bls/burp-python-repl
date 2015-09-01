
import sys
import os
import logging
from burp import IBurpExtender, IExtensionStateListener


log = logging.getLogger(__package__)

class BurpExtender(IBurpExtender, IExtensionStateListener):
    def __init__(self):
        self.repl = None
        self.callbacks = None
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("BurpPythonRepl")
        self.callbacks.registerExtensionStateListener(self)
        self.setImportPath()
        self.configureLogging()
        self.startRepl()

    def extensionUnloaded(self):
        self.stopRepl()

    def configureLogging(self):
        burp_stdout = self.callbacks.getStdout()
        logging.basicConfig(level=logging.DEBUG, stream=burp_stdout)
        
    def setImportPath(self):
        scriptFile = self.callbacks.getExtensionFilename()
        scriptDir = os.path.dirname(os.path.abspath(scriptFile))
        if scriptDir not in sys.path:
            sys.path.insert(0, scriptDir)
        
    def getConsoleBanner(self):
        burpVer = self.callbacks.getBurpVersion()
        return '\n'.join([
            'Python {0}'.format(sys.version),
            'Platform: {0}'.format(sys.platform),
            'Product: {0} {1}.{2}'.format(burpVer[0], burpVer[1], burpVer[2]),
            'Type "help", "copyright", "credits" or "license" for more information.'
        ])

    def startRepl(self):
        import repl
        self.repl = repl.Repl()
        repl.locals_dir['cb'] = self.callbacks
        repl.banner = self.getConsoleBanner()
        self.repl.run()

    def stopRepl(self):
        self.repl.shutdown()

