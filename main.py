
from burp import IBurpExtender, IExtensionStateListener
import repl
import logging

log = logging.getLogger(__package__)

class BurpExtender(IBurpExtender, IExtensionStateListener):
    def __init__(self):
        self.repl = repl.Repl()
        self.callbacks = None
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("BurpPythonRepl")
        self.callbacks.registerExtensionStateListener(self)
        self.configureLogging()
        repl.locals_dir['cb'] = self.callbacks
        repl.banner = self.getConsoleBanner()
        self.repl.run()

    def extensionUnloaded(self):
        self.repl.shutdown()

    def configureLogging(self):
        burp_stdout = self.callbacks.getStdout()
        logging.basicConfig(level=logging.DEBUG, stream=burp_stdout)

    def getConsoleBanner(self):
        burpVer = self.callbacks.getBurpVersion()
        return '\n'.join([
            'Python {0}'.format(sys.version),
            'Platform: {0}'.format(sys.platform),
            'Product: {0} {1}.{2}'.format(burpVer[0], burpVer[1], burpVer[2]),
            'Type "help", "copyright", "credits" or "license" for more information.'
        ])
