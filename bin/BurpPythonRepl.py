
#!/usr/bin/env python
import sys
import imp
import zlib
import base64

MODULES = {'repl': 'eJydV9tu4zYQfddXsAkKyYAjJ8WiWQTwU9qiW6RFsEnRh6IQaGlkc0OTKknZMYr+ew9FyZZsOVnUCWyZnDlzO5yhL7+Z1dbMFkLNSG1YtXMrraLokq2cq+zdbLYU1qVL4Vb1Is31eubE+qrizpGxWs0+fLi9+Xh7G0VxHD82ukwo7PHciQ2xXCurJTFLZkNmGj1rtiBG6wUVBRUQZRz/VSVFzp0AnhcUOU2ZVnmjrih3kHSaJYJYbYVaMpUzbVhVO7ebsJ2u2VZICeCoMnojPPAW/nrovi9Vz73KEN4ZwuD5KsADx7A1h0tAycnaadRzjFnHHRwCJgL4uyYjoMZVwda6EKX/shGcuZWwXdA+JVEk1pU2jj3p/IXcU5OGbs3ubPfo4CQteP7SLUi9XCJU1KE0eo1wl2nwP62dkKyV+uVBKLpvzTWCuS6o2/10CL6TeRvuM/FC9hDflh6B76JZGSB59yPEweZdNOmS3AMeySRZViFavqQsm4BtP4jcq3HXlRKV9vm1WCSo51xaVqLo/quhtXZ7bkVhNyuEgaV//o0WHKTxz3HrFvPe7OKGo/eSWxsswXXrLXBf8Ncd41LqracX6lmSIeXAFZQdRAy2D+shQBv9bqmsZbOJYqbWFbp2jFye+trnja3nRvbBO/no7SR68QWcntxFDK+CSpZlQgmXZYklWU79Eq9lJ+Bffj0thYQfTYSD9VYcO+3TfrtnAIkH183ehuJr6hmAS9A/mPGFSvZVTPPa+LBDJMlkOjA82aPgTNVGsdaWj3Pa2IkGzhjyHQUUCJ5AajTSP8+a/wuuQmuIWqsB7ihkWunqfFSgYVuxz1TJcFKT/rFNnzvVX8XrJzVlw837x/DUmr5k987Iq/tA6FwSV3LHXvwXEI3Zim+Vbzwtk5o4OIitsnYJUT6bmpqdhpqZIRyKjBeFQXfqts+xKHTcTnqKoNC0rPsZLUuSaY5BL0njoaT/A/OQ98OBmJ8egsPuiQYZ84YGdk800LPPKwjVErBX3dbjYXmfHADWw5h6p3TVrByzC50tFarUCTqLAJvu2Lf2rptbcXtS8mary9tYitIBe9Ot5+tYYr5KTqgjMTMUc2Z3CKDhajem54OJkly06xdTdmiyk69TrV159fHirPDRqEnO4R80TsfNe0ppN/2TMBIOQvSaU4WhvEOO1j++CjfMRwWeHMkeJewPYoXGINhyvHG1Y6iNNnYWhHFfsGxRLxbSj5O6CmM0jK5KDpD2gz+tDNzNAJBMzjtTCoVecFS+Ho16bXAyJuMp9J4M6NMXYQOZcb4Xwr5D+f7pe3cCeq15fPPdbXqNvxtg+mvF/Pvr6+vjxh5aUkOofdNOvH7QmUz7530y1A2NFrq/adVrpKZWozNkL34YIe3scNxg6M17DoWPDBcD2pyxm4Z2D7yfQGIaFcHtw7helXz2C1rUyyT2YbWesEaMivho0tpVDVZsT6I5RunkwM6m9+2R/EuUg+hxvVXaNRm7OyHGKGjrXJqm8RHd+unqXB0RaXPxRYs3trsqnjUQRlcutaUjlLOe49dOJfE7AX5HwpPU32ayjM1xtcwy/1Mhy+KQhY6BLTT6dO2djf4DRSVGqw=='}

class Importer(object):
    def find_module(self, fullname, path=None):
        if fullname in MODULES:
            return self
        return None

    def load_module(self, fullname):
        if fullname in sys.modules:
            return sys.modules[fullname]
        mod = imp.new_module(fullname)
        mod.__loader__ = self
        sys.modules[fullname] = mod
        packed_code = MODULES[fullname]
        unpacked_code = zlib.decompress(base64.b64decode(packed_code))
        mod.__file__ = "[packed module %r]" % fullname
        mod.__path__ = []
        exec unpacked_code in mod.__dict__
        return mod    

sys.meta_path = [Importer()]

# -----------------------------------------

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



