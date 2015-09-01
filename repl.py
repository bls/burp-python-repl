#!/usr/bin/env python

# https://gist.github.com/tim-patterson/4471877

'''Python interactive console server,
To be embedded in an application/service, once connected to (ie using nc or putty) you will be
provided with an interactive python interpreter attached to your main process,
application state can be queried and modified via this console
'''

import SocketServer
import sys
import traceback
import logging
# from org.python.util import JLineConsole
from code import InteractiveConsole
# from org.python.util import ReadlineConsole
# from org.python.util import InteractiveConsole
import threading

log = logging.getLogger(__package__)

#Dict that will be used as the locals for the remote console
locals_dir = {}
banner = 'Console ready'

'''Class that acts as a proxy allowing different instances for different threads
Useful for sys.stdout etc.'''
class ThreadLocalProxy(object):
    def __init__(self, default):
        self.files = {}
        self.default = default
        
    def __getattr__(self, name):
        obj = self.files.get(threading.currentThread(), self.default)
        return getattr(obj,name)
    
    def register(self, obj):
        self.files[threading.currentThread()] = obj
    
    def unregister(self):
        self.files.pop(threading.currentThread())


class ReplServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    # Ctrl-C will cleanly kill all spawned threads
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
        sys.stdout = ThreadLocalProxy(sys.stdout)
        sys.stderr = ThreadLocalProxy(sys.stderr)
        sys.stdin = ThreadLocalProxy(sys.stdin)
    

class ReplHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        log.info('Client: %s: connect', self.client_address)
        sys.stdout.register(self.wfile)
        sys.stderr.register(self.wfile)
        sys.stdin.register(self.rfile)
        try:
            #console = JLineConsole("console", locals_dir)
            #console = JLineConsole("utf-8")
            #console = ReadlineConsole(locals_dir)
            console = InteractiveConsole(locals_dir)
            console.interact(banner)
        except SystemExit:
            pass
        except:
            #We dont want any errors/exceptions bubbling up from the repl
            traceback.print_exc()
            pass
        finally:
            sys.stdout.unregister()
            sys.stderr.unregister()
            sys.stdin.unregister() 
            log.info('Client: %s: disconnect', self.client_address)


class Repl(object):
    def __init__(self, addr='127.0.0.1', port=6000):
        self.server = ReplServer((addr, port), ReplHandler)
        self.thread = None

    def run(self):
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = False
        self.thread.start()
        log.debug('Repl thread started')
    
    def shutdown(self):
        log.debug('Repl shutdown requested')
        if self.thread is not None:
            log.debug('Repl shutdown started...')
            self.server.shutdown()
            self.thread.join()
            self.thread = None
            self.server.server_close()
            log.debug('Repl shutdown complete')

if __name__ == '__main__':
    r = Repl()
    r.run()

