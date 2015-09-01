"""
Sadly, jython does not support termios. However, jython does support ctypes.
We need this so that "import pty" works.

However, 

See also: http://svn.python.org/projects/python/trunk/Modules/termios.c

"""

# Sadly, jython does not support termios.
# Fortunately, it does support ctypes...

from ctypes import *

# tcsetattr() constants
TCSANOW = 0
TCSADRAIN = 0
TCSAFLUSH = 0
# TCSASOFT = 0

# tcflush() constants
TCIFLUSH = 0
TCOFLUSH = 0
TCIOFLUSH = 0

# struct termios.c_iflag constants
IGNBRK = 0
BRKINT = 0
IGNPAR = 0
PARMRK = 0
INPCK = 0
ISTRIP = 0
INLCR = 0
IGNCR = 0
ICRNL = 0
# IUCLC = 0
IXON = 0
IXANY = 0
IXOFF = 0
# IMAXBEL = 0



def tcgetattr(fd):
    raise NotImplementedError

def tcsetattr(fd, when, attributes):
    raise NotImplementedError

def tcsendbreak(fd, duration):
    raise NotImplementedError

def tcdrain(fd):
    raise NotImplementedError

def tcflush(fd, queue):
    raise NotImplementedError

def tcflow(fd, action):
    raise NotImplementedError

