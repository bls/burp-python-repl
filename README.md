# burp-python-repl

A Python repl, embedded in Burp, via Telnet

## Installation

* You need to have "Python Environment" configured under "Extender -> Options".
* Navigate to: "Burp -> Extender -> Extensions -> Add"
* Extension Type: Python
* Extension File: Select "bin/BurpPythonRepl.py".

## Screenshots

The extension in burp:

![Ext](/docs/images/extension-enabled.png)

Connecting to the repl:

![Repl](/docs/images/repl-in-action.png)

## NOTES

* telnet localhost 6000
* You will have a Python repl.
* Editing sucks, because there's no pty.
* Burp callbacks available as 'cb'.

