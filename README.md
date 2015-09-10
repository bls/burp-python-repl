# burp-python-repl

A Python repl, embedded in Burp, via Telnet

## Installation

* You need to have "Python Environment" configured under "Extender -> Options".
* Navigate to: "Burp -> Extender -> Extensions -> Add"
* Extension Type: Python
* Extension File: Select "bin/BurpPythonRepl.py".

## Screenshots

![Ext](/docs/images/extension-enabled.png)

![Repl](/docs/images/repl-in-action.png)

## NOTES

* Burp callbacks available as 'cb'.
* Editing sucks, because there's no pty.

