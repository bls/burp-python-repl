
MAIN = main.py
MODULES = repl.py
TARGET = BurpPythonRepl.py

all:
	pypack.py $(MAIN) $(MODULES) > $(TARGET)

