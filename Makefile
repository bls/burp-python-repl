
MAIN = src/main.py
MODULES = src/repl.py
TARGET = bin/BurpPythonRepl.py

all:
	pypack.py $(MAIN) $(MODULES) > $(TARGET)

