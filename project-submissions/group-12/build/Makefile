CXX = g++
CXXFLAGS = -w
LIBS = -lssl -lcrypto

INSTALL_DIR = /usr/local/bin

all: server logread logappend

server: server.cpp
	$(CXX) $(CXXFLAGS) server.cpp -o server $(LIBS)

logread: logread.cpp
	$(CXX) $(CXXFLAGS) logread.cpp -o logread $(LIBS)

logappend: logappend.cpp
	$(CXX) $(CXXFLAGS) logappend.cpp -o logappend $(LIBS)

clean:
	rm -f server logread logappend

.PHONY: all clean