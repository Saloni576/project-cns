CXX = g++
CXXFLAGS = -std=c++20 -I/usr/include/openssl
LDFLAGS = -lstdc++fs -lssl -lcrypto -static

SRC = logread.cpp logappend.cpp server.cpp input_validation.cpp ciphering.cpp 
OBJ = $(SRC:.cpp=.o)

LOGREAD_EXEC = logread
LOGAPPEND_EXEC = logappend
SERVER_EXEC = server

INSTALL_DIR = /usr/local/bin

all: check_deps $(LOGREAD_EXEC) $(LOGAPPEND_EXEC) $(SERVER_EXEC)

$(LOGREAD_EXEC): logread.o input_validation.o ciphering.o
    $(CXX) $(CXXFLAGS) -w -o $@ $^ $(LDFLAGS)

$(LOGAPPEND_EXEC): logappend.o input_validation.o ciphering.o
    $(CXX) $(CXXFLAGS) -w -o $@ $^ $(LDFLAGS)

$(SERVER_EXEC): server.o input_validation.o ciphering.o
    $(CXX) $(CXXFLAGS) -w -o $@ $^ $(LDFLAGS)

%.o: %.cpp
    $(CXX) $(CXXFLAGS) -c $< -o $@

clean:
    rm -f $(OBJ) $(LOGREAD_EXEC) $(LOGAPPEND_EXEC) $(SERVER_EXEC)

install: all
    install -m 0755 $(LOGREAD_EXEC) $(INSTALL_DIR)
    install -m 0755 $(LOGAPPEND_EXEC) $(INSTALL_DIR)
    install -m 0755 $(SERVER_EXEC) $(INSTALL_DIR)

uninstall:
 	sudo rm -f $(INSTALL_DIR)/logread $(INSTALL_DIR)/logappend $(INSTALL_DIR)/server

check_deps:
    @echo "Checking for required libraries..."
    @which apt-get > /dev/null && sudo apt-get update && sudo apt-get install -y libssl-dev || echo "Please install libssl-dev manually."

.PHONY: all clean install uninstall
