CXX=g++
CC=gcc
XPIR_DIR=dependencies/XPIR/
TOR_DIR=dependencies/tor/
YAML_DIR=dependencies/yaml-cpp/
DEBUG=1

XPIR_FLAGS= -L$(XPIR_DIR)/build/pir -lpir -I$(XPIR_DIR) -lboost_system -pthread -fopenmp 
TOR_FLAGS= -I$(TOR_DIR)/src/or -I$(TOR_DIR) -I$(TOR_DIR)/src/common -I$(TOR_DIR)/src/ext
YAML_FLAGS= -I$(YAML_DIR)/include $(YAML_DIR)/build/libyaml-cpp.a
CXXFLAGS= -g -std=c++11 -fpermissive -Wno-write-strings $(TOR_FLAGS) $(XPIR_FLAGS) $(YAML_FLAGS) -L/usr/lib/x86_64-linux-gnu/ -lz -lssl -lcrypto

client:
	$(CXX) simulation_client.cpp -o $@ $(CXXFLAGS)
server:
	$(CXX) simulation_server.cpp -o $@ $(CXXFLAGS) -DDEBUG=$(DEBUG)
cs: client server
simp:
	$(CXX) $(CXXFLAGS) simplePIR.cpp -o simp $(XPIR_FLAGS)
wrap:
	$(CXX) $(CXXFLAGS) wrap.cpp -c -fPIC -$(XPIR_FLAGS)
	echo "turning static library wrap.o into shared library usable with c compiler"
	$(CXX) $(CXXFLAGS) -shared -o libwrap.so wrap.o
call: wrap
	$(CC) call.c -lwrap -lpir -lboost -o call
readme:
	pdflatex readme.tex
all : client server simp wrap call readme
# -f means silently ignore if file doesn't exist.
clean:
	rm -f client server simp call
	rm -f readme.{pdf,aux,log,out} 
