CXX ?= g++
LAB_ROOT ?= ../..
BACKEND ?= LINUX
CXXFLAGS ?= --std=c++11 -O3 -I $(LAB_ROOT)/HAL/include -DROUTER_BACKEND_$(BACKEND)
LDFLAGS ?= -lpcap

.PHONY: all clean
all: boilerplate

clean:
	rm -f *.o boilerplate std

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

hal.o: $(LAB_ROOT)/HAL/src/linux/router_hal.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

boilerplate: main.o hal.o protocol.o checksum.o lookup.o forwarding.o utils.o
	$(CXX) $^ -o $@ $(LDFLAGS) 
