CXX = g++
CFLAGS = -Wall -std=c++14 -lcapstone

all: sdb

sdb: sdb.cpp
	$(CXX) $^ $(CFLAGS) -o $@

clean:
	rm -f sdb

.PHONY: all clean test