CXX ?= g++
CXXFLAGS ?= -std=c++11 -Wall -Wextra -pedantic -O3 -g

all: sdb

sdb: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

.PHONY: clean
clean:
	$(RM) sdb

