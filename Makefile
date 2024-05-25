CXX ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -pedantic -O3 -g -Iinclude
LDFLAGS ?= -lreadline -lcapstone

SRC = $(wildcard src/*.cpp)
OBJ = $(SRC:.cpp=.o)
DEP = $(OBJS:.o=.d)


all: sdb

sdb: main.cpp $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $< $(OBJ) $(LDFLAGS)

.PHONY: clean
clean:
	$(RM) sdb $(OBJ) $(DEP)

-include $(DEP)
