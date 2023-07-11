CXX = g++
CXXFLAGS = -g

compile: test.cpp
	$(CXX) $(CFLAGS) test.cpp -O2 -o test_02.o
	$(CXX) $(CFLAGS) test.cpp -O3 -o test_03.o
	$(CXX) $(CFLAGS) test.cpp -Os -o test_0s.o
	$(CXX) $(CFLAGS) test.cpp -Ofast -o test_0fast.o

test: compile
	./test02.o

.PHONY: clean all

all: clean
clean:
	rm -f *.o
