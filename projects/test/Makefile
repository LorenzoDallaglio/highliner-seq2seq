CXX = g++
CXXFLAGS = -g

compile: test.cpp
	$(CXX) $(CXXFLAGS) test.cpp -O2 -o test_O2.o   
	$(CXX) $(CXXFLAGS) test.cpp -O3 -o test_O3.o
	$(CXX) $(CXXFLAGS) test.cpp -Os -o test_Os.o
	$(CXX) $(CXXFLAGS) test.cpp -Ofast -o test_Ofast.o

test: compile
	./test02.o

.PHONY: clean all

all: clean
clean:
	rm -f *.o
