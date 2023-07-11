#include <iostream>
#include <vector>

int main(){
	std::cout << "Hello World!\n" << "This is a test program!\n";
	std::vector<int> vec;
	for (int i = 0; i < 10; i++){
		vec.push_back(i);
	}
	for (int i = 0; i < 10; i++){
		std::cout << vec[i] << "\n";
	}
	return 0;
}
