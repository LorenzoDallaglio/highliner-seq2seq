#include <iostream>
#include <vector>

int simple_inline(int i){
	int res = 0x69;	
	return res + i;
}

int main(){
	std::vector<int> vec;
	int test = 0;
	for (int i = test; i < 10; i++){
		vec.push_back(i);
	}
	for (int i = test; i < 10; i++){
		std::cout << simple_inline(i) << "\n";
	}
	return 0;
}
