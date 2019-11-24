#include <iostream>
using std::cout;
using std::endl;

static void printBits(int a)
{
	auto b = (int *) (&a);
	for (int k = 0; k < 32; ++k) {
		cout << (bool) (*b & (1 << k));
	}
}

int main() {
    int a = 1;
    printBits(a);
    // for (int i = 0; i < 32; ++i) {
    //     int b = ( 1 << i );
    //     cout << (bool)(a & b);
    // }
    cout << endl;
}
