#include <iostream>
#include "des.h"

using namespace std;

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        cerr << "Uncorrect args!\n";
        return 1;
    }
    string key(argv[1]);
    if (key.size() > 8 or key.size() == 0)
    {
        cerr << "Uncorrect key lenght it must be 8 or less!\n";
        return 2;
    }
    string str(argv[2]);

    des d(key);
    auto crp = d.encrypt(str);
    auto mes = d.decrypt(crp);

    cout << "Encrypted: " << crp << '\n';
    cout << "Decrypted: " << mes << '\n';

    return 0;
}
