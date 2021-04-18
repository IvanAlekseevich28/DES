#include <iostream>
#include "des.h"

using namespace std;

int main() {
    string str = "Peaky Blinders!";
    string key = "12345670";

    des d(key);
    auto crp = d.encrypt(str);
    auto mes = d.decrypt(crp);

    cout << "Encrypted: " << crp << '\n';
    cout << "Decrypted: " << mes << '\n';

    return 0;
}
