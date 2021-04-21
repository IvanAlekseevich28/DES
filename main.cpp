#include <iostream>
#include <algorithm>
#include "des.h"

using namespace std;

int get_mode(const string& str_mode);
void print_mode_error(const string& str_mode);
void print_init_vec_error(const string& str_init_vec);
void print_argc_error();

int main(int argc, char* argv[])
{
    string key;
    string str;

    // block of parsing args
    bool wait_mode(false); int mode = des::ECB; // -m ECB | CFB
    bool wait_init_vec(false); string init_vec; // -i 12345678
    for (int i = 1; i < argc; i++)
    {
        string data(argv[i]);
        if (data == "-m" or data == "--mode")
        {
            wait_mode = true;
            continue;
        } else if (wait_mode)
        {
            mode = get_mode(data);
            wait_mode = false;
            if (mode == -1)
            {
                print_mode_error(data);
                return -0x01;
            }
            continue;
        }
        if (data == "-i" or data == "--mode")
        {
            wait_init_vec = true;
            continue;
        } else if (wait_init_vec)
        {
            wait_init_vec = false;
            if (data.length() != 8)
            {
                print_init_vec_error(data);
                return -0x02;
            }
            init_vec = data;

            continue;
        }
        if (key.empty())
        {
            key = data;
            continue;
        }
        if (str.empty())
        {
            str = data;
            continue;
        }

        print_argc_error();
        return -0x04;
    }

    if (key.empty())
    {
        cerr << "key can't be empty!\n";
        return -0x08;
    }
    if (str.empty())
    {
        cerr << "message for crypt was not found!\n";
        return -0x10;
    }

    des d(key);

    if (init_vec.size())
    {
        d.set_init_vector(init_vec);
    }
    auto crp = d.encrypt(str, mode);
    auto mes = d.decrypt(crp, mode);

    cout << "Encrypted: " << crp << '\n';
    cout << "Decrypted: " << mes << '\n';

    return 0;
}

int get_mode(const string& str_mode)
{
    auto s = str_mode;
    for (auto & c: s) c = toupper(c);

    if (s == "ECB")
        return des::ECB;
    if (s == "CFB")
        return des::CFB;

    return -1;
}

void print_mode_error(const string& str_mode)
{
    cerr << str_mode << " - not aviable as mode!\n";
}

void  print_init_vec_error(const string& str_init_vec)
{
    cerr << str_init_vec << " - not aviable as init vec!\n Need lenght 8!\n";
}

void print_argc_error()
{
    cerr << "Not enought args!\n";
}
