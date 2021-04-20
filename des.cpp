#include "des.h"

using namespace std;

// Initial replacement table
static int IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7};
// End substitution table
static int IP_1[] = {40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25};
/*------------------ Below is the table used to generate the key-----------------*/
// Key replacement table, change 64-bit key to 56-bit
static int PC_1[] = {57, 49, 41, 33, 25, 17, 9,
              1, 58, 50, 42, 34, 26, 18,
              10, 2, 59, 51, 43, 35, 27,
              19, 11, 3, 60, 52, 44, 36,
              63, 55, 47, 39, 31, 23, 15,
              7, 62, 54, 46, 38, 30, 22,
              14, 6, 61, 53, 45, 37, 29,
              21, 13, 5, 28, 20, 12, 4};
// Compression replacement, compress 56-bit key into 48-bit subkey
static int PC_2[] = {14, 17, 11, 24, 1, 5,
              3, 28, 15, 6, 21, 10,
              23, 19, 12, 4, 26, 8,
              16, 7, 27, 20, 13, 2,
              41, 52, 31, 37, 47, 55,
              30, 40, 51, 45, 33, 48,
              44, 49, 39, 56, 34, 53,
              46, 42, 50, 36, 29, 32};
// The number of bits shifted left in each round
static int shift_bits[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
/*------------------ Below is the table used by the cryptographic function f -----------------*/
// Extend the replacement table to extend 32 bits to 48 bits
static int E[] = {32, 1, 2, 3, 4, 5,
           4, 5, 6, 7, 8, 9,
           8, 9, 10, 11, 12, 13,
           12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21,
           20, 21, 22, 23, 24, 25,
           24, 25, 26, 27, 28, 29,
           28, 29, 30, 31, 32, 1};
// S boxes, each S box is a 4x16 replacement table, 6 bits -> 4 bits
static int S_BOX[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};
// P replacement, 32 bits -> 32 bits
static int P[] = {16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25 };


des::des(const std::string& key)
{
    set_key(key);
}

void des::set_key(const std::string& key)
{
    this->key = char_to_bitset(key.c_str());
    generate_keys();
}

bool des::set_init_vector(const std::string &init_str)
{
    if (init_str.size() != 8)
        return false;

    init_vec = char_to_bitset(init_str.c_str());

    return true;
}

bitset<32> des::f(bitset<32> R, bitset<48> k)
{
    bitset<48> expandR;
    // The first step: extended replacement, 32 -> 48
    for(int i = 0; i < 48; ++i)
        expandR[47 - i] = R[32 - E[i]];
    // Step 2: XOR
    expandR = expandR ^ k;
    // Step 3: Find the S_BOX replacement table
    bitset<32> output;
    int x = 0;
    for(int i = 0; i < 48; i += 6)
    {
        int row = expandR[47 - i] * 2 + expandR[47 - i - 5];
        int col = expandR[47 - i - 1] * 8 + expandR[47 - i - 2] * 4 + expandR[47 - i - 3] * 2 + expandR[47 - i - 4];
        int num = S_BOX[i / 6][row][col];
        bitset<4> binary(num);
        output[31-x] = binary[3];
        output[31-x-1] = binary[2];
        output[31-x-2] = binary[1];
        output[31-x-3] = binary[0];
        x += 4;
    }
    // The fourth step: P-replacement, 32 -> 32
    bitset<32> tmp = output;
    for(int i = 0; i < 32; ++i)
        output[31 - i] = tmp[32 - P[i]];

    return output;
}
/**
* Shift left and right of 56-bit key
*/
bitset<28> des::left_shift(bitset<28> k, int shift)
{
    bitset<28> tmp = k;
    for(int i=27; i>=0; --i)
    {
        if(i-shift<0)
            k[i] = tmp[i-shift+28];
        else
            k[i] = tmp[i-shift];
    }
    return k;
}
/**
* Generate 16 48-bit sub_keys
*/
void des::generate_keys()
{
    bitset<56> real_key;
    bitset<28> left;
    bitset<28> right;
    bitset<48> compress_key;
    // Remove the parity bit and change the 64-bit key to 56 bits
    for (int i = 0; i < 56; ++i)
        real_key[55 - i] = key[64 - PC_1[i]];
    // Generate sub_keys and save in sub_keys[16]
    for(int round = 0; round < 16; ++round)
    {
        // Top 28 and bottom 28
        for(int i = 28; i < 56; ++i)
            left[i - 28] = real_key[i];
        for(int i = 0; i < 28; ++i)
            right[i] = real_key[i];
        // shift left
        left = left_shift(left, shift_bits[round]);
        right = left_shift(right, shift_bits[round]);
        // Compression replacement, get 48-bit sub_key from 56-bit
        for(int i = 28; i < 56; ++i)
            real_key[i] = left[i - 28];
        for(int i = 0; i < 28; ++i)
            real_key[i] = right[i];
        for(int i = 0; i < 48; ++i)
            compress_key[47 - i] = real_key[56 - PC_2[i]];
        sub_key[round] = compress_key;
    }
}
/**
* Tool function: Convert char character array to binary
*/
bitset<64> des::char_to_bitset(const char s[8])
{
    bitset<64> bits;
    for(int i = 0; i < 8; ++i)
        for(int j = 0; j < 8; ++j)
            bits[i * 8 + j] = ((s[i] >> j) & 1);

    return bits;
}
/**
* Tool function: Convert binary to string
*/
string des::bitset_to_string(const bitset<64>& bs)
{
    string s;

    char c(0);
    for (unsigned i = 0; i < 64; i++)
    {
        c += (bs[i] << (i % 8));
        if ((i % 8) == 7)
        {
            s.push_back(c);
            c = 0;
        }
    }

    return s;
}
/**
* DES encryption
*/
bitset<64> des::encrypt_block(bitset<64>& plain)
{
    bitset<64> cipher;
    bitset<64> current_bits;
    bitset<32> left;
    bitset<32> right;
    bitset<32> new_left;
    // Step 1: Initial replacement of IP
    for(int i = 0; i < 64; ++i)
        current_bits[63 - i] = plain[64 - IP[i]];
    // Step 2: Get Li and Ri
    for(int i = 32; i < 64; ++i)
        left[i - 32] = current_bits[i];
    for(int i = 0; i < 32; ++i)
        right[i] = current_bits[i];
    // Step 3: 16 iterations
    for(int round = 0; round < 16; ++round)
    {
        new_left = right;
        right = left ^ f(right,sub_key[round]);
        left = new_left;
    }
    // The fourth step: merge L16 and R16, pay attention to merge into R16L16
    for(int i = 0; i < 32; ++i)
        cipher[i] = left[i];
    for(int i = 32; i < 64; ++i)
        cipher[i] = right[i - 32];
    // Step 5: Replace IP-1 at the end
    current_bits = cipher;
    for(int i = 0; i < 64; ++i)
        cipher[63 - i] = current_bits[64 - IP_1[i]];

    // return ciphertext
    return cipher;
}
/**
* DES decryption
*/
bitset<64> des::decrypt_block(bitset<64>& cipher)
{
    bitset<64> plain;
    bitset<64> current_bits;
    bitset<32> left;
    bitset<32> right;
    bitset<32> new_left;
    // Step 1: Initial replacement of IP
    for(int i = 0; i < 64; ++i)
        current_bits[63 - i] = cipher[64 - IP[i]];
    // Step 2: Get Li and Ri
    for(int i = 32; i < 64; ++i)
        left[i - 32] = current_bits[i];
    for(int i = 0; i < 32; ++i)
        right[i] = current_bits[i];
    // The third step: a total of 16 rounds of iteration (sub_key application in reverse order)
    for(int round = 0; round < 16; ++round)
    {
        new_left = right;
        right = left ^ f(right, sub_key[15 - round]);
        left = new_left;
    }
    // The fourth step: merge L16 and R16, pay attention to merge into R16L16
    for(int i = 0; i < 32; ++i)
        plain[i] = left[i];
    for(int i = 32; i < 64; ++i)
        plain[i] = right[i - 32];
    // Step 5: Replace IP-1 at the end
    current_bits = plain;
    for(int i = 0; i < 64; ++i)
        plain[63 - i] = current_bits[64 - IP_1[i]];

    // return to plaintext
    return plain;
}


string des::encrypt(const string& mes, int mode)
{
    switch (mode)
    {
    case des::ECB:
    {
        return encrypt_ECB(mes);
    }
    case des::CFB:
    {
        return encrypt_CFB(mes);
    }
    default:
        return "";
    }
}

string des::decrypt(const string& crp, int mode)
{
    switch (mode)
    {
    case des::ECB:
    {
        return decrypt_ECB(crp);
    }
    case des::CFB:
    {
        return decrypt_CFB(crp);
    }
    default:
        return "";
    }
}

string des::encrypt_ECB(const std::string& mes)
{
    auto blocks = split_string_for64(mes);
    string crp;
    for (auto& block : blocks)
        crp += bitset_to_string(encrypt_block(block));

    return crp;
}

string des::decrypt_ECB(const std::string& crp)
{
    auto blocks = split_string_for64(crp);
    string msg;
    for (auto& block : blocks)
        msg += bitset_to_string(decrypt_block(block));

    return msg;
}

list<bitset<64> > des::split_string_for64(const string &str)
{
    list<bitset<64> > blocks;
    char cstr[8] = "\0\0\0\0\0\0\0";
    unsigned i = 0;
    for (const auto& c : str)
    {
        cstr[i % 8] = c;
        if ((i % 8) == 7)
        {
            blocks.push_back(char_to_bitset(cstr));
            cstr[0] = '\0'; cstr[1] = '\0'; cstr[2] = '\0'; cstr[3] = '\0';
            cstr[4] = '\0'; cstr[5] = '\0'; cstr[6] = '\0'; cstr[7] = '\0';
        }
        i++;
    }

    if ((i % 8) != 0)
    {
        blocks.push_back(char_to_bitset(cstr));
    }

    return blocks;
}

std::string des::encrypt_CFB(const std::string& mes)
{

}

std::string des::decrypt_CFB(const std::string& crp)
{

}
