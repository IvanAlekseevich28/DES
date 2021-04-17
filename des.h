#pragma once
#include <memory.h>
#include <string.h>


class des
{
public:
    enum
    {
        ENCRYPT,
        DECRYPT
    };
    des();
//    void DES(char Out[8], char In[8], const PSubKey pSubKey, bool Type);//Standard DES encryption/decryption
private:
    void DES(char Out[8], char In[8], const PSubKey pSubKey, bool Type);//Standard DES encryption/decryption
    void SetKey(const char* Key, int len);// Set the key
    void SetSubKey(PSubKey pSubKey, const char Key[8]);// Set the subkey
    void F_func(bool In[32], const bool Ki[48]);// f function
    void S_func(bool Out[32], const bool In[48]);// S box instead
    void Transform(bool *Out, bool *In, const char *Table, int len);// Transform
    void Xor(bool *InA, const bool *InB, int len);// Xor
    void RotateL(bool *In, int len, int loop);// rotate left
    void ByteToBit(bool *Out, const char *In, int bits);// Byte group is converted to bit group
    void BitToByte(char *Out, const bool *In, int bits);// Bit group is converted to byte group
};
