#pragma once
#include <bitset>
#include <string>
#include <list>
#include <optional>

class des
{
public:
    enum : int
    {
        ECB,    // Electro Code Book
        CFB     // Cipher Feed Back
    };
    des(const std::string& key);
    void set_key(const std::string& key);
    bool set_init_vector(const std::string& init_str);

    std::string encrypt(const std::string& mes, int mode = ECB);
    std::string decrypt(const std::string& crp, int mode = ECB);

private:
    // Cryptographic function f, receives 32-bit data and 48-bit subkey, and produces a 32-bit output
    std::bitset<32> f(std::bitset<32> R, std::bitset<48> k) const;

    // Shift left and right of 56-bit key
    std::bitset<28> left_shift(std::bitset<28> k, int shift);

    // Generate 16 48-bit subkeys
    void generate_keys();

    std::string encrypt_ECB(const std::string& mes);
    std::string decrypt_ECB(const std::string& crp);

    std::string encrypt_CFB(const std::string& mes);
    std::string decrypt_CFB(const std::string& crp);

public:
    // Tool functions:
    static std::bitset<64> char_to_bitset(const char s[8]);
    static std::string     bitset_to_string(const std::bitset<64>& bs);
    static std::list<std::bitset<64> > split_string_for64(const std::string &str);

protected:
    // DES encryption
    std::bitset<64> encrypt_block(const std::bitset<64>& plain) const;

    // DES decryption
    std::bitset<64> decrypt_block(const std::bitset<64>& cipher) const;

private:
    std::bitset<64> key; // 64-bit key
    std::bitset<48> sub_key[16]; // Store the 16-wheel key

    std::optional<std::bitset<64> > init_vec; // store init vector for CFB mode
};
