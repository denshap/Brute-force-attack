#pragma once

#include <vector>
#include <mutex>
#include "openssl/evp.h"


# define MAX_PASS_LENGTH 4

class Timer {
private:
    std::chrono::time_point<std::chrono::steady_clock> m_start, m_end;
public:
    Timer();
    ~Timer();
    };

struct Password {
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char pass[MAX_PASS_LENGTH + 1];
};

class Permutations {
private:
    static const size_t m_charSize = 37;
    const unsigned  char m_symbols[m_charSize + 1] = "\0abcdefghijklmnopqrstuvwxyz0123456789";
    size_t m_pos[MAX_PASS_LENGTH] = {0};
    size_t m_count = 1;
    size_t m_maxCount = 0;
    std::mutex mtx;
public:
    Permutations();
    void GenPermutations(std::vector<Password>& collection);
    bool CheckEnd();
    ~Permutations() {}
};

void ReadFile(const char* filePath, std::vector<unsigned char>& buf);
void WriteFile(const char* filePath, const std::vector<unsigned char>& buf);
size_t GenLen(const Password& password);
void PasswordToKey(Password& password);
bool DecryptAes(const Password& password, const std::vector<unsigned char>& chipherText, std::vector<unsigned char>& decrypText);
void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hashTmp);
void Bruteforce(Permutations& Permutations, std::vector<unsigned char>& chipherText, const std::vector<unsigned char>& hash, char* filePath, bool* done);
