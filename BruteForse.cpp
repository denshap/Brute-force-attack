#include <vector>
#include <fstream>
#include <iostream>

#include "BruteForce.h"
#include "openssl/sha.h"


# define MAX_PASS_LENGTH 4

Timer::Timer() {
    m_start = std::chrono::high_resolution_clock::now();
}

Timer::~Timer() {
    m_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<float> duration = m_end - m_start;
    std::cout << "time:" << duration.count() << std::endl;
}

void Permutations::GenPermutations(std::vector<Password>& collection) {
    mtx.lock();
    size_t max = collection.size();
    for (size_t j = 0; j < max && m_count != m_maxCount; ++j) {
        m_pos[0]++;
        m_count++;
        for (size_t i = 0; i < MAX_PASS_LENGTH; i++) {
            if (m_pos[i] == m_charSize) {
                m_pos[i] = 1;
                m_pos[i + 1]++;
            }
            collection[j].pass[i] = m_symbols[m_pos[i]];
        }
    }
    mtx.unlock();
    }

bool Permutations::CheckEnd() {
    return m_count == m_maxCount;
}

Permutations::Permutations() {
    for (size_t i = 0; i < MAX_PASS_LENGTH; i++) {
        size_t tmp1 = m_charSize - 1;
        for (size_t q = i; q; q--) {
            int tmp2 = m_charSize - 1;
            tmp1 *= tmp2;
        }
        m_maxCount += tmp1;
    }
};

void ReadFile(const char* filePath, std::vector<unsigned char>& buf)
{
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open())
    {
        throw std::runtime_error("Can not open file ");
    }
    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());
    fileStream.close();
}
void WriteFile(const char* filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}
size_t GenLen(const Password& password) {
    for (size_t i = MAX_PASS_LENGTH + 1; i != 0; i--) {
        if (password.pass[i] == '\0') {
            return i;
        }
    }
    return 0;
}
void PasswordToKey(Password& password)
{
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), NULL,
        password.pass, GenLen(password), 1, password.key, password.iv))
    {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}

bool DecryptAes(const Password& password, const std::vector<unsigned char>& chipherText, std::vector<unsigned char>& decrypText)
{
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, password.key, password.iv))
    {
        throw std::runtime_error("EncryptInit error");
    }
        int chipherTextSize = 0;
    if (!EVP_DecryptUpdate(ctx, &decrypText[0], &chipherTextSize, &chipherText[0], chipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
        int lastPartLen = 0;
    if (!EVP_DecryptFinal_ex(ctx, &decrypText[0] + chipherTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    chipherTextSize += lastPartLen;
    decrypText.resize(chipherTextSize);
    EVP_CIPHER_CTX_free(ctx);
    return true;
    }

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hashTmp)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);
    }

void Bruteforce(Permutations& Permutations, std::vector<unsigned char>& chipherText, const std::vector<unsigned char>& hash, char* filePath, bool* done) {

    int n = 0;
    std::vector<Password> collection(60000);
    std::vector<unsigned char> decrypText(chipherText.size() * 1.1);
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    while (*done != true) {
        Permutations.GenPermutations(collection);
        size_t  max = collection.size();
        for (size_t i = 0; i < max && !(*done); i++) {
            PasswordToKey(collection[i]);
            if (DecryptAes(collection[i], chipherText, decrypText)) {
                CalculateHash(decrypText, hashTmp);
                if (hashTmp == hash) {
                    std::cout << std::endl << collection[i].pass << std::endl;
                    *done = true;
                    WriteFile(filePath, decrypText);
                }
            }
        }
        if (Permutations.CheckEnd()) {
            if (!*done) {
                std::cout << std::endl<< "Password not found" << std::endl;
            }
            *done = true;
        }
    }
}
