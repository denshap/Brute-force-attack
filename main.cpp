#include <vector>
#include <exception>
#include <iostream>

#include "BruteForce.h"
#include "openssl/sha.h"

# define THREADS_COUNT 8

int main(int argc, char* argv[])
{
    if (argc!=2 )
    {
       std::cout << "Invalid arguments" << std::endl;
       return -1;
    }
    Timer on;
    OpenSSL_add_all_digests();
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }
    bool done = false;
    std::vector<unsigned char> chipherText;
    ReadFile(argv[1], chipherText);
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    std::move(std::next(chipherText.end(), -SHA256_DIGEST_LENGTH), chipherText.end(), hash.begin());
    chipherText.erase(std::next(chipherText.end(), -SHA256_DIGEST_LENGTH), chipherText.end());
    Permutations Permutations;
    std::vector<std::thread> threads(THREADS_COUNT);
    for (size_t i = 0; i < THREADS_COUNT; i++) {
        threads[i]= std::thread(Bruteforce, std::ref(Permutations), std::ref(chipherText), std::ref(hash), argv[1], &done);
    }
     try
    {
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
    for (size_t i = 0; i < THREADS_COUNT; i++) {
        threads[i].join();
    }
}