#ifndef CRYPT_H
#define CRYPT_H

#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>
#include <stdexcept>
#include <cstring>

// Длина блока AES в байтах (16 байт = 128 бит)
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

// Генерация AES ключа
std::string generateAES();

// Шифрование/дешифрование AES
std::string encryptAES(const std::string& plaintext, const std::vector<unsigned char>& key);
std::string decryptAES(const std::string& encrypted, const std::vector<unsigned char>& key);

//Функция обфускации
std::string hideKey(const std::string& key);
// Функция восстановления
std::string extractKey(const std::string& obfuscated);


std::string hideKeyInJson(const std::string& obfuscatedKey);
std::string extractKeyFromJson(const std::string& json);
#endif