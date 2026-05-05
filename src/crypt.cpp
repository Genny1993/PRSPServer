#include "crypt.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <iostream>

// Глобальные генераторы случайных чисел (объявлены как static, чтобы были видны только в этом файле)
static std::random_device rd;
static std::mt19937 gen(rd());

std::string generateAES() {
    unsigned char key[32];
    
    // Генерируем случайные байты
    if (RAND_bytes(key, sizeof(key)) != 1) {
        throw std::runtime_error("Ошибка генерации ключа");
    }
    
    // Кодируем в base64
    size_t b64_len = ((sizeof(key) + 2) / 3) * 4 + 1;
    char* b64 = new char[b64_len];
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64), key, sizeof(key));
    
    std::string result(b64);
    delete[] b64;
    return result;
}

std::string encryptAES(const std::string& plaintext, const std::vector<unsigned char>& key) {
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");
    
    // Генерируем случайный IV (16 байт)
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) throw std::runtime_error("IV generation failed");
    
    // Контекст шифрования
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv);
    
    // Буфер для зашифрованных данных (с запасом на паддинг)
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int out_len = 0, tmp_len = 0;
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                      reinterpret_cast<const unsigned char*>(plaintext.data()),
                      plaintext.size());
    
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &tmp_len);
    out_len += tmp_len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    ciphertext.resize(out_len);
    
    // Результат: IV + шифротекст
    std::vector<unsigned char> result;
    result.reserve(sizeof(iv) + ciphertext.size());
    result.insert(result.end(), iv, iv + sizeof(iv));
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    
    // Возвращаем как строку (сырые байты)
    return std::string(result.begin(), result.end());
}

std::string decryptAES(const std::string& encrypted, const std::vector<unsigned char>& key) {
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");
    if (encrypted.size() < 16) throw std::runtime_error("Data too short (no IV)");
    
    // Преобразуем входную строку в вектор байтов для удобства
    const std::vector<unsigned char> encrypted_data(encrypted.begin(), encrypted.end());
    
    // Извлекаем IV (первые 16 байт)
    const unsigned char* iv = encrypted_data.data();
    const unsigned char* ciphertext = encrypted_data.data() + 16;
    size_t ciphertext_len = encrypted_data.size() - 16;
    
    // Контекст расшифровки
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv);
    
    std::vector<unsigned char> plaintext(ciphertext_len);
    int out_len = 0, tmp_len = 0;
    
    EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                      ciphertext, ciphertext_len);
    
    EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &tmp_len);
    out_len += tmp_len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    plaintext.resize(out_len);
    
    // Возвращаем как строку UTF-8
    return std::string(plaintext.begin(), plaintext.end());
}

std::string hideKey(const std::string& key) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned seed = std::chrono::steady_clock::now().time_since_epoch().count();
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dis(0, 63);
    
    std::string header(8, ' ');
    for (int i = 0; i < 8; ++i) {
        header[i] = base64_chars[dis(gen)];
    }
    
    int shift = 0;
    for (int i = 0; i < 8; ++i) {
        shift += (unsigned char)header[i];
    }
    shift = shift % 26 + 1;
    
    // Сдвигаем каждый символ ключа
    std::string shifted;
    for (size_t i = 0; i < key.length(); ++i) {
        char c = key[i];
        int pos = -1;
        for (int j = 0; j < 64; ++j) {
            if (base64_chars[j] == c) {
                pos = j;
                break;
            }
        }
        if (pos != -1) {
            shifted += base64_chars[(pos + shift) % 64];
        } else {
            shifted += c;
        }
    }
    
    // Количество мусора зависит от header
    int garbage_count = 5 + (shift % 10);
    
    // Генерируем мусорные символы и позиции на основе header
    std::string garbage_chars;
    std::vector<int> positions;
    for (int i = 0; i < garbage_count; ++i) {
        garbage_chars += base64_chars[((unsigned char)header[i % 8] + i) % 64];
        positions.push_back(((unsigned char)header[i % 8] + i * shift) % (shifted.length() + 1));
    }
    std::sort(positions.begin(), positions.end());
    
    // Вставляем мусор в сдвинутую строку
    std::string result = shifted;
    for (int i = 0; i < garbage_count; ++i) {
        int pos = positions[i];
        if (pos > (int)result.length()) pos = result.length();
        result.insert(result.begin() + pos, garbage_chars[i]);
    }
    
    return header + result;
}

std::string extractKey(const std::string& obfuscated) {
    if (obfuscated.length() < 9) {
        throw std::invalid_argument("Invalid obfuscated string");
    }
    
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string header = obfuscated.substr(0, 8);
    std::string with_garbage = obfuscated.substr(8);
    
    int shift = 0;
    for (int i = 0; i < 8; ++i) {
        shift += (unsigned char)header[i];
    }
    shift = shift % 26 + 1;
    
    int garbage_count = 5 + (shift % 10);
    
    // Восстанавливаем позиции мусора (те же самые, что и при обфускации)
    std::vector<int> positions;
    for (int i = 0; i < garbage_count; ++i) {
        // Вычисляем длину строки ДО вставки мусора
        int original_len = with_garbage.length() - garbage_count;
        positions.push_back(((unsigned char)header[i % 8] + i * shift) % (original_len + 1));
    }
    std::sort(positions.begin(), positions.end());
    
    // Удаляем мусорные символы (с конца, чтобы не смещать индексы)
    std::string shifted = with_garbage;
    for (int i = garbage_count - 1; i >= 0; --i) {
        int pos = positions[i];
        if (pos >= 0 && pos < (int)shifted.length()) {
            shifted.erase(shifted.begin() + pos);
        }
    }
    
    // Обратный сдвиг
    std::string result;
    for (size_t i = 0; i < shifted.length(); ++i) {
        char c = shifted[i];
        int pos = -1;
        for (int j = 0; j < 64; ++j) {
            if (base64_chars[j] == c) {
                pos = j;
                break;
            }
        }
        if (pos != -1) {
            int new_pos = pos - shift;
            if (new_pos < 0) new_pos += 64;
            result += base64_chars[new_pos];
        } else {
            result += c;
        }
    }
    
    return result;
}

std::string hideKeyInJson(const std::string& obfuscatedKey) {
    unsigned seed = std::chrono::steady_clock::now().time_since_epoch().count();
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dis(1000, 9999);
    std::uniform_int_distribution<> dis_bool(0, 1);
    
    // Раскидываем строку на 4 части с правильными индексами
    size_t len = obfuscatedKey.length();
    size_t part1_len = len / 4;
    size_t part2_len = len / 4;
    size_t part3_len = len / 4;
    size_t part4_len = len - part1_len - part2_len - part3_len;
    
    std::string p1 = obfuscatedKey.substr(0, part1_len);
    std::string p2 = obfuscatedKey.substr(part1_len, part2_len);
    std::string p3 = obfuscatedKey.substr(part1_len + part2_len, part3_len);
    std::string p4 = obfuscatedKey.substr(part1_len + part2_len + part3_len, part4_len);
    
    // Создаём невинный JSON со случайными полями
    std::string json = "{";
    json += "\"user_id\":" + std::to_string(dis(gen)) + ",";
    json += "\"session\":\"" + std::to_string(dis(gen)) + "\",";
    
    // Раскидываем части строки по разным полям
    json += "\"first_name\":\"" + p1 + "\",";
    json += "\"last_name\":\"" + p2 + "\",";
    json += "\"comment\":\"" + p3 + "\",";
    json += "\"note\":\"" + p4 + "\",";
    
    // Добавляем случайные поля для маскировки
    json += "\"timestamp\":" + std::to_string(seed / 1000000) + ",";
    json += "\"flag\":" + std::string(dis_bool(gen) ? "true" : "false") + ",";
    json += "\"code\":" + std::to_string(dis(gen));
    json += "}";
    
    return json;
}

std::string extractKeyFromJson(const std::string& json) {
    // Ищем каждое поле и извлекаем значение
    std::string parts[4];
    const char* field_names[] = {"first_name", "last_name", "comment", "note"};
    
    for (int i = 0; i < 4; ++i) {
        std::string pattern = "\"" + std::string(field_names[i]) + "\":\"";
        size_t start = json.find(pattern);
        if (start == std::string::npos) {
            throw std::runtime_error("Field not found: " + std::string(field_names[i]));
        }
        start += pattern.length();
        
        size_t end = json.find("\"", start);
        if (end == std::string::npos) {
            throw std::runtime_error("Invalid field value");
        }
        
        parts[i] = json.substr(start, end - start);
    }
    
    // Склеиваем обратно
    return parts[0] + parts[1] + parts[2] + parts[3];
}