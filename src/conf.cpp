#include "conf.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <codecvt>
#include <locale>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

std::string Conf::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, last - first + 1);
}

void Conf::setValue(const std::string& key, const std::string& value) {
    if (key == "dbhost") {
        dbhost = value;
    } else if (key == "dbport") {
        try {
            dbport = std::stoi(value);
        } catch (...) {
            std::cerr << "⚠️ Неверное значение dbport (необходимы только цифры): " << value << std::endl;
        }
    } else if (key == "dbname") {
        dbname = value;
    } else if (key == "dbuser") {
        dbuser = value;
    } else if (key == "dbpassword") {
        dbpassword = value;
    } else if (key == "serviceport") {
        try {
            serviceport = std::stoi(value);
        } catch (...) {
            std::cerr << "⚠️ Неверное значение serviceport (необходимы только цифры): " << value << std::endl;
        }
    } else if(key == "debug") {
        if(value == "true") {
            debug = true;
        }
        else if(value == "false") {
            debug = false;
        }
        else {
            std::cerr << "⚠️ Неверное значение debud (необходимы только значения true, false): " << value << std::endl;
        }
    } else if(key == "masterkey") {
        master_key = value;

        std::string clean = value;
        clean.erase(std::remove_if(clean.begin(), clean.end(), ::isspace), clean.end());
    
        BIO *bio = BIO_new_mem_buf(clean.data(), clean.size());
        BIO *b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
        std::vector<unsigned char> result(clean.size());
        int len = BIO_read(bio, result.data(), result.size());
        BIO_free_all(bio);
    
        if (len <= 0) {
            throw std::runtime_error("Base64 decode failed");
        }
    
        result.resize(len);
        master_key_bin = result;
    } else if(key == "freereg") {
        if(value == "true") {
            freereg = true;
        }
        else if(value == "false") {
            freereg = false;
        }
        else {
            std::cerr << "⚠️ Неверное значение freereg (необходимы только значения true, false): " << value << std::endl;
        }
    } else if(key == "privatemessages") {
        if(value == "true") {
            privatemessages = true;
        }
        else if(value == "false") {
            privatemessages = false;
        }
        else {
            std::cerr << "⚠️ Неверное значение privatemessages (необходимы только значения true, false): " << value << std::endl;
        }
    }
}

void Conf::parseLine(const std::string& line) {
    size_t eq_pos = line.find('=');
    if (eq_pos != std::string::npos) {
        std::string key = trim(line.substr(0, eq_pos));
        std::string value = trim(line.substr(eq_pos + 1));
        setValue(key, value);
    }
}

bool Conf::loadFromFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(mutex);
    
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "❌ Не получается открыть файл настроек: " << filename << std::endl;
        return false;
    }
    
    // Для UTF-8 файлов читаем как обычный байтовый поток
    std::string line;
    while (std::getline(file, line)) {
        // Пропускаем пустые строки и комментарии
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        parseLine(line);
    }
    
    file.close();
    is_loaded = true;
    
    // Проверка обязательных полей
    if (dbname.empty() || dbuser.empty() || dbpassword.empty()) {
        std::cerr << "⚠️ Внимание: Не все необходимые поля имеются в настройках!" << std::endl;
        return false;
    }
    
    return true;
}

void Conf::printAll() {
    std::lock_guard<std::mutex> lock(mutex);
    std::cout << "\nКОНФИГУРАЦИЯ СЕРВЕРА" << std::endl;
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
    std::cout << "🖥️  Database Host: " << dbhost << std::endl;
    std::cout << "🔌 Database Port: " << dbport << std::endl;
    std::cout << "🗄️  Database Name: " << dbname << std::endl;
    std::cout << "👤 Database User: " << dbuser << std::endl;
    std::cout << "🔐 Database Password: " << std::string(dbpassword.length(), '*') << std::endl;
    std::cout << "🌐 Service Port: " << serviceport << std::endl;
    std::cout << "🔐 Master Key: " << master_key << std::endl;
    std::cout << "🔐 Free Registration: " << (freereg ? "true" : "false") << std::endl;
    std::cout << "💬 Private Messages: " << (privatemessages ? "true" : "false") << std::endl;
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" << std::endl;
}