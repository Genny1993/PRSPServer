#pragma once

#include <string>
#include <cctype>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/sha.h>
#include "database.h"

bool validatePassword(const std::string& p) {
    if (p.length() < 8 || p.length() > 30) return false;
    
    bool lower = false, upper = false, digit = false, special = false;
    for (char c : p) {
        lower = lower || std::islower(c);
        upper = upper || std::isupper(c);
        digit = digit || std::isdigit(c);
        special = special || std::ispunct(c) || c == ' ';
    }
    return lower && upper && digit && special;
}

bool validatePseudonym(const std::string& p) {
    if (p.length() < 6 || p.length() > 50) return false;
    return true;
}

bool verifyPassword(const std::string& pwd, const std::string& storedHash) {
    // Извлекаем соль из сохранённого хеша
    size_t pos = storedHash.find(':');
    if (pos == std::string::npos) return false;
    
    std::string salt = storedHash.substr(0, pos);
    std::string originalHash = storedHash.substr(pos + 1);
    
    // Хешируем введённый пароль с той же солью
    std::string salted = pwd + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)salted.c_str(), salted.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    
    // Сравниваем хеши
    return ss.str() == originalHash;
}

bool verifyAuth(uWS::WebSocket<false, true, std::nullptr_t>* ws, long long int uin, const std::string& token) {
    if(WsServer::authKeys.find(uin) != WsServer::authKeys.end()) {
        if(WsServer::authKeys[uin]["auth_key"] == token && WsServer::authKeys[uin]["is_active"] == "1") {
            return true;
        } else {
            return false;
        }
    } else {
        if (Database::prepareStatement("SELECT password_hash, auth_token, aes_encryption_key, roles, is_active, pseudonym, status FROM users WHERE UIN = ? AND is_active = ?")) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                uin,
                true
            };
            json verifyUser = Database::executeSelect(params);

            if(verifyUser.empty()) {
                return false;
            } else {
                if(verifyUser[0]["auth_token"] == token && verifyUser[0]["is_active"] == "1") {
                    WsServer::addSocket(ws, token, verifyUser[0]["roles"], verifyUser[0]["aes_encryption_key"], verifyUser[0]["is_active"], uin, verifyUser[0]["pseudonym"], verifyUser[0]["status"]);
                    return true;
                } else {
                    return false;
                }
            }
       
        } else {
            return false;
        }
    }
    return false;
}

bool verifyRole(uWS::WebSocket<false, true, std::nullptr_t>* ws, long long int uin, const std::vector<std::string>& roles) {
    
    if(WsServer::authKeys.find(uin) != WsServer::authKeys.end()) {
        json parsedJson = json::parse(WsServer::authKeys[uin]["roles"]);
        // Проходим по всем ключам из вектора
        for (const auto& role : roles) {
            // Перебираем элементы массива
            for (const auto& element : parsedJson) {
                
                if (element.is_string() && element.get<std::string>() == role) {
                    return true;
                }
            }
        }
        return false;  // Ни один ключ не найден
    } else {
        if (Database::prepareStatement("SELECT password_hash, auth_token, aes_encryption_key, roles, is_active, pseudonym, status FROM users WHERE UIN = ? AND is_active = ?")) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                uin,
                true
            };
            json verifyUser = Database::executeSelect(params);

            if(verifyUser.empty()) {
                return false;
            } else {
                json parsedJson = json::parse(WsServer::authKeys[uin]["roles"]);
                for (const auto& role : roles) {
                
                // Перебираем элементы массива
                for (const auto& element : parsedJson) {
                    if (element.is_string() && element.get<std::string>() == role) {
                        WsServer::addSocket(ws, verifyUser[0]["auth_token"], verifyUser[0]["roles"], verifyUser[0]["aes_encryption_key"], verifyUser[0]["is_active"], uin, verifyUser[0]["pseudonym"], verifyUser[0]["status"]);
                        return true;
                    }
                }
            }
                return false;  // Ни один ключ не найден
        }
       
        } else {
            return false;
        }
    }
    return false;
}

bool validatePasswordEnv(uWS::WebSocket<false, true, std::nullptr_t>* ws, const std::string& p, std::string_view func_name) {
    if(!validatePassword(p)) {
        json j = json{
            {"action", func_name},
            {"message", "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол" << std::endl;
        return false;
    }
    return true;
}

bool validatePseudonymEnv(uWS::WebSocket<false, true, std::nullptr_t>* ws, const std::string& p, std::string_view func_name) {
    if(!validatePseudonym(p)) {
        json j = json{
            {"action", func_name},
            {"message", "Отображаемое имя должно содержать не менее 6 символов и не более 50"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Отображаемое имя должно содержать не менее 1 символа и не более 50" << std::endl;
        return false;
    }
    return true;
}

bool VerifyAuthEnv(uWS::WebSocket<false, true, std::nullptr_t>* ws, long long int uin, const std::string& ak, std::string_view func_name) {
    if(!verifyAuth(ws, uin, ak)) {
        json j = json{
            {"action", func_name},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return false;
    }
    return true;
}

bool VerifyRoleEnv(uWS::WebSocket<false, true, std::nullptr_t>* ws, long long int uin, const std::vector<std::string>& roles, std::string_view func_name) {
    if(!verifyRole(ws, uin, roles))
    {
        json j = json{
            {"action", func_name},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return false;
    }
    return true;
}

bool VerifyPasswordEnv(uWS::WebSocket<false, true, std::nullptr_t>* ws, const std::string& p, const std::string& phash, std::string_view func_name) {
    if(!verifyPassword(p, phash)) {
        json j = json{
            {"action", func_name},
            {"message", "UIN или пароль неверный"},
        };
        Answer(ws, clientError, j);
        return false;
    }
    return true;
}