#pragma once

#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string>
#include <chrono>
#include "database.h"
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <iostream>
#include "crypt.h"

std::string_view serverError = "SERVER_ERROR";
std::string_view clientError = "CLIENT_ERROR";
std::string_view ok = "OK";
std::string_view action = "CLIENT_ACTION";
std::string_view ping = "PING";

bool Answer(WebSocketType* ws, std::string_view status, const auto& pack) {
    nlohmann::json answer = {
            {"status", status},
            {"pack", pack }
        };

    std::string sanswer = answer.dump();
    sanswer = encryptAES(sanswer, Conf::getMasterKeyBin());
    bool result = ws->send(sanswer, uWS::OpCode::BINARY);
    if(!result) {
        ws->close();
    }
    return result;
}

//Рассылка всем контактам в онлайне
bool ContactsBroadcast(long long int uin, std::string_view status, const auto& pack) {

    nlohmann::json Contacts = nlohmann::json{};
    if (Database::prepareStatement("SELECT c.id, CASE WHEN c.initiator_uin = ? THEN c.destination_uin ELSE c.initiator_uin END AS UIN, CASE WHEN c.initiator_uin = ? THEN dest_user.pseudonym ELSE init_user.pseudonym END AS pseudonym, CASE WHEN c.initiator_uin = ? THEN 'initiator' ELSE 'destination' END AS my_role, CASE WHEN c.initiator_uin = ? THEN dest_user.status ELSE init_user.status END AS status, CASE WHEN c.initiator_uin = ? THEN dest_user.is_active ELSE init_user.is_active END AS is_active, c.is_approved FROM contacts c LEFT JOIN users init_user ON c.initiator_uin = init_user.UIN LEFT JOIN users dest_user ON c.destination_uin = dest_user.UIN WHERE (c.initiator_uin = ? OR c.destination_uin = ?) AND c.is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            uin,
            uin,
            uin,
            uin,
            uin,
            uin,
            true
        };

        Contacts = Database::executeSelect(params);

        for (auto& item : Contacts) {
            if (item.is_object()) {
                long long int c_uin = item["UIN"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    Answer(WsServer::authorizedSockets[c_uin], status, pack);
                }
            }
        }
    } else {
        return false;
    }

    return true;
}

std::string hashPassword(const std::string& pwd) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::string salt;
    const char* hex = "0123456789abcdef";
    for (int i = 0; i < 16; i++) salt += hex[dis(gen)];
    
    std::string salted = pwd + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)salted.c_str(), salted.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    
    return salt + ":" + ss.str();
}

std::string getTimestampNow() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string generateAuthToken(long long int uin) {
    // 1. Получаем текущее время в миллисекундах
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    // 2. Генерируем случайное число от 0 до 1000000
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1000000);
    int randomNum = dis(gen);
    
    // 3. Формируем строку для хеширования
    std::stringstream ss;
    ss << uin << ms << randomNum;
    std::string data = ss.str();
    
    // 4. SHA256 хеширование
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);
    
    // 5. Конвертируем хеш в hex строку
    std::stringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return result.str();
}

bool RequireField(WebSocketType* ws, const nlohmann::json& pack, std::string_view field, std::string_view func_name, std::string_view error_text) {
    if(!pack.contains(field)) {
        json j = json{
            {"action", func_name},
            {"message", error_text},
        };
        Answer(ws, clientError, j);
        std::cerr << error_text << std::endl;
        return false;
    }
    return true;
}

void ThrowSQLError(WebSocketType* ws, std::string_view func_name) {
    json j = json{
        {"action", func_name},
        {"message", "Ошибка при подготовке SQL-запроса"},
    };
    Answer(ws, serverError, j);
    std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
    return;
}

long long int getIntAnyway(nlohmann::json str) {
    if (str.is_number()) {
        return str.get<long long>();
    } else if (str.is_string()) {
        return std::stoll(str.get<std::string>());
    }
    return 0;
}
