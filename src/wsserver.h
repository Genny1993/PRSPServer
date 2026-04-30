#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <iostream>
#include <memory>
#include <App.h>
#include "conf.h"

// Тип для WebSocket с nullptr_t в качестве UserData
using WebSocketType = uWS::WebSocket<false, true, std::nullptr_t>;

class WsServer {
private:
    // Запрещаем создание экземпляров - только один конструктор delete
    WsServer() = delete;
    WsServer(const WsServer&) = delete;
    WsServer& operator=(const WsServer&) = delete;
    
    // Статические переменные - нужно объявить, но определить в .cpp
    static std::unique_ptr<uWS::App> app;  // Используем unique_ptr вместо прямого объявления
    static std::mutex socketsMutex;
    static bool debug;

public:

    static std::unordered_map<long long int, WebSocketType*> authorizedSockets;
    static std::unordered_map<long long int, std::unordered_map<std::string, std::string>> authKeys;

    static void addSocket(uWS::WebSocket<false, true, std::nullptr_t>* ws, std::string auth_key, std::string roles, std::string aes, std::string is_active, long long int uin, std::string pseudonym, std::string status);

    static void removeSocket(uWS::WebSocket<false, true, std::nullptr_t>* ws);
    //Режим отладки
    static void setDebug(bool val);

    //Инициализация
    static void init();

    //Запуск сервера
    static void run();

    //Закрытие сокета
    static void wsClose(WebSocketType* ws);
    
    // Для остановки сервера (опционально)
    static void stop();
};