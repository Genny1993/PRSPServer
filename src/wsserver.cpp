#include <nlohmann/json.hpp>
#include "wsserver.h"
#include "routefunc.h"

std::unique_ptr<uWS::App> WsServer::app = nullptr;
std::unordered_map<long long int, uWS::WebSocket<false, true, std::nullptr_t>*> WsServer::authorizedSockets;
std::unordered_map<long long int, std::unordered_map<std::string, std::string>> WsServer::authKeys;
std::mutex WsServer::socketsMutex;
bool WsServer::debug = false;

    void WsServer::setDebug(bool val) {
            debug = val;
        }

    /**
     * Добавление нового сокета в список активных соединений
     */
    void WsServer::addSocket(uWS::WebSocket<false, true, std::nullptr_t>* ws, std::string auth_key, std::string roles, std::string aes, std::string is_active, long long int uin, std::string pseudonym, std::string status) {
        std::lock_guard<std::mutex> lock(socketsMutex);
        authorizedSockets[uin] = ws;
        authKeys[uin] = {
            {"auth_key", auth_key},
            {"roles", roles},
            {"aes", aes},
            {"is_active", is_active},
            {"pseudonym", pseudonym},
            {"status", status}
        };

        if(debug) {
            std::cout << "📊 Total connected clients: " << authorizedSockets.size() << std::endl;
        }

        json pack = json{
            {"UIN", uin},
            {"auth_key", auth_key}
        };
        BroadcastOnline(ws, pack);
    }

    /**
     * Удаление сокета из списка активных соединений
     */
    void WsServer::removeSocket(uWS::WebSocket<false, true, std::nullptr_t>* ws) {
        std::lock_guard<std::mutex> lock(socketsMutex);
        
        // Ищем по значению (WebSocket*)
        for (auto it = authorizedSockets.begin(); it != authorizedSockets.end(); ++it) {
            if (it->second == ws) {
                nlohmann::json pack = nlohmann::json{
                    {"UIN", it->first},
                    {"auth_key", WsServer::authKeys[it->first]["auth_key"]}
                };
                BroadcastOffline(ws, pack);
                authKeys.erase(it->first);
                authorizedSockets.erase(it);
                if (debug) {
                    std::cout << "📊 Total connected clients: " << authorizedSockets.size() << std::endl;
                }
                return;
            }
        }
    }

    void WsServer::init() {
        // Создаем приложение через new (unique_ptr)
        app = std::make_unique<uWS::App>();
        
        // Настраиваем WebSocket с правильными типами
        app->ws<std::nullptr_t>("/*", {
            .idleTimeout = 10, // Если 10 секунд нет сообщений и подтверждений Ping — сокет закроется

            // Сервер решает, когда отправить Ping
            .sendPingsAutomatically = true,

            // Обработчик открытия соединения
            .open = [](WebSocketType* ws) {
                if(debug) {
                    std::cout << "🌐 Клиент подключен" << std::endl;
                }
                // Отправляем приветствие только новому клиенту
                std::string jstr = hideKeyInJson(hideKey(Conf::getMasterKey()));
                json j = json::parse(jstr);

                nlohmann::json answer = {
                    {"status", ok},
                    {"pack", j }
                };

                std::string sanswer = answer.dump();
                bool result = ws->send(sanswer, uWS::OpCode::TEXT);
                if(!result) {
                    ws->close();
                }
                return;
            },
            
            // Обработчик входящих сообщений
            .message = [](WebSocketType* ws, std::string_view message, uWS::OpCode opCode) {
                (void)opCode;
                
                if(debug) {
                    // Выводим полученное сообщение в консоль
                    std::cout << "📨 Получено: " << message << std::endl;
                }
                
                //Парсим JSON
                try {
                    nlohmann::json json = nlohmann::json::parse(decryptAES(std::string(message), Conf::getMasterKeyBin()));

                    if(!json.contains("func")) {
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", "Нет определения функции func"},
                        };
                        Answer(ws, clientError, j);
                        if(debug) {
                            std::cerr << "Нет определения функции func" << std::endl;
                        }
                        return;
                    }
                    if(!json.contains("pack")) {
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", "Нет передаваемого пакета данных pack"},
                        };
                        Answer(ws, clientError, j);
                        if(debug) {
                            std::cerr << "Нет передаваемого пакета данных pack" << std::endl;
                        }
                        return;
                    }

                    //Отдаем в роутер
                    try {
                        Router(ws, message, json["func"],  json["pack"]);
                    } catch (const nlohmann::json::exception& e) {
                        // Ошибки JSON библиотеки
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("JSON exception: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                    } catch (const std::invalid_argument& e) {
                        // Ошибки stoi, stoll и др.
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("Invalid argument: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                    } catch (const std::out_of_range& e) {
                        // Выход за пределы (stoi, stoll)
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("Out of range: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                    } catch (const std::length_error& e) {
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("Length error: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                    } catch (const std::runtime_error& e) {
                        // Ошибки времени выполнения (MariaDB, UWebSockets)
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("Runtime error: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                    } catch (const std::logic_error& e) {
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("Logic error: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                    } catch (const std::bad_alloc& e) {
                        // Нехватка памяти
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("Bad allocation: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                        // Критическая ошибка, может потребоваться перезапуск
                        std::terminate();
                    } catch (const std::exception& e) {
                        // Любые другие std::exception
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("Unknown std::exception: ") + e.what()},
                        };
                        Answer(ws, serverError, j);
                    } catch (const char* e) {
                        // Обработка C-style ошибок
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", std::string("C-string error: ") + e},
                        };
                        Answer(ws, serverError, j);
                    } catch (int e) {
                        // Обработка integer ошибок
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", "Integer error code: " + std::to_string(e)},
                        };
                        Answer(ws, serverError, j);
                    } catch (const std::string& e) {
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", "String error: " + e},
                        };
                    } catch (...) {
                        // Любая неизвестная ошибка
                        nlohmann::json j = nlohmann::json {
                            {"action", "startpoint"},
                            {"message", "Unknown exception (non-standard)"},
                        };
                    }
                    return;

                } catch (const nlohmann::json::parse_error& e) {
                    // Логируем ошибку, чтобы знать, что прислал клиент
                    if(debug) {
                        std::cerr << "Ошибка парсинга JSON: " << e.what() << std::endl;
                    }
                    // Сервер продолжает работу!
                    nlohmann::json j = nlohmann::json {
                        {"action", "startpoint"},
                        {"message", "Неверный JSON"},
                    };
                    Answer(ws, clientError, j);
                    return;
                }
                return;
            },
            
            // Обработчик закрытия соединения
            .close = [](WebSocketType* ws, int code, std::string_view message) {
                
                removeSocket(ws);
                
                if(debug) {
                    std::cout << "🔌 Клиент отключился. Код: " << code 
                              << " Сообщение: " << message << std::endl;
                }
                return;
            }
        });
    }

    void WsServer::run() {
        if (!app) {
            std::cout << "❌ Сервер не инициализирован. Вызовите init() сначала!" << std::endl;
            return;
        }
        
        // Запуск прослушивания порта
        app->listen(Conf::getServicePort(), [](auto* listenSocket) {
            if (listenSocket) {
                std::cout << "✅ Сервер прослушивает порт " + std::to_string(Conf::getServicePort()) 
                          << " (ws://localhost:" + std::to_string(Conf::getServicePort()) + ")" << std::endl;
                std::cout << "🛑 Нажмите Ctrl+C для остановки" << std::endl;
                std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
                std::cout << "✨ Готово к приему подключений" << std::endl;
            } else {
                std::cout << "❌ проблема с прослушиванием порта " + std::to_string(Conf::getServicePort()) << std::endl;
            }
        });
    
        // Запуск событийного цикла
        app->run();
    }


    void WsServer::wsClose(WebSocketType* ws) {
        if (ws) {
            ws->close();
        }
    }
    
    // Для остановки сервера (опционально)
    void WsServer::stop() {
        if (app) {
            // В uWS нет прямого метода stop, нужно выйти из run()
            // Обычно это делается через сигналы
            std::cout << "🛑 Остановка сервера..." << std::endl;
        }
    }