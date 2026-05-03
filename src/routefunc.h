#pragma once

#include <string>
#include <stdexcept>
#include "helpers.h"
#include "validators.h"
#include "database.h"

void Router(WebSocketType* ws, std::string_view message, const std::string& method, const nlohmann::json& pack);

void Echo(WebSocketType* ws, std::string_view message, const nlohmann::json& pack);
void Register(WebSocketType* ws, const nlohmann::json& pack);
void Login(WebSocketType* ws, const nlohmann::json& pack);
void Logout(WebSocketType* ws, const nlohmann::json& pack);
void IsAdmin(WebSocketType* ws, const nlohmann::json& pack);
void ChangePassword(WebSocketType* ws, const nlohmann::json& pack);
void FindUsers(WebSocketType* ws, const nlohmann::json& pack);
void AddContact(WebSocketType* ws, const nlohmann::json& pack);
void AcceptContact(WebSocketType* ws, const nlohmann::json& pack);
void DeclineContact(WebSocketType* ws, const nlohmann::json& pack);
void UndoAddContact(WebSocketType* ws, const nlohmann::json& pack);
void RemoveContact(WebSocketType* ws, const nlohmann::json& pack);
void GetContacts(WebSocketType* ws, const nlohmann::json& pack);
void GetOutgoingRequests(WebSocketType* ws, const nlohmann::json& pack);
void GetIncomingRequests(WebSocketType* ws, const nlohmann::json& pack);
void BroadcastOnline(WebSocketType* ws, const nlohmann::json& pack);
void BroadcastOffline(WebSocketType* ws, const nlohmann::json& pack);
void ChangePseudonym(WebSocketType* ws, const nlohmann::json& pack);
void ChangeStatus(WebSocketType* ws, const nlohmann::json& pack);
void ChangeAES(WebSocketType* ws, const nlohmann::json& pack);
void ChangePasswordAdmin(WebSocketType* ws, const nlohmann::json& pack);
void ChangePseudonymAdmin(WebSocketType* ws, const nlohmann::json& pack);
void ChangeStatusAdmin(WebSocketType* ws, const nlohmann::json& pack);
void ChangeStatusAdmin(WebSocketType* ws, const nlohmann::json& pack);
void BanUserAdmin(WebSocketType* ws, const nlohmann::json& pack);
void UnbanUserAdmin(WebSocketType* ws, const nlohmann::json& pack);
void KickUserAdmin(WebSocketType* ws, const nlohmann::json& pack);
void ChangeRoleAdmin(WebSocketType* ws, const nlohmann::json& pack);

void Router(WebSocketType* ws, std::string_view message, const std::string& method, const nlohmann::json& pack) {
    if(method == "echo") { Echo(ws, message, pack); return; }
    if(method == "register") { Register(ws, pack); return; }
    if(method == "login") { Login(ws, pack); return; }
    if(method == "logout") { Logout(ws, pack); return; }
    if(method == "isAdmin") { IsAdmin(ws, pack); return; }
    if(method == "changePassword") { ChangePassword(ws, pack); return; }
    if(method == "findUsers") { FindUsers(ws, pack); return; }
    if(method == "addContact") { AddContact(ws, pack); return; }
    if(method == "acceptContact") { AcceptContact(ws, pack); return; }
    if(method == "declineContact") { DeclineContact(ws, pack); return; }
    if(method == "undoAddContact") { UndoAddContact(ws, pack); return; }
    if(method == "removeContact") { RemoveContact(ws, pack); return; }
    if(method == "getContacts") { GetContacts(ws, pack); return; }
    if(method == "getOutgoingRequests") { GetOutgoingRequests(ws, pack); return; }
    if(method == "getIncomingRequests") { GetIncomingRequests(ws, pack); return; }
    if(method == "broadcastOnline") { BroadcastOnline(ws, pack); return; }
    if(method == "broadcastOffline") { BroadcastOffline(ws, pack); return; }
    if(method == "changePseudonym") { ChangePseudonym(ws, pack); return; }
    if(method == "changeStatus") { ChangeStatus(ws, pack); return; }
    if(method == "changeAES") { ChangeAES(ws, pack); return; }
    if(method == "changePasswordAdmin") { ChangePasswordAdmin(ws, pack); return; }
    if(method == "changePseudonymAdmin") { ChangePseudonymAdmin(ws, pack); return; }
    if(method == "changeStatusAdmin") { ChangeStatusAdmin(ws, pack); return; }
    if(method == "banUserAdmin") { BanUserAdmin(ws, pack); return; }
    if(method == "unbanUserAdmin") { UnbanUserAdmin(ws, pack); return; }
    if(method == "kickUserAdmin") { KickUserAdmin(ws, pack); return; }
    if(method == "changeRoleAdmin") { ChangeRoleAdmin(ws, pack); return; }
    
    json j = json{
        {"action", "router"},
        {"message", "Не найдена функция " + method},
    };
    Answer(ws, serverError, j);
}

void Echo(WebSocketType* ws, const std::string_view message, const nlohmann::json& pack) {
    (void)message;
    Answer(ws, ok, pack);
}

void Register(WebSocketType* ws, const nlohmann::json& pack) {
    
    const std::string_view func_name = "register";
    if(!RequireField(ws, pack, "password", func_name, "Нет передаваемого пароля password")) return;
    if(!RequireField(ws, pack, "pseudonym", func_name, "Нет отображаемого имени pseudonym")) return;

    if(!validatePasswordEnv(ws, pack["password"], func_name)) return;
    if(!validatePseudonymEnv(ws, pack["pseudonym"], func_name)) return; 

    std::string password_hash = hashPassword(pack["password"]);
    std::string pseudonym = pack["pseudonym"];
    std::string timestamp = getTimestampNow();
    std::string roles = "[\"user\"]";
    std::string status = "👋 Привет, мир!";
    std::string aes = "";
    bool is_active = true;

    try {
        aes = generateAES();
    } catch (const std::runtime_error& e) {
        std::cerr << "Ошибка генерации ключа шифрования: " << e.what() << std::endl;
        json j = json{
            {"action", "register"},
            {"message", "Не удалось сгенерировать ключ шифрования"},
        };
        Answer(ws, ok, j);
        return;
    }

    if (Database::prepareStatement("INSERT INTO users (password_hash, pseudonym, status, roles, registration_date, is_active, aes_encryption_key) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            password_hash,
            pseudonym,
            status,
            roles,
            timestamp,
            is_active,
            aes
        };
        
        long long newId = Database::executeInsertAndGetId(params);
        json j = json{
            {"action", func_name},
            {"UIN", newId},
            {"aes", aes}
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, "func_name");
        return;
    }
}

void Login(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "login";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "password", func_name, "Нет передаваемого пароля password")) return;

    long long uin = getIntAnyway(pack["UIN"]);

    if (Database::prepareStatement("SELECT password_hash, auth_token, aes_encryption_key, roles, is_active, pseudonym, status FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            true
        };

        json verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "UIN или пароль неверный"},
            };
            Answer(ws, clientError, j);
            return;
        }
        
        std::string passwordHash = verifyUser[0]["password_hash"].get<std::string>();
        if(!VerifyPasswordEnv(ws, pack["password"], passwordHash, func_name)) return;
                
        std::string token = "";
        //Достаем или генерируем токен авторизации
        if (!verifyUser[0]["auth_token"].is_null() && verifyUser[0]["auth_token"].is_string()) {
        
            //Отдаем токен (и ключ шифрования)
            std::string token = verifyUser[0]["auth_token"].get<std::string>();

            //Добавляем сокет в общий пул
            WsServer::addSocket(ws, token, verifyUser[0]["roles"], verifyUser[0]["aes_encryption_key"], verifyUser[0]["is_active"], uin, verifyUser[0]["pseudonym"], verifyUser[0]["status"]);

            //Отправляем ответ
            json j = json{
                {"action", func_name},
                {"auth_token", token},
                {"aes", verifyUser[0]["aes_encryption_key"]},
            };
            Answer(ws, ok, j);
            return;
        } else {
            //Генерируем новый токен (и отдаем ключ шифрования)
            std::string token = generateAuthToken(uin);

            if (Database::prepareStatement("UPDATE users SET auth_token = ? WHERE UIN = ?")) {
                std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                    token,
                    uin
                };

                Database::executeUpdate(params);
                            
                //Добавляем сокет в общий пул
                WsServer::addSocket(ws, token, verifyUser[0]["roles"], verifyUser[0]["aes_encryption_key"], verifyUser[0]["is_active"], uin, verifyUser[0]["pseudonym"], verifyUser[0]["status"]);

                //Отправляем ответ
                json j = json{
                    {"action", func_name},
                    {"auth_token", token},
                    {"aes", verifyUser[0]["aes_encryption_key"]},
                };
                Answer(ws, ok, j);
                return;
            } else {
                ThrowSQLError(ws, func_name);
                return;
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void Logout(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "logout";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if (Database::prepareStatement("UPDATE users SET auth_token = NULL WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["UIN"].get<std::string>())
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы вышли из системы"},
        };
        Answer(ws, ok, j);
        
        auto* loop = uWS::Loop::get();
        // Планируем закрытие в том же потоке
        loop->defer([ws]() {
            ws->close();
        });
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void IsAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "isAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;

    if(!verifyRole(ws, getIntAnyway(pack["UIN"]), {"admin"}))
    {
        json j = json{
            {"action", func_name},
            {"message", "0"},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", func_name},
            {"message", "1"},
        };
        Answer(ws, ok, j);
        return;
    }
}

void ChangePassword(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changePassword";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "old_password", func_name, "Нет передаваемого пароля old_password")) return;
    if(!RequireField(ws, pack, "new_password", func_name, "Нет передаваемого пароля new_password")) return;

    long long uin = getIntAnyway(pack["UIN"]);

    json verifyUser = json{};

    if (Database::prepareStatement("SELECT password_hash FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            true
        };

        verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "UIN или пароль неверный"},
            };
            Answer(ws, clientError, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    std::string passwordHash = verifyUser[0]["password_hash"].get<std::string>();

    if(!VerifyPasswordEnv(ws, pack["old_password"], passwordHash, func_name)) return;

    if(!validatePasswordEnv(ws, pack["new_password"], func_name)) return;

    std::string newPasswordHash = hashPassword(pack["new_password"]);

    if (Database::prepareStatement("UPDATE users SET password_hash = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            newPasswordHash,
            uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы сменили пароль"},
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

}

void FindUsers(WebSocketType* ws, const nlohmann::json& pack) {

    const std::string_view func_name = "findUsers";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "find_string", func_name, "Нет передаваемой строки поиска")) return;
    if(pack["find_string"].get<std::string>().length() < 3 ) {
        json j = json{
            {"action", func_name},
            {"message", "Строка поиска не должна быть менее 3 символов"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Строка поиска не должна быть менее 3 символов" << std::endl;
        return;
    };

    if (Database::prepareStatement("SELECT UIN, pseudonym, status FROM users WHERE is_active = ? AND (pseudonym LIKE CONCAT('%', ?, '%') OR CAST(UIN AS CHAR) LIKE CONCAT('%', ?, '%'))")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            true,
            pack["find_string"].get<std::string>(),
            pack["find_string"].get<std::string>()
        };

        json findUsers = Database::executeSelect(params);

        json j = json{
            {"action", func_name},
            {"users", findUsers}
        };
        Answer(ws, ok, j);
        return;

    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

}

void AddContact(WebSocketType* ws, const nlohmann::json& pack) {

    const std::string_view func_name = "addContact";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "contact_uin", func_name, "Нет передаваемого UIN нового контакта")) return;

    long long uin = getIntAnyway(pack["contact_uin"]);

    std::string pseudonym = "";
    std::string status = "";

    //проверяем, существует ли UIN
    json User = json{};
    if (Database::prepareStatement("SELECT UIN, pseudonym, status FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            true
        };

        User = Database::executeSelect(params);

        if(User.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Пользователь не существует"},
            };
            Answer(ws, clientError, j);
            return;
        }

        pseudonym = User[0]["pseudonym"].get<std::string>();
        status = User[0]["status"].get<std::string>();
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }    

    //проверяем, добавлен ли контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id FROM contacts WHERE (initiator_uin = ? AND destination_uin = ?) OR (initiator_uin = ? AND destination_uin = ?) AND is_chat = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["UIN"]),
            uin,
            uin,
            getIntAnyway(pack["UIN"]),
            false
        };

        Contact = Database::executeSelect(params);

        if(!Contact.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Контакт уже существует"},
            };
            Answer(ws, clientError, j);
            return;
        }

        pseudonym = User[0]["pseudonym"].get<std::string>();
        status = User[0]["status"].get<std::string>();
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }    

    //Добавляем в контакты
    if (Database::prepareStatement("INSERT INTO contacts (initiator_uin, destination_uin, is_chat, is_approved) VALUES (?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["UIN"]),
            uin,
            false,
            false
        };
        
        long long int newID = Database::executeInsertAndGetId(params);

        //Отправляем новый запрос в друзья инициатору
        json j = json{
            {"action", std::string(func_name) + "Sender"},
            {"id", newID},
            {"UIN", uin},
            {"pseudonym", pseudonym},
            {"status", status}
        };
        Answer(ws, ok, j);

        //Отправляем новый запрос в друзья второму пользоваетлю, если он онлайн
        std::string sender_pseudonym = WsServer::authKeys[std::stoll(pack["UIN"].get<std::string>())]["pseudonym"];
        std::string sender_status = WsServer::authKeys[std::stoll(pack["UIN"].get<std::string>())]["status"];
        if (WsServer::authorizedSockets.find(uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", std::string(func_name) + "Reciever"},
                {"id", newID},
                {"UIN", getIntAnyway(pack["UIN"])},
                {"pseudonym", sender_pseudonym},
                {"status", sender_status}
            };
            Answer(WsServer::authorizedSockets[uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void AcceptContact(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "acceptContact";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "contact_id", func_name, "Нет id контакта")) return;

    long long int initiator_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, initiator_uin FROM contacts WHERE id = ? AND destination_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["contact_id"]),
            getIntAnyway(pack["UIN"]),
            false
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            initiator_uin = getIntAnyway(Contact[0]["initiator_uin"]);
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }   
    
    if (Database::prepareStatement("UPDATE contacts SET is_approved = ? WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            true,
            getIntAnyway(pack["contact_id"])
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту
        std::string pseudonym = "";
        std::string status = "";

        if (Database::prepareStatement("SELECT pseudonym, status FROM users WHERE UIN = ?")) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                initiator_uin
            };

            Contact = Database::executeSelect(params);

            if(Contact.empty()) {
                json j = json{
                    {"action", func_name},
                    {"message", "Контакт не существует"},
                };
                Answer(ws, clientError, j);
                return;
            } else {
                pseudonym = Contact[0]["pseudonym"].get<std::string>();
                status = Contact[0]["status"].get<std::string>();
            }
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }   

        bool online = false;
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            online = true;
        }

        json j = json{
            {"action", std::string(func_name) + "Sender"},
            {"accepted_contact", getIntAnyway(pack["contact_id"])},
            {"initiator_uin", initiator_uin},
            {"pseudonym", pseudonym},
            {"status", status},
            {"is_online", online}
        };
        Answer(ws, ok, j);

        //Отправляем ответ инициатору, если он в сети
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", std::string(func_name) + "Reciever"},
                {"accepted_contact", getIntAnyway(pack["contact_id"])},
                {"accepter_uin", getIntAnyway(pack["UIN"])},
                {"pseudonym", WsServer::authKeys[getIntAnyway(pack["UIN"])]["pseudonym"]},
                {"status", WsServer::authKeys[getIntAnyway(pack["UIN"])]["status"]},
                {"is_online", true}
            };
            Answer(WsServer::authorizedSockets[initiator_uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    
}

void DeclineContact(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "declineContact";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "contact_id", func_name, "Нет id контакта")) return;

    long long int initiator_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, initiator_uin FROM contacts WHERE id = ? AND destination_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["contact_id"]),
            getIntAnyway(pack["UIN"]),
            false
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            initiator_uin = getIntAnyway(Contact[0]["initiator_uin"]);
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Удаляем контакт
    if (Database::prepareStatement("DELETE FROM contacts WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["contact_id"])
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту
        json j = json{
            {"action", std::string(func_name) + "Sender"},
            {"declined_contact", getIntAnyway(pack["contact_id"])},
            {"initiator_uin", initiator_uin}
        };
        Answer(ws, ok, j);

        //Отправляем ответ инициатору, если он в сети
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", std::string(func_name) + "Reciever"},
                {"declined_contact", getIntAnyway(pack["contact_id"])},
                {"accepter_uin", getIntAnyway(pack["UIN"])},
            };
            Answer(WsServer::authorizedSockets[initiator_uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void UndoAddContact(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "undoAddContact";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "contact_id", func_name, "Нет id контакта")) return;

    long long int destination_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, destination_uin FROM contacts WHERE id = ? AND initiator_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["contact_id"]),
            getIntAnyway(pack["UIN"]),
            false
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            destination_uin = getIntAnyway(Contact[0]["destination_uin"]);
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Удаляем контакт
    if (Database::prepareStatement("DELETE FROM contacts WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["contact_id"])
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту
        json j = json{
            {"action", std::string(func_name) + "Sender"},
            {"undoed_contact", getIntAnyway(pack["contact_id"])},
            {"destination_uin", destination_uin}
        };
        Answer(ws, ok, j);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(destination_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", std::string(func_name) + "Reciever"},
                {"undoed_contact", getIntAnyway(pack["contact_id"])},
                {"accepter_uin", getIntAnyway(pack["UIN"])},
            };
            Answer(WsServer::authorizedSockets[destination_uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void RemoveContact(WebSocketType* ws, const nlohmann::json& pack) {
    
    const std::string_view func_name = "removeContact";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "contact_id", func_name, "Нет id контакта")) return;

    long long int destination_uin = 0;
    long long int initiator_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, initiator_uin, destination_uin FROM contacts WHERE id = ? AND (initiator_uin = ? OR destination_uin = ?) AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["contact_id"]),
            getIntAnyway(pack["UIN"]),
            getIntAnyway(pack["UIN"]),
            true
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            destination_uin = getIntAnyway(Contact[0]["destination_uin"]);
            initiator_uin = getIntAnyway(Contact[0]["initiator_uin"]);
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Удаляем контакт
    if (Database::prepareStatement("DELETE FROM contacts WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["contact_id"])
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту инициатору, если он в сети
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", func_name},
                {"removed_contact", getIntAnyway(pack["contact_id"])},
            };
            Answer(WsServer::authorizedSockets[initiator_uin], ok, j);
        }

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(destination_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", func_name},
                {"removed_contact", getIntAnyway(pack["contact_id"])},
            };
            Answer(WsServer::authorizedSockets[destination_uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void GetContacts(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "getContacts";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    json Contacts = json{};
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
                long long int uin =  getIntAnyway(item["UIN"]);
                if (WsServer::authorizedSockets.find(uin) != WsServer::authorizedSockets.end()) {
                    item["online"] = true;
                } else {
                    item["online"] = false;
                }
            }
        }

        //Отправляем ответ клиенту
        json j = json{
            {"action", func_name},
            {"contacts", Contacts},
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void GetOutgoingRequests(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "getOutgoingRequests";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    json Contacts = json{};
    if (Database::prepareStatement("SELECT c.id, u.UIN, u.pseudonym, u.status, u.is_active FROM contacts AS c LEFT JOIN users AS u ON c.destination_uin = u.UIN WHERE initiator_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            false
        };

        Contacts = Database::executeSelect(params);

        //Отправляем ответ клиенту
        json j = json{
            {"action", func_name},
            {"contacts", Contacts},
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void GetIncomingRequests(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "getIncomingRequests";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    json Contacts = json{};
    if (Database::prepareStatement("SELECT c.id, u.UIN, u.pseudonym, u.status, u.is_active FROM contacts AS c LEFT JOIN users AS u ON c.initiator_uin = u.UIN WHERE destination_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            false
        };

        Contacts = Database::executeSelect(params);

        //Отправляем ответ клиенту
        json j = json{
            {"action", func_name},
            {"contacts", Contacts},
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

}

void BroadcastOnline(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "broadcastOnline";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;


    json j = json{
        {"action", func_name},
        {"UIN", uin}
    };

    ContactsBroadcast(uin, ok, j);
    return;
}

void BroadcastOffline(WebSocketType* ws, const nlohmann::json& pack) {
    
    const std::string_view func_name = "broadcastOffline";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    json j = json{
        {"action", func_name},
        {"UIN", uin}
    };

    ContactsBroadcast(uin, ok, j);
    return;
}

void ChangePseudonym(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changePseudonym";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "new_pseudonym", func_name, "Нет передаваемого new_pseudonym")) return;

    if (Database::prepareStatement("UPDATE users SET pseudonym = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_pseudonym"].get<std::string>(),
            uin
        };

        Database::executeUpdate(params);
        WsServer::authKeys[uin]["pseudonym"] = pack["new_pseudonym"].get<std::string>();
        json j = json{
            {"action", func_name},
            {"message", "Вы сменили псевдоним!"},
        };
        Answer(ws, ok, j);
        
        json broadcast = json{
            {"action", "broadcast" + std::string(func_name) },
            {"UIN", uin},
            {"pseudonym", pack["new_pseudonym"].get<std::string>()}
        };
        ContactsBroadcast(uin, ok, broadcast);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void ChangeStatus(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeStatus";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "new_status", func_name, "Нет передаваемого new_status")) return;

    if (Database::prepareStatement("UPDATE users SET status = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_status"].get<std::string>(),
            uin
        };

        Database::executeUpdate(params);
        WsServer::authKeys[uin]["status"] = pack["new_status"].get<std::string>();
        json j = json{
            {"action", func_name},
            {"message", "Вы сменили статус!"},
        };
        Answer(ws, ok, j);
        
        json broadcast = json{
            {"action", "broadcast" + std::string(func_name)},
            {"UIN", uin},
            {"status", pack["new_status"].get<std::string>()}
        };
        ContactsBroadcast(uin, ok, broadcast);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void ChangeAES(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeAES";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    //Генерируем новый AES
    std::string new_aes = generateAES();

    if (Database::prepareStatement("UPDATE users SET aes_encryption_key = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            new_aes,
            uin
        };

        Database::executeUpdate(params);
        WsServer::authKeys[uin]["aes"] = new_aes;
        json j = json{
            {"action", func_name},
            {"AES", new_aes},
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void ChangePasswordAdmin(WebSocketType* ws, const nlohmann::json& pack) {

    const std::string_view func_name = "changePasswordAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"admin"}, func_name)) return;

    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого клиента назначения")) return;
    if(!RequireField(ws, pack, "new_password", func_name, "Нет передаваемого пароля new_password")) return;
    json verifyUser = json{};

    
    if(!validatePasswordEnv(ws, pack["new_password"], func_name)) return;

    std::string newPasswordHash = hashPassword(pack["new_password"]);

    if (Database::prepareStatement("UPDATE users SET password_hash = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            newPasswordHash,
            getIntAnyway(pack["dest_uin"])
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы сменили пароль"},
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

}

void ChangePseudonymAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changePseudonymAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого клиента назначения")) return;
    if(!RequireField(ws, pack, "new_pseudonym", func_name, "Нет передаваемого new_pseudonym")) return;


    long long int dest_uin =  getIntAnyway(pack["dest_uin"]);

    if (Database::prepareStatement("UPDATE users SET pseudonym = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_pseudonym"].get<std::string>(),
            dest_uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы сменили псевдоним!"},
        };
        Answer(ws, ok, j);
        

        json broadcast = json{
            {"action", "broadcast" + std::string(func_name)},
            {"UIN", dest_uin},
            {"pseudonym", pack["new_pseudonym"].get<std::string>()}
        };
        ContactsBroadcast(dest_uin, ok, broadcast);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", func_name},
                {"pseudonym", pack["new_pseudonym"]},
            };
            WsServer::authKeys[dest_uin]["pseudonym"] = pack["new_pseudonym"].get<std::string>();
            Answer(WsServer::authorizedSockets[dest_uin], ok, j);
        }

        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void ChangeStatusAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeStatusAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого клиента назначения")) return;
    if(!RequireField(ws, pack, "new_status", func_name, "Нет передаваемого new_status")) return;


    long long int dest_uin =  getIntAnyway(pack["dest_uin"]);

    if (Database::prepareStatement("UPDATE users SET status = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_status"].get<std::string>(),
            dest_uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы сменили статус!"},
        };
        Answer(ws, ok, j);
        

        json broadcast = json{
            {"action", "broadcast" + std::string(func_name)},
            {"UIN", dest_uin},
            {"status", pack["new_status"].get<std::string>()}
        };
        ContactsBroadcast(dest_uin, ok, broadcast);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", func_name},
                {"status", getIntAnyway(pack["new_status"])},
            };
            WsServer::authKeys[dest_uin]["status"] = pack["new_status"].get<std::string>();
            Answer(WsServer::authorizedSockets[dest_uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void BanUserAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "banUserAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого клиента назначения")) return;


    long long int dest_uin =  getIntAnyway(pack["dest_uin"]);

    if (Database::prepareStatement("UPDATE users SET is_active = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            false,
            dest_uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы забанили пользователя"},
        };
        Answer(ws, ok, j);
        
        json broadcast = json{
            {"action", "broadcast" + std::string(func_name)},
            {"UIN", dest_uin},
            {"is_active", false}
        };
        ContactsBroadcast(dest_uin, ok, broadcast);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", func_name},
                {"is_active", false},
            };
            WsServer::authKeys[dest_uin]["is_active"] = "0";
            Answer(WsServer::authorizedSockets[dest_uin], ok, j);

            uWS::WebSocket<false, true, std::nullptr_t>* socket = WsServer::authorizedSockets[dest_uin];
            auto* loop = uWS::Loop::get();
            // Планируем закрытие в том же потоке
            loop->defer([socket]() {
               socket->close();
            });
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void UnbanUserAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "unbanUserAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого клиента назначения")) return;


    long long int dest_uin =  getIntAnyway(pack["dest_uin"]);

    if (Database::prepareStatement("UPDATE users SET is_active = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            true,
            dest_uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы разбанили пользователя"},
        };
        Answer(ws, ok, j);
        
        json broadcast = json{
            {"action", "broadcast" + std::string(func_name)},
            {"UIN", dest_uin},
            {"is_active", true}
        };
        ContactsBroadcast(dest_uin, ok, broadcast);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", func_name},
                {"is_active", true},
            };
            WsServer::authKeys[dest_uin]["is_active"] = "0";
            Answer(WsServer::authorizedSockets[dest_uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}

void KickUserAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "kickUserAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого клиента назначения")) return;


    long long int dest_uin =  getIntAnyway(pack["dest_uin"]);
    
    if (Database::prepareStatement("UPDATE users SET auth_token = NULL WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            dest_uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы кикнули пользователя"},
        };
        Answer(ws, ok, j);
        
        json broadcast = json{
            {"action", "broadcast" + std::string(func_name)},
            {"UIN", dest_uin},
            {"is_active", false}
        };
        ContactsBroadcast(dest_uin, ok, broadcast);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", func_name},
            };
            Answer(WsServer::authorizedSockets[dest_uin], ok, j);
            
            uWS::WebSocket<false, true, std::nullptr_t>* socket = WsServer::authorizedSockets[dest_uin];
            auto* loop = uWS::Loop::get();
            // Планируем закрытие в том же потоке
            loop->defer([socket]() {
               socket->close();
            });
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;

}

void ChangeRoleAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeRoleAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого клиента назначения")) return;
    if(!RequireField(ws, pack, "roles", func_name, "Нет передаваемой роли")) return;

    if(!json::accept(pack["roles"].get<std::string>())) {
        json j = json{
            {"action", func_name},
            {"message", "Некорректный json ролей"},
        };
        Answer(ws, clientError, j);
        return;
    }

    long long int dest_uin =  getIntAnyway(pack["dest_uin"]);

    if (Database::prepareStatement("UPDATE users SET roles = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["roles"].get<std::string>(),
            dest_uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", func_name},
            {"message", "Вы изменили роль пользователя"},
        };
        Answer(ws, ok, j);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
            WsServer::authKeys[dest_uin]["roles"] = pack["roles"].get<std::string>();
            json j = json{
                {"action", func_name},
                {"roles", pack["roles"]}
            };
            Answer(WsServer::authorizedSockets[dest_uin], ok, j);
        }
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
    return;
}