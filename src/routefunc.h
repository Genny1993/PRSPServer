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
    
    if(!pack.contains("password")) {
        json j = json{
            {"action", "register"},
            {"message", "Нет передаваемого пароля password"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого пароля password" << std::endl;
        return;
    }

    if(!pack.contains("pseudonym")) {
        json j = json{
            {"action", "register"},
            {"message", "Нет отображаемого имени pseudonym"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет отображаемого имени pseudonym" << std::endl;
        return;
    }

    if(!validatePassword(pack["password"])) {
        json j = json{
            {"action", "register"},
            {"message", "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол" << std::endl;
        return;
    }

    if(!validatePseudonym(pack["pseudonym"])) {
        json j = json{
            {"action", "register"},
            {"message", "Отображаемое имя должно содержать не менее 6 символов и не более 50"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Отображаемое имя должно содержать не менее 1 символа и не более 50" << std::endl;
        return;
    }

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
            {"action", "register"},
            {"UIN", newId},
            {"aes", aes}
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "register"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, ok, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void Login(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "login"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("password")) {
        json j = json{
            {"action", "login"},
            {"message", "Нет передаваемого пароля password"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого пароля password" << std::endl;
        return;
    }

    long long uin = 0;

    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    if (Database::prepareStatement("SELECT password_hash, auth_token, aes_encryption_key, roles, is_active, pseudonym, status FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            true
        };

        json verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            json j = json{
                {"action", "login"},
                {"message", "UIN или пароль неверный"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            std::string passwordHash = verifyUser[0]["password_hash"].get<std::string>();
            if(!verifyPassword(pack["password"], passwordHash)) {
                json j = json{
                    {"action", "login"},
                    {"message", "UIN или пароль неверный"},
                };
                Answer(ws, clientError, j);
                return;
            } else {
                std::string token = "";
                //Достаем или генерируем токен авторизации
                if (!verifyUser[0]["auth_token"].is_null() && verifyUser[0]["auth_token"].is_string())
                {   //Отдаем токен (и ключ шифрования)
                    std::string token = verifyUser[0]["auth_token"].get<std::string>();

                    //Добавляем сокет в общий пул
                    WsServer::addSocket(ws, token, verifyUser[0]["roles"], verifyUser[0]["aes_encryption_key"], verifyUser[0]["is_active"], uin, verifyUser[0]["pseudonym"], verifyUser[0]["status"]);

                    //Отправляем ответ
                    json j = json{
                        {"action", "login"},
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
                            {"action", "login"},
                            {"auth_token", token},
                            {"aes", verifyUser[0]["aes_encryption_key"]},
                        };
                        Answer(ws, ok, j);
                        return;
                    } else {
                        json j = json{
                            {"action", "login"},
                            {"message", "Ошибка при подготовке SQL-запроса"},
                        };
                        Answer(ws, serverError, j);
                        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
                        return;
                    }
                }
                
            }
        }
    } else {
        json j = json{
            {"action", "login"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void Logout(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "logout"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "logout"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "logout"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"user", "admin"}))
    {
        json j = json{
            {"action", "logout"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if (Database::prepareStatement("UPDATE users SET auth_token = NULL WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["UIN"].get<std::string>())
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", "logout"},
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
        json j = json{
            {"action", "logout"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
    return;
}

void IsAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "logout"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "logout"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "logout"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin"}))
    {
        json j = json{
            {"action", "isAdmin"},
            {"message", "0"},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "isAdmin"},
            {"message", "1"},
        };
        Answer(ws, ok, j);
        return;
    }
}

void ChangePassword(WebSocketType* ws, const nlohmann::json& pack) {

    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "changePassword"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("old_password")) {
        json j = json{
            {"action", "changePassword"},
            {"message", "Нет передаваемого пароля old_password"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого пароля old_password" << std::endl;
        return;
    }

    if(!pack.contains("new_password")) {
        json j = json{
            {"action", "changePassword"},
            {"message", "Нет передаваемого пароля new_password"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого пароля new_password" << std::endl;
        return;
    }

    long long uin = 0;

    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "changePassword"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "changePassword"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    json verifyUser = json{};

    if (Database::prepareStatement("SELECT password_hash FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            true
        };

        verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            json j = json{
                {"action", "changePassword"},
                {"message", "UIN или пароль неверный"},
            };
            Answer(ws, clientError, j);
            return;
        }
    } else {
        json j = json{
            {"action", "changePassword"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

    std::string passwordHash = verifyUser[0]["password_hash"].get<std::string>();

    if(!verifyPassword(pack["old_password"], passwordHash)) {
        json j = json{
            {"action", "changePassword"},
            {"message", "UIN или пароль неверный"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!validatePassword(pack["new_password"])) {
        json j = json{
            {"action", "changePassword"},
            {"message", "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол" << std::endl;
        return;
    }

    std::string newPasswordHash = hashPassword(pack["new_password"]);

    if (Database::prepareStatement("UPDATE users SET password_hash = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            newPasswordHash,
            uin
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", "changePassword"},
            {"message", "Вы сменили пароль"},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "changePassword"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

}

void FindUsers(WebSocketType* ws, const nlohmann::json& pack) {

    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "findUsers"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "findUsers"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "findUsers"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "findUsers"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("find_string")) {
        json j = json{
            {"action", "findUsers"},
            {"message", "Нет передаваемой строки поиска"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемой строки поиска" << std::endl;
        return;
    }

    if(pack["find_string"].get<std::string>().length() < 3 ) {
        json j = json{
            {"action", "findUsers"},
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
            {"action", "findUsers"},
            {"users", findUsers}
        };
        Answer(ws, ok, j);
        return;

    } else {
        json j = json{
            {"action", "findUsers"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

}

void AddContact(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "addContact"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "addContact"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "addContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "addContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }


    if(!pack.contains("contact_uin")) {
        json j = json{
            {"action", "addContact"},
            {"message", "Нет передаваемого UIN нового контакта"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN нового контакта" << std::endl;
        return;
    }

    long long uin = 0;

    if (pack["contact_uin"].is_number()) {
        uin = pack["contact_uin"].get<long long>();
    } else if (pack["contact_uin"].is_string()) {
        uin = std::stoll(pack["contact_uin"].get<std::string>());
    }

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
                {"action", "addContact"},
                {"message", "Пользователь не существует"},
            };
            Answer(ws, clientError, j);
            return;
        }

        pseudonym = User[0]["pseudonym"].get<std::string>();
        status = User[0]["status"].get<std::string>();
    } else {
        json j = json{
            {"action", "addContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }    

    //проверяем, добавлен ли контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id FROM contacts WHERE initiator_uin = ? AND destination_uin = ? AND is_chat = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["UIN"].get<std::string>()),
            uin,
            false
        };

        Contact = Database::executeSelect(params);

        if(!Contact.empty()) {
            json j = json{
                {"action", "addContact"},
                {"message", "Контакт уже существует"},
            };
            Answer(ws, clientError, j);
            return;
        }

        pseudonym = User[0]["pseudonym"].get<std::string>();
        status = User[0]["status"].get<std::string>();
    } else {
        json j = json{
            {"action", "addContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }    

    //Добавляем в контакты
    if (Database::prepareStatement("INSERT INTO contacts (initiator_uin, destination_uin, is_chat, is_approved) VALUES (?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["UIN"].get<std::string>()),
            uin,
            false,
            false
        };
        
        long long int newID = Database::executeInsertAndGetId(params);

        //Отправляем новый запрос в друзья инициатору
        json j = json{
            {"action", "newContactSender"},
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
                {"action", "newContactReciever"},
                {"id", newID},
                {"UIN", std::stoll(pack["UIN"].get<std::string>())},
                {"pseudonym", sender_pseudonym},
                {"status", sender_status}
            };
            Answer(WsServer::authorizedSockets[uin], ok, j);
        }
        return;
    } else {
        json j = json{
            {"action", "addContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, ok, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void AcceptContact(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "acceptContact"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "acceptContact"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "acceptContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "acceptContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("contact_id")) {
        json j = json{
            {"action", "acceptContact"},
            {"message", "Нет id контакта"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет id контакта" << std::endl;
        return;
    }

    long long int initiator_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, initiator_uin FROM contacts WHERE id = ? AND destination_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["contact_id"].get<std::string>()),
            std::stoll(pack["UIN"].get<std::string>()),
            false
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", "acceptContact"},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            initiator_uin = Contact[0]["initiator_uin"].get<long long int>();
        }
    } else {
        json j = json{
            {"action", "acceptContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }   
    
    if (Database::prepareStatement("UPDATE contacts SET is_approved = ? WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            true,
            std::stoll(pack["contact_id"].get<std::string>())
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
                    {"action", "acceptContact"},
                    {"message", "Контакт не существует"},
                };
                Answer(ws, clientError, j);
                return;
            } else {
                pseudonym = Contact[0]["pseudonym"].get<std::string>();
                status = Contact[0]["status"].get<std::string>();
            }
        } else {
            json j = json{
                {"action", "acceptContact"},
                {"message", "Ошибка при подготовке SQL-запроса"},
            };
            Answer(ws, serverError, j);
            std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
            return;
        }   

        bool online = false;
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            online = true;
        }

        json j = json{
            {"action", "acceptContactSender"},
            {"accepted_contact", std::stoll(pack["contact_id"].get<std::string>())},
            {"initiator_uin", initiator_uin},
            {"pseudonym", pseudonym},
            {"status", status},
            {"is_online", online}
        };
        Answer(ws, ok, j);

        //Отправляем ответ инициатору, если он в сети
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", "acceptContactReciever"},
                {"accepted_contact", std::stoll(pack["contact_id"].get<std::string>())},
                {"accepter_uin", std::stoll(pack["UIN"].get<std::string>())},
                {"pseudonym", WsServer::authKeys[std::stoll(pack["UIN"].get<std::string>())]["pseudonym"]},
                {"status", WsServer::authKeys[std::stoll(pack["UIN"].get<std::string>())]["status"]},
                {"is_online", true}
            };
            Answer(WsServer::authorizedSockets[initiator_uin], ok, j);
        }
        return;
    } else {
        json j = json{
            {"action", "acceptContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
    
}

void DeclineContact(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "declineContact"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "declineContact"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "declineContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "declineContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("contact_id")) {
        json j = json{
            {"action", "declineContact"},
            {"message", "Нет id контакта"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет id контакта" << std::endl;
        return;
    }

    long long int initiator_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, initiator_uin FROM contacts WHERE id = ? AND destination_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["contact_id"].get<std::string>()),
            std::stoll(pack["UIN"].get<std::string>()),
            false
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", "declineContact"},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            initiator_uin = Contact[0]["initiator_uin"].get<long long int>();
        }
    } else {
        json j = json{
            {"action", "declineContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

    //Удаляем контакт
    if (Database::prepareStatement("DELETE FROM contacts WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["contact_id"].get<std::string>())
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту
        json j = json{
            {"action", "declineContactSender"},
            {"declined_contact", std::stoll(pack["contact_id"].get<std::string>())},
            {"initiator_uin", initiator_uin}
        };
        Answer(ws, ok, j);

        //Отправляем ответ инициатору, если он в сети
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", "declineContactReciever"},
                {"declined_contact", std::stoll(pack["contact_id"].get<std::string>())},
                {"accepter_uin", std::stoll(pack["UIN"].get<std::string>())},
            };
            Answer(WsServer::authorizedSockets[initiator_uin], ok, j);
        }
        return;
    } else {
        json j = json{
            {"action", "declineContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void UndoAddContact(WebSocketType* ws, const nlohmann::json& pack) {
        if(!pack.contains("UIN")) {
        json j = json{
            {"action", "undoAddContact"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "undoAddContact"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "undoAddContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "undoAddContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("contact_id")) {
        json j = json{
            {"action", "undoAddContact"},
            {"message", "Нет id контакта"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет id контакта" << std::endl;
        return;
    }

    long long int destination_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, destination_uin FROM contacts WHERE id = ? AND initiator_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["contact_id"].get<std::string>()),
            std::stoll(pack["UIN"].get<std::string>()),
            false
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", "undoAddContact"},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            destination_uin = Contact[0]["destination_uin"].get<long long int>();
        }
    } else {
        json j = json{
            {"action", "undoAddContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

    //Удаляем контакт
    if (Database::prepareStatement("DELETE FROM contacts WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["contact_id"].get<std::string>())
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту
        json j = json{
            {"action", "undoAddContactSender"},
            {"undoed_contact", std::stoll(pack["contact_id"].get<std::string>())},
            {"destination_uin", destination_uin}
        };
        Answer(ws, ok, j);

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(destination_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", "undoAddContactReciever"},
                {"undoed_contact", std::stoll(pack["contact_id"].get<std::string>())},
                {"accepter_uin", std::stoll(pack["UIN"].get<std::string>())},
            };
            Answer(WsServer::authorizedSockets[destination_uin], ok, j);
        }
        return;
    } else {
        json j = json{
            {"action", "undoAddContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void RemoveContact(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "removeContact"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "removeContact"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "removeContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "removeContact"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("contact_id")) {
        json j = json{
            {"action", "removeContact"},
            {"message", "Нет id контакта"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет id контакта" << std::endl;
        return;
    }

    long long int destination_uin = 0;
    long long int initiator_uin = 0;
    //проверяем, есть ли такой контакт
    json Contact = json{};
    if (Database::prepareStatement("SELECT id, initiator_uin, destination_uin FROM contacts WHERE id = ? AND (initiator_uin = ? OR destination_uin = ?) AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["contact_id"].get<std::string>()),
            std::stoll(pack["UIN"].get<std::string>()),
            std::stoll(pack["UIN"].get<std::string>()),
            true
        };

        Contact = Database::executeSelect(params);

        if(Contact.empty()) {
            json j = json{
                {"action", "removeContact"},
                {"message", "Контакт не существует"},
            };
            Answer(ws, clientError, j);
            return;
        } else {
            destination_uin = Contact[0]["destination_uin"].get<long long int>();
            initiator_uin = Contact[0]["initiator_uin"].get<long long int>();
        }
    } else {
        json j = json{
            {"action", "removeContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

    //Удаляем контакт
    if (Database::prepareStatement("DELETE FROM contacts WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::stoll(pack["contact_id"].get<std::string>())
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту инициатору, если он в сети
        if (WsServer::authorizedSockets.find(initiator_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", "removeContact"},
                {"removed_contact", std::stoll(pack["contact_id"].get<std::string>())},
            };
            Answer(WsServer::authorizedSockets[initiator_uin], ok, j);
        }

        //Отправляем ответ клиенту назначения, если он в сети
        if (WsServer::authorizedSockets.find(destination_uin) != WsServer::authorizedSockets.end()) {
            json j = json{
                {"action", "removeContact"},
                {"removed_contact", std::stoll(pack["contact_id"].get<std::string>())},
            };
            Answer(WsServer::authorizedSockets[destination_uin], ok, j);
        }
        return;
    } else {
        json j = json{
            {"action", "removeContact"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void GetContacts(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "getContacts"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "getContacts"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "getContacts"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "getContacts"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    json Contacts = json{};
      if (Database::prepareStatement("SELECT c.id, CASE WHEN c.initiator_uin = ? THEN c.destination_uin ELSE c.initiator_uin END AS UIN, CASE WHEN c.initiator_uin = ? THEN dest_user.pseudonym ELSE init_user.pseudonym END AS pseudonym, CASE WHEN c.initiator_uin = ? THEN 'initiator' ELSE 'destination' END AS my_role, CASE WHEN c.initiator_uin = ? THEN dest_user.status ELSE init_user.status END AS status, CASE WHEN c.initiator_uin = ? THEN dest_user.is_active ELSE init_user.is_active END AS is_active, c.is_approved FROM contacts c LEFT JOIN users init_user ON c.initiator_uin = init_user.UIN LEFT JOIN users dest_user ON c.destination_uin = dest_user.UIN WHERE (c.initiator_uin = ? OR c.destination_uin = ?) AND c.is_approved = ?")) {
    //if (Database::prepareStatement("SELECT c.id, u.UIN, u.pseudonym, u.status, u.is_active FROM contacts AS c LEFT JOIN users AS u ON c.destination_uin = u.UIN WHERE (initiator_uin = ? OR destination_uin = ?) AND is_approved = ?")) {
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
                long long int uin = item["UIN"].get<long long int>();
                if (WsServer::authorizedSockets.find(uin) != WsServer::authorizedSockets.end()) {
                    item["online"] = true;
                } else {
                    item["online"] = false;
                }
            }
        }

        //Отправляем ответ клиенту
        json j = json{
            {"action", "getContacts"},
            {"contacts", Contacts},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "getContacts"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void GetOutgoingRequests(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "getOutgoingRequests"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "getOutgoingRequests"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "getOutgoingRequests"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "getOutgoingRequests"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    json Contacts = json{};
    if (Database::prepareStatement("SELECT c.id, u.UIN, u.pseudonym, u.status, u.is_active FROM contacts AS c LEFT JOIN users AS u ON c.destination_uin = u.UIN WHERE initiator_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            false
        };

        Contacts = Database::executeSelect(params);

        //Отправляем ответ клиенту
        json j = json{
            {"action", "getOutgoingRequests"},
            {"contacts", Contacts},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "getOutgoingRequests"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
}

void GetIncomingRequests(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "getIncomingRequests"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "getIncomingRequests"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "getIncomingRequests"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin", "user"}))
    {
        json j = json{
            {"action", "getIncomingRequests"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    json Contacts = json{};
    if (Database::prepareStatement("SELECT c.id, u.UIN, u.pseudonym, u.status, u.is_active FROM contacts AS c LEFT JOIN users AS u ON c.initiator_uin = u.UIN WHERE destination_uin = ? AND is_approved = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            false
        };

        Contacts = Database::executeSelect(params);

        //Отправляем ответ клиенту
        json j = json{
            {"action", "getIncomingRequests"},
            {"contacts", Contacts},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "getIncomingRequests"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

}

void BroadcastOnline(WebSocketType* ws, const nlohmann::json& pack) {
    
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "broadcastOnline"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "broadcastOnline"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, uin, pack["auth_key"])) {
        json j = json{
            {"action", "broadcastOnline"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, uin, {"admin", "user"}))
    {
        json j = json{
            {"action", "broadcastOnline"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }


    json j = json{
        {"action", "broadcastOnline"},
        {"UIN", uin}
    };

    ContactsBroadcast(uin, ok, j);
    return;
}

void BroadcastOffline(WebSocketType* ws, const nlohmann::json& pack) {
    
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "broadcastOffline"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "broadcastOffline"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, uin, pack["auth_key"])) {
        json j = json{
            {"action", "broadcastOffline"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, uin, {"admin", "user"}))
    {
        json j = json{
            {"action", "broadcastOffline"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }


    json j = json{
        {"action", "broadcastOffline"},
        {"UIN", uin}
    };

    ContactsBroadcast(uin, ok, j);
    return;
}

void ChangePseudonym(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "changePseudonym"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "changePseudonym"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, uin, pack["auth_key"])) {
        json j = json{
            {"action", "changePseudonym"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, uin, {"admin", "user"}))
    {
        json j = json{
            {"action", "changePseudonym"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("new_pseudonym")) {
        json j = json{
            {"action", "changePseudonym"},
            {"message", "Нет передаваемого new_pseudonym"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого new_pseudonym" << std::endl;
        return;
    }

    if (Database::prepareStatement("UPDATE users SET pseudonym = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_pseudonym"].get<std::string>(),
            uin
        };

        Database::executeUpdate(params);
        WsServer::authKeys[uin]["pseudonym"] = pack["new_pseudonym"].get<std::string>();
        json j = json{
            {"action", "changePseudonym"},
            {"message", "Вы сменили псевдоним!"},
        };
        Answer(ws, ok, j);
        
        json broadcast = json{
            {"action", "broadcastChangePseudonym"},
            {"UIN", uin},
            {"pseudonym", pack["new_pseudonym"].get<std::string>()}
        };
        ContactsBroadcast(uin, ok, broadcast);
        return;
    } else {
        json j = json{
            {"action", "changePseudonym"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
    return;
}

void ChangeStatus(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "changeStatus"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "changeStatus"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, uin, pack["auth_key"])) {
        json j = json{
            {"action", "changeStatus"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, uin, {"admin", "user"}))
    {
        json j = json{
            {"action", "changeStatus"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("new_status")) {
        json j = json{
            {"action", "changeStatus"},
            {"message", "Нет передаваемого new_pseudonym"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого new_status" << std::endl;
        return;
    }

    if (Database::prepareStatement("UPDATE users SET status = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_status"].get<std::string>(),
            uin
        };

        Database::executeUpdate(params);
        WsServer::authKeys[uin]["status"] = pack["new_status"].get<std::string>();
        json j = json{
            {"action", "changeStatus"},
            {"message", "Вы сменили статус!"},
        };
        Answer(ws, ok, j);
        
        json broadcast = json{
            {"action", "broadcastChangeStatus"},
            {"UIN", uin},
            {"status", pack["new_status"].get<std::string>()}
        };
        ContactsBroadcast(uin, ok, broadcast);
        return;
    } else {
        json j = json{
            {"action", "changeStatus"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
    return;
}

void ChangeAES(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "changeAES"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "changeAES"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, uin, pack["auth_key"])) {
        json j = json{
            {"action", "changeAES"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, uin, {"admin", "user"}))
    {
        json j = json{
            {"action", "changeAES"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

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
            {"action", "changeAES"},
            {"AES", new_aes},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "changeAES"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
    return;
}

void ChangePasswordAdmin(WebSocketType* ws, const nlohmann::json& pack) {

    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    if(!pack.contains("dest_uin")) {
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "Нет передаваемого клиента назначения"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого клиента назначения" << std::endl;
        return;
    }

    if(!pack.contains("new_password")) {
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "Нет передаваемого пароля new_password"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого пароля new_password" << std::endl;
        return;
    }

    if(!verifyAuth(ws, std::stoll(pack["UIN"].get<std::string>()), pack["auth_key"])) {
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, std::stoll(pack["UIN"].get<std::string>()), {"admin"}))
    {
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    json verifyUser = json{};

    
    if(!validatePassword(pack["new_password"])) {
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Пароль должен содержать не меньше 8 символов, не больше 30. Должен содержать хотя бы одну маленьку букву, большую букву, хотя бы 1 цифру и 1 спецсимвол" << std::endl;
        return;
    }

    std::string newPasswordHash = hashPassword(pack["new_password"]);

    if (Database::prepareStatement("UPDATE users SET password_hash = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            newPasswordHash,
            std::stoll(pack["dest_uin"].get<std::string>())
        };

        Database::executeUpdate(params);
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "Вы сменили пароль"},
        };
        Answer(ws, ok, j);
        return;
    } else {
        json j = json{
            {"action", "changePasswordAdmin"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }

}

void ChangePseudonymAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }
    

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, uin, pack["auth_key"])) {
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, uin, {"admin"}))
    {
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("dest_uin")) {
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "Нет передаваемого клиента назначения"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого клиента назначения" << std::endl;
        return;
    }

    long long int dest_uin = 0;
    if (pack["dest_uin"].is_number()) {
        dest_uin = pack["dest_uin"].get<long long>();
    } else if (pack["dest_uin"].is_string()) {
        dest_uin = std::stoll(pack["dest_uin"].get<std::string>());
    }

    if(!pack.contains("new_pseudonym")) {
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "Нет передаваемого new_pseudonym"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого new_pseudonym" << std::endl;
        return;
    }

    if (Database::prepareStatement("UPDATE users SET pseudonym = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_pseudonym"].get<std::string>(),
            dest_uin
        };

        Database::executeUpdate(params);
        WsServer::authKeys[dest_uin]["pseudonym"] = pack["new_pseudonym"].get<std::string>();
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "Вы сменили псевдоним!"},
        };
        Answer(ws, ok, j);
        

        json broadcast = json{
            {"action", "broadcastChangePseudonymAdmin"},
            {"UIN", dest_uin},
            {"pseudonym", pack["new_pseudonym"].get<std::string>()}
        };
        ContactsBroadcast(dest_uin, ok, broadcast);
        return;
    } else {
        json j = json{
            {"action", "changePseudonymAdmin"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
    return;
}

void ChangeStatusAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    if(!pack.contains("UIN")) {
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "Нет передаваемого UIN"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого UIN" << std::endl;
        return;
    }

    long long int uin = 0;
    if (pack["UIN"].is_number()) {
        uin = pack["UIN"].get<long long>();
    } else if (pack["UIN"].is_string()) {
        uin = std::stoll(pack["UIN"].get<std::string>());
    }
    

    if(!pack.contains("auth_key")) {
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "Нет передаваемого токена авторизации"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого токена авторизации" << std::endl;
        return;
    }

    if(!verifyAuth(ws, uin, pack["auth_key"])) {
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, clientError, j);
        return;
    }

    if(!verifyRole(ws, uin, {"admin"}))
    {
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "У пользователя не хватает прав для совершения этого действия"},
        };
        Answer(ws, ok, j);
        return;
    }

    if(!pack.contains("dest_uin")) {
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "Нет передаваемого клиента назначения"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого клиента назначения" << std::endl;
        return;
    }

    long long int dest_uin = 0;
    if (pack["dest_uin"].is_number()) {
        dest_uin = pack["dest_uin"].get<long long>();
    } else if (pack["dest_uin"].is_string()) {
        dest_uin = std::stoll(pack["dest_uin"].get<std::string>());
    }

    if(!pack.contains("new_status")) {
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "Нет передаваемого new_status"},
        };
        Answer(ws, clientError, j);
        std::cerr << "Нет передаваемого new_status" << std::endl;
        return;
    }

    if (Database::prepareStatement("UPDATE users SET status = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["new_status"].get<std::string>(),
            dest_uin
        };

        Database::executeUpdate(params);
        WsServer::authKeys[dest_uin]["status"] = pack["new_status"].get<std::string>();
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "Вы сменили статус!"},
        };
        Answer(ws, ok, j);
        

        json broadcast = json{
            {"action", "broadcastChangeStatusAdmin"},
            {"UIN", dest_uin},
            {"status", pack["new_status"].get<std::string>()}
        };
        ContactsBroadcast(dest_uin, ok, broadcast);
        return;
    } else {
        json j = json{
            {"action", "changeStatusAdmin"},
            {"message", "Ошибка при подготовке SQL-запроса"},
        };
        Answer(ws, serverError, j);
        std::cerr << "Ошибка при подготовке SQL-запроса" << std::endl;
        return;
    }
    return;
}