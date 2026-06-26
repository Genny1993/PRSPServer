#pragma once

#include <string>
#include <stdexcept>
#include "helpers.h"
#include "validators.h"
#include "database.h"
#include "crypt.h"

void NewChat(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "newChat";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!RequireField(ws, pack, "chat_name", func_name, "Нет передаваемого имени чата")) return;
    if(!RequireField(ws, pack, "chat_description", func_name, "Нет передаваемого имени чата")) return;

    if(pack["chat_name"].get<std::string>().length() < 1) {
        json j = json{
            {"action", func_name},
            {"message", "Имя чата слишком короткое. Должно быть не менее 1 символа"},
        };
        Answer(ws, clientError, j);
        return;
    }

    long long int uin = getIntAnyway(pack["UIN"]);
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    bool is_admin = verifyRole(ws, uin, {"admin"});

    if(!is_admin) {
        //Проверяем возможость создания чата
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "u.UIN, "
                "u.chat_enabled, "
                "u.max_chats_allowed, "
                "COUNT(c.id) AS current_chats_count, "
                "CASE "
                    "WHEN u.chat_enabled = FALSE THEN 0 "
                    "WHEN COUNT(c.id) >= u.max_chats_allowed THEN 1 "
                    "ELSE 2 "
                "END AS can_create_chat "
            "FROM "
                "users u "
            "LEFT JOIN "
                "chats c ON u.UIN = c.owner AND deleted = FALSE "
            "WHERE "
                "u.UIN = ? "
            "GROUP BY " 
                "u.UIN, u.chat_enabled, u.max_chats_allowed;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                uin
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }
        

        if(Permission[0]["can_create_chat"].get<int>() == 0 ) {
            json j = json{
                {"action", func_name},
                {"message", "У вас нет прав для создания чата"},
            };
            Answer(ws, clientError, j);
            return;
        } else if(Permission[0]["can_create_chat"].get<int>() == 1 ) {
            json j = json{
                {"action", func_name},
                {"message", "Превышен лимит создания чатов"},
            };
            Answer(ws, clientError, j);
            return;
        } else if(Permission[0]["can_create_chat"].get<int>() == 2 ) {
            long long new_id = 0;

            //Пытаемся вставить чат в базу данных
            if (Database::prepareStatement(
                "INSERT INTO chats (name, description, owner, deleted) "
                "VALUES (?, ?, ?, ?);")
            ) {
                std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                    pack["chat_name"].get<std::string>(),
                    pack["chat_description"].get<std::string>(),
                    uin,
                    false
                };
        
                new_id = Database::executeInsertAndGetId(params);
            } else {
                ThrowSQLError(ws, func_name);
                return;
            }

            //Пытаемся отправить ответ об успешном создании
            json j = json{
                {"action", func_name},
                {"id", new_id},
                {"is_owner", true},
                {"name", pack["chat_name"].get<std::string>()},
                {"description", pack["chat_description"].get<std::string>()},
                {"owner", uin}
            };
            Answer(ws, ok, j);
            return;
        }

    } else {
        long long new_id = 0;

        //Пытаемся вставить чат в базу данных
        if (Database::prepareStatement(
            "INSERT INTO chats (name, description, owner, deleted) "
            "VALUES (?, ?, ?, ?);")
        ) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_name"].get<std::string>(),
            pack["chat_description"].get<std::string>(),
            uin,
            false
        };
        
            new_id = Database::executeInsertAndGetId(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        //Пытаемся отправить ответ об успешном создании
        json j = json{
            {"action", func_name},
            {"id", new_id},
            {"is_owner", true},
            {"name", pack["chat_name"].get<std::string>()},
            {"description", pack["chat_description"].get<std::string>()},
            {"owner", uin}
        };
        Answer(ws, ok, j);
        return;
    }

    //TO DO: сделать владельца участником своего же чата
}

void DeleteChat(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "deleteChat";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;


    long long int uin = getIntAnyway(pack["UIN"]);
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    bool is_admin = verifyRole(ws, uin, {"admin"});

    if(!is_admin) {
        //Проверяем права на удаление чата
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "c.id "
            "FROM "
                "chats c "
            "WHERE "
                "c.id = ? AND c.owner = ? AND c.deleted = FALSE;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                pack["chat_id"].get<std::string>(),
                uin
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        if(Permission.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует, или удалён, или вы не имеете прав для удаления этого чата"},
            };
            Answer(ws, clientError, j);
            return;
        }
    }

    //Помечаем чат удаленным
    if (Database::prepareStatement("UPDATE chats SET deleted = ? WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            true,
            getIntAnyway(pack["chat_id"]),
        };
        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Доставляем сообщение о том, что чат удален
    json j = json{
        {"action", func_name},
        {"id", getIntAnyway(pack["chat_id"])},
        {"message", "Чат успешно удалён"}
    };
    Answer(ws, ok, j);

    //TO DO: Сделать рассылку участникам в сети об удалении чата
}

void ChangeChatName(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeChatName";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "chat_name", func_name, "Нет передаваемого имени чата")) return;

    if(pack["chat_name"].get<std::string>().length() < 1) {
        json j = json{
            {"action", func_name},
            {"message", "Имя чата слишком короткое. Должно быть не менее 1 символа"},
        };
        Answer(ws, clientError, j);
        return;
    }

    long long int uin = getIntAnyway(pack["UIN"]);
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    bool is_admin = verifyRole(ws, uin, {"admin"});

    if(!is_admin) {
        //Проверяем права на изменение чата
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "c.id "
            "FROM "
                "chats c "
            "WHERE "
                "c.id = ? AND c.owner = ? AND c.deleted = FALSE;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                pack["chat_id"].get<std::string>(),
                uin
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        if(Permission.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует, или удалён, или вы не имеете прав для изменения этого чата"},
            };
            Answer(ws, clientError, j);
            return;
        }
    }

    //Меняем имя
    if (Database::prepareStatement("UPDATE chats SET name = ? WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_name"].get<std::string>(),
            getIntAnyway(pack["chat_id"]),
        };
        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Доставляем сообщение о том, что имя чата изменено
    json j = json{
        {"action", func_name},
        {"id", pack["chat_id"]},
        {"name", pack["chat_name"]},
        {"message", "Имя чата успешно изменено"}
    };
    Answer(ws, ok, j);

    //TO DO: Сделать рассылку участникам в сети об изменении имени чата
}

void ChangeChatDesc(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeChatName";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "chat_description", func_name, "Нет передаваемого описания чата")) return;

    long long int uin = getIntAnyway(pack["UIN"]);
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    bool is_admin = verifyRole(ws, uin, {"admin"});

    if(!is_admin) {
        //Проверяем права на изменение чата
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "c.id "
            "FROM "
                "chats c "
            "WHERE "
                "c.id = ? AND c.owner = ? AND c.deleted = FALSE;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                pack["chat_id"].get<std::string>(),
                uin
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        if(Permission.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует, или удалён, или вы не имеете прав для изменения этого чата"},
            };
            Answer(ws, clientError, j);
            return;
        }
    }

    //Меняем описание
    if (Database::prepareStatement("UPDATE chats SET description = ? WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_description"].get<std::string>(),
            getIntAnyway(pack["chat_id"]),
        };
        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Доставляем сообщение о том, что описание чата изменено
    json j = json{
        {"action", func_name},
        {"id", pack["chat_id"]},
        {"description", pack["chat_description"]},
        {"message", "Описание чата успешно изменено"}
    };
    Answer(ws, ok, j);

    //TO DO: Сделать рассылку участникам в сети об изменении описания чата
}

void ChangeChatOwner(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeChatOwner";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "new_owner", func_name, "Нет передаваемого владельца чата")) return;

    long long int uin = getIntAnyway(pack["UIN"]);
    long long int new_owner = getIntAnyway(pack["new_owner"]);

    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"user", "admin"}, func_name)) return;

    bool is_admin = verifyRole(ws, uin, {"admin"});

    if(!is_admin) {
        //Проверяем права на изменение владельца чата
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "c.id "

            "FROM "
                "chats c "
            "WHERE "
                "c.id = ? AND c.owner = ? AND c.deleted = FALSE;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                pack["chat_id"].get<std::string>(),
                uin
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        if(Permission.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует, или удалён, или вы не имеете прав для изменения этого чата"},
            };
            Answer(ws, clientError, j);
            return;
        }
    }

    //Смотрим, cуществует ли такой пользоваетль
    if (Database::prepareStatement("SELECT UIN FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            new_owner,
            true
        };

        json verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Указанного пользователя не существует"},
            };
            Answer(ws, clientError, j);
            return;
        }
    }

    //Меняем владельца
    if (Database::prepareStatement("UPDATE chats SET owner = ? WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            new_owner,
            getIntAnyway(pack["chat_id"]),
        };
        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Доставляем сообщение о том, что владелец чата изменен
    json j = json{
        {"action", std::string(func_name) + "Sender"},
        {"chat_id", getIntAnyway(pack["chat_id"])},
        {"message", "Владелец чата успешно назначен"}
    };
    Answer(ws, ok, j);

    //Доставляем сообщение новому владельцу
    if (WsServer::authorizedSockets.find(new_owner) != WsServer::authorizedSockets.end()) {
        json j = json{
            {"action", std::string(func_name) + "Reciever"},
            {"chat_id", getIntAnyway(pack["chat_id"])},
            {"new_owner", new_owner},
            {"message", "Вы стали новым владельцем чата"}
        };
        Answer(WsServer::authorizedSockets[new_owner], ok, j);
    }

    //TO DO: Вписать нового владельца в участники чата
}

void ChangeUserChatPermAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeUserChatPermAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!RequireField(ws, pack, "new_permission", func_name, "Нет передаваемого разрешения участника")) return;
    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого пользователя")) return;

    long long int uin = getIntAnyway(pack["UIN"]);
    long long int dest_uin = getIntAnyway(pack["dest_uin"]);

    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    //Смотрим, cуществует ли такой пользоваетль
    if (Database::prepareStatement("SELECT UIN FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            dest_uin,
            true
        };

        json verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Указанного пользователя не существует"},
            };
            Answer(ws, clientError, j);
            return;
        }
    }

    //Меняем возможность создавать чаты
    if (Database::prepareStatement("UPDATE users SET chat_enabled = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["new_permission"]),
            dest_uin
        };
        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Доставляем сообщение о том, что возможность создавать чаты изменена
    json j = json{
        {"action", std::string(func_name) + "Sender"},
        {"permission", getIntAnyway(pack["new_permission"])},
        {"message", "Вы изменили возможность создания чатов для пользоваетля"}
    };
    Answer(ws, ok, j);

    //Доставляем сообщение об изменении 
    if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
        json j = json{
            {"action", std::string(func_name) + "Reciever"},
            {"permission", getIntAnyway(pack["new_permission"])},
            {"message", "Вам изменили возможность создавать чаты"}
        };
        Answer(WsServer::authorizedSockets[dest_uin], ok, j);
    }
}

void ChangeUserChatCountAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "changeUserChatCountAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!RequireField(ws, pack, "new_allowed_count", func_name, "Нет передаваемого количества разрешенных чатов")) return;
    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого пользователя")) return;

    long long int uin = getIntAnyway(pack["UIN"]);
    long long int dest_uin = getIntAnyway(pack["dest_uin"]);

    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin"}, func_name)) return;

    //Смотрим, cуществует ли такой пользоваетль
    if (Database::prepareStatement("SELECT UIN FROM users WHERE UIN = ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            dest_uin,
            true
        };

        json verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Указанного пользователя не существует"},
            };
            Answer(ws, clientError, j);
            return;
        }
    }

    //Меняем количество возможных чатов
    if (Database::prepareStatement("UPDATE users SET max_chats_allowed = ? WHERE UIN = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["new_allowed_count"]),
            dest_uin
        };
        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Доставляем сообщение о том, что возможность создавать чаты изменена
    json j = json{
        {"action", std::string(func_name) + "Sender"},
        {"count", getIntAnyway(pack["new_allowed_count"])},
        {"message", "Вы изменили лимит чатов пользователя"}
    };
    Answer(ws, ok, j);

    //Доставляем сообщение об изменении 
    if (WsServer::authorizedSockets.find(dest_uin) != WsServer::authorizedSockets.end()) {
        json j = json{
            {"action", std::string(func_name) + "Reciever"},
            {"count", getIntAnyway(pack["new_allowed_count"])},
            {"message", "Вам изменили лимит возможных чатов"}
        };
        Answer(WsServer::authorizedSockets[dest_uin], ok, j);
    }
}

void FindChats(WebSocketType* ws, const nlohmann::json& pack) {

    const std::string_view func_name = "findChats";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;
    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, getIntAnyway(pack["UIN"]), pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, getIntAnyway(pack["UIN"]), {"user", "admin"}, func_name)) return;

    if(!RequireField(ws, pack, "find_string", func_name, "Нет передаваемой строки поиска")) return;
    if(pack["find_string"].get<std::string>().length() < 1 ) {
        json j = json{
            {"action", func_name},
            {"message", "Строка поиска не должна быть менее 1 символа"},
        };
        Answer(ws, clientError, j);
        return;
    };

    if (Database::prepareStatement("SELECT id, name, description FROM chats WHERE deleted = ? AND (name LIKE CONCAT('%', ?, '%') OR description LIKE CONCAT('%', ?, '%'))")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            false,
            pack["find_string"].get<std::string>(),
            pack["find_string"].get<std::string>()
        };

        json findChats = Database::executeSelect(params);

        json j = json{
            {"action", func_name},
            {"chats", findChats}
        };
        Answer(ws, ok, j);
        return;

    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

}

void GetChats(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "getChats";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin", "user"}, func_name)) return;

    if(!RequireField(ws, pack, "limit", func_name, "Нет передаваемого limit")) return;
    if(!RequireField(ws, pack, "page", func_name, "Нет передаваемого page")) return;

    long long int limit = getIntAnyway(pack["limit"]);
    long long int page = getIntAnyway(pack["page"]);

    if(page < 1) {
        json j = json{
            {"action", func_name},
            {"message", "Страница не может быть меньше 1"},
        };
        Answer(ws, clientError, j);
        return;
    }
    
    //Достаем чаты
    json Chats = json{};
    if (Database::prepareStatement(R"(
        SELECT id, name, description
        FROM chats WHERE deleted = ? ORDER BY id ASC LIMIT )" + std::to_string(limit) + " OFFSET " + std::to_string(limit * (page - 1)) + ";"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            false
        };

        Chats = Database::executeSelect(params);
        
        //Отправляем ответ клиенту
        json j = json{
            {"action", func_name},
            {"chats", Chats},
        };
        Answer(ws, ok, j);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}