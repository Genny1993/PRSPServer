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

    long long new_id = 0;

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
        }

    } else {

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
    }

    //Добавляем заявку
    long long int newID = 0;
    if (Database::prepareStatement("INSERT INTO chat_users (user_uin, chat_id, confirmed, role) VALUES (?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            new_id,
            true,
            "[\"admin\"]"
        };
        
        newID = Database::executeInsertAndGetId(params);

        //Пытаемся отправить ответ об успешном создании
        json j = json{
            {"action", func_name},
            {"id", newID},
            {"chat_id", new_id},
            {"is_owner", true},
            {"name", pack["chat_name"].get<std::string>()},
            {"description", pack["chat_description"].get<std::string>()},
            {"owner", uin}
        };
        Answer(ws, ok, j);
        return;
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

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

    //Рассылка участникам в сети об удалении чата
    nlohmann::json ChatUsers = nlohmann::json{};
    if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            true
        };

        ChatUsers = Database::executeSelect(params);

        for (auto& item : ChatUsers) {
            if (item.is_object()) {
                long long int c_uin = item["user_uin"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    json j = json{
                        {"action", std::string(func_name) + "Reciever"},
                        {"id", pack["chat_id"]},
                        {"message", "Чат удален"},
                    };
                    Answer(WsServer::authorizedSockets[c_uin], ok, j);
                }
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    return;

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

    //Рассылка участникам в сети об изменении имени чата
    nlohmann::json ChatUsers = nlohmann::json{};
    if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            true
        };

        ChatUsers = Database::executeSelect(params);

        for (auto& item : ChatUsers) {
            if (item.is_object()) {
                long long int c_uin = item["user_uin"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    json j = json{
                        {"action", std::string(func_name) + "Reciever"},
                        {"id", pack["chat_id"]},
                        {"name", pack["chat_name"]}
                    };
                    Answer(WsServer::authorizedSockets[c_uin], ok, j);
                }
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
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

    //Рассылка участникам в сети об изменении описания чата
    nlohmann::json ChatUsers = nlohmann::json{};
    if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            true
        };

        ChatUsers = Database::executeSelect(params);

        for (auto& item : ChatUsers) {
            if (item.is_object()) {
                long long int c_uin = item["user_uin"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    json j = json{
                        {"action", std::string(func_name) + "Reciever"},
                        {"id", pack["chat_id"]},
                        {"description", pack["chat_description"]}
                    };
                    Answer(WsServer::authorizedSockets[c_uin], ok, j);
                }
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
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

    //Вписываем нового владельца в участники.
    if (Database::prepareStatement("SELECT id FROM chat_users WHERE chat_id = ? AND user_uin = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            new_owner
        };

        json verifyUser = Database::executeSelect(params);

        if(verifyUser.empty()) {
            //Создаем новую запись
            if (Database::prepareStatement("INSERT INTO chat_users (user_uin, chat_id, confirmed, role) VALUES (?, ?, ?, ?)")) {
                std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                    new_owner,
                    getIntAnyway(pack["chat_id"]),
                    true,
                    "[\"admin\"]"
                };
                
                Database::executeInsertAndGetId(params);
                return;
            } else {
                ThrowSQLError(ws, func_name);
                return;
            }
            return;
        } else {
            //Редактируем текущую
            if (Database::prepareStatement("UPDATE chat_users SET confirmed = ?, role = ? WHERE chat_id = ? AND user_uin = ?")) {
                std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                    true,
                    "[\"admin\"]",
                    getIntAnyway(pack["chat_id"]),
                    new_owner
                };
                Database::executeUpdate(params);
                return;
            } else {
                ThrowSQLError(ws, func_name);
                return;
            }
        }
    }
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

void NewChatRequest(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "newChatRequest";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin", "user"}, func_name)) return;

    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;

    //Проверяем чат на существование
    json Chats = json{};
    if (Database::prepareStatement(R"(
        SELECT id
        FROM chats WHERE deleted = ? AND id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            false,
            pack["chat_id"].get<std::string>()
        };

        Chats = Database::executeSelect(params);
        
        //Отправляем ответ клиенту если чата нет
        if(Chats.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует или удален"},
            };
            Answer(ws, ok, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Проверяем заявку на существование
    json Request = json{};
    if (Database::prepareStatement(R"(
        SELECT id
        FROM chat_users WHERE user_uin = ? AND chat_id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            pack["chat_id"].get<std::string>()
        };

        Request = Database::executeSelect(params);
        
        //Отправляем ответ клиенту если чата нет
        if(!Request.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Вы уже подали заявку или состоите в чате"},
            };
            Answer(ws, ok, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Добавляем заявку
    long long int newID = 0;
    if (Database::prepareStatement("INSERT INTO chat_users (user_uin, chat_id, confirmed, role) VALUES (?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            pack["chat_id"].get<std::string>(),
            false,
            "[\"user\"]"
        };
        
        newID = Database::executeInsertAndGetId(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправляем заявку вступившему
    json Chat = json{};
    if (Database::prepareStatement(R"(
        SELECT *
        FROM chats WHERE id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_id"].get<std::string>()
        };

        Chat = Database::executeSelect(params);
        
        if(!Chat.empty()) {
            json j = json{
                {"action", std::string(func_name) + "Sender"},
                {"id", newID},
                {"chat_id", Chat[0]["id"]},
                {"chat_name", Chat[0]["name"]},
                {"chat_description", Chat[0]["description"]},
            };
            Answer(ws, ok, j);
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправляем заявку админам чата, если они онлайн
    //Получаем данные о человеке
    json User = json{};
    if (Database::prepareStatement(R"(
        SELECT *
        FROM users WHERE UIN = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin
        };
        User = Database::executeSelect(params);

        if(!User.empty()) {
            nlohmann::json ChatAdmins = nlohmann::json{};
            if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ? AND role =?")) {
                std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                    getIntAnyway(pack["chat_id"]),
                    true,
                    "[\"admin\"]"
                };

                ChatAdmins = Database::executeSelect(params);

                for (auto& item : ChatAdmins) {
                    if (item.is_object()) {
                        long long int c_uin = item["user_uin"].get<long long int>();
                        if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                            json j = json{
                                {"action", std::string(func_name) + "Receiver"},
                                {"id", newID},
                                {"chat_id", Chat[0]["id"]},
                                {"UIN", User[0]["UIN"]},
                                {"pseudonym", User[0]["pseudonym"]},
                                {"status", User[0]["status"]},
                            };
                            Answer(WsServer::authorizedSockets[c_uin], ok, j);
                        }
                    }
                }
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

void CancelChatRequest(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "cancelChatRequest";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin", "user"}, func_name)) return;

    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "request_id", func_name, "Нет передаваемой id заявки")) return;

    //Проверяем заявку на существование
    json Request = json{};
    if (Database::prepareStatement(R"(
        SELECT id
        FROM chat_users WHERE user_uin = ? AND chat_id = ? AND confirmed = ? AND id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            pack["chat_id"].get<std::string>(),
            false,
            pack["request_id"].get<std::string>(),
        };

        Request = Database::executeSelect(params);
        
        //Отправляем ответ клиенту если чата нет
        if(Request.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Заявки не существует, или она уже принята"},
            };
            Answer(ws, ok, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Удаляем заявку
    if (Database::prepareStatement("DELETE FROM chat_users WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["request_id"])
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту
        json j = json{
            {"action", std::string(func_name) + "Sender"},
            {"id", pack["request_id"]},
            {"message", "Заявка отменена"}
        };
        Answer(ws, ok, j);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправляем отмену заявки админу чата, если он онлайн
    nlohmann::json ChatAdmins = nlohmann::json{};
    if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ? AND role =?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            true,
            "[\"admin\"]"
        };

        ChatAdmins = Database::executeSelect(params);

        for (auto& item : ChatAdmins) {
            if (item.is_object()) {
                long long int c_uin = item["user_uin"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    json j = json{
                        {"action", std::string(func_name) + "Receiver"},
                        {"id", pack["request_id"]},
                        {"message", "Заявка отменена пользователем"}
                    };
                    Answer(WsServer::authorizedSockets[c_uin], ok, j);
                }
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void RejectChatRequest(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "rejectChatRequest";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin", "user"}, func_name)) return;

    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "request_id", func_name, "Нет передаваемой id заявки")) return;
    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого UIN заявителя")) return;

    //Проверяем права админа чата
    json Permission = json{};
    if (Database::prepareStatement(
        "SELECT "
            "cu.id "
        "FROM "
            "chat_users cu "
        "WHERE "
            "cu.chat_id = ? AND cu.user_uin = ? AND cu.role = ? AND cu.confirmed = TRUE;"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_id"].get<std::string>(),
            uin,
            "[\"admin\"]"
        };
        Permission = Database::executeSelect(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    if(Permission.empty()) {
        json j = json{
            {"action", func_name},
            {"message", "Чат не существует, или вы не имеете прав на изменение"},
        };
        Answer(ws, clientError, j);
        return;
    }
    
    //Проверяем заявку на существование
    json Request = json{};
    if (Database::prepareStatement(R"(
        SELECT id
        FROM chat_users WHERE user_uin = ? AND chat_id = ? AND confirmed = ? AND id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["dest_uin"]),
            pack["chat_id"].get<std::string>(),
            false,
            pack["request_id"].get<std::string>()
        };

        Request = Database::executeSelect(params);
        
        //Отправляем ответ клиенту если чата нет
        if(Request.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Заявки не существует, или она уже принята"},
            };
            Answer(ws, ok, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Удаляем заявку
    if (Database::prepareStatement("DELETE FROM chat_users WHERE id = ? AND user_uin = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["request_id"]),
            getIntAnyway(pack["dest_uin"])
        };

        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправить админам в сети отказ
    nlohmann::json ChatAdmins = nlohmann::json{};
    if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ? AND role =?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            true,
            "[\"admin\"]"
        };

        ChatAdmins = Database::executeSelect(params);

        for (auto& item : ChatAdmins) {
            if (item.is_object()) {
                long long int c_uin = item["user_uin"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    json j = json{
                        {"action", std::string(func_name) + "Receiver"},
                        {"id", pack["request_id"]},
                        {"message", "Заявка отклонена администратором"}
                    };
                    Answer(WsServer::authorizedSockets[c_uin], ok, j);
                }
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправить пользователю отказ
    if (WsServer::authorizedSockets.find(getIntAnyway(pack["dest_uin"])) != WsServer::authorizedSockets.end()) {
        json j = json{
            {"action", std::string(func_name) + "Receiver"},
            {"id", pack["request_id"]},
            {"message", "Заявка отклонена"}
        };
        Answer(WsServer::authorizedSockets[getIntAnyway(pack["dest_uin"])], ok, j);
        return;
    }
}

void AcceptChatRequest(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "acceptChatRequest";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin", "user"}, func_name)) return;

    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "request_id", func_name, "Нет передаваемой id заявки")) return;
    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого UIN заявителя")) return;

    //Проверяем права админа чата
    json Permission = json{};
    if (Database::prepareStatement(
        "SELECT "
            "cu.id "
        "FROM "
            "chat_users cu "
        "WHERE "
            "cu.chat_id = ? AND cu.user_uin = ? AND cu.role = ? AND cu.confirmed = TRUE;"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_id"].get<std::string>(),
            uin,
            "[\"admin\"]"
        };
        Permission = Database::executeSelect(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    if(Permission.empty()) {
        json j = json{
            {"action", func_name},
            {"message", "Чат не существует, или вы не имеете прав на изменение"},
        };
        Answer(ws, clientError, j);
        return;
    }
    
    //Проверяем заявку на существование
    json Request = json{};
    if (Database::prepareStatement(R"(
        SELECT id
        FROM chat_users WHERE user_uin = ? AND chat_id = ? AND confirmed = ? AND id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["dest_uin"]),
            pack["chat_id"].get<std::string>(),
            false,
            pack["request_id"].get<std::string>()
        };

        Request = Database::executeSelect(params);
        
        //Отправляем ответ клиенту если чата нет
        if(Request.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Заявки не существует, или она уже принята"},
            };
            Answer(ws, ok, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Принимаем заяку
    if (Database::prepareStatement("UPDATE chat_users SET confirmed = ? WHERE id = ? AND user_uin = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            true,
            getIntAnyway(pack["request_id"]),
            getIntAnyway(pack["dest_uin"])
        };

        Database::executeUpdate(params);
        
        json User = json{};
        if (Database::prepareStatement(R"(
            SELECT *
            FROM users WHERE UIN = ?;)"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                getIntAnyway(pack["dest_uin"])
            };
            User = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        bool online;
        if (WsServer::authorizedSockets.find(getIntAnyway(pack["dest_uin"])) != WsServer::authorizedSockets.end()) {
            online = true;
        } else {
            online = false;
        }

        //Отправляем ответ всем пользователям чата в сети
        nlohmann::json ChatUsers = nlohmann::json{};
        if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ?")) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                getIntAnyway(pack["chat_id"]),
                true
            };

            ChatUsers = Database::executeSelect(params);

            for (auto& item : ChatUsers) {
                if (item.is_object()) {
                    long long int c_uin = item["user_uin"].get<long long int>();
                    if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                        json j = json{
                            {"action", std::string(func_name) + "Receiver"},
                            {"id", pack["request_id"]},
                            {"chat_id", getIntAnyway(pack["chat_id"]),},
                            {"UIN", User[0]["UIN"]},
                            {"pseudonym", User[0]["pseudonym"]},
                            {"status", User[0]["status"]},
                            {"online", online},
                            {"message", "Новый участник чата"}
                        };
                        Answer(WsServer::authorizedSockets[c_uin], ok, j);
                    }
                }
            }
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправляем оповещение поступившему
    json Chat = json{};
    if (Database::prepareStatement(R"(
        SELECT *
        FROM chats WHERE id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_id"].get<std::string>()
        };

        Chat = Database::executeSelect(params);
        
        if(!Chat.empty()) {
            if (WsServer::authorizedSockets.find(getIntAnyway(pack["dest_uin"])) != WsServer::authorizedSockets.end()) {
                json j = json{
                    {"action", std::string(func_name) + "Sender"},
                    {"id", pack["request_id"]},
                    {"chat_id", Chat[0]["id"]},
                    {"chat_name", Chat[0]["name"]},
                    {"chat_description", Chat[0]["description"]},
                };
                Answer(WsServer::authorizedSockets[getIntAnyway(pack["dest_uin"])], ok, j);
                return;
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void RemoveChatContact(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "removeChatContact";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin", "user"}, func_name)) return;

    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "request_id", func_name, "Нет передаваемой id заявки")) return;
    
    //Проверяем заявку на существование
    json Request = json{};
    if (Database::prepareStatement(R"(
        SELECT id
        FROM chat_users WHERE user_uin = ? AND chat_id = ? AND confirmed = ? AND id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            uin,
            pack["chat_id"].get<std::string>(),
            true,
            pack["request_id"].get<std::string>(),
        };

        Request = Database::executeSelect(params);
        
        //Отправляем ответ клиенту если чата нет
        if(Request.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Контакта чата не существует"},
            };
            Answer(ws, ok, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Удаляем заявку
    if (Database::prepareStatement("DELETE FROM chat_users WHERE id = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["request_id"])
        };

        Database::executeUpdate(params);
                        
      
        //Отправляем ответ клиенту
        json j = json{
            {"action", std::string(func_name) + "Sender"},
            {"id", pack["request_id"]},
            {"message", "Вы вышли из чата"}
        };
        Answer(ws, ok, j);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправляем удаление чата пользователем, если они онлайн
    nlohmann::json ChatUsers = nlohmann::json{};
    if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            true
        };

        ChatUsers = Database::executeSelect(params);

        for (auto& item : ChatUsers) {
            if (item.is_object()) {
                long long int c_uin = item["user_uin"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    json j = json{
                        {"action", std::string(func_name) + "Receiver"},
                        {"id", pack["request_id"]},
                        {"message", "Пользователь вышел из чата"}
                    };
                    Answer(WsServer::authorizedSockets[c_uin], ok, j);
                }
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }
}

void RemoveChatContactAdmin(WebSocketType* ws, const nlohmann::json& pack) {
    const std::string_view func_name = "removeChatContactAdmin";
    if(!RequireField(ws, pack, "UIN", func_name, "Нет передаваемого UIN")) return;

    long long int uin = getIntAnyway(pack["UIN"]);

    if(!RequireField(ws, pack, "auth_key", func_name, "Нет передаваемого токена авторизации")) return;
    if(!VerifyAuthEnv(ws, uin, pack["auth_key"], func_name )) return;
    if(!VerifyRoleEnv(ws, uin, {"admin", "user"}, func_name)) return;

    if(!RequireField(ws, pack, "chat_id", func_name, "Нет передаваемого id чата")) return;
    if(!RequireField(ws, pack, "request_id", func_name, "Нет передаваемой id заявки")) return;
    if(!RequireField(ws, pack, "dest_uin", func_name, "Нет передаваемого UIN заявителя")) return;

    //Проверяем права админа чата
    json Permission = json{};
    if (Database::prepareStatement(
        "SELECT "
            "cu.id "
        "FROM "
            "chat_users cu "
        "WHERE "
            "cu.chat_id = ? AND cu.user_uin = ? AND cu.role = ? AND cu.confirmed = TRUE;"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            pack["chat_id"].get<std::string>(),
            uin,
            "[\"admin\"]"
        };
        Permission = Database::executeSelect(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    if(Permission.empty()) {
        json j = json{
            {"action", func_name},
            {"message", "Чат не существует, или вы не имеете прав на изменение"},
        };
        Answer(ws, clientError, j);
        return;
    }
    
    //Проверяем заявку на существование
    json Request = json{};
    if (Database::prepareStatement(R"(
        SELECT id
        FROM chat_users WHERE user_uin = ? AND chat_id = ? AND confirmed = ? AND id = ?;)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["dest_uin"]),
            pack["chat_id"].get<std::string>(),
            true,
            pack["request_id"].get<std::string>()
        };

        Request = Database::executeSelect(params);
        
        //Отправляем ответ клиенту если чата нет
        if(Request.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Пользователя не существует"},
            };
            Answer(ws, ok, j);
            return;
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Удаляем заявку
    if (Database::prepareStatement("DELETE FROM chat_users WHERE id = ? AND user_uin = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["request_id"]),
            getIntAnyway(pack["dest_uin"])
        };

        Database::executeUpdate(params);
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправить пользователям в сети удаление участника
    nlohmann::json ChatUsers = nlohmann::json{};
    if (Database::prepareStatement("SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? and confirmed = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            getIntAnyway(pack["chat_id"]),
            true
        };

        ChatUsers = Database::executeSelect(params);

        for (auto& item : ChatUsers) {
            if (item.is_object()) {
                long long int c_uin = item["user_uin"].get<long long int>();
                if (WsServer::authorizedSockets.find(c_uin) != WsServer::authorizedSockets.end()) {
                    json j = json{
                        {"action", std::string(func_name) + "Receiver"},
                        {"id", pack["request_id"]},
                        {"message", "Пользователь удален из чата"}
                    };
                    Answer(WsServer::authorizedSockets[c_uin], ok, j);
                }
            }
        }
    } else {
        ThrowSQLError(ws, func_name);
        return;
    }

    //Отправить пользователю удаление
    if (WsServer::authorizedSockets.find(getIntAnyway(pack["dest_uin"])) != WsServer::authorizedSockets.end()) {
        json j = json{
            {"action", std::string(func_name) + "ReceiverDest"},
            {"id", pack["request_id"]},
            {"message", "Администратор удалил вас из чата"}
        };
        Answer(WsServer::authorizedSockets[getIntAnyway(pack["dest_uin"])], ok, j);
        return;
    }
}