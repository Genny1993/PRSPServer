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
            {"id", pack["chat_id"]},
            {"message", "Чат успешно удалён"}
        };
        Answer(ws, ok, j);

    } else {
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "c.id "
            "FROM "
                "chats c "
            "WHERE "
                "c.id = ? AND c.deleted = FALSE;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                pack["chat_id"].get<std::string>(),
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        if(Permission.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует, или удалён"},
            };
            Answer(ws, clientError, j);
            return;
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
            {"id", pack["chat_id"]},
            {"message", "Чат успешно удалён"}
        };
        Answer(ws, ok, j);
    }

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

    } else {
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "c.id "
            "FROM "
                "chats c "
            "WHERE "
                "c.id = ? AND c.deleted = FALSE;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                pack["chat_id"].get<std::string>(),
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        if(Permission.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует, или удалён"},
            };
            Answer(ws, clientError, j);
            return;
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
    }

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

    } else {
        json Permission = json{};
        if (Database::prepareStatement(
            "SELECT "
                "c.id "
            "FROM "
                "chats c "
            "WHERE "
                "c.id = ? AND c.deleted = FALSE;"
        )) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                pack["chat_id"].get<std::string>(),
            };
            Permission = Database::executeSelect(params);
        } else {
            ThrowSQLError(ws, func_name);
            return;
        }

        if(Permission.empty()) {
            json j = json{
                {"action", func_name},
                {"message", "Чат не существует, или удалён"},
            };
            Answer(ws, clientError, j);
            return;
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
    }

    //TO DO: Сделать рассылку участникам в сети об изменении описания чата
}