#include "prepared_statement_pool.h"
#include "logger.h"
#include <chrono>

// Инициализация статических переменных
std::unordered_map<std::string, PreparedStatementWrapper> PreparedStatementPool::statements;
std::mutex PreparedStatementPool::poolMutex;

// ==================== Вспомогательный метод ====================

bool PreparedStatementPool::prepareAndStore(const std::string& name, const std::string& sqlQuery) {
    try {
        PreparedStatementWrapper wrapper = Database::prepareStatement(sqlQuery);
        
        if (!wrapper.isValid()) {
            return false;
        }
        
        statements[name] = std::move(wrapper);
        return true;
        
    } catch (const std::exception& e) {
        return false;
    }
}

// ==================== Инициализация всех запросов ====================

bool PreparedStatementPool::initializeAll() {
    std::lock_guard<std::mutex> lock(poolMutex);
    
    Logger::info("[POOL] 🚀 Начало инициализации пула подготовленных запросов...");
    auto startTime = std::chrono::steady_clock::now();
    
    // Очищаем старые запросы
    statements.clear();
    
    int successCount = 0;
    int failCount = 0;
    
    // ===== ВСЕ ПОДГОТОВЛЕННЫЕ ЗАПРОСЫ =====
    
    // Регистрация
    if (prepareAndStore("registration_insert", "INSERT INTO users (password_hash, pseudonym, status, roles, registration_date, is_active, aes_encryption_key, chat_enabled, max_chats_allowed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка существования пользователя
    if (prepareAndStore("exist_user", "SELECT password_hash, auth_token, aes_encryption_key, roles, is_active, pseudonym, status, is_addable FROM users WHERE UIN = ? AND is_active = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка роли
    if (prepareAndStore("get_role", "UPDATE users SET auth_token = ? WHERE UIN = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Создание нового токена авторизации
    if (prepareAndStore("new_auth_token", "UPDATE users SET auth_token = ? WHERE UIN = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Удаление токена авторизации
    if (prepareAndStore("delete_auth_token", "UPDATE users SET auth_token = NULL WHERE UIN = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Извелечение хеша пароля
    if (prepareAndStore("get_pass_hash", "SELECT password_hash FROM users WHERE UIN = ? AND is_active = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Замена хеша пароля
    if (prepareAndStore("update_pass_hash", "UPDATE users SET password_hash = ? WHERE UIN = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Поиск пользователей
    if (prepareAndStore("find_users", "SELECT UIN, pseudonym, status FROM users WHERE is_active = ? AND (pseudonym LIKE CONCAT('%', ?, '%') OR CAST(UIN AS CHAR) LIKE CONCAT('%', ?, '%'))")) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на существование UIN
    if (prepareAndStore("UIN_exist", "SELECT UIN, pseudonym, status, is_addable FROM users WHERE UIN = ? AND is_active = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на добавление контакта
    if (prepareAndStore("contact_exist", "SELECT id FROM contacts WHERE (initiator_uin = ? AND destination_uin = ?) OR (initiator_uin = ? AND destination_uin = ?) AND is_chat = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Создание заявки в контакты
    if (prepareAndStore("insert_new_contact", "INSERT INTO contacts (initiator_uin, destination_uin, is_chat, is_approved) VALUES (?, ?, ?, ?)")) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на существование контакта
    if (prepareAndStore("contact_exist_option", "SELECT id, initiator_uin FROM contacts WHERE id = ? AND destination_uin = ? AND is_approved = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на существование контакта с обоих сторон
    if (prepareAndStore("contact_exist_option_2", "SELECT id, initiator_uin, destination_uin FROM contacts WHERE id = ? AND (initiator_uin = ? OR destination_uin = ?) AND is_approved = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на существование сторона отправителя
    if (prepareAndStore("contact_exist_option_3", "SELECT id, destination_uin FROM contacts WHERE id = ? AND initiator_uin = ? AND is_approved = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Добавление в контакты
    if (prepareAndStore("accept_contact", "UPDATE contacts SET is_approved = ? WHERE id = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечение имени и статуса
    if (prepareAndStore("get_pseudo_stat", "SELECT pseudonym, status FROM users WHERE UIN = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Удаление контакта
    if (prepareAndStore("delete_contact", "DELETE FROM contacts WHERE id = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь все контакты
    if (prepareAndStore("get_contacts", 
        R"(SELECT
            c.id,
            CASE WHEN c.initiator_uin = ? THEN c.destination_uin ELSE c.initiator_uin END AS UIN,
            CASE WHEN c.initiator_uin = ? THEN dest_user.pseudonym ELSE init_user.pseudonym END AS pseudonym,
            CASE WHEN c.initiator_uin = ? THEN 'initiator' ELSE 'destination' END AS my_role, 
            CASE WHEN c.initiator_uin = ? THEN dest_user.status ELSE init_user.status END AS status,
            CASE WHEN c.initiator_uin = ? THEN dest_user.is_active ELSE init_user.is_active END AS is_active,
            c.is_approved,
            (
                SELECT COUNT(*)
                FROM messages m
                WHERE m.dest_uin = ?
                AND m.delivered = ?
                AND is_chat = ?
                AND dest_id = c.id
                AND m.deleted = FALSE
            ) AS undelivered_count
        FROM contacts c
        LEFT JOIN users init_user ON c.initiator_uin = init_user.UIN
        LEFT JOIN users dest_user ON c.destination_uin = dest_user.UIN
        WHERE (c.initiator_uin = ? OR c.destination_uin = ?) AND c.is_approved = ?
        ORDER BY c.id ASC)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь исходящие запросы
    if (prepareAndStore("outgoing_req", "SELECT c.id, u.UIN, u.pseudonym, u.status, u.is_active FROM contacts AS c LEFT JOIN users AS u ON c.destination_uin = u.UIN WHERE initiator_uin = ? AND is_approved = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь входящие запросы
    if (prepareAndStore("ingoing_req", "SELECT c.id, u.UIN, u.pseudonym, u.status, u.is_active FROM contacts AS c LEFT JOIN users AS u ON c.initiator_uin = u.UIN WHERE destination_uin = ? AND is_approved = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь ID всех контактов
    if (prepareAndStore("all_contacts_uins", "SELECT c.id, CASE WHEN c.initiator_uin = ? THEN c.destination_uin ELSE c.initiator_uin END AS UIN, CASE WHEN c.initiator_uin = ? THEN dest_user.pseudonym ELSE init_user.pseudonym END AS pseudonym, CASE WHEN c.initiator_uin = ? THEN 'initiator' ELSE 'destination' END AS my_role, CASE WHEN c.initiator_uin = ? THEN dest_user.status ELSE init_user.status END AS status, CASE WHEN c.initiator_uin = ? THEN dest_user.is_active ELSE init_user.is_active END AS is_active, c.is_approved FROM contacts c LEFT JOIN users init_user ON c.initiator_uin = init_user.UIN LEFT JOIN users dest_user ON c.destination_uin = dest_user.UIN WHERE (c.initiator_uin = ? OR c.destination_uin = ?) AND c.is_approved = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь все ID участников во всех чатах, в которых состоит пользователь
    if (prepareAndStore("all_chat_contacts_uins", 
        R"(
        SELECT DISTINCT cu2.user_uin, cu2.chat_id, cu.id
        FROM chat_users AS cu
        LEFT JOIN chats AS c ON c.id = cu.chat_id
        INNER JOIN chat_users AS cu2 ON cu.chat_id = cu2.chat_id 
            AND cu.user_uin != cu2.user_uin
            AND cu2.confirmed = TRUE
        WHERE cu.user_uin = ? 
            AND cu.confirmed = TRUE
            AND c.deleted = FALSE;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Изменить псевдоним
    if (prepareAndStore("change_pseudo", "UPDATE users SET pseudonym = ? WHERE UIN = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Изменить статус
    if (prepareAndStore("change_status", "UPDATE users SET status = ? WHERE UIN = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Смена AES ключа
    if (prepareAndStore("change_AES", "UPDATE users SET aes_encryption_key = ? WHERE UIN = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Бан пользователя
    if (prepareAndStore("ban_user", "UPDATE users SET is_active = ? WHERE UIN = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Обнуление авторизационного
    if (prepareAndStore("kick_user", "UPDATE users SET auth_token = NULL WHERE UIN = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Установить роль
    if (prepareAndStore("set_user_role", "UPDATE users SET roles = ? WHERE UIN = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Установить возможность добавления в контакты
    if (prepareAndStore("set_addable", "UPDATE users SET is_addable = ? WHERE UIN = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    // ===== КОНЕЦ СПИСКА ЗАПРОСОВ =====
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    Logger::info("[POOL] ✅ Инициализация завершена: " + 
                std::to_string(successCount) + " запросов подготовлено, " +
                std::to_string(failCount) + " ошибок за " +
                std::to_string(duration.count()) + " мс");
    
    if (successCount == 0) {
        Logger::error("[POOL] ❌ Критическая ошибка: не удалось подготовить ни одного запроса!");
        return false;
    }
    
    if (failCount > 0) {
        Logger::warning("[POOL] ⚠️ Некоторые запросы не были подготовлены. Проверьте логи выше.");
        return false;
    }
    
    Logger::info("[POOL] 📋 Список подготовленных запросов:");
    for (const auto& [name, stmt] : statements) {
        Logger::info("  ✅ " + name);
    }
    
    return true;
}

// ==================== Получение запросов ====================

PreparedStatementWrapper& PreparedStatementPool::getStatement(const std::string& name) {
    std::lock_guard<std::mutex> lock(poolMutex);
    
    auto it = statements.find(name);
    if (it == statements.end()) {
        Logger::error("[POOL] ❌ Запрос не найден: " + name);
        static PreparedStatementWrapper emptyWrapper;
        return emptyWrapper;
    }
    
    return it->second;
}

// ==================== Вспомогательные методы ====================

bool PreparedStatementPool::hasStatement(const std::string& name) {
    std::lock_guard<std::mutex> lock(poolMutex);
    return statements.find(name) != statements.end();
}

size_t PreparedStatementPool::size() {
    std::lock_guard<std::mutex> lock(poolMutex);
    return statements.size();
}

void PreparedStatementPool::clear() {
    std::lock_guard<std::mutex> lock(poolMutex);
    statements.clear();
    Logger::info("[POOL] 🗑️ Все запросы очищены");
}

std::vector<std::string> PreparedStatementPool::getStatementNames() {
    std::lock_guard<std::mutex> lock(poolMutex);
    
    std::vector<std::string> names;
    names.reserve(statements.size());
    
    for (const auto& [name, stmt] : statements) {
        names.push_back(name);
    }
    
    return names;
}

bool PreparedStatementPool::reloadStatement(const std::string& name, const std::string& sqlQuery) {
    std::lock_guard<std::mutex> lock(poolMutex);
    
    Logger::info("[POOL] 🔄 Перезагрузка запроса: " + name);
    statements.erase(name);
    return prepareAndStore(name, sqlQuery);
}