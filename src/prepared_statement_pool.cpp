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