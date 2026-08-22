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

    //Проверка на существование пользователя с UIN
    if (prepareAndStore("user_exist", "SELECT UIN FROM users WHERE UIN = ? AND is_active = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на существование контакта 4
    if (prepareAndStore("contact_exist_option_4", "SELECT id, initiator_uin, destination_uin FROM contacts WHERE (initiator_uin = ? AND destination_uin = ?) OR (initiator_uin = ? AND destination_uin = ?) AND is_chat = ? AND id = ? AND is_approved = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на на возможность цитирования
    if (prepareAndStore("answer_possible", "SELECT id FROM messages WHERE dest_id = ? AND id = ? AND deleted = ? AND is_chat = FALSE"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на на возможность цитирования чаты
    if (prepareAndStore("answer_possible_chat", "SELECT id FROM messages WHERE dest_id = ? AND id = ? AND deleted = ? AND is_chat = TRUE"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Вставка нового сообщения в базу
    if (prepareAndStore("new_message",  "INSERT INTO messages (in_uin, dest_uin, dest_id, is_chat, time_stamp, delivered, deleted, message, answer_id, attachment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Вставка нового сообщения в базу для чата
    if (prepareAndStore("new_message_chat",  "INSERT INTO messages (in_uin, dest_id, is_chat, time_stamp, delivered, deleted, message, answer_id, attachment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Получение цитаты
    if (prepareAndStore("message_answer",  
        R"(SELECT m.id, u.pseudonym, m.message FROM messages AS m
        LEFT JOIN users AS u ON u.UIN = in_uin
        WHERE dest_id = ? AND id = ? AND deleted = ? LIMIT 1)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка прав на группу
    if (prepareAndStore("chat_permission",  
        R"(SELECT
                cu.id
            FROM
                chat_users cu
            LEFT JOIN chats AS c ON cu.chat_id = c.id
            WHERE
                cu.chat_id = ? 
                AND cu.user_uin = ? 
                AND (
                        cu.role = ? 
                        OR cu.role = ?
                    ) 
                AND cu.confirmed = TRUE 
                AND c.deleted = FALSE;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь данные о пользователе
    if (prepareAndStore("user_data", "SELECT * FROM users WHERE UIN = ? AND is_active = ?"   
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //получить всех пользователей в чате кроме отправителя
    if (prepareAndStore("all_chat_users", "SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? AND confirmed = ? AND user_uin != ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //получить всех пользователей в чате
    if (prepareAndStore("all_chat_users_all", "SELECT cu.user_uin FROM chat_users as cu WHERE chat_id = ? AND confirmed = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка на существование контакта 5
    if (prepareAndStore("contact_exist_option_5", "SELECT id FROM contacts WHERE (initiator_uin = ? OR destination_uin = ?) AND is_chat = ? AND id = ? AND is_approved = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Количество страниц
    if (prepareAndStore("count_page", R"(
        SELECT (COUNT(*) + ? - 1) / ? AS total_pages
        FROM messages AS m
        WHERE m.dest_id = ? AND m.deleted = ? AND m.is_chat = ?;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь сообщения
    if (prepareAndStore("get_last_messages", R"(
        SELECT 
            m.*,
            CASE WHEN u2.pseudonym IS NOT NULL THEN u2.pseudonym END AS sender_pseudonym,
            CASE WHEN m2.id IS NOT NULL THEN m2.id END AS answer_id,
            CASE WHEN m2.message IS NOT NULL THEN m2.message END AS answer_message,
            CASE WHEN u.pseudonym IS NOT NULL THEN u.pseudonym END AS answer_pseudonym,
            CASE 
                WHEN m.in_uin = ? THEN 1 
                ELSE 0 
            END AS is_my 
        FROM messages AS m
        LEFT JOIN messages AS m2 ON m.answer_id = m2.id AND m2.deleted = FALSE
        LEFT JOIN users AS u ON m2.in_uin = u.UIN
        LEFT JOIN users AS u2 ON m.in_uin = u2.UIN
        WHERE m.dest_id = ? AND m.deleted = ? AND m.is_chat = ? ORDER BY m.id DESC LIMIT ?;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Извлечь сообщения
    if (prepareAndStore("get_history_messages", R"(
        SELECT 
            m.*,
            CASE WHEN u2.pseudonym IS NOT NULL THEN u2.pseudonym END AS sender_pseudonym,
            CASE WHEN m2.id IS NOT NULL THEN m2.id END AS answer_id,
            CASE WHEN m2.message IS NOT NULL THEN m2.message END AS answer_message,
            CASE WHEN u.pseudonym IS NOT NULL THEN u.pseudonym END AS answer_pseudonym,
            CASE 
                WHEN m.in_uin = ? THEN 1 
                ELSE 0 
            END AS is_my 
        FROM messages AS m
        LEFT JOIN messages AS m2 ON m.answer_id = m2.id AND m2.deleted = FALSE
        LEFT JOIN users AS u ON m2.in_uin = u.UIN
        LEFT JOIN users AS u2 ON m.in_uin = u2.UIN
        WHERE m.dest_id = ? AND m.deleted = ? AND m.is_chat = ? ORDER BY m.id DESC LIMIT ? OFFSET ?;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Соотносится ли сообщение с личным чатом.
    if (prepareAndStore("message_request", "SELECT id FROM messages WHERE id = ? AND is_chat = ? AND dest_id = ? AND deleted = ? AND dest_uin = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Соотносится ли сообщение с личным чатом.
    if (prepareAndStore("message_request_admin", "SELECT id FROM messages WHERE id = ? AND is_chat = ? AND dest_id = ? AND deleted = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Пометить сообщение доставленным
    if (prepareAndStore("set_delivered", "UPDATE messages SET delivered = ? WHERE id = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Пометить сообщение удаленным
    if (prepareAndStore("set_deleted", "UPDATE messages SET deleted = ? WHERE id = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Является ли пользователь админом
    if (prepareAndStore("is_chat_admin", 
        R"(SELECT
            cu.id
        FROM
            chat_users cu
        WHERE
            cu.chat_id = ? 
            AND cu.user_uin = ? 
            AND cu.role = ? 
            AND cu.confirmed = TRUE;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Является ли сообщение от этого пользователя
    if (prepareAndStore("is_mess_chat", 
        R"(SELECT
            m.id
        FROM
            messages m
        WHERE
            m.dest_id = ? AND m.in_uin = ? AND m.deleted = FALSE;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Является ли сообщение от этого пользователя
    if (prepareAndStore("set_edited", "UPDATE messages SET message = ? WHERE id = ?"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Является ли сообщение доступным в личке
    if (prepareAndStore("message_perm", R"(
        SELECT m.id
        FROM
            messages AS m
        WHERE
            (m.in_uin = ? OR m.dest_uin = ?) AND is_chat = FALSE AND deleted = FALSE AND id = ?)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Является ли сообщение доступным в чате?
    if (prepareAndStore("message_perm_chat", R"(
        SELECT m.id
        FROM
            messages AS m
        JOIN chats AS c ON c.id = m.dest_id
        JOIN chat_users AS cu ON cu.confirmed = TRUE AND cu.chat_id = c.id
        WHERE
            m.is_chat = TRUE AND m.deleted = FALSE AND m.id = ? AND cu.user_uin = ?)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Достать сообщение с заданным id
    if (prepareAndStore("get_message", R"(
        SELECT m.*,
            CASE WHEN u2.pseudonym IS NOT NULL THEN u2.pseudonym END AS sender_pseudonym,
            CASE WHEN m2.id IS NOT NULL THEN m2.id END AS answer_id,
            CASE WHEN m2.message IS NOT NULL THEN m2.message END AS answer_message,
            CASE WHEN u.pseudonym IS NOT NULL THEN u.pseudonym END AS answer_pseudonym,
            CASE 
                WHEN m.in_uin = ? THEN 1 
                ELSE 0 
            END AS is_my 
        FROM messages AS m
        LEFT JOIN messages AS m2 ON m.answer_id = m2.id AND m2.deleted = FALSE
        LEFT JOIN users AS u ON m2.in_uin = u.UIN
        LEFT JOIN users AS u2 ON m.in_uin = u2.UIN
        WHERE m.id = ?;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка возмоности создания чата
    if (prepareAndStore("new_chat_perm", 
        R"(SELECT
            u.UIN,
            u.chat_enabled,
            u.max_chats_allowed,
            COUNT(c.id) AS current_chats_count,
            CASE
                WHEN u.chat_enabled = FALSE THEN 0
                WHEN COUNT(c.id) >= u.max_chats_allowed THEN 1
                ELSE 2
                END AS can_create_chat 
        FROM
            users u
        LEFT JOIN
            chats c ON u.UIN = c.owner AND deleted = FALSE
        WHERE
            u.UIN = ?
        GROUP BY
            u.UIN, u.chat_enabled, u.max_chats_allowed;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Вставка нового чата в БД
    if (prepareAndStore("insert_chat", R"(INSERT INTO chats (name, description, owner, deleted) VALUES (?, ?, ?, ?);)"
    )) {
        successCount++;
    } else {
        failCount++;
    }
    

    //Добавление админа в новый чат
    if (prepareAndStore("insert_admin", R"(INSERT INTO chat_users (user_uin, chat_id, confirmed, role) VALUES (?, ?, ?, ?);)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Проверка прав на владение чатом
    if (prepareAndStore("owner_perm", 
        R"(SELECT
            c.id
        FROM
            chats c
        WHERE
            c.id = ? AND c.owner = ? AND c.deleted = FALSE;)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //Удаление чата
    if (prepareAndStore("del_chat", "UPDATE chats SET deleted = ? WHERE id = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Изменение имени чата
    if (prepareAndStore("c_name_chat", "UPDATE chats SET name = ? WHERE id = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Изменение описания чата
    if (prepareAndStore("c_desc_chat", "UPDATE chats SET description = ? WHERE id = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //Изменение владельца чата
    if (prepareAndStore("c_owner_chat", "UPDATE chats SET owner = ? WHERE id = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //проверка, состоит ли пользователь в чате
    if (prepareAndStore("user_is_member", "SELECT id FROM chat_users WHERE chat_id = ? AND user_uin = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //изменение роли пользователя чата
    if (prepareAndStore("c_member_role", "UPDATE chat_users SET confirmed = ?, role = ? WHERE chat_id = ? AND user_uin = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //изменение возможности создать чат
    if (prepareAndStore("c_chat_creatable", "UPDATE users SET chat_enabled = ? WHERE UIN = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //изменение количества возможных чатов
    if (prepareAndStore("c_chat_count", "UPDATE users SET max_chats_allowed = ? WHERE UIN = ?")) {
        successCount++;
    } else {
        failCount++;
    }

    //определение количества существующих страниц поиска чатов
    if (prepareAndStore("chat_count_page", R"(
        SELECT (COUNT(*) + ? - 1) / ? AS total_pages
        FROM chats
        WHERE deleted = ? 
            AND 
                (name LIKE CONCAT('%', ?, '%') 
                OR 
                description LIKE CONCAT('%', ?, '%'));)"
    )) {
        successCount++;
    } else {
        failCount++;
    }

    //поиск чатов
    if (prepareAndStore("get_find_chats", "SELECT id, name, description FROM chats WHERE deleted = ? AND (name LIKE CONCAT('%', ?, '%') OR description LIKE CONCAT('%', ?, '%')) LIMIT ? OFFSET ?;)")) {
        successCount++;
    } else {
        failCount++;
    }

    //Чаты по популярности
    if (prepareAndStore("get_find_pop_chats", R"(
        SELECT 
            c.id,
            c.name,
            c.description,
            COALESCE(mc.cnt, 0) AS messages,
            COALESCE(uc.cnt, 0) AS members,
            COALESCE(mc.cnt, 0) * LOG(COALESCE(uc.cnt, 1) + 1) AS popularity
        FROM chats AS c
        LEFT JOIN (
            SELECT dest_id, COUNT(*) AS cnt
            FROM messages
            WHERE is_chat = TRUE AND deleted = FALSE
            GROUP BY dest_id
        ) AS mc ON c.id = mc.dest_id
        LEFT JOIN (
            SELECT chat_id, COUNT(*) AS cnt
            FROM chat_users
            WHERE confirmed = TRUE
            GROUP BY chat_id
        ) AS uc ON c.id = uc.chat_id
        WHERE c.deleted = FALSE
        ORDER BY popularity DESC LIMIT ? OFFSET ?;)")) {
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