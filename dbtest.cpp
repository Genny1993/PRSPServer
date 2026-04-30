#include <iostream>
#include "database.h"

void printSeparator(const std::string& title) {
    std::cout << "\n========================================" << std::endl;
    std::cout << title << std::endl;
    std::cout << "========================================\n" << std::endl;
}

int main() {
    // ==================== 1. ПОДКЛЮЧЕНИЕ К БД ====================
    printSeparator("1. ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ");
    
    if (!Database::openConnection("localhost", "root", "password", "test_db", 3306)) {
        std::cerr << "Не удалось подключиться к БД" << std::endl;
        return 1;
    }
    
    // Проверка соединения
    if (Database::isConnectedToDB()) {
        std::cout << "Соединение активно" << std::endl;
    }
    
    // ==================== 2. СОЗДАНИЕ ТАБЛИЦ ====================
    printSeparator("2. СОЗДАНИЕ ТАБЛИЦ");
    
    // Создание таблицы пользователей
    if (Database::prepareStatement(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INT AUTO_INCREMENT PRIMARY KEY, "
        "username VARCHAR(50) NOT NULL UNIQUE, "
        "email VARCHAR(100) NOT NULL, "
        "age INT, "
        "salary DECIMAL(10,2), "
        "is_active BOOLEAN DEFAULT TRUE, "
        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    )) {
        int result = Database::executeUpdate();
        std::cout << "Таблица users создана/проверена" << std::endl;
    }
    
    // Создание таблицы логов
    if (Database::prepareStatement(
        "CREATE TABLE IF NOT EXISTS logs ("
        "id INT AUTO_INCREMENT PRIMARY KEY, "
        "user_id INT, "
        "action VARCHAR(100), "
        "log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    )) {
        Database::executeUpdate();
        std::cout << "Таблица logs создана/проверена" << std::endl;
    }
    
    // ==================== 3. INSERT - БЕЗ ВОЗВРАТА ID ====================
    printSeparator("3. INSERT (обычная вставка)");
    
    if (Database::prepareStatement("INSERT INTO users (username, email, age, salary) VALUES (?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("john_doe"),
            std::string("john@example.com"),
            25,
            50000.50
        };
        
        int affected = Database::executeUpdate(params);
        std::cout << "Вставлено строк: " << affected << std::endl;
    }
    
    // ==================== 4. INSERT С ВОЗВРАТОМ ID ====================
    printSeparator("4. INSERT С ПОЛУЧЕНИЕМ ID");
    
    if (Database::prepareStatement("INSERT INTO users (username, email, age, salary, is_active) VALUES (?, ?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("jane_smith"),
            std::string("jane@example.com"),
            30,
            65000.75,
            true
        };
        
        long long newId = Database::executeInsertAndGetId(params);
        if (newId > 0) {
            std::cout << "Вставлен пользователь с ID: " << newId << std::endl;
        }
    }
    
    // ==================== 5. SELECT - ПРОСТОЙ ЗАПРОС ====================
    printSeparator("5. SELECT (все пользователи)");
    
    if (Database::prepareStatement("SELECT id, username, email, age, salary, is_active FROM users")) {
        json users = Database::executeSelect();
        std::cout << "Результат в JSON:" << std::endl;
        std::cout << users.dump(4) << std::endl;
    }
    
    // ==================== 6. SELECT С ПАРАМЕТРАМИ ====================
    printSeparator("6. SELECT С ПАРАМЕТРАМИ (WHERE)");
    
    if (Database::prepareStatement("SELECT id, username, email, age FROM users WHERE age > ? AND is_active = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            25,     // age > 25
            true    // is_active = true
        };
        
        json activeUsers = Database::executeSelect(params);
        std::cout << "Активные пользователи старше 25 лет:" << std::endl;
        std::cout << activeUsers.dump(4) << std::endl;
    }
    
    // ==================== 7. SELECT С LIKE ====================
    printSeparator("7. SELECT С LIKE");
    
    if (Database::prepareStatement("SELECT * FROM users WHERE email LIKE ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("%@example.com")
        };
        
        json users = Database::executeSelect(params);
        std::cout << "Пользователи с email в домене example.com:" << std::endl;
        std::cout << users.dump(2) << std::endl;
    }
    
    // ==================== 8. UPDATE ====================
    printSeparator("8. UPDATE");
    
    if (Database::prepareStatement("UPDATE users SET salary = ?, age = ? WHERE username = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            75000.00,           // новая зарплата
            28,                 // новый возраст
            std::string("john_doe")  // пользователь
        };
        
        int affected = Database::executeUpdate(params);
        std::cout << "Обновлено пользователей: " << affected << std::endl;
    }
    
    // ==================== 9. DELETE ====================
    printSeparator("9. DELETE");
    
    // Сначала вставим тестового пользователя
    if (Database::prepareStatement("INSERT INTO users (username, email, age) VALUES (?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("temp_user"),
            std::string("temp@example.com"),
            99
        };
        Database::executeUpdate(params);
        std::cout << "Добавлен тестовый пользователь" << std::endl;
    }
    
    // Удаляем тестового пользователя
    if (Database::prepareStatement("DELETE FROM users WHERE username = ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("temp_user")
        };
        
        int affected = Database::executeUpdate(params);
        std::cout << "Удалено пользователей: " << affected << std::endl;
    }
    
    // ==================== 10. РАБОТА С NULL ====================
    printSeparator("10. РАБОТА С NULL");
    
    if (Database::prepareStatement("INSERT INTO users (username, email, age, salary) VALUES (?, ?, ?, ?)")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("user_with_null"),
            std::string("null@example.com"),
            35,
            std::nullptr_t()  // NULL значение
        };
        
        long long id = Database::executeInsertAndGetId(params);
        std::cout << "Вставлен пользователь с NULL salary, ID: " << id << std::endl;
    }
    
    // ==================== 11. ТРАНЗАКЦИИ ====================
    printSeparator("11. ТРАНЗАКЦИИ");
    
    // Начинаем транзакцию
    if (Database::beginTransaction()) {
        std::cout << "Транзакция начата" << std::endl;
        
        bool success = true;
        
        // Первая вставка
        if (Database::prepareStatement("INSERT INTO logs (user_id, action) VALUES (?, ?)")) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                1,
                std::string("user_login")
            };
            
            if (Database::executeUpdate(params) < 0) {
                success = false;
            }
        } else {
            success = false;
        }
        
        // Вторая вставка
        if (Database::prepareStatement("INSERT INTO logs (user_id, action) VALUES (?, ?)")) {
            std::vector<std::variant<int, double, std::string, bool, long long>> params = {
                2,
                std::string("user_logout")
            };
            
            if (Database::executeUpdate(params) < 0) {
                success = false;
            }
        } else {
            success = false;
        }
        
        if (success) {
            Database::commit();
            std::cout << "Транзакция зафиксирована" << std::endl;
        } else {
            Database::rollback();
            std::cout << "Транзакция откачена из-за ошибки" << std::endl;
        }
    }
    
    // ==================== 12. РАЗНЫЕ ТИПЫ ПАРАМЕТРОВ ====================
    printSeparator("12. РАЗНЫЕ ТИПЫ ПАРАМЕТРОВ");
    
    if (Database::prepareStatement(
        "INSERT INTO users (username, email, age, salary, is_active) VALUES (?, ?, ?, ?, ?)"
    )) {
        // Демонстрация всех типов параметров
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("multi_type_user"),  // string
            std::string("multi@example.com"), // string
            25,                               // int
            12345.67,                         // double
            true                              // bool
        };
        
        long long id = Database::executeInsertAndGetId(params);
        std::cout << "Вставлен пользователь со смешанными типами, ID: " << id << std::endl;
    }
    
    // ==================== 13. ПОЛУЧЕНИЕ ПОСЛЕДНЕЙ ОШИБКИ ====================
    printSeparator("13. ПОЛУЧЕНИЕ ПОСЛЕДНЕЙ ОШИБКИ");
    
    // Делаем ошибочный запрос (таблица не существует)
    if (Database::prepareStatement("SELECT * FROM non_existent_table")) {
        Database::executeSelect();
    }
    
    std::string lastError = Database::getLastError();
    if (!lastError.empty()) {
        std::cout << "Последняя ошибка: " << lastError << std::endl;
    }
    
    // ==================== 14. ОЧИСТКА ПОДГОТОВЛЕННОГО ЗАПРОСА ====================
    printSeparator("14. ОЧИСТКА ПОДГОТОВЛЕННОГО ЗАПРОСА");
    
    if (Database::prepareStatement("SELECT * FROM users WHERE age > ?")) {
        std::cout << "Запрос подготовлен" << std::endl;
        Database::clearPreparedStatement();
        std::cout << "Запрос очищен" << std::endl;
    }
    
    // ==================== 15. РАБОТА С РАЗНЫМИ ТИПАМИ ДАННЫХ В РЕЗУЛЬТАТАХ ====================
    printSeparator("15. ОБРАБОТКА РАЗНЫХ ТИПОВ ДАННЫХ ИЗ РЕЗУЛЬТАТА");
    
    if (Database::prepareStatement(
        "SELECT id, username, age, salary, is_active, created_at FROM users LIMIT 5"
    )) {
        json results = Database::executeSelect();
        
        for (const auto& user : results) {
            std::cout << "Пользователь: " << user["username"] << std::endl;
            std::cout << "  - ID: " << user["id"] << " (int)" << std::endl;
            std::cout << "  - Возраст: " << user["age"] << " (int)" << std::endl;
            std::cout << "  - Зарплата: " << user["salary"] << " (double/decimal)" << std::endl;
            std::cout << "  - Активен: " << user["is_active"] << " (boolean)" << std::endl;
            std::cout << "  - Создан: " << user["created_at"] << " (timestamp)" << std::endl;
            
            // Проверка на NULL
            if (user["salary"].is_null()) {
                std::cout << "  - Зарплата: NULL" << std::endl;
            }
        }
    }
    
    // ==================== 16. ПРЯМОЙ ДОСТУП К CONNECTION ====================
    printSeparator("16. ПРЯМОЙ ДОСТУП К CONNECTION (для особых случаев)");
    
    sql::Connection* rawConn = Database::getConnection();
    if (rawConn) {
        std::cout << "Получен прямой указатель на connection" << std::endl;
        
        // Пример использования raw connection для специфических операций
        try {
            std::unique_ptr<sql::Statement> stmt(rawConn->createStatement());
            std::unique_ptr<sql::ResultSet> res(stmt->executeQuery("SELECT VERSION()"));
            if (res->next()) {
                std::cout << "Версия MariaDB: " << res->getString(1) << std::endl;
            }
        } catch (sql::SQLException& e) {
            std::cerr << "Ошибка: " << e.what() << std::endl;
        }
    }
    
    // ==================== 17. ПАРТИРОВАННЫЙ SELECT (LIMIT/OFFSET) ====================
    printSeparator("17. ПАРТИРОВАННЫЙ SELECT");
    
    // Вставляем больше данных для демонстрации
    for (int i = 0; i < 10; i++) {
        if (Database::prepareStatement("INSERT INTO users (username, email, age) VALUES (?, ?, ?)")) {
            std::string username = "user_" + std::to_string(i);
            std::string email = username + "@example.com";
            Database::executeUpdate({username, email, 20 + i});
        }
    }
    
    if (Database::prepareStatement("SELECT id, username, email FROM users LIMIT ? OFFSET ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            5,   // LIMIT 5
            0    // OFFSET 0
        };
        
        json firstPage = Database::executeSelect(params);
        std::cout << "Первая страница (5 записей):" << std::endl;
        std::cout << firstPage.dump(2) << std::endl;
    }
    
    // ==================== 18. АГРЕГАТНЫЕ ЗАПРОСЫ ====================
    printSeparator("18. АГРЕГАТНЫЕ ЗАПРОСЫ");
    
    if (Database::prepareStatement("SELECT COUNT(*) as total, AVG(age) as avg_age, MAX(salary) as max_salary FROM users")) {
        json stats = Database::executeSelect();
        if (!stats.empty()) {
            std::cout << "Статистика по пользователям:" << std::endl;
            std::cout << "  - Всего: " << stats[0]["total"] << std::endl;
            std::cout << "  - Средний возраст: " << stats[0]["avg_age"] << std::endl;
            std::cout << "  - Макс зарплата: " << stats[0]["max_salary"] << std::endl;
        }
    }
    
    // ==================== 19. ГРУППИРОВКА ====================
    printSeparator("19. ГРУППИРОВКА");
    
    if (Database::prepareStatement("SELECT is_active, COUNT(*) as count FROM users GROUP BY is_active")) {
        json groups = Database::executeSelect();
        std::cout << "Группировка по статусу активности:" << std::endl;
        for (const auto& group : groups) {
            std::cout << "  - is_active=" << group["is_active"] 
                      << ": " << group["count"] << " пользователей" << std::endl;
        }
    }
    
    // ==================== 20. ОБНОВЛЕНИЕ С ВОЗВРАТОМ КОЛИЧЕСТВА ====================
    printSeparator("20. МАССОВОЕ ОБНОВЛЕНИЕ");
    
    if (Database::prepareStatement("UPDATE users SET age = age + 1 WHERE age < ?")) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {30};
        
        int updated = Database::executeUpdate(params);
        std::cout << "Увеличено возраст у " << updated << " пользователей (кому < 30 лет)" << std::endl;
    }
    
    // ==================== 21. INSERT ... ON DUPLICATE KEY UPDATE ====================
    printSeparator("21. INSERT ... ON DUPLICATE KEY UPDATE");
    
    if (Database::prepareStatement(
        "INSERT INTO users (username, email, age, salary) VALUES (?, ?, ?, ?) "
        "ON DUPLICATE KEY UPDATE age = VALUES(age), salary = VALUES(salary)"
    )) {
        std::vector<std::variant<int, double, std::string, bool, long long>> params = {
            std::string("john_doe"),      // Существующий пользователь
            std::string("john_new@example.com"),
            26,                           // Новый возраст
            55000.00                      // Новая зарплата
        };
        
        int affected = Database::executeUpdate(params);
        std::cout << "Затронуто строк: " << affected << " (обновлен существующий)" << std::endl;
    }
    
    // ==================== 22. ЗАКРЫТИЕ СОЕДИНЕНИЯ ====================
    printSeparator("22. ЗАКРЫТИЕ СОЕДИНЕНИЯ");
    
    Database::closeConnection();
    std::cout << "Соединение закрыто" << std::endl;
    
    // Проверка статуса
    if (!Database::isConnectedToDB()) {
        std::cout << "Соединение действительно закрыто" << std::endl;
    }
    
    return 0;
}