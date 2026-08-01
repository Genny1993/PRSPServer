#ifndef DATABASE_H
#define DATABASE_H

#include <memory>
#include <string>
#include <vector>
#include <variant>
#include <mutex>
#include <mariadb/conncpp.hpp>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Вспомогательная структура для параметров
using Param = std::variant<int, double, std::string, bool, long long>;
using Params = std::vector<Param>;

// Класс-обёртка для подготовленного запроса
class PreparedStatementWrapper {
private:
    std::unique_ptr<sql::PreparedStatement> stmt;
    sql::Connection* connection; // Для операций, требующих connection
    
public:
    PreparedStatementWrapper() = default;
    
    PreparedStatementWrapper(sql::PreparedStatement* s, sql::Connection* conn) 
        : stmt(s), connection(conn) {}
    
    // Запрещаем копирование
    PreparedStatementWrapper(const PreparedStatementWrapper&) = delete;
    PreparedStatementWrapper& operator=(const PreparedStatementWrapper&) = delete;
    
    // Разрешаем перемещение
    PreparedStatementWrapper(PreparedStatementWrapper&&) = default;
    PreparedStatementWrapper& operator=(PreparedStatementWrapper&&) = default;
    
    // Проверка валидности
    bool isValid() const { return stmt != nullptr; }
    
    // Получить сырой указатель (для совместимости)
    sql::PreparedStatement* get() { return stmt.get(); }
    
    // Выполнить SELECT и вернуть JSON
    json executeSelect(const std::vector<Param>& params);
    
    // Выполнить INSERT/UPDATE/DELETE
    int executeUpdate(const std::vector<Param>& params);
    
    // Выполнить INSERT и вернуть ID
    long long executeInsertAndGetId(const std::vector<Param>& params);
    
    // Очистить параметры
    void clearParameters() {
        if (stmt) stmt->clearParameters();
    }
    
    // Установить параметры напрямую (для особых случаев)
    bool setParams(const std::vector<Param>& params);
};

// Основной класс Database
class Database {
private:
    // Статические переменные
    static std::unique_ptr<sql::Driver> driver;
    static std::unique_ptr<sql::Connection> connection;
    static bool isConnected;
    static std::string lastError;
    static bool debug;
    
    // Мьютекс для потокобезопасности
    static std::mutex connectionMutex;
    
    // Вспомогательные методы (теперь public)
public:
    // Делаем эти методы public, чтобы PreparedStatementWrapper мог их использовать
    static std::string sqlStringToString(const sql::SQLString& sqlStr);
    static void setParameter(sql::PreparedStatement* stmt, int index, const Param& value);
    
    // Инициализация и управление соединением
    static bool openConnection(const std::string& host, 
                              const std::string& username, 
                              const std::string& password,
                              const std::string& database,
                              int port = 3306);
    
    static void closeConnection();
    static bool isConnectedToDB();
    static std::string getLastError();
    static void setDebug(bool val);
    
    // Подготовить запрос и вернуть объект
    static PreparedStatementWrapper prepareStatement(const std::string& sqlQuery);
    
    // Выполнение с переданным подготовленным запросом
    static json executeSelect(PreparedStatementWrapper& wrapper, 
                             const std::vector<Param>& params);
    
    static int executeUpdate(PreparedStatementWrapper& wrapper, 
                            const std::vector<Param>& params);
    
    static long long executeInsertAndGetId(PreparedStatementWrapper& wrapper, 
                                          const std::vector<Param>& params);
    
    // Транзакции
    static bool beginTransaction();
    static bool commit();
    static bool rollback();
    
    // Прямой доступ (для особых случаев)
    static sql::Connection* getConnection();
    
    // Добавляем дружественный класс, чтобы он имел доступ к private членам
    friend class PreparedStatementWrapper;
};

#endif // DATABASE_H