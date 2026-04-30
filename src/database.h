#pragma once

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Woverloaded-virtual"
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4251)
#endif

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <variant>
#include <map>
#include <mariadb/conncpp.hpp>
#include <nlohmann/json.hpp>

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif


using ParamValue = std::variant<int, double, std::string, bool, long long>;
using json = nlohmann::json;

class Database {

private:
    // Статические переменные
    static std::unique_ptr<sql::Driver> driver;
    static std::unique_ptr<sql::Connection> connection;
    static std::unique_ptr<sql::PreparedStatement> preparedStatement;
    static bool isConnected;
    static std::string lastError;
    static bool debug;
    
    // Приватный конструктор (статический класс)
    Database() = delete;
    ~Database() = delete;
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    
    // Внутренний метод для установки параметров
    template<typename T>
    static void setParameter(sql::PreparedStatement* pstmt, int index, const T& value) {
        if constexpr (std::is_same_v<T, int>) {
            pstmt->setInt(index, value);
        }
        else if constexpr (std::is_same_v<T, long long>) {
            pstmt->setInt64(index, value);
        }
        else if constexpr (std::is_same_v<T, double>) {
            pstmt->setDouble(index, value);
        }
        else if constexpr (std::is_same_v<T, float>) {
            pstmt->setDouble(index, static_cast<double>(value));
        }
        else if constexpr (std::is_same_v<T, std::string>) {
            pstmt->setString(index, value);
        }
        else if constexpr (std::is_same_v<T, const char*>) {
            pstmt->setString(index, std::string(value));
        }
        else if constexpr (std::is_same_v<T, bool>) {
            pstmt->setBoolean(index, value);
        }
        else if constexpr (std::is_same_v<T, std::nullptr_t>) {
            pstmt->setNull(index, 0);
        }
        else {
            pstmt->setString(index, std::to_string(value));
        }
    }
    
    // Конвертация sql::SQLString в std::string
    static std::string sqlStringToString(const sql::SQLString& sqlStr);

public:

    //Включен режим отладки
    static void setDebug(bool val);

    // Открыть соединение с БД
    static bool openConnection(const std::string& host, const std::string& username, const std::string& password, const std::string& database, int port = 3306);
    
    // Закрыть соединение
    static void closeConnection();

    // Подготовить SQL запрос
    static bool prepareStatement(const std::string& sqlQuery);
    
    // Выполнить SELECT запрос с параметрами и вернуть JSON
    static json executeSelect(const std::vector<std::variant<int, double, std::string, bool, long long>>& params = {});
    
    // Выполнить INSERT/UPDATE/DELETE запрос с параметрами
    static int executeUpdate(const std::vector<std::variant<int, double, std::string, bool, long long>>& params = {});
    
    // Выполнить INSERT и вернуть сгенерированный ID
    static long long executeInsertAndGetId(const std::vector<std::variant<int, double, std::string, bool, long long>>& params = {});
    
    // Получить последнюю ошибку
    static std::string getLastError();
    
    // Проверить соединение
    static bool isConnectedToDB();
    
    // Очистить подготовленный запрос
    static void clearPreparedStatement();
    
    // Начать транзакцию
    static bool beginTransaction();
    
    // Зафиксировать транзакцию
    static bool commit();
    
    // Откатить транзакцию
    static bool rollback();
    
    // Прямой доступ к connection для особых случаев
    static sql::Connection* getConnection();
    
    // Прямой доступ к prepared statement
    static sql::PreparedStatement* getPreparedStatement();
};