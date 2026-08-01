#include "database.h"
#include "logger.h"

// Инициализация статических переменных
std::unique_ptr<sql::Driver> Database::driver = nullptr;
std::unique_ptr<sql::Connection> Database::connection = nullptr;
bool Database::isConnected = false;
std::string Database::lastError = "";
bool Database::debug = false;
std::mutex Database::connectionMutex;

// ==================== Вспомогательные функции ====================

std::string Database::sqlStringToString(const sql::SQLString& sqlStr) {
    return std::string(sqlStr.c_str());
}

void Database::setParameter(sql::PreparedStatement* stmt, int index, const Param& value) {
    std::visit([stmt, index](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, int>) {
            stmt->setInt(index, arg);
        } else if constexpr (std::is_same_v<T, double>) {
            stmt->setDouble(index, arg);
        } else if constexpr (std::is_same_v<T, std::string>) {
            stmt->setString(index, arg);
        } else if constexpr (std::is_same_v<T, bool>) {
            stmt->setBoolean(index, arg);
        } else if constexpr (std::is_same_v<T, long long>) {
            stmt->setInt64(index, arg);
        }
    }, value);
}

// ==================== Управление соединением ====================

void Database::setDebug(bool val) {
    debug = val;
}

bool Database::openConnection(const std::string& host, 
                             const std::string& username, 
                             const std::string& password,
                             const std::string& database,
                             int port) {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    try {
        driver.reset(sql::mariadb::get_driver_instance());
        
        sql::Properties properties({
            {"hostName", host},
            {"port", std::to_string(port)},
            {"userName", username},
            {"password", password},
            {"schema", database},
            {"autoReconnect", "true"}
        });
        
        connection.reset(driver->connect(properties));
        isConnected = true;
        lastError.clear();
        
        if(debug) {
            Logger::info("[DB] ✅ Успешное подключение к MariaDB");
        }
        return true;
        
    } catch (sql::SQLException& e) {
        lastError = "Ошибка подключения: " + std::string(e.what());
        if(debug) {
            Logger::error("[DB] ❌ " + lastError + " Код ошибки: " + std::to_string(e.getErrorCode()));
        }
        isConnected = false;
        return false;
    } catch (std::exception& e) {
        lastError = "Ошибка: " + std::string(e.what());
        if(debug) {
            Logger::error("[DB] ❌ " + lastError);
        }
        isConnected = false;
        return false;
    }
}

void Database::closeConnection() {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    try {
        if (connection) {
            connection->close();
            connection.reset();
        }
        isConnected = false;
        if(debug) {
            Logger::info("[DB] ✅ Соединение с MariaDB закрыто");
        }
    } catch (sql::SQLException& e) {
        if(debug) {
            Logger::error("[DB] ❌ Ошибка при закрытии соединения: " + std::string(e.what()));
        }
    }
}

bool Database::isConnectedToDB() {
    std::lock_guard<std::mutex> lock(connectionMutex);
    return isConnected && connection;
}

std::string Database::getLastError() {
    return lastError;
}

sql::Connection* Database::getConnection() {
    return connection.get();
}

// ==================== Подготовка запроса ====================

PreparedStatementWrapper Database::prepareStatement(const std::string& sqlQuery) {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    if (!isConnected || !connection) {
        lastError = "Нет активного соединения с БД";
        if(debug) {
            Logger::error("[DB] ❌ " + lastError);
        }
        return PreparedStatementWrapper();
    }
    
    try {
        auto* rawStmt = connection->prepareStatement(sqlQuery);
        if(debug) {
            Logger::info("[DB] ✅ Подготовлен запрос: " + sqlQuery);
        }
        return PreparedStatementWrapper(rawStmt, connection.get());
        
    } catch (sql::SQLException& e) {
        lastError = "Ошибка подготовки запроса: " + std::string(e.what());
        if(debug) {
            Logger::error("[DB] ❌ Ошибка подготовки: " + sqlQuery + " - " + lastError);
        }
        return PreparedStatementWrapper();
    }
}

// ==================== Методы PreparedStatementWrapper ====================

bool PreparedStatementWrapper::setParams(const std::vector<Param>& params) {
    if (!stmt) return false;
    
    try {
        stmt->clearParameters();
        for (size_t i = 0; i < params.size(); ++i) {
            Database::setParameter(stmt.get(), i + 1, params[i]);
        }
        return true;
    } catch (sql::SQLException& e) {
        return false;
    }
}

json PreparedStatementWrapper::executeSelect(const std::vector<Param>& params) {
    json result = json::array();
    
    if (!stmt) {
        return result;
    }
    
    try {
        stmt->clearParameters();
        for (size_t i = 0; i < params.size(); ++i) {
            Database::setParameter(stmt.get(), i + 1, params[i]);
        }
        
        std::unique_ptr<sql::ResultSet> res(stmt->executeQuery());
        sql::ResultSetMetaData* meta = res->getMetaData();
        int columnCount = meta->getColumnCount();
        
        while (res->next()) {
            json row;
            for (int i = 1; i <= columnCount; ++i) {
                std::string columnName = Database::sqlStringToString(meta->getColumnName(i));
                
                if (res->isNull(i)) {
                    row[columnName] = nullptr;
                } else {
                    int columnType = meta->getColumnType(i);
                    
                    switch (columnType) {
                        case sql::DataType::INTEGER:
                        case sql::DataType::SMALLINT:
                        case sql::DataType::TINYINT:
                            row[columnName] = res->getInt(i);
                            break;
                        case sql::DataType::BIGINT:
                            row[columnName] = (long long)res->getInt64(i);
                            break;
                        case sql::DataType::DOUBLE:
                        case sql::DataType::DECIMAL:
                        case sql::DataType::FLOAT:
                            row[columnName] = res->getDouble(i);
                            break;
                        case sql::DataType::VARCHAR:
                        case sql::DataType::CHAR:
                        case sql::DataType::LONGVARCHAR:
                            row[columnName] = Database::sqlStringToString(res->getString(i));
                            break;
                        case sql::DataType::TIMESTAMP:
                        case sql::DataType::DATE:
                        case sql::DataType::TIME:
                            row[columnName] = Database::sqlStringToString(res->getString(i));
                            break;
                        case sql::DataType::BOOLEAN:
                            row[columnName] = res->getBoolean(i);
                            break;
                        default:
                            row[columnName] = Database::sqlStringToString(res->getString(i));
                            break;
                    }
                }
            }
            result.push_back(row);
        }
        
        if (Database::debug) {
            Logger::info("[DB] ✅ SELECT выполнен. Результатов: " + std::to_string(result.size()));
        }
        
    } catch (sql::SQLException& e) {
        Database::lastError = "Ошибка выполнения SELECT: " + std::string(e.what());
        Logger::error("[DB] ❌ " + Database::lastError);
    }
    
    return result;
}

int PreparedStatementWrapper::executeUpdate(const std::vector<Param>& params) {
    if (!stmt) {
        Database::lastError = "Неподготовлен запрос";
        return -1;
    }
    
    try {
        stmt->clearParameters();
        for (size_t i = 0; i < params.size(); ++i) {
            Database::setParameter(stmt.get(), i + 1, params[i]);
        }
        
        int affectedRows = stmt->executeUpdate();
        if (Database::debug) {
            Logger::info("[DB] ✅ UPDATE выполнен. Затронуто строк: " + std::to_string(affectedRows));
        }
        return affectedRows;
        
    } catch (sql::SQLException& e) {
        Database::lastError = "Ошибка выполнения UPDATE: " + std::string(e.what());
        Logger::error("[DB] ❌ " + Database::lastError);
        return -1;
    }
}

long long PreparedStatementWrapper::executeInsertAndGetId(const std::vector<Param>& params) {
    if (!stmt) {
        Database::lastError = "Неподготовлен запрос";
        return -1;
    }
    
    try {
        stmt->clearParameters();
        for (size_t i = 0; i < params.size(); ++i) {
            Database::setParameter(stmt.get(), i + 1, params[i]);
        }
        
        int affectedRows = stmt->executeUpdate();
        
        if (affectedRows > 0 && connection) {
            std::unique_ptr<sql::Statement> stmt2(connection->createStatement());
            std::unique_ptr<sql::ResultSet> generatedKeys(stmt2->executeQuery("SELECT LAST_INSERT_ID()"));
            
            if (generatedKeys && generatedKeys->next()) {
                long long newId = generatedKeys->getInt64(1);
                if (Database::debug) {
                    Logger::info("[DB] ✅ INSERT выполнен. Получен ID: " + std::to_string(newId));
                }
                return newId;
            }
        }
        
        if (Database::debug) {
            Logger::warning("[DB] ⚠️ INSERT выполнен, но ID не получен");
        }
        return -1;
        
    } catch (sql::SQLException& e) {
        Database::lastError = "Ошибка выполнения INSERT: " + std::string(e.what());
        Logger::error("[DB] ❌ " + Database::lastError);
        return -1;
    }
}

// ==================== Выполнение с переданным запросом ====================

json Database::executeSelect(PreparedStatementWrapper& wrapper, 
                            const std::vector<Param>& params) {
    return wrapper.executeSelect(params);
}

int Database::executeUpdate(PreparedStatementWrapper& wrapper, 
                           const std::vector<Param>& params) {
    return wrapper.executeUpdate(params);
}

long long Database::executeInsertAndGetId(PreparedStatementWrapper& wrapper, 
                                         const std::vector<Param>& params) {
    return wrapper.executeInsertAndGetId(params);
}

// ==================== Транзакции ====================

bool Database::beginTransaction() {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    if (!isConnected || !connection) {
        lastError = "Нет активного соединения";
        return false;
    }
    
    try {
        connection->setAutoCommit(false);
        if(debug) {
            Logger::info("[DB] ✅ Транзакция начата.");
        }
        return true;
    } catch (sql::SQLException& e) {
        lastError = "Ошибка начала транзакции: " + std::string(e.what());
        if(debug) {
            Logger::error("[DB] ❌ " + lastError);
        }
        return false;
    }
}

bool Database::commit() {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    if (!isConnected || !connection) {
        lastError = "Нет активного соединения";
        return false;
    }
    
    try {
        connection->commit();
        connection->setAutoCommit(true);
        if(debug) {
            Logger::info("[DB] ✅ Транзакция зафиксирована.");
        }
        return true;
    } catch (sql::SQLException& e) {
        lastError = "Ошибка фиксации транзакции: " + std::string(e.what());
        if(debug) {
            Logger::error("[DB] ❌ " + lastError);
        }
        return false;
    }
}

bool Database::rollback() {
    std::lock_guard<std::mutex> lock(connectionMutex);
    
    if (!isConnected || !connection) {
        lastError = "Нет активного соединения";
        return false;
    }
    
    try {
        connection->rollback();
        connection->setAutoCommit(true);
        if(debug) {
            Logger::info("[DB] ✅ Транзакция откачена.");
        }
        return true;
    } catch (sql::SQLException& e) {
        lastError = "Ошибка отката транзакции: " + std::string(e.what());
        if(debug) {
            Logger::error("[DB] ❌ " + lastError);
        }
        return false;
    }
}