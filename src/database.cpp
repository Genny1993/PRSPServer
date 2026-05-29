#include "database.h"
  
// Инициализация статических переменных
std::unique_ptr<sql::Driver> Database::driver = nullptr;
std::unique_ptr<sql::Connection> Database::connection = nullptr;
std::unique_ptr<sql::PreparedStatement> Database::preparedStatement = nullptr;
bool Database::isConnected = false;
std::string Database::lastError = "";
bool Database::debug = false;
    
    // Конвертация sql::SQLString в std::string
    std::string Database::sqlStringToString(const sql::SQLString& sqlStr) {
        return std::string(sqlStr.c_str());
    }
    
    void Database::setDebug(bool val) {
        debug = val;
    }
    // Открыть соединение с БД
    bool Database::openConnection(const std::string& host, 
                               const std::string& username, 
                               const std::string& password,
                               const std::string& database,
                               int port) {
        try {
            // Получаем экземпляр драйвера
            driver.reset(sql::mariadb::get_driver_instance());
            
            // Настраиваем свойства соединения
            sql::Properties properties({
                {"hostName", host},
                {"port", std::to_string(port)},
                {"userName", username},
                {"password", password},
                {"schema", database},
                {"autoReconnect", "true"}
            });
            
            // Устанавливаем соединение
            connection.reset(driver->connect(properties));

            isConnected = true;
            lastError.clear();
            
            std::cout << "✅ [DB] Успешное подключение к MariaDB" << std::endl;
            return true;
            
        } catch (sql::SQLException& e) {
            lastError = "Ошибка подключения: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            std::cerr << "Код ошибки: " << e.getErrorCode() << std::endl;
            isConnected = false;
            return false;
        } catch (std::exception& e) {
            lastError = "Ошибка: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            isConnected = false;
            return false;
        }
    }
    
    // Закрыть соединение
    void Database::closeConnection() {
        try {
            if (preparedStatement) {
                preparedStatement->close();
                preparedStatement.reset();
            }
            
            if (connection) {
                connection->close();
                connection.reset();
            }
            
            isConnected = false;
            std::cout << "✅[DB] Соединение с MariaDB закрыто" << std::endl;
            
        } catch (sql::SQLException& e) {
            std::cerr << "❌[DB ERROR] Ошибка при закрытии соединения: " << e.what() << std::endl;
        }
    }
    
    // Подготовить SQL запрос
    bool Database::prepareStatement(const std::string& sqlQuery) {
        if (!isConnected || !connection) {
            lastError = "Нет активного соединения с БД";
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return false;
        }
        
        try {
            preparedStatement.reset(connection->prepareStatement(sqlQuery));
            if(debug) {
                std::cout << "✅ [DB] Подготовлен запрос: " << sqlQuery << std::endl;
            }
            return true;
            
        } catch (sql::SQLException& e) {
            lastError = "Ошибка подготовки запроса: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return false;
        }
    }
    
    // Выполнить SELECT запрос с параметрами и вернуть JSON
    json Database::executeSelect(const std::vector<std::variant<int, double, std::string, bool, long long>>& params) {
        json result = json::array();
        
        if (!isConnected || !connection || !preparedStatement) {
            lastError = "Нет активного соединения или неподготовлен запрос";
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return result;
        }
        
        try {
            // Очищаем предыдущие параметры
            preparedStatement->clearParameters();
            
            // Устанавливаем параметры
            for (size_t i = 0; i < params.size(); ++i) {
                int index = i + 1;
                std::visit([index](auto&& arg) {
                    setParameter(preparedStatement.get(), index, arg);
                }, params[i]);
            }
            
            // Выполняем запрос
            std::unique_ptr<sql::ResultSet> res(preparedStatement->executeQuery());
            
            // Получаем метаданные
            sql::ResultSetMetaData* meta = res->getMetaData();
            int columnCount = meta->getColumnCount();
            
            // Формируем JSON
            while (res->next()) {
                json row;
                for (int i = 1; i <= columnCount; ++i) {
                    std::string columnName = sqlStringToString(meta->getColumnName(i));
                    
                    if (res->isNull(i)) {
                        row[columnName] = nullptr;
                    } else {
                        int columnType = meta->getColumnType(i);
                        
                        // Определяем тип и получаем значение
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
                                row[columnName] = sqlStringToString(res->getString(i));
                                break;
                            case sql::DataType::TIMESTAMP:
                            case sql::DataType::DATE:
                            case sql::DataType::TIME:
                                row[columnName] = sqlStringToString(res->getString(i));
                                break;
                            case sql::DataType::BOOLEAN:
                                row[columnName] = res->getBoolean(i);
                                break;
                            default:
                                row[columnName] = sqlStringToString(res->getString(i));
                                break;
                        }
                    }
                }
                result.push_back(row);
            }
            if(debug) {
                std::cout << "✅ [DB] SELECT выполнен успешно. Получено строк: " << result.size() << std::endl;
            }
            
        } catch (sql::SQLException& e) {
            lastError = "Ошибка выполнения SELECT: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
        }
        
        return result;
    }
    
    // Выполнить INSERT/UPDATE/DELETE запрос с параметрами
    int Database::executeUpdate(const std::vector<std::variant<int, double, std::string, bool, long long>>& params) {
        if (!isConnected || !connection || !preparedStatement) {
            lastError = "Нет активного соединения или неподготовлен запрос";
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return -1;
        }
        
        try {
            // Очищаем предыдущие параметры
            preparedStatement->clearParameters();
            
            // Устанавливаем параметры
            for (size_t i = 0; i < params.size(); ++i) {
                int index = i + 1;
                std::visit([index](auto&& arg) {
                    setParameter(preparedStatement.get(), index, arg);
                }, params[i]);
            }
            
            // Выполняем запрос
            int affectedRows = preparedStatement->executeUpdate();
            if(debug) {
                std::cout << "✅ [DB] UPDATE выполнен успешно. Затронуто строк: " << affectedRows << std::endl;
            }
            return affectedRows;
            
        } catch (sql::SQLException& e) {
            lastError = "Ошибка выполнения UPDATE: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return -1;
        }
    }
    
    // Выполнить INSERT и вернуть сгенерированный ID
    long long Database::executeInsertAndGetId(const std::vector<std::variant<int, double, std::string, bool, long long>>& params) {
        if (!isConnected || !connection || !preparedStatement) {
            lastError = "Нет активного соединения или неподготовлен запрос";
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return -1;
        }
        
        try {
            // Очищаем предыдущие параметры
            preparedStatement->clearParameters();
            
            // Устанавливаем параметры
            for (size_t i = 0; i < params.size(); ++i) {
                int index = i + 1;
                std::visit([index](auto&& arg) {
                    setParameter(preparedStatement.get(), index, arg);
                }, params[i]);
            }
            
            // Выполняем запрос
            int affectedRows = preparedStatement->executeUpdate();
            
            if (affectedRows > 0) {
                // Получаем сгенерированный ID через отдельный запрос
                std::unique_ptr<sql::Statement> stmt(connection->createStatement());
                std::unique_ptr<sql::ResultSet> generatedKeys(stmt->executeQuery("SELECT LAST_INSERT_ID()"));
                
                if (generatedKeys && generatedKeys->next()) {
                    long long newId = generatedKeys->getInt64(1);
                    if(debug) {
                        std::cout << "✅ [DB] INSERT выполнен успешно. Получен ID: " << newId << std::endl;
                    }
                    return newId;
                }
            }
            if(debug) {
                std::cout << "⚠️ [DB] INSERT выполнен, но ID не получен" << std::endl;
            }
            return -1;
            
        } catch (sql::SQLException& e) {
            lastError = "Ошибка выполнения INSERT: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return -1;
        }
    }
    
    // Получить последнюю ошибку
    std::string Database::getLastError() {
        return lastError;
    }
    
    // Проверить соединение
    bool Database::isConnectedToDB() {
        return isConnected && connection;
    }
    
    // Очистить подготовленный запрос
    void Database::clearPreparedStatement() {
        if (preparedStatement) {
            preparedStatement->close();
            preparedStatement.reset();
        }
        if(debug) {
            std::cout << "✅ [DB] Подготовленный запрос очищен" << std::endl;
        }
    }
    
    // Начать транзакцию
    bool Database::beginTransaction() {
        if (!isConnected || !connection) {
            lastError = "Нет активного соединения";
            return false;
        }
        
        try {
            connection->setAutoCommit(false);
            if(debug) {
                std::cout << "✅ [DB] Транзакция начата" << std::endl;
            }
            return true;
        } catch (sql::SQLException& e) {
            lastError = "Ошибка начала транзакции: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return false;
        }
    }
    
    // Зафиксировать транзакцию
    bool Database::commit() {
        if (!isConnected || !connection) {
            lastError = "Нет активного соединения";
            return false;
        }
        
        try {
            connection->commit();
            connection->setAutoCommit(true);
            std::cout << "✅ [DB] Транзакция зафиксирована" << std::endl;
            return true;
        } catch (sql::SQLException& e) {
            lastError = "Ошибка фиксации транзакции: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return false;
        }
    }
    
    // Откатить транзакцию
    bool Database::rollback() {
        if (!isConnected || !connection) {
            lastError = "Нет активного соединения";
            return false;
        }
        
        try {
            connection->rollback();
            connection->setAutoCommit(true);
            std::cout << "✅ [DB] Транзакция откачена" << std::endl;
            return true;
        } catch (sql::SQLException& e) {
            lastError = "Ошибка отката транзакции: " + std::string(e.what());
            std::cerr << "❌ [DB ERROR] " << lastError << std::endl;
            return false;
        }
    }
    
    // Прямой доступ к connection для особых случаев
    sql::Connection* Database::getConnection() {
        return connection.get();
    }
    
    // Прямой доступ к prepared statement
    sql::PreparedStatement* Database::getPreparedStatement() {
        return preparedStatement.get();
    }
