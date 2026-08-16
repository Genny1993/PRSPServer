#ifndef PREPARED_STATEMENT_POOL_H
#define PREPARED_STATEMENT_POOL_H

#include <unordered_map>
#include <string>
#include <mutex>
#include <vector>
#include "database.h"

// Полностью статический класс-хранилище подготовленных запросов
class PreparedStatementPool {
private:
    // Хранилище запросов: ключ -> обёртка подготовленного запроса
    static std::unordered_map<std::string, PreparedStatementWrapper> statements;
    
    // Мьютекс для потокобезопасности
    static std::mutex poolMutex;
    
    // Приватный конструктор (запрещаем создание объектов)
    PreparedStatementPool() = delete;
    
    // Вспомогательный метод: подготовить и сохранить запрос
    static bool prepareAndStore(const std::string& name, const std::string& sqlQuery);
    
public:
    // Инициализация всех запросов при старте сервера
    static bool initializeAll();
    
    // Получить подготовленный запрос по ключу
    static PreparedStatementWrapper& getStatement(const std::string& name);
    
    // Проверить, существует ли запрос с таким именем
    static bool hasStatement(const std::string& name);
    
    // Получить количество подготовленных запросов
    static size_t size();
    
    // Очистить все запросы
    static void clear();
    
    // Получить все имена запросов (для отладки)
    static std::vector<std::string> getStatementNames();
    
    // Перезагрузить конкретный запрос
    static bool reloadStatement(const std::string& name, const std::string& sqlQuery);
};

#endif // PREPARED_STATEMENT_POOL_H