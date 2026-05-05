#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <vector>

class Conf {
private:
    // Запрещаем создание экземпляров
    Conf() = delete;
    ~Conf() = delete;
    Conf(const Conf&) = delete;
    Conf& operator=(const Conf&) = delete;
    
    // Статические поля для настроек
    inline static std::string dbhost = "localhost";
    inline static int dbport = 3306;
    inline static std::string dbname = "";
    inline static std::string dbuser = "";
    inline static std::string dbpassword = "";
    inline static int serviceport = 3000;
    inline static bool debug = false;
    inline static std::string master_key = "";
    inline static std::vector<unsigned char> master_key_bin;
    
    inline static std::mutex mutex;
    inline static bool is_loaded = false;
    
    // Вспомогательные методы
    static void parseLine(const std::string& line);
    static void setValue(const std::string& key, const std::string& value);
    static std::string trim(const std::string& str);
    
public:
    // Загрузка конфигурации из файла
    static bool loadFromFile(const std::string& filename);
    
    // Геттеры для настроек
    static std::string getDbHost() {
        std::lock_guard<std::mutex> lock(mutex);
        return dbhost;
    }
    
    static int getDbPort() {
        std::lock_guard<std::mutex> lock(mutex);
        return dbport;
    }
    
    static std::string getDbName() {
        std::lock_guard<std::mutex> lock(mutex);
        return dbname;
    }
    
    static std::string getDbUser() {
        std::lock_guard<std::mutex> lock(mutex);
        return dbuser;
    }
    
    static std::string getDbPassword() {
        std::lock_guard<std::mutex> lock(mutex);
        return dbpassword;
    }
    
    static int getServicePort() {
        std::lock_guard<std::mutex> lock(mutex);
        return serviceport;
    }

    static int getDebug() {
        std::lock_guard<std::mutex> lock(mutex);
        return debug;
    }
    
    static bool isConfigLoaded() {
        std::lock_guard<std::mutex> lock(mutex);
        return is_loaded;
    }
    
    static std::string getMasterKey() {
        std::lock_guard<std::mutex> lock(mutex);
        return master_key;
    }

    static std::vector<unsigned char> getMasterKeyBin() {
        std::lock_guard<std::mutex> lock(mutex);
        return master_key_bin;
    }

    // Отображение всех настроек (для отладки)
    static void printAll();
};