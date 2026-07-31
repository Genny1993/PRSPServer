#include "logger.h"

// ========== ИНИЦИАЛИЗАЦИЯ СТАТИЧЕСКИХ ПОЛЕЙ ==========
std::ofstream Logger::logFile;
std::string Logger::logFilename = "server.log";
bool Logger::logToConsole = true;
bool Logger::logToFile = true;
bool Logger::isInitialized = false;

// ========== РЕАЛИЗАЦИЯ МЕТОДОВ ==========

void Logger::init(const std::string& filename, bool console, bool file) {
    logFilename = filename;
    logToConsole = console;
    logToFile = file;

    if (logToFile) {
        logFile.open(logFilename, std::ios::app);
        if (!logFile.is_open()) {
            std::cerr << "[ERROR] Не удалось открыть файл лога: " << logFilename << std::endl;
            logToFile = false;
        }
    }
    isInitialized = true;
}

void Logger::close() {
    if (logFile.is_open()) {
        logFile.close();
    }
    isInitialized = false;
}

std::string Logger::getTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setw(3) << std::setfill('0') << ms.count();
    return ss.str();
}

void Logger::log(const std::string& level, const std::string& message) {
    
    if(!Conf::getDebug()) {
        return;
    }

    if (!isInitialized) {
        std::cerr << "[ERROR] Logger не инициализирован! Вызовите Logger::init()" << std::endl;
        return;
    }

    std::string formatted = "[" + getTimestamp() + "] [" + level + "] " + message;

    if (logToConsole) {
        std::cout << formatted << std::endl;
    }

    if (logToFile && logFile.is_open()) {
        logFile << formatted << std::endl;
        logFile.flush();
    }
}

void Logger::log(const std::string& message) {
    log("INFO", message);
}

void Logger::info(const std::string& message) {
    log("INFO", message);
}

void Logger::debug(const std::string& message) {
    log("DEBUG", message);
}

void Logger::warning(const std::string& message) {
    log("WARN", message);
}

void Logger::error(const std::string& message) {
    log("ERROR", message);
}

std::string Logger::getFilename() {
    return logFilename;
}