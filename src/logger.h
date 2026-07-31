#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include "conf.h"

class Logger {
private:
    static std::ofstream logFile;
    static std::string logFilename;
    static bool logToConsole;
    static bool logToFile;
    static bool isInitialized;

public:
    static void init(const std::string& filename = "server.log", bool console = true, bool file = true);
    static void close();
    static std::string getTimestamp();
    static void log(const std::string& level, const std::string& message);
    static void log(const std::string& message);
    static void info(const std::string& message);
    static void debug(const std::string& message);
    static void warning(const std::string& message);
    static void error(const std::string& message);
    static std::string getFilename();
};

#endif // LOGGER_H