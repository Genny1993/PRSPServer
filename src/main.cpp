#include <iostream>
#include <locale>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <App.h>
#include "conf.h"
#include "database.h"
#include "wsserver.h"

void setupUnicodeSupport();

int main() {
    setupUnicodeSupport();

    std::cout << "╔══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                  ║\n";
    std::cout << "║                    🪪 ПРСП Сервер v0.0.4 🪪                      ║\n";
    std::cout << "║                                                                  ║\n";
    std::cout << "║            🔐 Паспортно-релейная система передачи 🔐             ║\n";
    std::cout << "║                                                                  ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════╝\n";

    if(!Conf::loadFromFile("settings.ini")) {
        return 1;
    }

    Conf::printAll();

    Database::setDebug(Conf::getDebug());
    if (!Database::openConnection(Conf::getDbHost(), Conf::getDbUser(), Conf::getDbPassword(), Conf::getDbName(), Conf::getDbPort())) {
        return 1;
    }

    WsServer::setDebug(Conf::getDebug());
    WsServer::init();
    WsServer::run();

    return 0;
}

void setupUnicodeSupport() {

    std::locale::global(std::locale("en_US.UTF-8"));
    std::wcout.imbue(std::locale());
}
