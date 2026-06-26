cmake_minimum_required(VERSION 3.14)

project(prsp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=x86-64 -fstrict-aliasing -funroll-loops -flto -fno-rtti -DNDEBUG")

# Поиск установленных библиотек
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)

# Исходники
file(GLOB_RECURSE SRC_FILES src/*.cpp)

# Исполняемый файл
add_executable(prsp ${SRC_FILES})

# Пути к заголовочным файлам uWebSockets и uSockets
target_include_directories(prsp PRIVATE
    /usr/local/include/uWebSockets
    /usr/local/include/uSockets
)

# Пути к заголовкам MariaDB Connector
target_include_directories(prsp PRIVATE
    /usr/include/mariadb
    /usr/include/mariadb/conncpp
)

# Линковка библиотек
target_link_libraries(prsp
    PRIVATE
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    ${CMAKE_THREAD_LIBS_INIT}
    ${ZLIB_LIBRARIES}
    /usr/local/lib/uSockets.a
    /usr/lib64/mariadb/libmariadbcpp.so
)

# Определения
target_compile_definitions(prsp PRIVATE UWS_WITH_SSL)

# Флаги компиляции
target_compile_options(prsp PRIVATE -Wall -Wextra -Wpedantic)
