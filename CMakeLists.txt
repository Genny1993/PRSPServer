cmake_minimum_required(VERSION 3.30.8)

set(CMAKE_CXX_COMPILER g++)
project(psrp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=x86-64 -fstrict-aliasing -funroll-loops -flto -fno-rtti -DNDEBUG")

# ------------------------------------------------------------
# Путь к библиотеке uWebSockets
set(UWS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/uWebSockets)

# Путь к библиотеке MariaDB Connector/C++
set(MARIADB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/mariadb-connector)

# Подключаем заголовочные файлы
include_directories(
    ${UWS_DIR}/src
    ${UWS_DIR}/uSockets/src
    ${MARIADB_DIR}/include          # Путь к заголовкам MariaDB
)

# Находим библиотеку MariaDB Connector/C++
find_library(MARIADB_LIBRARY 
    NAMES mariadbcpp libmariadbcpp
    PATHS ${MARIADB_DIR}/lib64/mariadb ${MARIADB_DIR}/lib/mariadb
    REQUIRED
)


# Находим системные библиотеки
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# Для libuv используем простой поиск (Fedora не предоставляет libuv::libuv)
find_library(LIBUV_LIBRARY NAMES uv libuv REQUIRED)
find_path(LIBUV_INCLUDE_DIR NAMES uv.h REQUIRED)

# Исходники
file(GLOB_RECURSE SRC_FILES src/*.cpp)

# Исполняемый файл
add_executable(prsp ${SRC_FILES})

# Линковка
target_link_libraries(prsp
    ${MARIADB_LIBRARY}
    ${UWS_DIR}/uSockets/uSockets.a
    ${LIBUV_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    Threads::Threads
    dl
)

# Добавляем include директорию для libuv
target_include_directories(prsp PRIVATE ${LIBUV_INCLUDE_DIR})
target_include_directories(prsp PRIVATE ${MARIADB_DIR}/include)
target_include_directories(prsp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/extern)

# Флаги компиляции
target_compile_options(prsp PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(prsp PRIVATE UWS_WITH_SSL)