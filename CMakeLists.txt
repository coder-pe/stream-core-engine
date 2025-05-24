cmake_minimum_required(VERSION 3.10)
project(VideoStreamingPlatform CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Buscar SQLite3 manualmente si el objetivo importado falla
find_package(SQLite3 REQUIRED)
if(NOT TARGET SQLite3::SQLite3)
    find_library(SQLITE3_LIB sqlite3)
    find_path(SQLITE3_INCLUDE_DIR sqlite3.h)
    if(SQLITE3_LIB AND SQLITE3_INCLUDE_DIR)
        add_library(SQLite3::SQLite3 INTERFACE IMPORTED)
        set_target_properties(SQLite3::SQLite3 PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${SQLITE3_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${SQLITE3_LIB}"
        )
    else()
        message(FATAL_ERROR "SQLite3 no encontrado")
    endif()
endif()

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/Server.cpp
    src/HttpParser.cpp
    src/DatabaseManager.cpp
    src/AuthManager.cpp
    src/VideoManager.cpp
    src/ThreadPool.cpp
    src/Utils.cpp
)

# Enlazar bibliotecas
target_link_libraries(${PROJECT_NAME} PRIVATE
    SQLite3::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Crear directorios para uploads y static
file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/uploads")
file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/static")

# Copiar archivos estáticos
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_SOURCE_DIR}/static/index.html
    ${CMAKE_SOURCE_DIR}/static/style.css
    ${CMAKE_SOURCE_DIR}/static/script.js
    ${CMAKE_BINARY_DIR}/static/
)
