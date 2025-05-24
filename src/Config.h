#pragma once

#include <string>
#include <thread>

struct ServerConfig {
    int port = 8080;
    int max_connections = 1000;
    int thread_pool_size = std::thread::hardware_concurrency() * 2;
    std::string upload_dir = "./uploads/";
    std::string static_dir = "./static/";
    std::string db_path = "./database.db";
    std::string jwt_secret = "your-super-secret-jwt-key-change-this-in-production"; // CAMBIAR ESTO EN PRODUCCIÓN
    long jwt_expiry_seconds = 3600; // 1 hora
};
