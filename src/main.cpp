#include "Server.h"
#include "Config.h"
#include "DatabaseManager.h"
#include "AuthManager.h"
#include "VideoManager.h"
#include <iostream>
#include <csignal>

// Global pointer for signal handler to stop the server gracefully
Server* global_server_ptr = nullptr;

void signal_handler(int signal) {
    if (signal == SIGINT && global_server_ptr) {
        std::cout << "\nSIGINT received. Shutting down server..." << std::endl;
        global_server_ptr->stop();
    }
}

int main() {
    ServerConfig config;
    // You can load config from a file here if needed

    DatabaseManager db_manager(config.db_path);
    if (!db_manager.open()) {
        std::cerr << "Failed to open database. Exiting." << std::endl;
        return 1;
    }

    // Initialize database tables
    if (!db_manager.createUserTable() || !db_manager.createVideoTable()) {
        std::cerr << "Failed to create database tables. Exiting." << std::endl;
        return 1;
    }

    AuthManager auth_manager(db_manager, config);
    VideoManager video_manager(db_manager, config);

    Server server(config, db_manager, auth_manager, video_manager);
    global_server_ptr = &server; // Set global pointer for signal handling

    // Register signal handler for graceful shutdown
    std::signal(SIGINT, signal_handler);

    server.start();

    // Keep main thread alive while server runs
    // The server's accept_thread_ handles incoming connections
    // and the thread_pool_ processes them.
    // The main thread waits for the server to stop.
    // Since accept_thread_ is blocking on accept(), it needs to be interrupted
    // by shutting down the server_sock_ to allow the thread to exit.
    while (server.isRunning()) { // Assuming you add an isRunning() method to Server
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
