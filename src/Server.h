#pragma once

#include "Config.h"
#include "HttpParser.h"
#include "ThreadPool.h"
#include "DatabaseManager.h"
#include "AuthManager.h"
#include "VideoManager.h"

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <stdexcept>
#include <filesystem>

// Headers para networking
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

// Headers para SSL
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace fs = std::filesystem;

class Server {
public:
    Server(const ServerConfig& config,
           DatabaseManager& db_manager,
           AuthManager& auth_manager,
           VideoManager& video_manager);
    ~Server();

    void start();
    void stop();
    bool isRunning() const { return running_; }

private:
    ServerConfig config_;
    DatabaseManager& db_manager_;
    AuthManager& auth_manager_;
    VideoManager& video_manager_;

    int server_sock_ = -1;
    ThreadPool thread_pool_;
    bool running_ = false;
    std::thread accept_thread_;

    UniqueSslCtxPtr ssl_ctx_;

    HttpParser http_parser_;

    // Map of routes to handlers
    std::unordered_map<std::string, std::function<HttpResponse(HttpRequest&, const nlohmann::json& user_payload)>> routes_;

    void setupSSL();
    void createSocket();
    void bindSocket();
    void listenSocket();
    void acceptConnections();
    void handleClient(int client_sock, UniqueSslPtr ssl_conn);
    HttpResponse handleRequest(HttpRequest& request);
    void sendResponse(int client_sock, UniqueSslPtr& ssl_conn, const HttpResponse& response);

    // Route Handlers
    HttpResponse handleRoot(HttpRequest& request, const nlohmann::json& user_payload);
    HttpResponse handleStaticFile(HttpRequest& request, const nlohmann::json& user_payload);

    HttpResponse handleRegister(HttpRequest& request, const nlohmann::json& user_payload);
    HttpResponse handleLogin(HttpRequest& request, const nlohmann::json& user_payload);
    HttpResponse handleProfile(HttpRequest& request, const nlohmann::json& user_payload);

    HttpResponse handleUploadVideo(HttpRequest& request, const nlohmann::json& user_payload);
    HttpResponse handleListVideos(HttpRequest& request, const nlohmann::json& user_payload);
    HttpResponse handleGetVideoDetails(HttpRequest& request, const nlohmann::json& user_payload);
    HttpResponse handleStreamVideo(HttpRequest& request, const nlohmann::json& user_payload);

    // Helper for JSON responses
    HttpResponse jsonResponse(int status_code, const std::string& status_text, const nlohmann::json& data);
    HttpResponse errorResponse(int status_code, const std::string& message);
};
