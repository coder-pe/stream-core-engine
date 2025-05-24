#include "Server.h"
#include "Utils.h" // For JWT and other utilities
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <regex>
#include <nlohmann/json.hpp>

// OpenSSL error handling
void printOpenSSLErrors() {
    unsigned long err;
    while ((err = ERR_get_error())) {
        char* err_str = ERR_error_string(err, nullptr);
        std::cerr << "OpenSSL Error: " << err_str << std::endl;
    }
}

Server::Server(const ServerConfig& config,
               DatabaseManager& db_manager,
               AuthManager& auth_manager,
               VideoManager& video_manager)
    : config_(config),
      db_manager_(db_manager),
      auth_manager_(auth_manager),
      video_manager_(video_manager),
      thread_pool_(config.thread_pool_size) {

    // Initialize SSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Setup routes
    routes_["/"] = std::bind(&Server::handleRoot, this, std::placeholders::_1, std::placeholders::_2);
    routes_["/static/"] = std::bind(&Server::handleStaticFile, this, std::placeholders::_1, std::placeholders::_2);

    // Auth routes
    routes_["/api/register"] = std::bind(&Server::handleRegister, this, std::placeholders::_1, std::placeholders::_2);
    routes_["/api/login"] = std::bind(&Server::handleLogin, this, std::placeholders::_1, std::placeholders::_2);
    routes_["/api/profile"] = std::bind(&Server::handleProfile, this, std::placeholders::_1, std::placeholders::_2);

    // Video routes
    routes_["/api/upload"] = std::bind(&Server::handleUploadVideo, this, std::placeholders::_1, std::placeholders::_2);
    routes_["/api/videos"] = std::bind(&Server::handleListVideos, this, std::placeholders::_1, std::placeholders::_2);
    routes_["/api/videos/details"] = std::bind(&Server::handleGetVideoDetails, this, std::placeholders::_1, std::placeholders::_2);
    routes_["/stream/"] = std::bind(&Server::handleStreamVideo, this, std::placeholders::_1, std::placeholders::_2);
}

Server::~Server() {
    stop();
}

void Server::setupSSL() {
    // Using TLSv1.2 or TLSv1.3 only
    ssl_ctx_.reset(SSL_CTX_new(TLS_server_method()));
    if (!ssl_ctx_) {
        std::cerr << "Error creating SSL context." << std::endl;
        printOpenSSLErrors();
        throw std::runtime_error("SSL_CTX_new failed");
    }

    // Load server certificate and private key
    // You'll need to generate these:
    // openssl genrsa -out server.key 2048
    // openssl req -new -x509 -key server.key -out server.crt -days 365
    if (SSL_CTX_use_certificate_file(ssl_ctx_.get(), "server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading server certificate." << std::endl;
        printOpenSSLErrors();
        throw std::runtime_error("SSL_CTX_use_certificate_file failed");
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_.get(), "server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error loading private key." << std::endl;
        printOpenSSLErrors();
        throw std::runtime_error("SSL_CTX_use_privatekey_file failed");
    }
    if (!SSL_CTX_check_private_key(ssl_ctx_.get())) {
        std::cerr << "Private key does not match the certificate public key." << std::endl;
        printOpenSSLErrors();
        throw std::runtime_error("Private key mismatch");
    }

    // Optional: enforce strong cipher suites and protocols
    // SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS1_2_VERSION);
    // SSL_CTX_set_cipher_list(ssl_ctx_.get(), "HIGH:!aNULL:!MD5");
}

void Server::createSocket() {
    server_sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock_ < 0) {
        throw std::runtime_error("Failed to create socket.");
    }

    // Allow reusing address
    int opt = 1;
    if (setsockopt(server_sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt SO_REUSEADDR failed." << std::endl;
        // Not critical, continue
    }
}

void Server::bindSocket() {
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(config_.port);

    if (bind(server_sock_, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        throw std::runtime_error("Failed to bind socket.");
    }
}

void Server::listenSocket() {
    if (listen(server_sock_, config_.max_connections) < 0) {
        throw std::runtime_error("Failed to listen on socket.");
    }
    std::cout << "Server listening on port " << config_.port << "..." << std::endl;
}

void Server::start() {
    try {
        setupSSL(); // Setup SSL context
        createSocket();
        bindSocket();
        listenSocket();

        running_ = true;
        accept_thread_ = std::thread(&Server::acceptConnections, this);
    } catch (const std::exception& e) {
        std::cerr << "Server startup failed: " << e.what() << std::endl;
        running_ = false;
        if (server_sock_ != -1) close(server_sock_);
    }
}

void Server::stop() {
    if (running_) {
        running_ = false;
        if (server_sock_ != -1) {
            shutdown(server_sock_, SHUT_RDWR); // Stop new connections and close existing
            close(server_sock_);
        }
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
        std::cout << "Server stopped." << std::endl;
    }
}

void Server::acceptConnections() {
    while (running_) {
        sockaddr_in client_addr{};
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock_, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);

        if (client_sock < 0) {
            if (running_) { // Only log error if server is still supposed to be running
                std::cerr << "Failed to accept connection." << std::endl;
            }
            continue;
        }

        UniqueSslPtr ssl_conn(SSL_new(ssl_ctx_.get()));
        if (!ssl_conn) {
            std::cerr << "Error creating SSL object for client." << std::endl;
            printOpenSSLErrors();
            close(client_sock);
            continue;
        }

        SSL_set_fd(ssl_conn.get(), client_sock);

        if (SSL_accept(ssl_conn.get()) <= 0) {
            std::cerr << "SSL_accept failed." << std::endl;
            printOpenSSLErrors();
            close(client_sock);
            continue;
        }

        // Enqueue client handling to thread pool
        // thread_pool_.enqueue(&Server::handleClient, this, client_sock, std::move(ssl_conn));
	thread_pool_.enqueue([this, client_sock, ssl_conn = std::move(ssl_conn)]() mutable {
	    this->handleClient(client_sock, std::move(ssl_conn));
	});
    }
}


void Server::handleClient(int client_sock, UniqueSslPtr ssl_conn) {
    char buffer[4096]; // Max request size
    std::string raw_request_str;
    int bytes_read = 0;

    // Read HTTP request using SSL_read
    bytes_read = SSL_read(ssl_conn.get(), buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        raw_request_str = buffer;
    } else {
        int ssl_err = SSL_get_error(ssl_conn.get(), bytes_read);
        if (ssl_err != SSL_ERROR_ZERO_RETURN && ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
            std::cerr << "SSL_read error: " << ssl_err << std::endl;
            printOpenSSLErrors();
        }
        SSL_shutdown(ssl_conn.get()); // Attempt graceful shutdown
        close(client_sock);
        return;
    }

    try {
        HttpRequest request = http_parser_.parseRequest(raw_request_str);
        HttpResponse response = handleRequest(request);
        sendResponse(client_sock, ssl_conn, response);
    } catch (const std::exception& e) {
        std::cerr << "Error processing request: " << e.what() << std::endl;
        HttpResponse error_resp = errorResponse(500, "Internal Server Error");
        sendResponse(client_sock, ssl_conn, error_resp);
    }

    SSL_shutdown(ssl_conn.get());
    close(client_sock);
}


HttpResponse Server::handleRequest(HttpRequest& request) {
    std::cout << "Request: " << request.method << " " << request.path << std::endl;

    // Authenticate request globally if Authorization header is present
    request.jwt_payload = auth_manager_.authenticateRequest(request);

    // Check for exact path matches first
    auto it_exact = routes_.find(request.path);
    if (it_exact != routes_.end()) {
        return it_exact->second(request, request.jwt_payload ? *request.jwt_payload : nlohmann::json());
    }

    // Check for prefix matches (e.g., /static/, /stream/)
    for (auto const& [prefix, handler] : routes_) {
        if (request.path.rfind(prefix, 0) == 0) { // Check if path starts with prefix
            if (prefix == "/static/" || prefix == "/stream/") {
                 return handler(request, request.jwt_payload ? *request.jwt_payload : nlohmann::json());
            }
        }
    }


    return errorResponse(404, "Not Found");
}


void Server::sendResponse(int client_sock, UniqueSslPtr& ssl_conn, const HttpResponse& response) {
    std::string raw_response = http_parser_.buildResponse(response);
    if (SSL_write(ssl_conn.get(), raw_response.c_str(), raw_response.length()) <= 0) {
        std::cerr << "SSL_write error." << std::endl;
        printOpenSSLErrors();
    }
}

HttpResponse Server::jsonResponse(int status_code, const std::string& status_text, const nlohmann::json& data) {
    HttpResponse response;
    response.status_code = status_code;
    response.status_text = status_text;
    response.headers["Content-Type"] = "application/json";
    response.body = data.dump();
    return response;
}

HttpResponse Server::errorResponse(int status_code, const std::string& message) {
    HttpResponse response;
    response.status_code = status_code;
    response.status_text = message;
    response.headers["Content-Type"] = "application/json";
    response.body = nlohmann::json{{"error", message}}.dump();
    return response;
}


// --- Route Handlers ---

HttpResponse Server::handleRoot(HttpRequest& request, const nlohmann::json& user_payload) {
    HttpResponse response;
    response.status_code = 200;
    response.status_text = "OK";
    response.headers["Content-Type"] = "text/html";

    std::string file_path = config_.static_dir + "index.html";
    std::ifstream file(file_path, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Root HTML file not found: " << file_path << std::endl;
        return errorResponse(500, "Internal Server Error: index.html missing");
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    response.body = buffer.str();
    return response;
}

HttpResponse Server::handleStaticFile(HttpRequest& request, const nlohmann::json& user_payload) {
    HttpResponse response;
    response.status_code = 200;
    response.status_text = "OK";

    std::string file_path = config_.static_dir + request.path.substr(8); // Remove "/static/"
    
    // Simple path traversal prevention (basic, not exhaustive)
    if (file_path.find("..") != std::string::npos) {
        return errorResponse(400, "Bad Request");
    }

    std::ifstream file(file_path, std::ios::binary);

    if (!file.is_open()) {
        response.status_code = 404;
        response.status_text = "Not Found";
        response.body = "File not found";
        return response;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    response.body = buffer.str();

    // Determine Content-Type based on extension using Utils
    response.headers["Content-Type"] = getMimeType(file_path);

    return response;
}

HttpResponse Server::handleRegister(HttpRequest& request, const nlohmann::json& user_payload) {
    if (request.method != "POST") {
        return errorResponse(405, "Method Not Allowed");
    }

    try {
        nlohmann::json request_body = nlohmann::json::parse(request.body);
        std::string username = request_body["username"];
        std::string email = request_body["email"];
        std::string password = request_body["password"];
        std::string role = request_body.count("role") ? request_body["role"].get<std::string>() : "student"; // Default role

        if (auth_manager_.registerUser(username, email, password, role)) {
            return jsonResponse(201, "Created", {{"message", "User registered successfully"}});
        } else {
            return errorResponse(400, "Registration failed (username/email might be taken or invalid data).");
        }
    } catch (const nlohmann::json::parse_error& e) {
        return errorResponse(400, "Invalid JSON format: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return errorResponse(400, "Bad Request: " + std::string(e.what()));
    }
}

HttpResponse Server::handleLogin(HttpRequest& request, const nlohmann::json& user_payload) {
    if (request.method != "POST") {
        return errorResponse(405, "Method Not Allowed");
    }

    try {
        nlohmann::json request_body = nlohmann::json::parse(request.body);
        std::string username = request_body["username"];
        std::string password = request_body["password"];

        std::optional<std::string> jwt_token = auth_manager_.loginUser(username, password);

        if (jwt_token.has_value()) {
            return jsonResponse(200, "OK", {{"message", "Login successful"}, {"token", jwt_token.value()}});
        } else {
            return errorResponse(401, "Invalid credentials");
        }
    } catch (const nlohmann::json::parse_error& e) {
        return errorResponse(400, "Invalid JSON format: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return errorResponse(400, "Bad Request: " + std::string(e.what()));
    }
}

HttpResponse Server::handleProfile(HttpRequest& request, const nlohmann::json& user_payload) {
    if (request.method != "GET") {
        return errorResponse(405, "Method Not Allowed");
    }

    if (!auth_manager_.authorizeRequest(request, {"student", "instructor", "admin"})) {
        return errorResponse(403, "Forbidden: Authentication required.");
    }

    // User payload is already in request.jwt_payload if authenticated
    if (request.jwt_payload.has_value()) {
        nlohmann::json profile_data;
        profile_data["username"] = request.jwt_payload.value()["username"];
        profile_data["role"] = request.jwt_payload.value()["role"];
        profile_data["user_id"] = request.jwt_payload.value()["user_id"];
        // Add more profile data as needed, potentially from DB lookup
        return jsonResponse(200, "OK", profile_data);
    } else {
        return errorResponse(401, "Unauthorized");
    }
}

HttpResponse Server::handleUploadVideo(HttpRequest& request, const nlohmann::json& user_payload) {
    if (request.method != "POST") {
        return errorResponse(405, "Method Not Allowed");
    }

    if (!auth_manager_.authorizeRequest(request, {"instructor", "admin"})) {
        return errorResponse(403, "Forbidden: Only instructors can upload videos.");
    }

    if (!request.jwt_payload.has_value() || !request.jwt_payload.value().count("user_id")) {
        return errorResponse(401, "Unauthorized: User ID missing from token.");
    }

    int user_id = request.jwt_payload.value()["user_id"].get<int>();
    std::optional<Video> uploaded_video = video_manager_.handleVideoUpload(request, user_id);

    if (uploaded_video.has_value()) {
        // Return a simplified video object to the client
        nlohmann::json video_json;
        video_json["id"] = uploaded_video->id; // Will be 0 if not fetched from DB
        video_json["title"] = uploaded_video->title;
        video_json["description"] = uploaded_video->description;
        video_json["file_path"] = "/stream/" + fs::path(uploaded_video->file_path).filename().string(); // Client-facing URL
        video_json["category"] = uploaded_video->category;
        video_json["tags"] = uploaded_video->tags;
        video_json["uploaded_at"] = uploaded_video->uploaded_at;
        video_json["user_id"] = uploaded_video->user_id;

        return jsonResponse(201, "Created", {{"message", "Video uploaded successfully"}, {"video", video_json}});
    } else {
        return errorResponse(500, "Failed to upload video.");
    }
}

HttpResponse Server::handleListVideos(HttpRequest& request, const nlohmann::json& user_payload) {
    if (request.method != "GET") {
        return errorResponse(405, "Method Not Allowed");
    }

    // This API can be public or require authentication
    // For now, let's make it accessible to authenticated users
    if (!auth_manager_.authorizeRequest(request, {"student", "instructor", "admin"})) {
        return errorResponse(403, "Forbidden: Authentication required.");
    }

    std::string search_query = "";
    if (request.query_params.count("q")) {
        search_query = request.query_params["q"];
    }

    std::vector<Video> videos = video_manager_.getVideos(search_query);
    nlohmann::json videos_json = nlohmann::json::array();

    for (const auto& video : videos) {
        nlohmann::json video_item;
        video_item["id"] = video.id;
        video_item["title"] = video.title;
        video_item["description"] = video.description;
        video_item["file_url"] = "/stream/" + fs::path(video.file_path).filename().string(); // Client-facing URL
        video_item["thumbnail_url"] = video.thumbnail_path.empty() ? "" : "/static/thumbnails/" + fs::path(video.thumbnail_path).filename().string(); // Placeholder
        video_item["user_id"] = video.user_id;
        video_item["category"] = video.category;
        video_item["tags"] = video.tags;
        video_item["uploaded_at"] = video.uploaded_at;
        video_item["views"] = video.views;
        videos_json.push_back(video_item);
    }

    return jsonResponse(200, "OK", {{"videos", videos_json}});
}

HttpResponse Server::handleGetVideoDetails(HttpRequest& request, const nlohmann::json& user_payload) {
    if (request.method != "GET") {
        return errorResponse(405, "Method Not Allowed");
    }

    if (!auth_manager_.authorizeRequest(request, {"student", "instructor", "admin"})) {
        return errorResponse(403, "Forbidden: Authentication required.");
    }

    if (!request.query_params.count("id")) {
        return errorResponse(400, "Bad Request: Video ID is required.");
    }

    try {
        int video_id = std::stoi(request.query_params["id"]);
        std::optional<Video> video_opt = video_manager_.getVideoDetails(video_id);

        if (video_opt.has_value()) {
            Video video = video_opt.value();
            nlohmann::json video_json;
            video_json["id"] = video.id;
            video_json["title"] = video.title;
            video_json["description"] = video.description;
            video_json["file_url"] = "/stream/" + fs::path(video.file_path).filename().string();
            video_json["thumbnail_url"] = video.thumbnail_path.empty() ? "" : "/static/thumbnails/" + fs::path(video.thumbnail_path).filename().string();
            video_json["user_id"] = video.user_id;
            video_json["category"] = video.category;
            video_json["tags"] = video.tags;
            video_json["uploaded_at"] = video.uploaded_at;
            video_json["views"] = video.views;

            // Increment views on detail access (or on actual stream start)
            video_manager_.incrementViews(video.id);

            return jsonResponse(200, "OK", {{"video", video_json}});
        } else {
            return errorResponse(404, "Video not found.");
        }
    } catch (const std::exception& e) {
        return errorResponse(400, "Invalid video ID: " + std::string(e.what()));
    }
}

HttpResponse Server::handleStreamVideo(HttpRequest& request, const nlohmann::json& user_payload) {
    if (request.method != "GET") {
        return errorResponse(405, "Method Not Allowed");
    }

    // Video streaming typically does not require explicit authentication for every byte.
    // Instead, the initial request for the video URL (or manifest) is authenticated,
    // and subsequent requests for segments might use a temporary token or rely on referrer/IP.
    // For simplicity, we'll assume direct access to the /stream/ URL is allowed after initial access.
    // In a real system, you'd want proper session validation for streaming.
    if (!auth_manager_.authorizeRequest(request, {"student", "instructor", "admin"})) {
        return errorResponse(403, "Forbidden: Authentication required to stream videos.");
    }

    std::string requested_filename = request.path.substr(8); // Remove "/stream/"
    // fs::path full_file_path = config_.upload_dir / requested_filename;
    fs::path full_file_path = fs::path(config_.upload_dir) / requested_filename;

    if (!fs::exists(full_file_path) || !fs::is_regular_file(full_file_path)) {
        std::cerr << "Stream file not found: " << full_file_path << std::endl;
        return errorResponse(404, "Video file not found.");
    }

    HttpResponse response;
    response.status_code = 200;
    response.status_text = "OK";
    response.headers["Content-Type"] = getMimeType(full_file_path.string());
    response.headers["Accept-Ranges"] = "bytes"; // Enable range requests

    std::ifstream file(full_file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open video file for streaming: " << full_file_path << std::endl;
        return errorResponse(500, "Internal Server Error: Cannot stream video.");
    }

    long long file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    long long start_byte = 0;
    long long end_byte = file_size - 1;

    // Handle Range header for partial content
    auto range_it = request.headers.find("Range");
    if (range_it != request.headers.end()) {
        response.status_code = 206; // Partial Content
        response.status_text = "Partial Content";

        std::string range_header = range_it->second;
        // Expected format: bytes=start-end or bytes=start- or bytes=-end
        std::regex range_regex("bytes=(\\d*)-(\\d*)");
        std::smatch matches;

        if (std::regex_search(range_header, matches, range_regex)) {
            if (matches[1].matched) {
                start_byte = std::stoll(matches[1].str());
            }
            if (matches[2].matched) {
                end_byte = std::stoll(matches[2].str());
            } else if (!matches[1].matched) { // e.g., bytes=-100
                start_byte = file_size - end_byte;
                end_byte = file_size - 1;
            }
        }
        
        // Ensure valid range
        if (start_byte < 0) start_byte = 0;
        if (end_byte >= file_size) end_byte = file_size - 1;
        if (start_byte > end_byte) { // Invalid range, return full content or error
             start_byte = 0;
             end_byte = file_size - 1;
             response.status_code = 200;
             response.status_text = "OK";
        }

        response.headers["Content-Range"] = "bytes " + std::to_string(start_byte) + "-" + std::to_string(end_byte) + "/" + std::to_string(file_size);
        response.headers["Content-Length"] = std::to_string(end_byte - start_byte + 1);

        file.seekg(start_byte, std::ios::beg);
        long long bytes_to_read = end_byte - start_byte + 1;
        std::vector<char> buffer(bytes_to_read);
        file.read(buffer.data(), bytes_to_read);
        response.body.assign(buffer.begin(), buffer.end());

    } else {
        // No Range header, send entire file
        response.headers["Content-Length"] = std::to_string(file_size);
        std::ostringstream buffer_stream;
        buffer_stream << file.rdbuf();
        response.body = buffer_stream.str();
    }

    return response;
}
