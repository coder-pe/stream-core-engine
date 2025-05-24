#include "AuthManager.h"
#include <iostream>

AuthManager::AuthManager(DatabaseManager& db_manager, const ServerConfig& config)
    : db_manager_(db_manager), config_(config) {}

std::optional<std::string> AuthManager::registerUser(const std::string& username, const std::string& email, const std::string& password, const std::string& role) {
    // Basic validation
    if (username.empty() || email.empty() || password.empty()) {
        std::cerr << "Registration error: Username, email, or password cannot be empty." << std::endl;
        return std::nullopt;
    }

    if (db_manager_.getUserByUsername(username).has_value()) {
        std::cerr << "Registration error: Username already exists." << std::endl;
        return std::nullopt;
    }

    // Generate salt and hash password
    std::string salt = generateSalt(16); // 16 bytes for salt
    std::string password_hash = hashPassword(password, salt);

    User new_user;
    new_user.username = username;
    new_user.email = email;
    new_user.password_hash = password_hash;
    new_user.salt = salt;
    new_user.role = role;
    new_user.created_at = static_cast<long long>(std::time(nullptr));

    if (db_manager_.insertUser(new_user)) {
        return "Registration successful.";
    }
    return std::nullopt;
}

std::optional<std::string> AuthManager::loginUser(const std::string& username, const std::string& password) {
    std::optional<User> user_opt = db_manager_.getUserByUsername(username);
    if (!user_opt.has_value()) {
        std::cerr << "Login error: User not found." << std::endl;
        return std::nullopt;
    }

    User user = user_opt.value();
    std::string hashed_input_password = hashPassword(password, user.salt);

    if (hashed_input_password == user.password_hash) {
        // Generate JWT
        nlohmann::json payload;
        payload["user_id"] = user.id;
        payload["username"] = user.username;
        payload["role"] = user.role;
        payload["exp"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + config_.jwt_expiry_seconds;

        return createJWT(payload, config_.jwt_secret);
    } else {
        std::cerr << "Login error: Incorrect password." << std::endl;
        return std::nullopt;
    }
}

std::optional<nlohmann::json> AuthManager::authenticateRequest(const HttpRequest& request) {
    auto auth_header_it = request.headers.find("Authorization");
    if (auth_header_it == request.headers.end()) {
        return std::nullopt;
    }

    std::string auth_header = auth_header_it->second;
    if (auth_header.rfind("Bearer ", 0) != 0) { // Check if it starts with "Bearer "
        return std::nullopt;
    }

    std::string token = auth_header.substr(7); // Extract token
    return verifyJWT(token, config_.jwt_secret);
}

bool AuthManager::authorizeRequest(const HttpRequest& request, const std::vector<std::string>& allowed_roles) {
    std::optional<nlohmann::json> payload_opt = authenticateRequest(request);
    if (!payload_opt.has_value()) {
        return false; // Not authenticated
    }

    nlohmann::json payload = payload_opt.value();
    if (!payload.count("role")) {
        return false; // No role in token
    }

    std::string user_role = payload["role"].get<std::string>();

    for (const std::string& allowed_role : allowed_roles) {
        if (user_role == allowed_role) {
            return true;
        }
    }
    return false; // Role not allowed
}
