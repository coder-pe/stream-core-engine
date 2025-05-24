#include "AuthManager.h"
#include <iostream>
#include <chrono>

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
        // Generate JWT with correct timestamp calculation
        nlohmann::json payload;
        payload["user_id"] = user.id;
        payload["username"] = user.username;
        payload["role"] = user.role;
        
        // Current time in seconds since epoch
        auto now = std::chrono::system_clock::now();
        auto current_time_seconds = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
            
        // Add expiry time (ensure config_.jwt_expiry_seconds is reasonable, like 3600 for 1 hour)
        payload["exp"] = current_time_seconds + config_.jwt_expiry_seconds;
        
        // Add issued at time for debugging
        payload["iat"] = current_time_seconds;
        
        std::cout << "JWT created - Current time: " << current_time_seconds 
                  << ", Expires at: " << (current_time_seconds + config_.jwt_expiry_seconds)
                  << ", Expiry in seconds: " << config_.jwt_expiry_seconds << std::endl;

        return createJWT(payload, config_.jwt_secret);
    } else {
        std::cerr << "Login error: Incorrect password." << std::endl;
        return std::nullopt;
    }
}

std::optional<nlohmann::json> AuthManager::authenticateRequest(const HttpRequest& request) {
    auto auth_header_it = request.headers.find("Authorization");
    if (auth_header_it == request.headers.end()) {
        std::cerr << "Authentication error: No Authorization header found." << std::endl;
        return std::nullopt;
    }

    std::string auth_header = auth_header_it->second;
    if (auth_header.rfind("Bearer ", 0) != 0) { // Check if it starts with "Bearer "
        std::cerr << "Authentication error: Invalid Authorization header format." << std::endl;
        return std::nullopt;
    }

    std::string token = auth_header.substr(7); // Extract token
    
    std::optional<nlohmann::json> payload_opt = verifyJWT(token, config_.jwt_secret);
    
    if (!payload_opt.has_value()) {
        std::cerr << "Authentication error: Invalid or expired token." << std::endl;
        return std::nullopt;
    }
    
    // Additional expiry check (in case verifyJWT doesn't handle it properly)
    nlohmann::json payload = payload_opt.value();
    if (payload.count("exp")) {
        auto current_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        long long exp_time = payload["exp"].get<long long>();
        
        if (current_time >= exp_time) {
            std::cerr << "Authentication error: Token expired. Current: " << current_time 
                      << ", Expires: " << exp_time << std::endl;
            return std::nullopt;
        }
        
        std::cout << "Token validation - Current time: " << current_time 
                  << ", Expires at: " << exp_time 
                  << ", Time remaining: " << (exp_time - current_time) << " seconds" << std::endl;
    }
    
    return payload_opt;
}

bool AuthManager::authorizeRequest(const HttpRequest& request, const std::vector<std::string>& allowed_roles) {
    std::optional<nlohmann::json> payload_opt = authenticateRequest(request);
    if (!payload_opt.has_value()) {
        return false; // Not authenticated
    }

    nlohmann::json payload = payload_opt.value();
    if (!payload.count("role")) {
        std::cerr << "Authorization error: No role found in token." << std::endl;
        return false; // No role in token
    }

    std::string user_role = payload["role"].get<std::string>();

    for (const std::string& allowed_role : allowed_roles) {
        if (user_role == allowed_role) {
            std::cout << "Authorization successful for role: " << user_role << std::endl;
            return true;
        }
    }
    
    std::cerr << "Authorization error: Role '" << user_role 
              << "' not in allowed roles." << std::endl;
    return false; // Role not allowed
}
