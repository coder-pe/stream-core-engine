#pragma once

#include "DatabaseManager.h"
#include "Utils.h"
#include "Config.h"
#include "HttpParser.h"
#include <optional>
#include <string>

class AuthManager {
public:
    AuthManager(DatabaseManager& db_manager, const ServerConfig& config);

    std::optional<std::string> registerUser(const std::string& username, const std::string& email, const std::string& password, const std::string& role = "student");
    std::optional<std::string> loginUser(const std::string& username, const std::string& password);
    std::optional<nlohmann::json> authenticateRequest(const HttpRequest& request);
    bool authorizeRequest(const HttpRequest& request, const std::vector<std::string>& allowed_roles);

private:
    DatabaseManager& db_manager_;
    const ServerConfig& config_;
};
