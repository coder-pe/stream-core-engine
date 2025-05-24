#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

struct HttpRequest {
    std::string method;
    std::string path;
    std::string http_version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    std::unordered_map<std::string, std::string> query_params;
    std::unordered_map<std::string, std::string> form_data; // For x-www-form-urlencoded
    std::unordered_map<std::string, std::string> cookies; // For cookies

    // For file uploads
    struct FilePart {
        std::string name;
        std::string filename;
        std::string content_type;
        std::vector<char> data;
    };
    std::unordered_map<std::string, FilePart> files;

    // Parsed JWT payload
    std::optional<nlohmann::json> jwt_payload;
};

struct HttpResponse {
    int status_code = 200;
    std::string status_text = "OK";
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

class HttpParser {
public:
    HttpRequest parseRequest(const std::string& raw_request);
    std::string buildResponse(const HttpResponse& response);

private:
    void parseHeaderLine(HttpRequest& request, const std::string& header_str);
    void parseUrlEncodedBody(HttpRequest& request);
    void parseMultipartFormData(HttpRequest& request, const std::string& boundary);
    void parseCookies(HttpRequest& request, const std::string& cookie_header);
    std::string urlDecode(const std::string& str);
};
