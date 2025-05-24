#include "HttpParser.h"
#include "Utils.h"
#include <sstream>
#include <algorithm>
#include <iostream>
#include <regex>
#include <optional>

// Helper to trim whitespace from a string
/*std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r");
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}*/

HttpRequest HttpParser::parseRequest(const std::string& raw_request) {
    HttpRequest request;
    std::istringstream iss(raw_request);
    std::string line;

    // Parse request line
    std::getline(iss, line);
    std::stringstream ss_line(line);
    ss_line >> request.method >> request.path >> request.http_version;

    // Parse query parameters
    size_t query_pos = request.path.find('?');
    if (query_pos != std::string::npos) {
        std::string query_string = request.path.substr(query_pos + 1);
        request.path = request.path.substr(0, query_pos);
        std::stringstream ss_query(query_string);
        std::string param;
        while (std::getline(ss_query, param, '&')) {
            size_t eq_pos = param.find('=');
            if (eq_pos != std::string::npos) {
                request.query_params[urlDecode(param.substr(0, eq_pos))] = urlDecode(param.substr(eq_pos + 1));
            } else {
                request.query_params[urlDecode(param)] = "";
            }
        }
    }

    // Parse headers and body
    std::string current_line;
    std::stringstream header_ss;
    bool in_body = false;
    while (std::getline(iss, current_line)) {
        if (current_line == "\r" || current_line == "") { // End of headers
            in_body = true;
            continue;
        }
        if (in_body) {
            request.body += current_line;
        } else {
            header_ss << current_line;
        }
    }
    parseHeaders(request, header_ss.str());

    // Parse cookies
    if (request.headers.count("Cookie")) {
        parseCookies(request, request.headers["Cookie"]);
    }

    // Parse body based on Content-Type
    if (request.headers.count("Content-Type")) {
        std::string content_type = request.headers["Content-Type"];
        if (content_type.find("application/x-www-form-urlencoded") != std::string::npos) {
            parseUrlEncodedBody(request);
        } else if (content_type.find("multipart/form-data") != std::string::npos) {
            size_t boundary_pos = content_type.find("boundary=");
            if (boundary_pos != std::string::npos) {
                std::string boundary = content_type.substr(boundary_pos + 9);
                parseMultipartFormData(request, boundary);
            }
        }
    }

    return request;
}

void HttpParser::parseHeaders(HttpRequest& request, const std::string& header_str) {
    std::istringstream iss(header_str);
    std::string line;
    while (std::getline(iss, line) && line != "\r") {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = trim(line.substr(0, colon_pos));
            std::string value = trim(line.substr(colon_pos + 1));
            request.headers[key] = value;
        }
    }
}

void HttpParser::parseUrlEncodedBody(HttpRequest& request) {
    std::stringstream ss_body(request.body);
    std::string param;
    while (std::getline(ss_body, param, '&')) {
        size_t eq_pos = param.find('=');
        if (eq_pos != std::string::npos) {
            request.form_data[urlDecode(param.substr(0, eq_pos))] = urlDecode(param.substr(eq_pos + 1));
        } else {
            request.form_data[urlDecode(param)] = "";
        }
    }
}

void HttpParser::parseMultipartFormData(HttpRequest& request, const std::string& boundary) {
    std::string full_boundary = "--" + boundary;
    std::string end_boundary = "--" + boundary + "--";

    size_t current_pos = 0;
    while (current_pos < request.body.length()) {
        size_t start_part = request.body.find(full_boundary, current_pos);
        if (start_part == std::string::npos) break; // No more parts

        start_part += full_boundary.length();
        if (request.body.substr(start_part, 2) == "--") break; // End boundary

        size_t end_part = request.body.find(full_boundary, start_part);
        if (end_part == std::string::npos) break; // Malformed or last part

        std::string part_content = request.body.substr(start_part, end_part - start_part);

        // Extract headers for this part
        std::istringstream part_iss(part_content);
        std::string part_line;
        std::string part_headers_str;
        bool in_part_body = false;
        while (std::getline(part_iss, part_line)) {
            if (part_line == "\r" || part_line == "") {
                in_part_body = true;
                break;
            }
            part_headers_str += part_line;
        }

        std::unordered_map<std::string, std::string> part_headers;
        std::istringstream headers_iss(part_headers_str);
        while (std::getline(headers_iss, part_line)) {
            size_t colon_pos = part_line.find(':');
            if (colon_pos != std::string::npos) {
                std::string key = trim(part_line.substr(0, colon_pos));
                std::string value = trim(part_line.substr(colon_pos + 1));
                part_headers[key] = value;
            }
        }

        if (part_headers.count("Content-Disposition")) {
            std::string disposition = part_headers["Content-Disposition"];
            std::smatch matches;

            // Extract name and filename
            std::regex name_regex("name=\"([^\"]+)\"");
            std::regex filename_regex("filename=\"([^\"]+)\"");

            std::string name_str, filename_str;
            if (std::regex_search(disposition, matches, name_regex) && matches.size() > 1) {
                name_str = matches[1].str();
            }
            if (std::regex_search(disposition, matches, filename_regex) && matches.size() > 1) {
                filename_str = matches[1].str();
            }

            // Extract part body
            std::string part_body;
            if (in_part_body) {
                size_t body_start_pos = part_content.find("\r\n\r\n"); // Find end of headers
                if (body_start_pos != std::string::npos) {
                    body_start_pos += 4; // Move past \r\n\r\n
                    part_body = part_content.substr(body_start_pos);
                    // Remove trailing \r\n if present
                    if (!part_body.empty() && part_body.back() == '\n') part_body.pop_back();
                    if (!part_body.empty() && part_body.back() == '\r') part_body.pop_back();
                }
            }


            if (!name_str.empty()) {
                if (!filename_str.empty()) {
                    // This is a file
                    HttpRequest::FilePart file_part;
                    file_part.name = name_str;
                    file_part.filename = filename_str;
                    if (part_headers.count("Content-Type")) {
                        file_part.content_type = part_headers["Content-Type"];
                    } else {
                        file_part.content_type = "application/octet-stream"; // Default
                    }
                    file_part.data.assign(part_body.begin(), part_body.end());
                    request.files[name_str] = file_part;
                } else {
                    // This is a regular form field
                    request.form_data[name_str] = part_body;
                }
            }
        }
        current_pos = end_part;
    }
}


void HttpParser::parseCookies(HttpRequest& request, const std::string& cookie_header) {
    std::stringstream ss(cookie_header);
    std::string segment;
    while (std::getline(ss, segment, ';')) {
        size_t eq_pos = segment.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = trim(segment.substr(0, eq_pos));
            std::string value = trim(segment.substr(eq_pos + 1));
            request.cookies[key] = value;
        }
    }
}

std::string HttpParser::urlDecode(const std::string& str) {
    std::string decoded_str;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%') {
            if (i + 2 < str.length()) {
                std::string hex = str.substr(i + 1, 2);
                try {
                    decoded_str += static_cast<char>(std::stoi(hex, nullptr, 16));
                    i += 2;
                } catch (const std::exception& e) {
                    decoded_str += str[i]; // Fallback if conversion fails
                }
            } else {
                decoded_str += str[i];
            }
        } else if (str[i] == '+') {
            decoded_str += ' ';
        } else {
            decoded_str += str[i];
        }
    }
    return decoded_str;
}

std::string HttpParser::buildResponse(const HttpResponse& response) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << response.status_code << " " << response.status_text << "\r\n";

    for (const auto& header : response.headers) {
        oss << header.first << ": " << header.second << "\r\n";
    }

    oss << "Content-Length: " << response.body.length() << "\r\n";
    oss << "\r\n";
    oss << response.body;

    return oss.str();
}
