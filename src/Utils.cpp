#include "Utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <filesystem>
#include <algorithm> 
#include <cctype>

// Para base64
#include <vector>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

std::string trim(const std::string& str) {
    auto start = str.begin();
    while (start != str.end() && std::isspace(*start)) start++;
    
    auto end = str.end();
    do {
        end--;
    } while (std::distance(start, end) > 0 && std::isspace(*end));
    
    return std::string(start, end + 1);
}

std::string bytesToHex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string generateSalt(size_t length) {
    std::string salt_str(length, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&salt_str[0]), length) != 1) {
        throw std::runtime_error("Error generating random bytes for salt.");
    }
    return bytesToHex(reinterpret_cast<const unsigned char*>(salt_str.data()), length);
}

std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string combined = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, combined.c_str(), combined.length());
    SHA256_Final(hash, &sha256);
    return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

// Base64 encoding/decoding (simplificado para JWT)
std::string base64Encode(const std::string& input) {
    BIO* bio, *b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // No agregar CRLF
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    // JWT base64url encoding: replace + with -, / with _ and remove padding =
    std::replace(result.begin(), result.end(), '+', '-');
    std::replace(result.begin(), result.end(), '/', '_');
    result.erase(std::remove(result.begin(), result.end(), '='), result.end());

    return result;
}

std::string base64Decode(const std::string& input) {
    // JWT base64url decoding: replace - with +, _ with /
    std::string temp = input;
    std::replace(temp.begin(), temp.end(), '-', '+');
    std::replace(temp.begin(), temp.end(), '_', '/');

    // Add padding back
    while (temp.length() % 4 != 0) {
        temp += '=';
    }

    BIO* bio, *b64;
    char* buffer = new char[temp.length()]; // Max possible length
    memset(buffer, 0, temp.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(temp.c_str(), temp.length());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines

    int decoded_len = BIO_read(bio, buffer, temp.length());
    if (decoded_len < 0) {
        delete[] buffer;
        throw std::runtime_error("Base64 decoding failed.");
    }
    std::string result(buffer, decoded_len);
    delete[] buffer;
    BIO_free_all(bio);
    return result;
}


std::string createJWT(const nlohmann::json& payload, const std::string& secret) {
    // Header
    nlohmann::json header = {
        {"alg", "HS256"},
        {"typ", "JWT"}
    };

    std::string encoded_header = base64Encode(header.dump());
    std::string encoded_payload = base64Encode(payload.dump());

    std::string signature_input = encoded_header + "." + encoded_payload;

    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), secret.c_str(), secret.length(),
         reinterpret_cast<const unsigned char*>(signature_input.c_str()), signature_input.length(),
         hmac_result, &hmac_len);

    std::string encoded_signature = base64Encode(std::string(reinterpret_cast<char*>(hmac_result), hmac_len));

    return encoded_header + "." + encoded_payload + "." + encoded_signature;
}

std::optional<nlohmann::json> verifyJWT(const std::string& token, const std::string& secret) {
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);

    if (first_dot == std::string::npos || second_dot == std::string::npos) {
        return std::nullopt; // Invalid JWT format
    }

    std::string encoded_header = token.substr(0, first_dot);
    std::string encoded_payload = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string encoded_signature = token.substr(second_dot + 1);

    std::string signature_input = encoded_header + "." + encoded_payload;

    unsigned char expected_hmac[EVP_MAX_MD_SIZE];
    unsigned int expected_hmac_len = 0;

    HMAC(EVP_sha256(), secret.c_str(), secret.length(),
         reinterpret_cast<const unsigned char*>(signature_input.c_str()), signature_input.length(),
         expected_hmac, &expected_hmac_len);

    std::string expected_encoded_signature = base64Encode(std::string(reinterpret_cast<char*>(expected_hmac), expected_hmac_len));

    if (expected_encoded_signature != encoded_signature) {
        return std::nullopt; // Signature mismatch
    }

    try {
        std::string decoded_payload_str = base64Decode(encoded_payload);
        nlohmann::json payload = nlohmann::json::parse(decoded_payload_str);

        // Check expiration
        if (payload.count("exp")) {
            long long exp_time = payload["exp"].get<long long>();
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (now >= exp_time) {
                return std::nullopt; // Token expired
            }
        }
        return payload;
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JWT payload parse error: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::runtime_error& e) {
        std::cerr << "JWT decode error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

std::string getMimeType(const std::string& filename) {
    namespace fs = std::filesystem;
    fs::path p(filename);
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    if (ext == ".html" || ext == ".htm") return "text/html";
    if (ext == ".css") return "text/css";
    if (ext == ".js") return "application/javascript";
    if (ext == ".json") return "application/json";
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif") return "image/gif";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".mp4") return "video/mp4";
    if (ext == ".webm") return "video/webm";
    if (ext == ".ogg") return "video/ogg";
    if (ext == ".pdf") return "application/pdf";
    if (ext == ".txt") return "text/plain";
    if (ext == ".ico") return "image/x-icon";
    // Add more as needed
    return "application/octet-stream"; // Default
}
