#pragma once

#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <memory>
#include <optional>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <nlohmann/json.hpp>

std::string trim(const std::string& str);

// Helper para convertir bytes a string hexadecimal
std::string bytesToHex(const unsigned char* data, size_t len);

// Generar un salt aleatorio para hashing de contraseñas
std::string generateSalt(size_t length);

// Hashing de contraseña con SHA256 y salt
std::string hashPassword(const std::string& password, const std::string& salt);

// JWT Utilities
std::string base64Encode(const std::string& input);
std::string base64Decode(const std::string& input);
std::string createJWT(const nlohmann::json& payload, const std::string& secret);
std::optional<nlohmann::json> verifyJWT(const std::string& token, const std::string& secret);

// MIME type detector
std::string getMimeType(const std::string& filename);

// RAII wrapper for SSL_CTX and SSL
struct SslContextDeleter {
    void operator()(SSL_CTX* ctx) const {
        if (ctx) SSL_CTX_free(ctx);
    }
};

struct SslDeleter {
    void operator()(SSL* ssl) const {
        if (ssl) SSL_free(ssl);
    }
};

using UniqueSslCtxPtr = std::unique_ptr<SSL_CTX, SslContextDeleter>;
using UniqueSslPtr = std::unique_ptr<SSL, SslDeleter>;
