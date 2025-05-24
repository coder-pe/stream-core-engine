#pragma once

#include <string>
#include <sqlite3.h>
#include <mutex>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

struct User {
    int id = 0;
    std::string username;
    std::string email;
    std::string password_hash;
    std::string salt;
    std::string role; // "student", "instructor", "admin"
    long long created_at = 0; // Unix timestamp
};

struct Video {
    int id = 0;
    std::string title;
    std::string description;
    std::string file_path; // Path on server filesystem
    std::string thumbnail_path;
    int user_id = 0; // Instructor ID
    std::string category;
    std::vector<std::string> tags; // Stored as JSON string in DB
    long long uploaded_at = 0; // Unix timestamp
    long long views = 0;
};

class DatabaseManager {
public:
    DatabaseManager(const std::string& db_path);
    ~DatabaseManager();

    bool open();
    void close();

    // User management
    bool createUserTable();
    bool insertUser(const User& user);
    std::optional<User> getUserByUsername(const std::string& username);
    std::optional<User> getUserById(int id);

    // Video management
    bool createVideoTable();
    bool insertVideo(const Video& video);
    std::optional<Video> getVideoById(int id);
    std::vector<Video> getAllVideos();
    std::vector<Video> searchVideos(const std::string& query);
    bool incrementVideoViews(int video_id);

private:
    std::string db_path_;
    sqlite3* db_ = nullptr;
    std::mutex db_mutex_;

    static int callback(void* data, int argc, char** argv, char** azColName);
    bool executeSql(const std::string& sql);
};
