#include "DatabaseManager.h"
#include <iostream>
#include <ctime>

DatabaseManager::DatabaseManager(const std::string& db_path) : db_path_(db_path) {}

DatabaseManager::~DatabaseManager() {
    close();
}

bool DatabaseManager::open() {
    if (sqlite3_open(db_path_.c_str(), &db_) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db_) << std::endl;
        db_ = nullptr;
        return false;
    }
    std::cout << "Opened database successfully: " << db_path_ << std::endl;
    return true;
}

void DatabaseManager::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
        std::cout << "Database closed." << std::endl;
    }
}

bool DatabaseManager::executeSql(const std::string& sql) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::cerr << "SQL error: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}

bool DatabaseManager::createUserTable() {
    std::string sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at INTEGER
        );
    )";
    return executeSql(sql);
}

bool DatabaseManager::insertUser(const User& user) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::string sql = "INSERT INTO users (username, email, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, user.username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user.email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user.password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, user.salt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, user.role.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, user.created_at == 0 ? static_cast<long long>(std::time(nullptr)) : user.created_at);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert user: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

std::optional<User> DatabaseManager::getUserByUsername(const std::string& username) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::string sql = "SELECT id, username, email, password_hash, salt, role, created_at FROM users WHERE username = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return std::nullopt;
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<User> user_opt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        User user;
        user.id = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        user.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        user.created_at = sqlite3_column_int64(stmt, 6);
        user_opt = user;
    }
    sqlite3_finalize(stmt);
    return user_opt;
}

std::optional<User> DatabaseManager::getUserById(int id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::string sql = "SELECT id, username, email, password_hash, salt, role, created_at FROM users WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return std::nullopt;
    }
    sqlite3_bind_int(stmt, 1, id);

    std::optional<User> user_opt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        User user;
        user.id = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        user.salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        user.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        user.created_at = sqlite3_column_int64(stmt, 6);
        user_opt = user;
    }
    sqlite3_finalize(stmt);
    return user_opt;
}


bool DatabaseManager::createVideoTable() {
    std::string sql = R"(
        CREATE TABLE IF NOT EXISTS videos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            file_path TEXT NOT NULL,
            thumbnail_path TEXT,
            user_id INTEGER NOT NULL,
            category TEXT,
            tags TEXT, -- Stored as JSON array
            uploaded_at INTEGER,
            views INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    )";
    return executeSql(sql);
}

bool DatabaseManager::insertVideo(const Video& video) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::string sql = "INSERT INTO videos (title, description, file_path, thumbnail_path, user_id, category, tags, uploaded_at, views) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, video.title.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, video.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, video.file_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, video.thumbnail_path.empty() ? nullptr : video.thumbnail_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, video.user_id);
    sqlite3_bind_text(stmt, 6, video.category.c_str(), -1, SQLITE_TRANSIENT);
    
    nlohmann::json tags_json = video.tags;
    std::string tags_str = tags_json.dump();
    sqlite3_bind_text(stmt, 7, tags_str.c_str(), -1, SQLITE_TRANSIENT);
    
    sqlite3_bind_int64(stmt, 8, video.uploaded_at == 0 ? static_cast<long long>(std::time(nullptr)) : video.uploaded_at);
    sqlite3_bind_int64(stmt, 9, video.views);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert video: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}

std::optional<Video> DatabaseManager::getVideoById(int id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::string sql = "SELECT id, title, description, file_path, thumbnail_path, user_id, category, tags, uploaded_at, views FROM videos WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return std::nullopt;
    }
    sqlite3_bind_int(stmt, 1, id);

    std::optional<Video> video_opt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        Video video;
        video.id = sqlite3_column_int(stmt, 0);
        video.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        video.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        video.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        video.thumbnail_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        video.user_id = sqlite3_column_int(stmt, 5);
        video.category = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));

        std::string tags_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        try {
            video.tags = nlohmann::json::parse(tags_str).get<std::vector<std::string>>();
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "Failed to parse video tags JSON: " << e.what() << std::endl;
            video.tags = {};
        }

        video.uploaded_at = sqlite3_column_int64(stmt, 8);
        video.views = sqlite3_column_int64(stmt, 9);
        video_opt = video;
    }
    sqlite3_finalize(stmt);
    return video_opt;
}

std::vector<Video> DatabaseManager::getAllVideos() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<Video> videos;
    std::string sql = "SELECT id, title, description, file_path, thumbnail_path, user_id, category, tags, uploaded_at, views FROM videos ORDER BY uploaded_at DESC;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return {};
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Video video;
        video.id = sqlite3_column_int(stmt, 0);
        video.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        video.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        video.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        video.thumbnail_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        video.user_id = sqlite3_column_int(stmt, 5);
        video.category = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));

        std::string tags_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        try {
            video.tags = nlohmann::json::parse(tags_str).get<std::vector<std::string>>();
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "Failed to parse video tags JSON: " << e.what() << std::endl;
            video.tags = {};
        }

        video.uploaded_at = sqlite3_column_int64(stmt, 8);
        video.views = sqlite3_column_int64(stmt, 9);
        videos.push_back(video);
    }
    sqlite3_finalize(stmt);
    return videos;
}

std::vector<Video> DatabaseManager::searchVideos(const std::string& query) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<Video> videos;
    std::string sql = "SELECT id, title, description, file_path, thumbnail_path, user_id, category, tags, uploaded_at, views FROM videos WHERE title LIKE ? OR description LIKE ? OR tags LIKE ? OR category LIKE ? ORDER BY uploaded_at DESC;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return {};
    }

    std::string search_param = "%" + query + "%";
    sqlite3_bind_text(stmt, 1, search_param.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, search_param.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, search_param.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, search_param.c_str(), -1, SQLITE_TRANSIENT);


    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Video video;
        video.id = sqlite3_column_int(stmt, 0);
        video.title = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        video.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        video.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        video.thumbnail_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        video.user_id = sqlite3_column_int(stmt, 5);
        video.category = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));

        std::string tags_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        try {
            video.tags = nlohmann::json::parse(tags_str).get<std::vector<std::string>>();
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "Failed to parse video tags JSON: " << e.what() << std::endl;
            video.tags = {};
        }

        video.uploaded_at = sqlite3_column_int64(stmt, 8);
        video.views = sqlite3_column_int64(stmt, 9);
        videos.push_back(video);
    }
    sqlite3_finalize(stmt);
    return videos;
}


bool DatabaseManager::incrementVideoViews(int video_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::string sql = "UPDATE videos SET views = views + 1 WHERE id = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        return false;
    }
    sqlite3_bind_int(stmt, 1, video_id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to increment video views: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);
    return true;
}
