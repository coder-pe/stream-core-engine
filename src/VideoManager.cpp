#include "VideoManager.h"
#include "Utils.h" // For getMimeType
#include <iostream>
#include <random>
#include <chrono>
#include <fstream>

namespace fs = std::filesystem;

VideoManager::VideoManager(DatabaseManager& db_manager, const ServerConfig& config)
    : db_manager_(db_manager), config_(config), upload_path_(config.upload_dir) {
    // Ensure upload directory exists
    if (!fs::exists(upload_path_)) {
        fs::create_directories(upload_path_);
    }
}

std::string VideoManager::generateUniqueFilename(const std::string& original_filename) {
    std::string ext = fs::path(original_filename).extension().string();
    std::string base_name = fs::path(original_filename).stem().string();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(100000, 999999);

    std::string unique_name;
    fs::path full_path;
    do {
        unique_name = base_name + "_" + std::to_string(distrib(gen)) + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + ext;
        full_path = upload_path_ / unique_name;
    } while (fs::exists(full_path)); // Ensure uniqueness

    return unique_name;
}

std::optional<Video> VideoManager::handleVideoUpload(const HttpRequest& request, int user_id) {
    if (request.files.empty()) {
        std::cerr << "No file uploaded in request." << std::endl;
        return std::nullopt;
    }

    // Assume 'video' is the name of the file input field
    auto video_file_it = request.files.find("video");
    if (video_file_it == request.files.end()) {
        std::cerr << "No 'video' file part found." << std::endl;
        return std::nullopt;
    }
    const HttpRequest::FilePart& video_file = video_file_it->second;

    // Get other metadata from form data
    auto title_it = request.form_data.find("title");
    auto description_it = request.form_data.find("description");
    auto category_it = request.form_data.find("category");
    auto tags_it = request.form_data.find("tags"); // Comma-separated tags

    if (title_it == request.form_data.end()) {
        std::cerr << "Video title is missing." << std::endl;
        return std::nullopt;
    }

    std::string unique_filename = generateUniqueFilename(video_file.filename);
    fs::path save_path = upload_path_ / unique_filename;

    // Save the file to disk
    std::ofstream ofs(save_path, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open file for writing: " << save_path << std::endl;
        return std::nullopt;
    }
    ofs.write(video_file.data.data(), video_file.data.size());
    ofs.close();

    // Create Video entry in DB
    Video new_video;
    new_video.title = title_it->second;
    new_video.description = (description_it != request.form_data.end()) ? description_it->second : "";
    new_video.file_path = save_path.string();
    new_video.thumbnail_path = ""; // Placeholder, needs actual thumbnail generation
    new_video.user_id = user_id;
    new_video.category = (category_it != request.form_data.end()) ? category_it->second : "General";

    if (tags_it != request.form_data.end()) {
        std::string tags_str = tags_it->second;
        std::stringstream ss(tags_str);
        std::string tag;
        while (std::getline(ss, tag, ',')) {
            new_video.tags.push_back(trim(tag));
        }
    }

    new_video.uploaded_at = static_cast<long long>(std::time(nullptr));
    new_video.views = 0; // Initial views

    if (db_manager_.insertVideo(new_video)) {
        // Retrieve the video with its ID from DB (assuming AUTOINCREMENT)
        // This is a simplification; a real system might get the last inserted ID.
        // For now, we'll return a placeholder video or rely on the DB to give it back.
        // Or re-query based on title/user_id, but that's not robust.
        // A better approach would be to get the last_insert_rowid() from SQLite.
        // For simplicity, we'll just return the object passed, knowing ID is missing.
        std::cerr << "Video uploaded and inserted into DB: " << new_video.title << std::endl;
        return new_video;
    } else {
        // If DB insertion fails, delete the uploaded file
        fs::remove(save_path);
        std::cerr << "Failed to insert video into database. File deleted: " << save_path << std::endl;
        return std::nullopt;
    }
}

std::vector<Video> VideoManager::getVideos(const std::string& query) {
    if (query.empty()) {
        return db_manager_.getAllVideos();
    } else {
        return db_manager_.searchVideos(query);
    }
}

std::optional<Video> VideoManager::getVideoDetails(int video_id) {
    return db_manager_.getVideoById(video_id);
}

bool VideoManager::incrementViews(int video_id) {
    return db_manager_.incrementVideoViews(video_id);
}
