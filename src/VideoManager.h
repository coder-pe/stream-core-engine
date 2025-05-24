#pragma once

#include "DatabaseManager.h"
#include "Config.h"
#include "HttpParser.h" // For HttpRequest::FilePart
#include <string>
#include <vector>
#include <filesystem>

class VideoManager {
public:
    VideoManager(DatabaseManager& db_manager, const ServerConfig& config);

    // Handles video upload from HttpRequest
    std::optional<Video> handleVideoUpload(const HttpRequest& request, int user_id);

    // Get list of videos
    std::vector<Video> getVideos(const std::string& query = "");

    // Get a specific video by ID
    std::optional<Video> getVideoDetails(int video_id);

    // Increment views
    bool incrementViews(int video_id);

private:
    DatabaseManager& db_manager_;
    const ServerConfig& config_;
    std::filesystem::path upload_path_;

    // Helper to generate a unique filename
    std::string generateUniqueFilename(const std::string& original_filename);
};
