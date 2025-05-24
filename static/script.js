document.addEventListener('DOMContentLoaded', () => {
    const sections = ['authSection', 'profileSection', 'uploadSection', 'videoListSection', 'videoDetailSection'];
    const showSection = (id) => {
        sections.forEach(sectionId => {
            document.getElementById(sectionId).style.display = 'none';
        });
        document.getElementById(id).style.display = 'block';
    };

    // Navigation links
    document.getElementById('homeLink').addEventListener('click', (e) => {
        e.preventDefault();
        showSection('videoListSection');
        loadVideos();
    });
    document.getElementById('uploadLink').addEventListener('click', (e) => {
        e.preventDefault();
        if (getToken()) {
            showSection('uploadSection');
        } else {
            alert('Please login as an instructor to upload videos.');
            showSection('authSection');
        }
    });
    document.getElementById('profileLink').addEventListener('click', (e) => {
        e.preventDefault();
        if (getToken()) {
            showSection('profileSection');
            loadProfile();
        } else {
            alert('Please login to view your profile.');
            showSection('authSection');
        }
    });
    document.getElementById('loginRegisterLink').addEventListener('click', (e) => {
        e.preventDefault();
        showSection('authSection');
    });
    document.getElementById('logoutLink').addEventListener('click', (e) => {
        e.preventDefault();
        localStorage.removeItem('jwtToken');
        updateAuthUI();
        showSection('authSection'); // Go to login/register page
        alert('You have been logged out.');
    });
    document.getElementById('backToVideos').addEventListener('click', (e) => {
        e.preventDefault();
        showSection('videoListSection');
        loadVideos();
    });

    // Helper functions for JWT and UI
    const getToken = () => localStorage.getItem('jwtToken');
    const setToken = (token) => localStorage.setItem('jwtToken', token);
    const getUserRole = () => {
        const token = getToken();
        if (!token) return null;
        try {
            const payloadBase64 = token.split('.')[1];
            const decodedPayload = JSON.parse(atob(payloadBase64));
            return decodedPayload.role;
        } catch (e) {
            console.error("Error decoding JWT:", e);
            return null;
        }
    };

    const updateAuthUI = () => {
        const token = getToken();
        const loginRegisterLink = document.getElementById('loginRegisterLink');
        const logoutLink = document.getElementById('logoutLink');
        const uploadLink = document.getElementById('uploadLink');

        if (token) {
            loginRegisterLink.style.display = 'none';
            logoutLink.style.display = 'inline';
            const role = getUserRole();
            if (role === 'instructor' || role === 'admin') {
                uploadLink.style.display = 'inline';
            } else {
                uploadLink.style.display = 'none';
            }
        } else {
            loginRegisterLink.style.display = 'inline';
            logoutLink.style.display = 'none';
            uploadLink.style.display = 'none';
        }
    };

    // Form Submissions
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = e.target.loginUsername.value;
        const password = e.target.loginPassword.value;
        const messageDiv = document.getElementById('loginMessage');

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await response.json();
            if (response.ok) {
                setToken(data.token);
                messageDiv.className = 'message success';
                messageDiv.textContent = data.message;
                updateAuthUI();
                showSection('profileSection');
                loadProfile(); // Load profile after successful login
            } else {
                messageDiv.className = 'message error';
                messageDiv.textContent = data.error;
            }
        } catch (error) {
            messageDiv.className = 'message error';
            messageDiv.textContent = 'Network error or server unavailable.';
        }
    });

    document.getElementById('registerForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = e.target.registerUsername.value;
        const email = e.target.registerEmail.value;
        const password = e.target.registerPassword.value;
        const role = e.target.registerRole.value;
        const messageDiv = document.getElementById('registerMessage');

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, password, role })
            });
            const data = await response.json();
            if (response.ok) {
                messageDiv.className = 'message success';
                messageDiv.textContent = data.message;
                e.target.reset(); // Clear form
            } else {
                messageDiv.className = 'message error';
                messageDiv.textContent = data.error;
            }
        } catch (error) {
            messageDiv.className = 'message error';
            messageDiv.textContent = 'Network error or server unavailable.';
        }
    });

    document.getElementById('uploadVideoForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const messageDiv = document.getElementById('uploadMessage');
        const token = getToken();

        if (!token) {
            messageDiv.className = 'message error';
            messageDiv.textContent = 'You must be logged in to upload videos.';
            return;
        }

        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                    // FormData automatically sets Content-Type for multipart
                },
                body: formData
            });
            const data = await response.json();
            if (response.ok) {
                messageDiv.className = 'message success';
                messageDiv.textContent = data.message;
                e.target.reset(); // Clear form
                loadVideos(); // Refresh video list
                showSection('videoListSection');
            } else {
                messageDiv.className = 'message error';
                messageDiv.textContent = data.error;
            }
        } catch (error) {
            messageDiv.className = 'message error';
            messageDiv.textContent = 'Network error or server unavailable.';
        }
    });

    // Load Profile
    const loadProfile = async () => {
        const token = getToken();
        if (!token) {
            document.getElementById('profileUsername').textContent = 'Not logged in';
            document.getElementById('profileRole').textContent = '';
            return;
        }

        try {
            const response = await fetch('/api/profile', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();
            if (response.ok) {
                document.getElementById('profileUsername').textContent = data.username;
                document.getElementById('profileRole').textContent = data.role;
            } else {
                console.error("Failed to load profile:", data.error);
                document.getElementById('profileUsername').textContent = 'Error loading profile';
                document.getElementById('profileRole').textContent = '';
                // If token is invalid/expired, log out
                if (response.status === 401 || response.status === 403) {
                    localStorage.removeItem('jwtToken');
                    updateAuthUI();
                    showSection('authSection');
                    alert('Session expired. Please log in again.');
                }
            }
        } catch (error) {
            console.error("Network error loading profile:", error);
            document.getElementById('profileUsername').textContent = 'Network error';
            document.getElementById('profileRole').textContent = '';
        }
    };


    // Load Videos
    const loadVideos = async (query = '') => {
        const videoListDiv = document.getElementById('videoList');
        const messageDiv = document.getElementById('videoListMessage');
        videoListDiv.innerHTML = '';
        messageDiv.textContent = 'Loading videos...';
        messageDiv.className = 'message';

        const token = getToken();
        const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
        const url = query ? `/api/videos?q=${encodeURIComponent(query)}` : '/api/videos';

        try {
            const response = await fetch(url, { headers });
            const data = await response.json();
            if (response.ok) {
                if (data.videos && data.videos.length > 0) {
                    data.videos.forEach(video => {
                        const videoItem = document.createElement('div');
                        videoItem.className = 'video-item';
                        videoItem.dataset.videoId = video.id; // Store video ID

                        // Simple placeholder for thumbnail
                        const thumbnailUrl = video.thumbnail_url || 'https://via.placeholder.com/280x180?text=Video+Thumbnail';
                        
                        videoItem.innerHTML = `
                            <img src="${thumbnailUrl}" alt="${video.title}">
                            <div class="video-item-info">
                                <h3>${video.title}</h3>
                                <p><strong>Category:</strong> ${video.category}</p>
                                <p><strong>Views:</strong> ${video.views}</p>
                            </div>
                        `;
                        videoItem.addEventListener('click', () => showVideoDetails(video.id));
                        videoListDiv.appendChild(videoItem);
                    });
                    messageDiv.textContent = '';
                } else {
                    messageDiv.className = 'message';
                    messageDiv.textContent = query ? 'No videos found for your search.' : 'No videos available yet.';
                }
            } else {
                messageDiv.className = 'message error';
                messageDiv.textContent = data.error || 'Failed to load videos.';
            }
        } catch (error) {
            messageDiv.className = 'message error';
            messageDiv.textContent = 'Network error or server unavailable.';
        }
    };

    // Search functionality
    document.getElementById('videoSearchButton').addEventListener('click', () => {
        const query = document.getElementById('videoSearchInput').value;
        loadVideos(query);
    });
    document.getElementById('videoSearchInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('videoSearchButton').click();
        }
    });


    // Show Video Details
    const showVideoDetails = async (videoId) => {
        const token = getToken();
        const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

        try {
            const response = await fetch(`/api/videos/details?id=${videoId}`, { headers });
            const data = await response.json();

            if (response.ok) {
                const video = data.video;
                document.getElementById('videoDetailTitle').textContent = video.title;
                document.getElementById('videoPlayer').src = video.file_url;
                document.getElementById('videoDetailDescription').textContent = video.description;
                document.getElementById('videoDetailCategory').textContent = video.category;
                document.getElementById('videoDetailTags').textContent = video.tags ? video.tags.join(', ') : 'None';
                // You'd fetch uploader's username via another API call based on video.user_id
                document.getElementById('videoDetailUploader').textContent = `User ID: ${video.user_id}`; // Placeholder
                document.getElementById('videoDetailViews').textContent = video.views;
                document.getElementById('videoDetailUploadedAt').textContent = new Date(video.uploaded_at * 1000).toLocaleString();

                showSection('videoDetailSection');
            } else {
                alert(data.error || 'Failed to load video details.');
                // If token invalid/expired, log out
                if (response.status === 401 || response.status === 403) {
                    localStorage.removeItem('jwtToken');
                    updateAuthUI();
                    showSection('authSection');
                    alert('Session expired. Please log in again.');
                }
            }
        } catch (error) {
            alert('Network error or server unavailable when loading video details.');
            console.error("Error loading video details:", error);
        }
    };


    // Initial setup
    updateAuthUI();
    showSection('videoListSection'); // Start on video list
    loadVideos(); // Load videos on initial page load
});
